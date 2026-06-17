/* frames/eapol_crypto.c — see eapol_crypto.h.
 * Self-contained SHA1 / HMAC-SHA1 / PBKDF2-SHA1 / 802.11i PRF, plus the WPA2 PTK
 * derivation and EAPOL-Key MIC. Validated offline against published test vectors
 * (SHA1 "abc", RFC 2202 HMAC, the WPA "password"/"IEEE" PMK vector).
 */
#include "eapol_crypto.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* ---------------- SHA1 ---------------- */
typedef struct { uint32_t s[5]; uint64_t bits; uint8_t buf[64]; size_t n; } sha1_ctx;

#define ROL(v, b) (((v) << (b)) | ((v) >> (32 - (b))))

static void sha1_block(uint32_t s[5], const uint8_t *p)
{
	uint32_t w[80], a, b, c, d, e, t;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
		       (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
	for (i = 16; i < 80; i++)
		w[i] = ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	a = s[0]; b = s[1]; c = s[2]; d = s[3]; e = s[4];
	for (i = 0; i < 80; i++) {
		if (i < 20)      t = ROL(a, 5) + ((b & c) | (~b & d)) + e + w[i] + 0x5A827999;
		else if (i < 40) t = ROL(a, 5) + (b ^ c ^ d) + e + w[i] + 0x6ED9EBA1;
		else if (i < 60) t = ROL(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[i] + 0x8F1BBCDC;
		else             t = ROL(a, 5) + (b ^ c ^ d) + e + w[i] + 0xCA62C1D6;
		e = d; d = c; c = ROL(b, 30); b = a; a = t;
	}
	s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e;
}

static void sha1_init(sha1_ctx *x)
{
	x->s[0] = 0x67452301; x->s[1] = 0xEFCDAB89; x->s[2] = 0x98BADCFE;
	x->s[3] = 0x10325476; x->s[4] = 0xC3D2E1F0; x->bits = 0; x->n = 0;
}

static void sha1_update(sha1_ctx *x, const uint8_t *p, size_t len)
{
	x->bits += (uint64_t)len * 8;
	while (len) {
		size_t k = 64 - x->n;
		if (k > len) k = len;
		memcpy(x->buf + x->n, p, k);
		x->n += k; p += k; len -= k;
		if (x->n == 64) { sha1_block(x->s, x->buf); x->n = 0; }
	}
}

static void sha1_final(sha1_ctx *x, uint8_t out[20])
{
	uint8_t pad = 0x80;
	uint8_t lenbe[8];
	uint64_t bits = x->bits;
	int i;

	for (i = 7; i >= 0; i--) { lenbe[i] = bits & 0xff; bits >>= 8; }
	sha1_update(x, &pad, 1);
	{ uint8_t z = 0; while (x->n != 56) sha1_update(x, &z, 1); }
	sha1_update(x, lenbe, 8);
	for (i = 0; i < 5; i++) {
		out[4 * i]     = x->s[i] >> 24; out[4 * i + 1] = x->s[i] >> 16;
		out[4 * i + 2] = x->s[i] >> 8;  out[4 * i + 3] = x->s[i];
	}
}

/* ---------------- HMAC-SHA1 (vector message) ---------------- */
static void hmac_sha1_v(const uint8_t *key, size_t klen, size_t nseg,
			const uint8_t *const *seg, const size_t *slen, uint8_t mac[20])
{
	uint8_t k[64], ipad[64], opad[64], tk[20], inner[20];
	sha1_ctx c;
	size_t i;

	if (klen > 64) {
		sha1_init(&c); sha1_update(&c, key, klen); sha1_final(&c, tk);
		key = tk; klen = 20;
	}
	memset(k, 0, 64); memcpy(k, key, klen);
	for (i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
	sha1_init(&c); sha1_update(&c, ipad, 64);
	for (i = 0; i < nseg; i++) sha1_update(&c, seg[i], slen[i]);
	sha1_final(&c, inner);
	sha1_init(&c); sha1_update(&c, opad, 64); sha1_update(&c, inner, 20);
	sha1_final(&c, mac);
}

static void hmac_sha1(const uint8_t *key, size_t klen, const uint8_t *data, size_t dlen, uint8_t mac[20])
{
	const uint8_t *seg[1] = { data };
	size_t slen[1] = { dlen };
	hmac_sha1_v(key, klen, 1, seg, slen, mac);
}

/* ---------------- PBKDF2-HMAC-SHA1 ---------------- */
static void pbkdf2_sha1(const char *pass, const uint8_t *salt, size_t saltlen,
			int iter, uint8_t *out, size_t outlen)
{
	size_t passlen = strlen(pass);
	uint32_t i = 1;

	while (outlen) {
		uint8_t u[20], t[20], ibe[4];
		const uint8_t *seg[2]; size_t slen[2];
		int j; size_t k, n;

		ibe[0] = i >> 24; ibe[1] = i >> 16; ibe[2] = i >> 8; ibe[3] = i;
		seg[0] = salt; slen[0] = saltlen; seg[1] = ibe; slen[1] = 4;
		hmac_sha1_v((const uint8_t *)pass, passlen, 2, seg, slen, u);
		memcpy(t, u, 20);
		for (j = 1; j < iter; j++) {
			hmac_sha1((const uint8_t *)pass, passlen, u, 20, u);
			for (k = 0; k < 20; k++) t[k] ^= u[k];
		}
		n = outlen < 20 ? outlen : 20;
		memcpy(out, t, n); out += n; outlen -= n; i++;
	}
}

/* ---------------- 802.11i SHA1 PRF (matches hostapd sha1_prf) ---------------- */
static void sha1_prf(const uint8_t *key, size_t klen, const char *label,
		     const uint8_t *data, size_t dlen, uint8_t *buf, size_t buflen)
{
	uint8_t counter = 0, hash[20];
	const uint8_t *seg[3]; size_t slen[3], pos = 0;

	seg[0] = (const uint8_t *)label; slen[0] = strlen(label) + 1;  /* label incl NUL */
	seg[1] = data;                   slen[1] = dlen;
	seg[2] = &counter;               slen[2] = 1;
	while (pos < buflen) {
		size_t plen = buflen - pos;
		if (plen >= 20) { hmac_sha1_v(key, klen, 3, seg, slen, &buf[pos]); pos += 20; }
		else { hmac_sha1_v(key, klen, 3, seg, slen, hash); memcpy(&buf[pos], hash, plen); break; }
		counter++;
	}
}

/* ---------------- EAPOL-Key field locating ---------------- */
/* EAPOL body offsets (from the EAPOL version byte): keyinfo 5-6, nonce 17-48, MIC 81-96. */
#define EK_KEYINFO 5
#define EK_NONCE   17
#define EK_MIC     81
#define KEY_INFO_MIC 0x0100  /* bit 8 (hi byte 0x01) */
#define KEY_INFO_ACK 0x0080  /* bit 7 (lo byte 0x80) */

static const uint8_t LLC_EAPOL[8] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e };

/* Return the offset of the EAPOL version byte in `frame`, or -1. */
static int eapol_off(const uint8_t *f, int len)
{
	int i, lim = len - 8; if (lim > 48) lim = 48;
	for (i = 0; i <= lim; i++)
		if (memcmp(f + i, LLC_EAPOL, 8) == 0)
			return i + 8;
	return -1;
}

static uint16_t key_info(const uint8_t *ek)
{
	return (uint16_t)ek[EK_KEYINFO] << 8 | ek[EK_KEYINFO + 1];
}

/* ---------------- state ---------------- */
static int g_enabled, g_anonce_set, g_need_derive;
static uint8_t g_pmk[32], g_anonce[32], g_snonce[32], g_kck[16];

int eapol_crypto_enabled(void) { return g_enabled; }

int eapol_crypto_init(const char *psk, const char *ssid)
{
	size_t i;

	if (!psk || !ssid || !*psk) return 0;
	pbkdf2_sha1(psk, (const uint8_t *)ssid, strlen(ssid), 4096, g_pmk, 32);
	srandom((unsigned)time(NULL) ^ (unsigned)(size_t)psk);
	for (i = 0; i < 32; i++) g_snonce[i] = (uint8_t)(random() & 0xff);
	g_enabled = 1; g_anonce_set = 0; g_need_derive = 0;
	return 1;
}

void eapol_crypto_observe(const uint8_t *frame, int len)
{
	int o = eapol_off(frame, len);
	if (o < 0 || o + EK_NONCE + 32 > len) return;
	if (frame[o + 1] != 0x03) return;                    /* EAPOL type = Key */
	if (!(key_info(frame + o) & KEY_INFO_ACK)) return;   /* M1/M3 carry ANonce */
	memcpy(g_anonce, frame + o + EK_NONCE, 32);
	g_anonce_set = 1; g_need_derive = 1;
}

static void derive_ptk(const uint8_t *aa, const uint8_t *spa)
{
	uint8_t data[76], ptk[48];
	const uint8_t *a1, *a2, *n1, *n2;

	a1 = (memcmp(aa, spa, 6) < 0) ? aa : spa;
	a2 = (a1 == aa) ? spa : aa;
	n1 = (memcmp(g_anonce, g_snonce, 32) < 0) ? g_anonce : g_snonce;
	n2 = (n1 == g_anonce) ? g_snonce : g_anonce;
	memcpy(data, a1, 6); memcpy(data + 6, a2, 6);
	memcpy(data + 12, n1, 32); memcpy(data + 44, n2, 32);
	sha1_prf(g_pmk, 32, "Pairwise key expansion", data, 76, ptk, 48);
	memcpy(g_kck, ptk, 16);
	g_need_derive = 0;
}

void eapol_crypto_sign(uint8_t *frame, int len, const uint8_t *aa, const uint8_t *spa)
{
	int o = eapol_off(frame, len);
	uint8_t mac[20];

	if (o < 0 || o + EK_MIC + 16 > len) return;
	if (frame[o + 1] != 0x03) return;
	if (!(key_info(frame + o) & KEY_INFO_MIC)) return;   /* only M2/M4 carry a MIC */
	if (!g_anonce_set) return;                            /* need the AP's ANonce first */

	if (g_need_derive) derive_ptk(aa, spa);
	memcpy(frame + o + EK_NONCE, g_snonce, 32);           /* our SNonce */
	memset(frame + o + EK_MIC, 0, 16);                    /* MIC computed over zeroed field */
	hmac_sha1(g_kck, 16, frame + o, len - o, mac);        /* HMAC-SHA1 over the EAPOL frame */
	memcpy(frame + o + EK_MIC, mac, 16);                  /* key-descriptor v2 -> first 16 bytes */
}
