/* frames/ccmp.c — see ccmp.h.
 * Self-contained AES-128 + AES-CCM (RFC 3610 / SP800-38C, L=2) + 802.11 CCMP
 * framing. The AES-CCM core is validated against FIPS-197 and RFC 3610 PV#1.
 */
#include "ccmp.h"
#include <string.h>

/* ---------------- AES-128 (encrypt only) ---------------- */
static const uint8_t SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }

static void key_expand(const uint8_t key[16], uint8_t rk[176])
{
	uint8_t rcon = 1;
	int i;
	memcpy(rk, key, 16);
	for (i = 16; i < 176; i += 4) {
		uint8_t t[4];
		memcpy(t, rk + i - 4, 4);
		if (i % 16 == 0) {
			uint8_t tmp = t[0];
			t[0] = SBOX[t[1]] ^ rcon; t[1] = SBOX[t[2]];
			t[2] = SBOX[t[3]]; t[3] = SBOX[tmp];
			rcon = xtime(rcon);
		}
		rk[i + 0] = rk[i - 16 + 0] ^ t[0];
		rk[i + 1] = rk[i - 16 + 1] ^ t[1];
		rk[i + 2] = rk[i - 16 + 2] ^ t[2];
		rk[i + 3] = rk[i - 16 + 3] ^ t[3];
	}
}

static void aes_encrypt(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16])
{
	uint8_t s[16];
	int r, i;
	memcpy(s, in, 16);
	for (i = 0; i < 16; i++) s[i] ^= rk[i];
	for (r = 1; r <= 10; r++) {
		uint8_t t[16];
		for (i = 0; i < 16; i++) t[i] = SBOX[s[i]];
		/* ShiftRows */
		{ uint8_t a;
		  a = t[1];  t[1] = t[5];  t[5] = t[9];  t[9] = t[13]; t[13] = a;
		  a = t[2];  t[2] = t[10]; t[10] = a; a = t[6]; t[6] = t[14]; t[14] = a;
		  a = t[15]; t[15] = t[11]; t[11] = t[7]; t[7] = t[3]; t[3] = a; }
		if (r < 10) {
			for (i = 0; i < 16; i += 4) {
				uint8_t a0 = t[i], a1 = t[i+1], a2 = t[i+2], a3 = t[i+3];
				uint8_t x = a0 ^ a1 ^ a2 ^ a3;
				t[i+0] ^= x ^ xtime(a0 ^ a1);
				t[i+1] ^= x ^ xtime(a1 ^ a2);
				t[i+2] ^= x ^ xtime(a2 ^ a3);
				t[i+3] ^= x ^ xtime(a3 ^ a0);
			}
		}
		for (i = 0; i < 16; i++) s[i] = t[i] ^ rk[16 * r + i];
	}
	memcpy(out, s, 16);
}

/* ---------------- AES-CCM (L=2) ---------------- */
static void xor16(uint8_t *a, const uint8_t *b) { int i; for (i = 0; i < 16; i++) a[i] ^= b[i]; }

void aes_ccm_encrypt(const uint8_t key[16], const uint8_t *nonce, size_t nlen,
		     const uint8_t *aad, size_t alen,
		     const uint8_t *pt, size_t plen, int M,
		     uint8_t *ct, uint8_t *mic)
{
	uint8_t rk[176], x[16], b[16], s0[16], a[16], scratch[16];
	size_t i, off;
	uint32_t ctr;

	(void)nlen;  /* L=2 fixed -> nlen must be 13 */
	key_expand(key, rk);

	/* B0 = flags | nonce(13) | l(m) (2 bytes BE) */
	b[0] = (uint8_t)((alen ? 0x40 : 0) | (((M - 2) / 2) << 3) | 1);  /* L-1 = 1 */
	memcpy(b + 1, nonce, 13);
	b[14] = (uint8_t)(plen >> 8); b[15] = (uint8_t)plen;
	aes_encrypt(rk, b, x);

	/* AAD: 2-byte length prefix, then AAD, zero-padded to 16-byte blocks */
	if (alen) {
		memset(b, 0, 16);
		b[0] = (uint8_t)(alen >> 8); b[1] = (uint8_t)alen;
		off = 2;
		for (i = 0; i < alen; i++) {
			b[off++] = aad[i];
			if (off == 16) { xor16(x, b); aes_encrypt(rk, x, x); memset(b, 0, 16); off = 0; }
		}
		if (off) { xor16(x, b); aes_encrypt(rk, x, x); }
	}
	/* payload blocks (zero-padded) into the CBC-MAC */
	for (i = 0; i < plen; i += 16) {
		size_t n = plen - i < 16 ? plen - i : 16;
		memset(b, 0, 16); memcpy(b, pt + i, n);
		xor16(x, b); aes_encrypt(rk, x, x);
	}
	/* T = x[:M] (raw tag, to be encrypted with S0) */

	/* CTR: A_i = flags(L-1=1) | nonce(13) | counter(2 BE) */
	a[0] = 1; memcpy(a + 1, nonce, 13);
	a[14] = 0; a[15] = 0;
	aes_encrypt(rk, a, s0);                 /* S0 (counter 0) */
	for (i = 0; i < (size_t)M; i++) mic[i] = x[i] ^ s0[i];

	ctr = 1;
	for (i = 0; i < plen; i += 16) {
		size_t n = plen - i < 16 ? plen - i : 16, j;
		a[14] = (uint8_t)(ctr >> 8); a[15] = (uint8_t)ctr; ctr++;
		aes_encrypt(rk, a, scratch);
		for (j = 0; j < n; j++) ct[i + j] = pt[i + j] ^ scratch[j];
	}
}

/* ---------------- 802.11 CCMP framing ---------------- */
/* Non-QoS data MPDU only (priority 0, no A4). in = MAC header(24) + payload.
 * out = MAC header (Protected set) | CCMP header(8) | enc payload | MIC(8). */
int ccmp_protect(const uint8_t tk[16], const uint8_t *in, int ilen, const uint8_t pn[6], uint8_t *out)
{
	const int hdr = 24;
	uint8_t nonce[13], aad[22], mic[8];
	const uint8_t *a1 = in + 4, *a2 = in + 10, *a3 = in + 16;
	int plen = ilen - hdr;

	if (ilen < hdr) return -1;

	/* MAC header, Protected Frame bit set (FC octet1 bit 6 = 0x40) */
	memcpy(out, in, hdr);
	out[1] |= 0x40;

	/* CCMP header: PN0 PN1 Rsvd KeyId|ExtIV PN2 PN3 PN4 PN5 (pn[] is big-endian PN5..PN0) */
	out[hdr + 0] = pn[5]; out[hdr + 1] = pn[4]; out[hdr + 2] = 0x00; out[hdr + 3] = 0x20;
	out[hdr + 4] = pn[3]; out[hdr + 5] = pn[2]; out[hdr + 6] = pn[1]; out[hdr + 7] = pn[0];

	/* Nonce = flags(priority 0) | A2 | PN(big-endian) */
	nonce[0] = 0x00;
	memcpy(nonce + 1, a2, 6);
	memcpy(nonce + 7, pn, 6);

	/* AAD (non-QoS, no A4) = FC(masked) | A1 | A2 | A3 | SC(seq masked) */
	aad[0] = in[0];
	aad[1] = (uint8_t)(in[1] & ~0x38);          /* clear Retry/PwrMgmt/MoreData */
	memcpy(aad + 2, a1, 6);
	memcpy(aad + 8, a2, 6);
	memcpy(aad + 14, a3, 6);
	aad[20] = (uint8_t)(in[22] & 0x0f);          /* keep fragment number, mask sequence */
	aad[21] = 0x00;

	aes_ccm_encrypt(tk, nonce, 13, aad, sizeof(aad), in + hdr, plen, 8,
			out + hdr + 8, mic);
	memcpy(out + hdr + 8 + plen, mic, 8);
	return hdr + 8 + plen + 8;
}
