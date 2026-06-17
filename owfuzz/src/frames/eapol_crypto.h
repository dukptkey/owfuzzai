/* frames/eapol_crypto.h — optional WPA2 4-way MIC signing for owfuzz (-K).
 *
 * When a PSK is provided (-K), owfuzz can complete the 4-way handshake: it stashes
 * the AP's ANonce from M1, derives the PTK (PMK from the PSK+SSID, then PRF over the
 * nonces+MACs), and writes a valid SNonce + Key MIC into the (possibly fuzzed) M2/M4
 * before sending. This lifts fuzzing past the MIC gate into the post-authentication
 * surface. Self-contained crypto (SHA1/HMAC/PBKDF2/PRF) — no external lib. See
 * corpusgen/samples/wpa2_4way_crypto.md for the design.
 */
#ifndef EAPOL_CRYPTO_H
#define EAPOL_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* Derive the PMK from psk+ssid and enable signing. Returns 1 on success, 0 otherwise. */
int eapol_crypto_init(const char *psk, const char *ssid);

/* 1 if -K signing is enabled. */
int eapol_crypto_enabled(void);

/* Copy out the CCMP Temporal Key (PTK[32..47]) once a PTK has been derived (after
 * an M1 was observed and an M2/M4 signed). Returns 1 if available, else 0. Lets the
 * CCMP layer encrypt post-association data frames with the session key. */
int eapol_crypto_get_tk(uint8_t tk[16]);

/* Inspect a received frame; if it is an EAPOL-Key with the ACK flag (M1/M3), stash its
 * Key Nonce as the ANonce so the next M2/M4 can be signed. */
void eapol_crypto_observe(const uint8_t *frame, int len);

/* If `frame` is an outgoing EAPOL-Key with the MIC flag (M2/M4) and an ANonce is known,
 * write our SNonce into the Key Nonce field, zero the MIC field, and write a valid
 * HMAC-SHA1 MIC (key-descriptor version 2). aa = AP MAC, spa = our STA MAC (6 bytes each). */
void eapol_crypto_sign(uint8_t *frame, int len, const uint8_t *aa, const uint8_t *spa);

#endif
