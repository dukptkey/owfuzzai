/* frames/ccmp.h — AES-128-CCM and 802.11 CCMP framing for owfuzz.
 *
 * Lets owfuzz encrypt a fuzzed data frame with a session Temporal Key (TK) so a
 * post-association AP decrypts and parses it — reaching the encrypted-data parser
 * surface. The TK comes from the 4-way PTK (eapol_crypto, bytes 32..47 for CCMP).
 *
 * Self-contained crypto (no external lib). The AES-CCM core is validated offline
 * against FIPS-197 (AES) and RFC 3610 Packet Vector #1 (CCM with L=2, M=8, Nlen=13
 * — exactly the 802.11 CCMP parameters).
 */
#ifndef CCMP_H
#define CCMP_H

#include <stdint.h>
#include <stddef.h>

/* Generic AES-128-CCM (L=2, so 13-byte nonce; M = MIC length in bytes).
 * Encrypts `plen` bytes of `pt` in place into `ct` (caller-sized >= plen), and
 * writes the M-byte MIC to `mic`. `aad`/`alen` is the additional authenticated data. */
void aes_ccm_encrypt(const uint8_t key[16], const uint8_t *nonce, size_t nlen,
		     const uint8_t *aad, size_t alen,
		     const uint8_t *pt, size_t plen, int M,
		     uint8_t *ct, uint8_t *mic);

/* 802.11 CCMP-protect a plaintext MPDU (24/26-byte MAC header + payload).
 * `in`/`ilen` = the full plaintext frame; `tk` = 16-byte Temporal Key; `pn` = the
 * 6-byte Packet Number (big-endian PN5..PN0). Writes the protected MPDU to `out`
 * (MAC header | 8-byte CCMP header | encrypted payload | 8-byte MIC), sets the
 * Protected bit, and returns the protected length, or -1 on error. `out` must hold
 * ilen + 16 bytes. Non-QoS data frames only (priority 0). */
int ccmp_protect(const uint8_t tk[16], const uint8_t *in, int ilen,
		 const uint8_t pn[6], uint8_t *out);

#endif
