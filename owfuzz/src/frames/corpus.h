/* src/frames/corpus.h
 *
 * State-tagged corpus for stateful (-T 1 -p) corpus injection.
 *
 * A corpus file uses owfuzz's existing replay format (one frame per line as
 * \xHH bytes) plus directive comments that tag the following frame(s) with the
 * protocol state and frame type they belong to, e.g.:
 *
 *     # @state=AUTHENTICATING @type=AUTH
 *     \xb0\x00...                          <- mutated Authentication frame
 *
 * Parsed once at startup; lookup keyed by (wpa_state, frame_type). Untagged
 * frames (no directive) fall back to state=DISCONNECTED and a type derived from
 * the frame's own FC octet, so legacy corpora still load.
 */
#ifndef CORPUS_H
#define CORPUS_H

#include <stdint.h>
#include "frame.h" /* struct packet, enum wpa_states, str_to_hex, IEEE80211_TYPE_* */

/* Load one or more comma-separated corpus files. Returns # of frames loaded. */
int corpus_load(const char *paths);

/* Fetch the next corpus frame tagged for (state, frame_type). Returns 1 and
 * fills *out on hit (round-robin across variants for that slot), else 0. */
int corpus_lookup(enum wpa_states state, uint8_t frame_type, struct packet *out);

/* Fetch the next corpus frame tagged @send=send_id (round-robin across variants),
 * used by the flow engine. Returns 1 and fills *out on hit, else 0. */
int corpus_lookup_send(const char *send_id, struct packet *out);

#endif /* CORPUS_H */
