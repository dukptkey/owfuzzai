/* src/frames/flow.h
 *
 * Generic, protocol-agnostic flow engine for stateful corpus fuzzing.
 *
 * The state machine is supplied as DATA (a flow file), not C — so owfuzz can
 * drive protocol flows whose states are not hardcoded in handle_*_auth /
 * enum wpa_states. The engine knows nothing about 802.11 semantics: it matches
 * received frames against rules, emits a corpus frame (by @send id), and moves
 * to the next state. States are arbitrary strings defined by the flow file.
 *
 * Flow file format (one rule per line; '#' and blank lines ignored):
 *   in_state | on_rx | send | goto_state
 * where:
 *   in_state    arbitrary state name (the first rule's in_state is the start).
 *   on_rx       START          -> spontaneous send on entering in_state, or
 *               <TYPE>         -> fires when a frame of that type is received, or
 *               <TYPE> match=OFF:HH  -> also requires rx->data[OFF] == 0xHH
 *               (<TYPE> names match corpus.c, e.g. AUTH, ASSOCRES, ACTION).
 *   send        @send id of the corpus frame(s) to emit ('-' = send nothing).
 *   goto_state  state to move to after firing.
 *
 * Example (WPA3 SAE, owfuzz as STA fuzzing the AP):
 *   INIT         | START            | sae_commit  | COMMIT_SENT
 *   COMMIT_SENT  | AUTH match=24:03 | sae_confirm | CONFIRM_SENT
 *   CONFIRM_SENT | AUTH match=24:03 | -           | DONE
 */
#ifndef FLOW_H
#define FLOW_H

#include <stdint.h>
#include "frame.h" /* struct packet */

typedef struct {
	char    in_state[32];
	uint8_t on_rx_type; /* IEEE80211_TYPE_*; 0xFF = START (spontaneous) */
	int     match_off;  /* body-byte match offset, -1 = none */
	uint8_t match_byte;
	char    send_id[32]; /* corpus @send id; "" = send nothing */
	char    goto_state[32];
} flow_rule_t;

int         flow_load(const char *path); /* parse flow file; returns rule count */
int         flow_loaded(void);           /* 1 if a flow table is active */
const char *flow_cur_state(void);
void        flow_set_state(const char *s);
void        flow_reset(void); /* back to the start state; clear "started" latch */

/* START rule for the current state, returned at most once per state entry
 * (NULL after it has fired, until the state changes). */
const flow_rule_t *flow_start_rule(void);

/* Reactive rule matching the current state and a received frame, or NULL. */
const flow_rule_t *flow_match_rule(struct packet *rx);

/* REPEAT rule for the current state (fires every loop iteration; no once-guard), or NULL. */
const flow_rule_t *flow_repeat_rule(void);

#endif /* FLOW_H */
