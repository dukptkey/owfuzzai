/* src/frames/corpus.c — see corpus.h for the format. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "corpus.h"
#include "ieee80211_def.h"

/* enum wpa_states currently has <= 11 members; 16 is a safe upper bound for the
 * per-slot round-robin cursor table. */
#define CORPUS_NUM_STATES 16

/* Flat list of tagged frames + per-(state,type) cursors. The corpus is small
 * (hundreds of frames) and lookups happen a handful of times per handshake, so
 * a linear scan is fine and avoids a multi-hundred-MB [state][type] table. */
typedef struct {
	enum wpa_states st;
	uint8_t ty;
	char send_id[32]; /* flow-engine key (@send=...); "" if untagged */
	struct packet pkt;
} corpus_entry_t;

static corpus_entry_t *g_entries = NULL;
static int g_count = 0;
static int g_cap = 0;
static uint16_t g_cursor[CORPUS_NUM_STATES][256];

/* round-robin cursors for send-id lookups (flow engine) */
#define MAX_SEND_IDS 32
static struct { char id[32]; uint16_t cur; } g_send_cursors[MAX_SEND_IDS];
static int g_send_cursor_cnt = 0;

static uint16_t *send_cursor(const char *id)
{
	int i;
	for (i = 0; i < g_send_cursor_cnt; i++)
		if (!strcmp(g_send_cursors[i].id, id))
			return &g_send_cursors[i].cur;
	if (g_send_cursor_cnt < MAX_SEND_IDS) {
		strncpy(g_send_cursors[g_send_cursor_cnt].id, id, 31);
		g_send_cursors[g_send_cursor_cnt].cur = 0;
		return &g_send_cursors[g_send_cursor_cnt++].cur;
	}
	return &g_send_cursors[0].cur;
}

static enum wpa_states state_from_name(const char *s)
{
	if (!strcmp(s, "DISCONNECTED"))    return WPA_DISCONNECTED;
	if (!strcmp(s, "SCANNING"))        return WPA_SCANNING;
	if (!strcmp(s, "AUTHENTICATING"))  return WPA_AUTHENTICATING;
	if (!strcmp(s, "ASSOCIATING"))     return WPA_ASSOCIATING;
	if (!strcmp(s, "ASSOCIATED"))      return WPA_ASSOCIATED;
	if (!strcmp(s, "EAP_HANDSHAKE"))   return WPA_EAP_HANDSHAKE;
	if (!strcmp(s, "4WAY_HANDSHAKE"))  return WPA_4WAY_HANDSHAKE;
	if (!strcmp(s, "GROUP_HANDSHAKE")) return WPA_GROUP_HANDSHAKE;
	if (!strcmp(s, "COMPLETED"))       return WPA_COMPLETED;
	return WPA_DISCONNECTED;
}

/* -1 = unknown (caller derives type from the frame's FC octet). */
static int type_from_name(const char *s)
{
	if (!strcmp(s, "BEACON"))     return IEEE80211_TYPE_BEACON;
	if (!strcmp(s, "PROBEREQ"))   return IEEE80211_TYPE_PROBEREQ;
	if (!strcmp(s, "PROBERES"))   return IEEE80211_TYPE_PROBERES;
	if (!strcmp(s, "AUTH"))       return IEEE80211_TYPE_AUTH;
	if (!strcmp(s, "ASSOCREQ"))   return IEEE80211_TYPE_ASSOCREQ;
	if (!strcmp(s, "ASSOCRES"))   return IEEE80211_TYPE_ASSOCRES;
	if (!strcmp(s, "REASSOCREQ")) return IEEE80211_TYPE_REASSOCREQ;
	if (!strcmp(s, "REASSOCRES")) return IEEE80211_TYPE_REASSOCRES;
	if (!strcmp(s, "DEAUTH"))     return IEEE80211_TYPE_DEAUTH;
	if (!strcmp(s, "DISASSOC"))   return IEEE80211_TYPE_DISASSOC;
	if (!strcmp(s, "ACTION"))     return IEEE80211_TYPE_ACTION;
	if (!strcmp(s, "QOSDATA"))    return IEEE80211_TYPE_QOSDATA;
	if (!strcmp(s, "DATA"))       return IEEE80211_TYPE_DATA;
	return -1;
}

static void parse_directive(const char *line, enum wpa_states *st, int *ty, char *send)
{
	const char *p;
	char buf[64];

	p = strstr(line, "@state=");
	if (p && sscanf(p + 7, "%63[A-Z0-9_]", buf) == 1)
		*st = state_from_name(buf);

	p = strstr(line, "@type=");
	if (p && sscanf(p + 6, "%63[A-Z0-9_]", buf) == 1) {
		int t = type_from_name(buf);
		if (t >= 0)
			*ty = t;
	}

	p = strstr(line, "@send=");
	if (p && sscanf(p + 6, "%63[A-Za-z0-9_]", buf) == 1)
		strncpy(send, buf, 31);
}

static void add_entry(enum wpa_states st, uint8_t ty, const char *send_id,
		      const struct packet *pkt)
{
	if (g_count == g_cap) {
		int nc = g_cap ? g_cap * 2 : 256;
		corpus_entry_t *ne = realloc(g_entries, (size_t)nc * sizeof(*ne));
		if (!ne)
			return;
		g_entries = ne;
		g_cap = nc;
	}
	g_entries[g_count].st = st;
	g_entries[g_count].ty = ty;
	g_entries[g_count].send_id[0] = '\0';
	if (send_id)
		strncpy(g_entries[g_count].send_id, send_id, 31);
	g_entries[g_count].pkt = *pkt;
	g_count++;
}

static int load_one(const char *path)
{
	FILE *fp = fopen(path, "r");
	char line[8192];
	enum wpa_states st = WPA_DISCONNECTED;
	int ty = -1;
	char send[32] = "";
	int count = 0;

	if (!fp) {
		fprintf(stderr, "[corpus] fopen '%s' failed\n", path);
		return 0;
	}

	while (fgets(line, sizeof(line), fp)) {
		struct packet pkt;
		int key;

		if (line[0] == '#') {
			parse_directive(line, &st, &ty, send);
			continue;
		}
		if (line[0] == '\n' || line[0] == '\r' || line[0] == '\0')
			continue;

		memset(&pkt, 0, sizeof(pkt));
		pkt.len = str_to_hex(line, pkt.data, sizeof(pkt.data));
		if (pkt.len == 0)
			continue;

		key = (ty >= 0) ? ty : pkt.data[0]; /* derive from FC octet if untyped */
		add_entry(st, (uint8_t)key, send, &pkt);
		count++;
	}

	fclose(fp);
	return count;
}

int corpus_load(const char *paths)
{
	char buf[1024];
	char *tok;
	int total = 0;

	strncpy(buf, paths, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	for (tok = strtok(buf, ","); tok; tok = strtok(NULL, ","))
		total += load_one(tok);

	fprintf(stderr, "[corpus] loaded %d state-tagged frame(s)\n", total);
	return total;
}

/* Type-primary lookup with state as a preferred refinement. The protocol moment
 * is already enforced by the C FSM (a frame is only injected when the handler
 * reaches that point), so the corpus just supplies the bytes: if any frame of
 * this type is tagged for this exact state, pick among those; otherwise fall
 * back to any frame of this type regardless of state tag. This keeps a tagged
 * corpus usable even when the injecting handler's wpa_s differs from the tag,
 * while still honoring state to disambiguate recurring types (QOSDATA/DATA). */
static int pick_match(enum wpa_states state, uint8_t frame_type, int use_state,
		      struct packet *out)
{
	int matches = 0, pick, i;

	for (i = 0; i < g_count; i++)
		if (g_entries[i].ty == frame_type && (!use_state || g_entries[i].st == state))
			matches++;
	if (matches == 0)
		return 0;

	pick = g_cursor[state][frame_type] % matches;
	g_cursor[state][frame_type]++;

	for (i = 0; i < g_count; i++) {
		if (g_entries[i].ty == frame_type && (!use_state || g_entries[i].st == state)) {
			if (pick-- == 0) {
				*out = g_entries[i].pkt;
				return 1;
			}
		}
	}
	return 0;
}

int corpus_lookup(enum wpa_states state, uint8_t frame_type, struct packet *out)
{
	if ((int)state < 0 || (int)state >= CORPUS_NUM_STATES)
		return 0;
	if (pick_match(state, frame_type, 1, out)) /* prefer exact (state,type) */
		return 1;
	return pick_match(state, frame_type, 0, out); /* fall back to type-only */
}

/* Flow-engine lookup: next corpus frame tagged @send=send_id (round-robin across
 * the mutation variants sharing that id). Returns 1 and fills *out on hit. */
int corpus_lookup_send(const char *send_id, struct packet *out)
{
	int matches = 0, pick, i;
	uint16_t *cur;

	if (!send_id || !send_id[0])
		return 0;

	for (i = 0; i < g_count; i++)
		if (!strcmp(g_entries[i].send_id, send_id))
			matches++;
	if (matches == 0)
		return 0;

	cur = send_cursor(send_id);
	pick = (*cur)++ % matches;

	for (i = 0; i < g_count; i++) {
		if (!strcmp(g_entries[i].send_id, send_id)) {
			if (pick-- == 0) {
				*out = g_entries[i].pkt;
				return 1;
			}
		}
	}
	return 0;
}
