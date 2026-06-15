/* src/frames/flow.c — see flow.h for the format. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "flow.h"
#include "ieee80211_def.h"

#define FLOW_MAX_RULES 64

static flow_rule_t g_rules[FLOW_MAX_RULES];
static int  g_nrules = 0;
static char g_cur[32] = "";
static char g_first[32] = "";
static int  g_started = 0; /* START already fired for g_cur */

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
	return 0xFF; /* unknown -> treat as START/never-match */
}

static char *trim(char *s)
{
	char *e;
	while (*s && isspace((unsigned char)*s))
		s++;
	e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = '\0';
	return s;
}

int flow_load(const char *path)
{
	FILE *fp = fopen(path, "r");
	char line[512];

	if (!fp) {
		fprintf(stderr, "[flow] fopen '%s' failed\n", path);
		return 0;
	}

	g_nrules = 0;
	while (fgets(line, sizeof(line), fp) && g_nrules < FLOW_MAX_RULES) {
		char *fields[4] = {0};
		int nf = 0;
		char *tok, *onrx, *snd, *m;
		char tyname[32] = "";
		flow_rule_t *r;

		if (line[0] == '#' || line[0] == '\n' || line[0] == '\r' || line[0] == '\0')
			continue;

		for (tok = strtok(line, "|"); tok && nf < 4; tok = strtok(NULL, "|"))
			fields[nf++] = tok;
		if (nf < 4)
			continue;

		r = &g_rules[g_nrules];
		memset(r, 0, sizeof(*r));
		r->match_off = -1;

		strncpy(r->in_state, trim(fields[0]), sizeof(r->in_state) - 1);

		onrx = trim(fields[1]);
		if (!strcmp(onrx, "START")) {
			r->on_rx_type = 0xFF;
		} else {
			unsigned int off, hb;
			if (sscanf(onrx, "%31s", tyname) == 1)
				r->on_rx_type = (uint8_t)type_from_name(tyname);
			m = strstr(onrx, "match=");
			if (m && sscanf(m + 6, "%u:%x", &off, &hb) == 2) {
				r->match_off = (int)off;
				r->match_byte = (uint8_t)hb;
			}
		}

		snd = trim(fields[2]);
		if (strcmp(snd, "-") != 0)
			strncpy(r->send_id, snd, sizeof(r->send_id) - 1);

		strncpy(r->goto_state, trim(fields[3]), sizeof(r->goto_state) - 1);

		if (g_nrules == 0)
			strncpy(g_first, r->in_state, sizeof(g_first) - 1);
		g_nrules++;
	}
	fclose(fp);

	strncpy(g_cur, g_first, sizeof(g_cur) - 1);
	g_started = 0;
	fprintf(stderr, "[flow] loaded %d rule(s); start state '%s'\n", g_nrules, g_cur);
	return g_nrules;
}

int flow_loaded(void) { return g_nrules > 0; }

const char *flow_cur_state(void) { return g_cur; }

void flow_set_state(const char *s)
{
	if (strcmp(g_cur, s) != 0) {
		strncpy(g_cur, s, sizeof(g_cur) - 1);
		g_cur[sizeof(g_cur) - 1] = '\0';
		g_started = 0; /* allow the new state's START (if any) to fire */
	}
}

void flow_reset(void)
{
	strncpy(g_cur, g_first, sizeof(g_cur) - 1);
	g_cur[sizeof(g_cur) - 1] = '\0';
	g_started = 0;
}

const flow_rule_t *flow_start_rule(void)
{
	int i;
	if (g_started)
		return NULL;
	for (i = 0; i < g_nrules; i++) {
		if (g_rules[i].on_rx_type == 0xFF && !strcmp(g_rules[i].in_state, g_cur)) {
			g_started = 1;
			return &g_rules[i];
		}
	}
	return NULL;
}

const flow_rule_t *flow_match_rule(struct packet *rx)
{
	int i;
	if (!rx || rx->len == 0)
		return NULL;
	for (i = 0; i < g_nrules; i++) {
		flow_rule_t *r = &g_rules[i];
		if (r->on_rx_type == 0xFF || strcmp(r->in_state, g_cur))
			continue;
		if (rx->data[0] != r->on_rx_type)
			continue;
		if (r->match_off >= 0 &&
		    ((unsigned int)r->match_off >= rx->len || rx->data[r->match_off] != r->match_byte))
			continue;
		return r;
	}
	return NULL;
}
