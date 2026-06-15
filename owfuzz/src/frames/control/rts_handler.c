/* src/frames/control/rts_handler.c */
#include "rts.h"
#include "../frame_handler.h"

static struct packet rts_create(struct ether_addr bssid,
                                 struct ether_addr smac,
                                 struct ether_addr dmac,
                                 struct packet *recv_pkt) {
    (void)recv_pkt;
    return create_rts(bssid, smac, dmac);
}

static struct packet rts_create_default(struct ether_addr bssid,
                                         struct ether_addr smac,
                                         struct ether_addr dmac,
                                         struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t rts_handler = {
    .type           = IEEE80211_TYPE_RTS,
    .name           = "IEEE80211_TYPE_RTS",
    .create         = rts_create,
    .create_default = rts_create_default,
};

__attribute__((constructor))
static void rts_handler_register(void) {
    frame_register(&rts_handler);
}
