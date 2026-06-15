/* src/frames/control/cts_handler.c */
#include "cts.h"
#include "../frame_handler.h"

static struct packet cts_create(struct ether_addr bssid,
                                 struct ether_addr smac,
                                 struct ether_addr dmac,
                                 struct packet *recv_pkt) {
    (void)recv_pkt;
    return create_cts(bssid, smac, dmac);
}

static struct packet cts_create_default(struct ether_addr bssid,
                                         struct ether_addr smac,
                                         struct ether_addr dmac,
                                         struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t cts_handler = {
    .type           = IEEE80211_TYPE_CTS,
    .name           = "IEEE80211_TYPE_CTS",
    .create         = cts_create,
    .create_default = cts_create_default,
};

__attribute__((constructor))
static void cts_handler_register(void) {
    frame_register(&cts_handler);
}
