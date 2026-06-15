/* src/frames/control/cf_end_cf_ack_handler.c */
#include "cf_end_cf_ack.h"
#include "../frame_handler.h"

static struct packet cf_end_cf_ack_create(struct ether_addr bssid,
                                           struct ether_addr smac,
                                           struct ether_addr dmac,
                                           struct packet *recv_pkt) {
    (void)recv_pkt;
    return create_cf_end_cf_ack(bssid, smac, dmac);
}

static struct packet cf_end_cf_ack_create_default(struct ether_addr bssid,
                                                   struct ether_addr smac,
                                                   struct ether_addr dmac,
                                                   struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t cf_end_cf_ack_handler = {
    .type           = IEEE80211_TYPE_CFENDACK,
    .name           = "IEEE80211_TYPE_CFENDACK",
    .create         = cf_end_cf_ack_create,
    .create_default = cf_end_cf_ack_create_default,
};

__attribute__((constructor))
static void cf_end_cf_ack_handler_register(void) {
    frame_register(&cf_end_cf_ack_handler);
}
