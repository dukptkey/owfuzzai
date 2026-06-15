/* src/frames/data/d_cf_ack_handler.c */
#include "d_cf_ack.h"
#include "../frame_handler.h"

static struct packet d_cf_ack_create(struct ether_addr bssid,
                                      struct ether_addr smac,
                                      struct ether_addr dmac,
                                      struct packet *recv_pkt) {
    return create_d_cf_ack(bssid, smac, dmac, 0, recv_pkt);
}

static struct packet d_cf_ack_create_default(struct ether_addr bssid,
                                              struct ether_addr smac,
                                              struct ether_addr dmac,
                                              struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t d_cf_ack_handler = {
    .type           = IEEE80211_TYPE_CFACK,
    .name           = "IEEE80211_TYPE_CFACK",
    .create         = d_cf_ack_create,
    .create_default = d_cf_ack_create_default,
};

__attribute__((constructor))
static void d_cf_ack_handler_register(void) {
    frame_register(&d_cf_ack_handler);
}
