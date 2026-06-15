/* src/frames/management/atim_handler.c */
#include "atim.h"
#include "../frame_handler.h"

static struct packet atim_create(struct ether_addr bssid,
                                  struct ether_addr smac,
                                  struct ether_addr dmac,
                                  struct packet *recv_pkt) {
    return create_atim(bssid, smac, dmac, 0, recv_pkt);
}

static struct packet atim_create_default(struct ether_addr bssid,
                                          struct ether_addr smac,
                                          struct ether_addr dmac,
                                          struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t atim_handler = {
    .type           = IEEE80211_TYPE_ATIM,
    .name           = "IEEE80211_TYPE_ATIM",
    .create         = atim_create,
    .create_default = atim_create_default,
};

__attribute__((constructor))
static void atim_handler_register(void) {
    frame_register(&atim_handler);
}
