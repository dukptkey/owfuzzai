/* src/frames/management/timing_advertisement_handler.c */
#include "timing_advertisement.h"
#include "../frame_handler.h"

static struct packet timing_advertisement_create(struct ether_addr bssid,
                                                  struct ether_addr smac,
                                                  struct ether_addr dmac,
                                                  struct packet *recv_pkt) {
    (void)smac; (void)recv_pkt;
    return create_timing_advertisement(bssid, dmac, 0);
}

static struct packet timing_advertisement_create_default(struct ether_addr bssid,
                                                          struct ether_addr smac,
                                                          struct ether_addr dmac,
                                                          struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t timing_advertisement_handler = {
    .type           = IEEE80211_TYPE_TIMADVERT,
    .name           = "IEEE80211_TYPE_TIMADVERT",
    .create         = timing_advertisement_create,
    .create_default = timing_advertisement_create_default,
};

__attribute__((constructor))
static void timing_advertisement_handler_register(void) {
    frame_register(&timing_advertisement_handler);
}
