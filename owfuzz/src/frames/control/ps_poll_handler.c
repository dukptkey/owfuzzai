/* src/frames/control/ps_poll_handler.c */
#include "ps_poll.h"
#include "../frame_handler.h"

static struct packet ps_poll_create(struct ether_addr bssid,
                                     struct ether_addr smac,
                                     struct ether_addr dmac,
                                     struct packet *recv_pkt) {
    (void)recv_pkt;
    return create_ps_poll(bssid, smac, dmac);
}

static struct packet ps_poll_create_default(struct ether_addr bssid,
                                             struct ether_addr smac,
                                             struct ether_addr dmac,
                                             struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t ps_poll_handler = {
    .type           = IEEE80211_TYPE_PSPOLL,
    .name           = "IEEE80211_TYPE_PSPOLL",
    .create         = ps_poll_create,
    .create_default = ps_poll_create_default,
};

__attribute__((constructor))
static void ps_poll_handler_register(void) {
    frame_register(&ps_poll_handler);
}
