/* src/frames/management/action_no_ack_handler.c */
#include "action_no_ack.h"
#include "../frame_handler.h"

static struct packet action_no_ack_create(struct ether_addr bssid,
                                           struct ether_addr smac,
                                           struct ether_addr dmac,
                                           struct packet *recv_pkt) {
    return create_action_no_ack(bssid, smac, dmac, 0, recv_pkt);
}

static struct packet action_no_ack_create_default(struct ether_addr bssid,
                                                   struct ether_addr smac,
                                                   struct ether_addr dmac,
                                                   struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t action_no_ack_handler = {
    .type           = IEEE80211_TYPE_ACTIONNOACK,
    .name           = "IEEE80211_TYPE_ACTIONNOACK",
    .create         = action_no_ack_create,
    .create_default = action_no_ack_create_default,
};

__attribute__((constructor))
static void action_no_ack_handler_register(void) {
    frame_register(&action_no_ack_handler);
}
