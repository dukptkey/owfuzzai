/* src/frames/control/acknowledgement_handler.c */
#include "acknowledgement.h"
#include "../frame_handler.h"

static struct packet acknowledgement_create(struct ether_addr bssid,
                                             struct ether_addr smac,
                                             struct ether_addr dmac,
                                             struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)recv_pkt;
    return create_ack(dmac);
}

static struct packet acknowledgement_create_default(struct ether_addr bssid,
                                                     struct ether_addr smac,
                                                     struct ether_addr dmac,
                                                     struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t acknowledgement_handler = {
    .type           = IEEE80211_TYPE_ACK,
    .name           = "IEEE80211_TYPE_ACK",
    .create         = acknowledgement_create,
    .create_default = acknowledgement_create_default,
};

__attribute__((constructor))
static void acknowledgement_handler_register(void) {
    frame_register(&acknowledgement_handler);
}
