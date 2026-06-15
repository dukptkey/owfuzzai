/* src/frames/management/reassociation_request_handler.c */
#include "reassociation_request.h"
#include "../frame_handler.h"

static struct packet reassociation_request_create(struct ether_addr bssid,
                                                   struct ether_addr smac,
                                                   struct ether_addr dmac,
                                                   struct packet *recv_pkt) {
    return create_reassociation_request(bssid, smac, dmac, 0, recv_pkt);
}

static struct packet reassociation_request_create_default(struct ether_addr bssid,
                                                           struct ether_addr smac,
                                                           struct ether_addr dmac,
                                                           struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t reassociation_request_handler = {
    .type           = IEEE80211_TYPE_REASSOCREQ,
    .name           = "IEEE80211_TYPE_REASSOCREQ",
    .create         = reassociation_request_create,
    .create_default = reassociation_request_create_default,
};

__attribute__((constructor))
static void reassociation_request_handler_register(void) {
    frame_register(&reassociation_request_handler);
}
