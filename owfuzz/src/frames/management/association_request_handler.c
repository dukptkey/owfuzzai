/* src/frames/management/association_request_handler.c */
#include "association_request.h"
#include "../frame_handler.h"

static struct packet association_request_create(struct ether_addr bssid,
                                                struct ether_addr smac,
                                                struct ether_addr dmac,
                                                struct packet *recv_pkt) {
    return create_association_request(bssid, smac, dmac, 0, recv_pkt);
}

static struct packet association_request_create_default(struct ether_addr bssid,
                                                        struct ether_addr smac,
                                                        struct ether_addr dmac,
                                                        struct packet *recv_pkt) {
    (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t association_request_handler = {
    .type           = IEEE80211_TYPE_ASSOCREQ,
    .name           = "IEEE80211_TYPE_ASSOCREQ",
    .create         = association_request_create,
    .create_default = association_request_create_default,
};

__attribute__((constructor))
static void association_request_handler_register(void) {
    frame_register(&association_request_handler);
}
