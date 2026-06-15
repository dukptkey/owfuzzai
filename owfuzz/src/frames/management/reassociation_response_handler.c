/* src/frames/management/reassociation_response_handler.c */
#include "reassociation_response.h"
#include "../frame_handler.h"

static struct packet reassociation_response_create(struct ether_addr bssid,
                                                    struct ether_addr smac,
                                                    struct ether_addr dmac,
                                                    struct packet *recv_pkt) {
    (void)smac; (void)recv_pkt;
    return create_reassociation_response(bssid, dmac, 0);
}

static struct packet reassociation_response_create_default(struct ether_addr bssid,
                                                            struct ether_addr smac,
                                                            struct ether_addr dmac,
                                                            struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t reassociation_response_handler = {
    .type           = IEEE80211_TYPE_REASSOCRES,
    .name           = "IEEE80211_TYPE_REASSOCRES",
    .create         = reassociation_response_create,
    .create_default = reassociation_response_create_default,
};

__attribute__((constructor))
static void reassociation_response_handler_register(void) {
    frame_register(&reassociation_response_handler);
}
