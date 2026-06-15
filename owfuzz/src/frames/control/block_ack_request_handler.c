/* src/frames/control/block_ack_request_handler.c */
#include "block_ack_request.h"
#include "../frame_handler.h"

static struct packet block_ack_request_create(struct ether_addr bssid,
                                               struct ether_addr smac,
                                               struct ether_addr dmac,
                                               struct packet *recv_pkt) {
    (void)recv_pkt;
    return create_block_ack_request(bssid, smac, dmac);
}

static struct packet block_ack_request_create_default(struct ether_addr bssid,
                                                       struct ether_addr smac,
                                                       struct ether_addr dmac,
                                                       struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t block_ack_request_handler = {
    .type           = IEEE80211_TYPE_BLOCKACKREQ,
    .name           = "IEEE80211_TYPE_BLOCKACKREQ",
    .create         = block_ack_request_create,
    .create_default = block_ack_request_create_default,
};

__attribute__((constructor))
static void block_ack_request_handler_register(void) {
    frame_register(&block_ack_request_handler);
}
