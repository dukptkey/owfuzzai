/* src/frames/control/block_ack_handler.c */
#include "block_ack.h"
#include "../frame_handler.h"

static struct packet block_ack_create(struct ether_addr bssid,
                                       struct ether_addr smac,
                                       struct ether_addr dmac,
                                       struct packet *recv_pkt) {
    (void)recv_pkt;
    return create_block_ack(bssid, smac, dmac);
}

static struct packet block_ack_create_default(struct ether_addr bssid,
                                               struct ether_addr smac,
                                               struct ether_addr dmac,
                                               struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t block_ack_handler = {
    .type           = IEEE80211_TYPE_BLOCKACK,
    .name           = "IEEE80211_TYPE_BLOCKACK",
    .create         = block_ack_create,
    .create_default = block_ack_create_default,
};

__attribute__((constructor))
static void block_ack_handler_register(void) {
    frame_register(&block_ack_handler);
}
