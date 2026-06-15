/* src/frames/data/data_null_handler.c */
#include "data_null.h"
#include "../frame_handler.h"

static struct packet data_null_create(struct ether_addr bssid,
                                       struct ether_addr smac,
                                       struct ether_addr dmac,
                                       struct packet *recv_pkt) {
    return create_data_null(bssid, smac, dmac, 0, recv_pkt);
}

static struct packet data_null_create_default(struct ether_addr bssid,
                                               struct ether_addr smac,
                                               struct ether_addr dmac,
                                               struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t data_null_handler = {
    .type           = IEEE80211_TYPE_NULL,
    .name           = "IEEE80211_TYPE_NULL",
    .create         = data_null_create,
    .create_default = data_null_create_default,
};

__attribute__((constructor))
static void data_null_handler_register(void) {
    frame_register(&data_null_handler);
}
