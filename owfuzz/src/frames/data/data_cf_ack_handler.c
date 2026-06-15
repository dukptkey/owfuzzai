/* src/frames/data/data_cf_ack_handler.c */
#include "data_cf_ack.h"
#include "../frame_handler.h"

static struct packet data_cf_ack_create(struct ether_addr bssid,
                                         struct ether_addr smac,
                                         struct ether_addr dmac,
                                         struct packet *recv_pkt) {
    return create_data_cf_ack(bssid, smac, dmac, 0, recv_pkt);
}

static struct packet data_cf_ack_create_default(struct ether_addr bssid,
                                                  struct ether_addr smac,
                                                  struct ether_addr dmac,
                                                  struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t data_cf_ack_handler = {
    .type           = IEEE80211_TYPE_DATACFACK,
    .name           = "IEEE80211_TYPE_DATACFACK",
    .create         = data_cf_ack_create,
    .create_default = data_cf_ack_create_default,
};

__attribute__((constructor))
static void data_cf_ack_handler_register(void) {
    frame_register(&data_cf_ack_handler);
}
