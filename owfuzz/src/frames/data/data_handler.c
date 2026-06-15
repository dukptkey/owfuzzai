/* src/frames/data/data_handler.c */
#include "data.h"
#include "../frame_handler.h"

static struct packet data_create(struct ether_addr bssid,
                                  struct ether_addr smac,
                                  struct ether_addr dmac,
                                  struct packet *recv_pkt) {
    return create_data(bssid, smac, dmac, 0, recv_pkt);
}

static struct packet data_create_default(struct ether_addr bssid,
                                          struct ether_addr smac,
                                          struct ether_addr dmac,
                                          struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t data_handler = {
    .type           = IEEE80211_TYPE_DATA,
    .name           = "IEEE80211_TYPE_DATA",
    .create         = data_create,
    .create_default = data_create_default,
};

__attribute__((constructor))
static void data_handler_register(void) {
    frame_register(&data_handler);
}
