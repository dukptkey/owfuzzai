/* src/frames/data/qos_data_cf_poll_handler.c */
#include "qos_data_cf_poll.h"
#include "../frame_handler.h"

static struct packet qos_data_cf_poll_create(struct ether_addr bssid,
                                              struct ether_addr smac,
                                              struct ether_addr dmac,
                                              struct packet *recv_pkt) {
    return create_qos_data_cf_poll(bssid, smac, dmac, 0, recv_pkt);
}

static struct packet qos_data_cf_poll_create_default(struct ether_addr bssid,
                                                      struct ether_addr smac,
                                                      struct ether_addr dmac,
                                                      struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t qos_data_cf_poll_handler = {
    .type           = IEEE80211_TYPE_QOSDATACFPOLL,
    .name           = "IEEE80211_TYPE_QOSDATACFPOLL",
    .create         = qos_data_cf_poll_create,
    .create_default = qos_data_cf_poll_create_default,
};

__attribute__((constructor))
static void qos_data_cf_poll_handler_register(void) {
    frame_register(&qos_data_cf_poll_handler);
}
