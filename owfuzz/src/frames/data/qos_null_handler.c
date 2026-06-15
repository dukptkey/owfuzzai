/* src/frames/data/qos_null_handler.c */
#include "qos_null.h"
#include "../frame_handler.h"

static struct packet qos_null_create(struct ether_addr bssid,
                                      struct ether_addr smac,
                                      struct ether_addr dmac,
                                      struct packet *recv_pkt) {
    return create_qos_null(bssid, smac, dmac, 0, recv_pkt);
}

static struct packet qos_null_create_default(struct ether_addr bssid,
                                              struct ether_addr smac,
                                              struct ether_addr dmac,
                                              struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t qos_null_handler = {
    .type           = IEEE80211_TYPE_QOSNULL,
    .name           = "IEEE80211_TYPE_QOSNULL",
    .create         = qos_null_create,
    .create_default = qos_null_create_default,
};

__attribute__((constructor))
static void qos_null_handler_register(void) {
    frame_register(&qos_null_handler);
}
