/* src/frames/control/cf_end_handler.c */
#include "cf_end.h"
#include "../frame_handler.h"

static struct packet cf_end_create(struct ether_addr bssid,
                                    struct ether_addr smac,
                                    struct ether_addr dmac,
                                    struct packet *recv_pkt) {
    (void)recv_pkt;
    return create_cf_end(bssid, smac, dmac);
}

static struct packet cf_end_create_default(struct ether_addr bssid,
                                            struct ether_addr smac,
                                            struct ether_addr dmac,
                                            struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t cf_end_handler = {
    .type           = IEEE80211_TYPE_CFEND,
    .name           = "IEEE80211_TYPE_CFEND",
    .create         = cf_end_create,
    .create_default = cf_end_create_default,
};

__attribute__((constructor))
static void cf_end_handler_register(void) {
    frame_register(&cf_end_handler);
}
