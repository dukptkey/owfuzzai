/* src/frames/management/beacon_handler.c */
#include "beacon.h"
#include "../frame_handler.h"
#include "../../common/include.h"

extern fuzzing_option fuzzing_opt;

static struct packet beacon_create(struct ether_addr bssid,
                                   struct ether_addr smac,
                                   struct ether_addr dmac,
                                   struct packet *recv_pkt) {
    (void)smac; (void)dmac; (void)recv_pkt;
    return create_beacon(bssid, 0, NULL);
}

static struct packet beacon_create_default(struct ether_addr bssid,
                                           struct ether_addr smac,
                                           struct ether_addr dmac,
                                           struct packet *recv_pkt) {
    (void)smac; (void)dmac; (void)recv_pkt;
    return create_ap_beacon(bssid, 0, fuzzing_opt.auth_type);
}

static const frame_handler_t beacon_handler = {
    .type           = IEEE80211_TYPE_BEACON,
    .name           = "IEEE80211_TYPE_BEACON",
    .create         = beacon_create,
    .create_default = beacon_create_default,
};

__attribute__((constructor))
static void beacon_handler_register(void) {
    frame_register(&beacon_handler);
}
