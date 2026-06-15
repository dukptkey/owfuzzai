/* src/frames/management/probe_response_handler.c */
#include "probe_response.h"
#include "../frame_handler.h"
#include "../../common/include.h"

extern fuzzing_option fuzzing_opt;

static struct packet probe_response_create(struct ether_addr bssid,
                                           struct ether_addr smac,
                                           struct ether_addr dmac,
                                           struct packet *recv_pkt) {
    (void)smac;
    if (recv_pkt)
        return create_probe_response(bssid, dmac, 0, NULL,
                                     recv_pkt->data + sizeof(struct ieee_hdr),
                                     recv_pkt->len - sizeof(struct ieee_hdr));
    return create_probe_response(bssid, dmac, 0, NULL, NULL, 0);
}

static struct packet probe_response_create_default(struct ether_addr bssid,
                                                   struct ether_addr smac,
                                                   struct ether_addr dmac,
                                                   struct packet *recv_pkt) {
    (void)smac; (void)dmac; (void)recv_pkt;
    return create_ap_probe_response(bssid, 0, fuzzing_opt.auth_type);
}

static const frame_handler_t probe_response_handler = {
    .type           = IEEE80211_TYPE_PROBERES,
    .name           = "IEEE80211_TYPE_PROBERES",
    .create         = probe_response_create,
    .create_default = probe_response_create_default,
};

__attribute__((constructor))
static void probe_response_handler_register(void) {
    frame_register(&probe_response_handler);
}
