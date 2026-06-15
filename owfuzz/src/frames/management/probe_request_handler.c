/* src/frames/management/probe_request_handler.c */
#include "probe_request.h"
#include "../frame_handler.h"

static struct packet probe_request_create(struct ether_addr bssid,
                                          struct ether_addr smac,
                                          struct ether_addr dmac,
                                          struct packet *recv_pkt) {
    return create_probe_request(bssid, smac, dmac, 0, recv_pkt);
}

static struct packet probe_request_create_default(struct ether_addr bssid,
                                                   struct ether_addr smac,
                                                   struct ether_addr dmac,
                                                   struct packet *recv_pkt) {
    (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t probe_request_handler = {
    .type           = IEEE80211_TYPE_PROBEREQ,
    .name           = "IEEE80211_TYPE_PROBEREQ",
    .create         = probe_request_create,
    .create_default = probe_request_create_default,
};

__attribute__((constructor))
static void probe_request_handler_register(void) {
    frame_register(&probe_request_handler);
}
