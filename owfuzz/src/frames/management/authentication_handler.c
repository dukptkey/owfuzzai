/* src/frames/management/authentication_handler.c */
#include "authentication.h"
#include "../frame_handler.h"

static struct packet authentication_create(struct ether_addr bssid,
                                           struct ether_addr smac,
                                           struct ether_addr dmac,
                                           struct packet *recv_pkt) {
    return create_authentication(bssid, smac, dmac, 0, recv_pkt);
}

static struct packet authentication_create_default(struct ether_addr bssid,
                                                   struct ether_addr smac,
                                                   struct ether_addr dmac,
                                                   struct packet *recv_pkt) {
    (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t authentication_handler = {
    .type           = IEEE80211_TYPE_AUTH,
    .name           = "IEEE80211_TYPE_AUTH",
    .create         = authentication_create,
    .create_default = authentication_create_default,
};

__attribute__((constructor))
static void authentication_handler_register(void) {
    frame_register(&authentication_handler);
}
