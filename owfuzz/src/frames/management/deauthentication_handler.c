/* src/frames/management/deauthentication_handler.c */
#include "deauthentication.h"
#include "../frame_handler.h"

static struct packet deauthentication_create(struct ether_addr bssid,
                                              struct ether_addr smac,
                                              struct ether_addr dmac,
                                              struct packet *recv_pkt) {
    return create_deauthentication(bssid, smac, dmac, 0, recv_pkt);
}

static struct packet deauthentication_create_default(struct ether_addr bssid,
                                                      struct ether_addr smac,
                                                      struct ether_addr dmac,
                                                      struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t deauthentication_handler = {
    .type           = IEEE80211_TYPE_DEAUTH,
    .name           = "IEEE80211_TYPE_DEAUTH",
    .create         = deauthentication_create,
    .create_default = deauthentication_create_default,
};

__attribute__((constructor))
static void deauthentication_handler_register(void) {
    frame_register(&deauthentication_handler);
}
