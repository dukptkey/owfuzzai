/* src/frames/management/association_response_handler.c */
#include "association_response.h"
#include "../frame_handler.h"

static struct packet association_response_create(struct ether_addr bssid,
                                                 struct ether_addr smac,
                                                 struct ether_addr dmac,
                                                 struct packet *recv_pkt) {
    return create_association_response(bssid, smac, dmac, 0, recv_pkt);
}

static struct packet association_response_create_default(struct ether_addr bssid,
                                                         struct ether_addr smac,
                                                         struct ether_addr dmac,
                                                         struct packet *recv_pkt) {
    (void)recv_pkt;
    return create_ap_association_response(bssid, smac, dmac, 0);
}

static const frame_handler_t association_response_handler = {
    .type           = IEEE80211_TYPE_ASSOCRES,
    .name           = "IEEE80211_TYPE_ASSOCRES",
    .create         = association_response_create,
    .create_default = association_response_create_default,
};

__attribute__((constructor))
static void association_response_handler_register(void) {
    frame_register(&association_response_handler);
}
