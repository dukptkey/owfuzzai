/* src/frames/control/vht_ndp_announcement_handler.c */
#include "vht_ndp_announcement.h"
#include "../frame_handler.h"

static struct packet vht_ndp_announcement_create(struct ether_addr bssid,
                                                  struct ether_addr smac,
                                                  struct ether_addr dmac,
                                                  struct packet *recv_pkt) {
    (void)recv_pkt;
    return create_vht_ndp_announcement(bssid, smac, dmac);
}

static struct packet vht_ndp_announcement_create_default(struct ether_addr bssid,
                                                          struct ether_addr smac,
                                                          struct ether_addr dmac,
                                                          struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t vht_ndp_announcement_handler = {
    .type           = IEEE80211_TYPE_VHT,
    .name           = "IEEE80211_TYPE_VHT",
    .create         = vht_ndp_announcement_create,
    .create_default = vht_ndp_announcement_create_default,
};

__attribute__((constructor))
static void vht_ndp_announcement_handler_register(void) {
    frame_register(&vht_ndp_announcement_handler);
}
