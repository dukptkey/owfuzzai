/* src/frames/control/control_frame_extension_handler.c */
#include "control_frame_extension.h"
#include "../frame_handler.h"

static struct packet control_frame_extension_create(struct ether_addr bssid,
                                                     struct ether_addr smac,
                                                     struct ether_addr dmac,
                                                     struct packet *recv_pkt) {
    (void)recv_pkt;
    return create_control_frame_extension(bssid, smac, dmac);
}

static struct packet control_frame_extension_create_default(struct ether_addr bssid,
                                                             struct ether_addr smac,
                                                             struct ether_addr dmac,
                                                             struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t control_frame_extension_handler = {
    .type           = IEEE80211_TYPE_CTRLFRMEXT,
    .name           = "IEEE80211_TYPE_CTRLFRMEXT",
    .create         = control_frame_extension_create,
    .create_default = control_frame_extension_create_default,
};

__attribute__((constructor))
static void control_frame_extension_handler_register(void) {
    frame_register(&control_frame_extension_handler);
}
