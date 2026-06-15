/* src/frames/control/control_wrapper_handler.c */
#include "control_wrapper.h"
#include "../frame_handler.h"

static struct packet control_wrapper_create(struct ether_addr bssid,
                                             struct ether_addr smac,
                                             struct ether_addr dmac,
                                             struct packet *recv_pkt) {
    (void)recv_pkt;
    return create_control_wrapper(bssid, smac, dmac);
}

static struct packet control_wrapper_create_default(struct ether_addr bssid,
                                                     struct ether_addr smac,
                                                     struct ether_addr dmac,
                                                     struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t control_wrapper_handler = {
    .type           = IEEE80211_TYPE_CTRLWRAP,
    .name           = "IEEE80211_TYPE_CTRLWRAP",
    .create         = control_wrapper_create,
    .create_default = control_wrapper_create_default,
};

__attribute__((constructor))
static void control_wrapper_handler_register(void) {
    frame_register(&control_wrapper_handler);
}
