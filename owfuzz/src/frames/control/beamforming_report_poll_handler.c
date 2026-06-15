/* src/frames/control/beamforming_report_poll_handler.c */
#include "beamforming_report_poll.h"
#include "../frame_handler.h"

static struct packet beamforming_report_poll_create(struct ether_addr bssid,
                                                     struct ether_addr smac,
                                                     struct ether_addr dmac,
                                                     struct packet *recv_pkt) {
    (void)recv_pkt;
    return create_beamforming_report_poll(bssid, smac, dmac);
}

static struct packet beamforming_report_poll_create_default(struct ether_addr bssid,
                                                             struct ether_addr smac,
                                                             struct ether_addr dmac,
                                                             struct packet *recv_pkt) {
    (void)bssid; (void)smac; (void)dmac; (void)recv_pkt;
    struct packet pkt = {0};
    return pkt;
}

static const frame_handler_t beamforming_report_poll_handler = {
    .type           = IEEE80211_TYPE_BEAMFORMING,
    .name           = "IEEE80211_TYPE_BEAMFORMING",
    .create         = beamforming_report_poll_create,
    .create_default = beamforming_report_poll_create_default,
};

__attribute__((constructor))
static void beamforming_report_poll_handler_register(void) {
    frame_register(&beamforming_report_poll_handler);
}
