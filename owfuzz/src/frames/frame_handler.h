/* src/frames/frame_handler.h */
#ifndef FRAME_HANDLER_H
#define FRAME_HANDLER_H

#include <stdint.h>
#include "80211_packet_common.h"

typedef struct frame_handler {
    uint8_t      type;          /* IEEE80211_TYPE_* */
    const char  *name;          /* "IEEE80211_TYPE_BEACON" etc. */

    struct packet (*create)(struct ether_addr bssid,
                            struct ether_addr smac,
                            struct ether_addr dmac,
                            struct packet *recv_pkt);

    struct packet (*create_default)(struct ether_addr bssid,
                                    struct ether_addr smac,
                                    struct ether_addr dmac,
                                    struct packet *recv_pkt);
} frame_handler_t;

void                    frame_register(const frame_handler_t *h);
const frame_handler_t  *frame_lookup(uint8_t type);

#endif
