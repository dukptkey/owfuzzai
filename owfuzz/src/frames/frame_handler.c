/* src/frames/frame_handler.c */
#include <stddef.h>
#include "frame_handler.h"

/* IEEE 802.11 type/subtype fits in one byte, so a flat 256-entry table is fine
 * and lookup is O(1). NULL means "not registered, fall back to legacy switch". */
static const frame_handler_t *handlers[256] = {0};

void frame_register(const frame_handler_t *h) {
    if (h) handlers[h->type] = h;
}

const frame_handler_t *frame_lookup(uint8_t type) {
    return handlers[type];
}
