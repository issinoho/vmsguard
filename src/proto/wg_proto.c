/*
 * WireGuard wire format helpers — vmsguard
 *
 * Explicit little-endian conversion, independent of host byte order.
 */

#include "wg_proto.h"

void wg_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) (v & 0xFF);
    p[1] = (uint8_t) ((v >> 8) & 0xFF);
    p[2] = (uint8_t) ((v >> 16) & 0xFF);
    p[3] = (uint8_t) ((v >> 24) & 0xFF);
}

uint32_t wg_get32(const uint8_t *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) |
           ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

void wg_put64(uint8_t *p, uint64_t v)
{
    int i;

    for (i = 0; i < 8; i++)
        p[i] = (uint8_t) ((v >> (8 * i)) & 0xFF);
}

uint64_t wg_get64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;

    for (i = 7; i >= 0; i--)
        v = (v << 8) | (uint64_t) p[i];
    return v;
}
