/*
 * IP-in-IP encapsulation — vmsguard
 */

#include <string.h>

#include "encap.h"

#define IPV4_HDR 20

/* The largest inner packet worth wrapping. Beyond this the outer packet
   would exceed a normal Ethernet MTU and be fragmented, which the
   receiving stack would have to reassemble before it could even see the
   tunnel — possible, but not something to do by accident. */
#define ENCAP_MAX_INNER 1480

static uint16_t checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i + 1 < len; i += 2)
        sum += ((uint32_t) data[i] << 8) | data[i + 1];
    if (i < len)
        sum += (uint32_t) data[i] << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t) (~sum & 0xFFFF);
}

size_t ip4_encap(uint8_t *out, size_t cap, uint32_t src, uint32_t dst,
                 uint8_t proto, uint16_t id,
                 const uint8_t *inner, size_t innerlen)
{
    size_t total = IPV4_HDR + innerlen;
    uint16_t ck;

    if (innerlen == 0 || innerlen > ENCAP_MAX_INNER || total > cap)
        return 0;

    memset(out, 0, IPV4_HDR);
    out[0] = 0x45;                              /* version 4, 20-byte hdr */
    out[2] = (uint8_t) (total >> 8);
    out[3] = (uint8_t) (total & 0xFF);
    out[4] = (uint8_t) (id >> 8);
    out[5] = (uint8_t) (id & 0xFF);
    /*
     * Fragment field left zero: not DF. The outer packet travels no
     * further than this machine's own input path, so there is no path
     * MTU to discover, and forbidding fragmentation could only turn a
     * deliverable packet into a rejected one.
     */
    out[8] = 64;                                /* TTL */
    out[9] = proto;
    out[12] = (uint8_t) (src >> 24);
    out[13] = (uint8_t) (src >> 16);
    out[14] = (uint8_t) (src >> 8);
    out[15] = (uint8_t) src;
    out[16] = (uint8_t) (dst >> 24);
    out[17] = (uint8_t) (dst >> 16);
    out[18] = (uint8_t) (dst >> 8);
    out[19] = (uint8_t) dst;

    ck = checksum(out, IPV4_HDR);
    out[10] = (uint8_t) (ck >> 8);
    out[11] = (uint8_t) (ck & 0xFF);

    memcpy(out + IPV4_HDR, inner, innerlen);
    return total;
}
