/*
 * Ethernet and IPv4 header inspection — vmsguard
 */

#include <stdio.h>
#include <string.h>

#include "ethip.h"

/* Addresses are handled as big-endian 32-bit values throughout, built
   byte by byte so host byte order never enters into it. */
static uint32_t load32_be(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
           ((uint32_t) p[2] << 8)  |  (uint32_t) p[3];
}

const uint8_t *ethip_ipv4(const uint8_t *frame, size_t framelen,
                          size_t *iplen)
{
    const uint8_t *ip;
    size_t avail, ihl, total;
    uint16_t ethertype;

    if (framelen < ETH_HDR_LEN + IPV4_MIN_HDR)
        return NULL;

    ethertype = (uint16_t) (((uint16_t) frame[12] << 8) | frame[13]);
    if (ethertype != ETH_TYPE_IPV4)
        return NULL;

    ip = frame + ETH_HDR_LEN;
    avail = framelen - ETH_HDR_LEN;

    if ((ip[0] >> 4) != 4)
        return NULL;

    ihl = (size_t) (ip[0] & 0x0F) * 4;
    if (ihl < IPV4_MIN_HDR || ihl > avail)
        return NULL;

    total = ((size_t) ip[2] << 8) | ip[3];
    if (total < ihl || total > avail)
        return NULL;   /* truncated capture, or a length field we cannot trust */

    /*
     * Report the IP total length rather than what was captured.
     * Ethernet pads frames below 60 bytes, and forwarding that padding
     * as though it were packet data would corrupt what the far end
     * receives.
     */
    *iplen = total;
    return ip;
}

uint32_t ipv4_src(const uint8_t *ip)
{
    return load32_be(ip + 12);
}

uint32_t ipv4_dst(const uint8_t *ip)
{
    return load32_be(ip + 16);
}

uint8_t ipv4_proto(const uint8_t *ip)
{
    return ip[9];
}

int ipv4_in_subnet(uint32_t addr, uint32_t network, uint32_t mask)
{
    return (addr & mask) == (network & mask) ? 1 : 0;
}

int ethip_parse_cidr(const char *text, uint32_t *network, uint32_t *mask)
{
    unsigned a, b, c, d;
    unsigned bits = 32;
    char extra;
    int n;

    if (text == NULL)
        return -1;

    n = sscanf(text, "%u.%u.%u.%u/%u%c", &a, &b, &c, &d, &bits, &extra);
    if (n == 4) {
        bits = 32;               /* a bare address is a single host */
    } else if (n != 5) {
        return -1;               /* 6 means trailing rubbish */
    }

    if (a > 255 || b > 255 || c > 255 || d > 255 || bits > 32)
        return -1;

    *mask = (bits == 0) ? 0u : (uint32_t) (0xFFFFFFFFu << (32 - bits));
    *network = (((uint32_t) a << 24) | ((uint32_t) b << 16) |
                ((uint32_t) c << 8)  |  (uint32_t) d) & *mask;
    return 0;
}

void ipv4_format(char *out, size_t cap, uint32_t addr)
{
    snprintf(out, cap, "%u.%u.%u.%u",
             (unsigned) ((addr >> 24) & 0xFF),
             (unsigned) ((addr >> 16) & 0xFF),
             (unsigned) ((addr >> 8) & 0xFF),
             (unsigned) (addr & 0xFF));
}

int ipv4_in_any(const struct ipv4_subnet *list, int n, uint32_t addr)
{
    int i;

    for (i = 0; i < n; i++) {
        if (ipv4_in_subnet(addr, list[i].net, list[i].mask))
            return 1;
    }
    return 0;
}
