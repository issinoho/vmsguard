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

int ipv4_best_match(const struct ipv4_subnet *list, int n, uint32_t addr,
                    uint32_t *mask)
{
    int found = 0;
    uint32_t best = 0;
    int i;

    for (i = 0; i < n; i++) {
        if (!ipv4_in_subnet(addr, list[i].net, list[i].mask))
            continue;
        if (!found || list[i].mask > best) {
            best = list[i].mask;
            found = 1;
        }
    }
    if (found && mask != NULL)
        *mask = best;
    return found;
}

/* ---- IPv6 ------------------------------------------------------------ */

const uint8_t *ethip_ipv6(const uint8_t *frame, size_t framelen,
                          size_t *iplen)
{
    size_t off = 14;
    uint16_t type;
    size_t payload;

    if (framelen < off + IPV6_MIN_HDR)
        return NULL;

    type = (uint16_t) ((frame[12] << 8) | frame[13]);

    /* One VLAN tag, as the IPv4 path allows. */
    if (type == 0x8100) {
        if (framelen < off + 4 + IPV6_MIN_HDR)
            return NULL;
        type = (uint16_t) ((frame[16] << 8) | frame[17]);
        off += 4;
    }
    if (type != 0x86DD)
        return NULL;

    if ((frame[off] >> 4) != 6)
        return NULL;

    /*
     * The header's own length, not what was captured. An Ethernet frame
     * is padded to 60 bytes and tunnelling the padding would corrupt
     * the packet -- the same reasoning as ethip_ipv4.
     */
    payload = ((size_t) frame[off + 4] << 8) | frame[off + 5];
    if (off + IPV6_MIN_HDR + payload > framelen)
        return NULL;

    *iplen = IPV6_MIN_HDR + payload;
    return frame + off;
}

const uint8_t *ipv6_src(const uint8_t *pkt)
{
    return pkt + 8;
}

const uint8_t *ipv6_dst(const uint8_t *pkt)
{
    return pkt + 24;
}

int ipv6_looks_valid(const uint8_t *pkt, size_t len)
{
    size_t payload;

    if (len < IPV6_MIN_HDR || (pkt[0] >> 4) != 6)
        return 0;
    payload = ((size_t) pkt[4] << 8) | pkt[5];
    return IPV6_MIN_HDR + payload <= len;
}

int ipv6_in_subnet(const uint8_t *addr, const uint8_t *net, uint8_t prefix)
{
    size_t whole = (size_t) prefix / 8;
    unsigned bits = (unsigned) prefix % 8;

    if (prefix > 128)
        return 0;
    if (whole > 0 && memcmp(addr, net, whole) != 0)
        return 0;
    if (bits != 0) {
        /* The partial byte, masked to the bits the prefix covers. */
        uint8_t mask = (uint8_t) (0xFF << (8 - bits));
        if (((addr[whole] ^ net[whole]) & mask) != 0)
            return 0;
    }
    return 1;
}

int ipv6_in_any(const struct ipv6_subnet *list, int n, const uint8_t *addr)
{
    int i;

    for (i = 0; i < n; i++) {
        if (ipv6_in_subnet(addr, list[i].net, list[i].prefix))
            return 1;
    }
    return 0;
}

int ipv6_best_match(const struct ipv6_subnet *list, int n,
                    const uint8_t *addr, uint8_t *prefix)
{
    int found = 0;
    uint8_t best = 0;
    int i;

    for (i = 0; i < n; i++) {
        if (!ipv6_in_subnet(addr, list[i].net, list[i].prefix))
            continue;
        if (!found || list[i].prefix > best) {
            best = list[i].prefix;
            found = 1;
        }
    }
    if (found && prefix != NULL)
        *prefix = best;
    return found;
}

/* ---- text ------------------------------------------------------------ */

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int ethip_parse_cidr6(const char *text, uint8_t net[16], uint8_t *prefix)
{
    uint8_t groups[8][2];
    int ngroups = 0;
    int gap = -1;           /* where "::" appeared, in groups */
    const char *p = text;
    long plen = 128;
    int i;

    memset(net, 0, 16);

    /* Leading "::" is the only case where a colon may start the text. */
    if (p[0] == ':' && p[1] != ':')
        return -1;

    while (*p != '\0' && *p != '/') {
        int digits = 0;
        unsigned long v = 0;

        if (*p == ':') {
            p++;
            if (*p == ':') {
                if (gap >= 0)
                    return -1;      /* only one "::" is allowed */
                gap = ngroups;
                p++;
                if (*p == '\0' || *p == '/')
                    break;
            } else if (ngroups == 0) {
                return -1;
            }
            continue;
        }

        while (hexval(*p) >= 0) {
            if (++digits > 4)
                return -1;
            v = v * 16 + (unsigned long) hexval(*p);
            p++;
        }
        if (digits == 0)
            return -1;
        if (ngroups >= 8)
            return -1;
        groups[ngroups][0] = (uint8_t) (v >> 8);
        groups[ngroups][1] = (uint8_t) (v & 0xFF);
        ngroups++;

        if (*p != ':' && *p != '\0' && *p != '/')
            return -1;
    }

    if (gap < 0) {
        if (ngroups != 8)
            return -1;
    } else if (ngroups >= 8) {
        return -1;              /* "::" must stand for at least one group */
    }

    /* Groups before the gap sit at the front, those after at the back. */
    for (i = 0; i < gap || (gap < 0 && i < ngroups); i++)
        memcpy(net + i * 2, groups[i], 2);
    if (gap >= 0) {
        int tail = ngroups - gap;
        for (i = 0; i < tail; i++)
            memcpy(net + (8 - tail + i) * 2, groups[gap + i], 2);
    }

    if (*p == '/') {
        const char *q = ++p;
        int d = 0;

        plen = 0;
        while (*q >= '0' && *q <= '9') {
            plen = plen * 10 + (*q - '0');
            if (++d > 3)
                return -1;
            q++;
        }
        if (d == 0 || *q != '\0' || plen > 128)
            return -1;
    }

    *prefix = (uint8_t) plen;
    return 0;
}

void ipv6_format(char *out, size_t cap, const uint8_t *addr)
{
    uint16_t g[8];
    int best_at = -1, best_len = 0;
    int run_at = -1, run_len = 0;
    size_t n = 0;
    int i;

    for (i = 0; i < 8; i++)
        g[i] = (uint16_t) ((addr[i * 2] << 8) | addr[i * 2 + 1]);

    /* Longest run of zero groups, which is what "::" replaces. A run of
       one is left alone: "::" saves nothing and reads worse. */
    for (i = 0; i < 8; i++) {
        if (g[i] == 0) {
            if (run_at < 0) {
                run_at = i;
                run_len = 0;
            }
            run_len++;
            if (run_len > best_len) {
                best_at = run_at;
                best_len = run_len;
            }
        } else {
            run_at = -1;
        }
    }
    if (best_len < 2)
        best_at = -1;

    if (cap == 0)
        return;
    out[0] = '\0';
    for (i = 0; i < 8; i++) {
        int written;

        if (i == best_at) {
            written = snprintf(out + n, cap - n, "::");
            if (written < 0 || (size_t) written >= cap - n)
                return;
            n += (size_t) written;
            i += best_len - 1;
            continue;
        }
        written = snprintf(out + n, cap - n, "%s%x",
                           (n > 0 && out[n - 1] != ':') ? ":" : "", g[i]);
        if (written < 0 || (size_t) written >= cap - n)
            return;
        n += (size_t) written;
    }
}
