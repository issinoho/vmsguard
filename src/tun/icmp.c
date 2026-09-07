/*
 * ICMP error generation — vmsguard
 */

#include <string.h>

#include "ethip.h"
#include "icmp.h"

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

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t) (v >> 8);
    p[1] = (uint8_t) (v & 0xFF);
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) ((v >> 24) & 0xFF);
    p[1] = (uint8_t) ((v >> 16) & 0xFF);
    p[2] = (uint8_t) ((v >> 8) & 0xFF);
    p[3] = (uint8_t) (v & 0xFF);
}

int ipv4_dont_fragment(const uint8_t *pkt, size_t len)
{
    if (len < IPV4_MIN_HDR)
        return 0;
    return (((uint16_t) pkt[6] << 8) | pkt[7]) & IPV4_FLAG_DF ? 1 : 0;
}

size_t icmp_frag_needed(uint8_t *out, size_t outcap, uint32_t src_addr,
                        const uint8_t *orig, size_t origlen,
                        uint16_t next_mtu)
{
    size_t orig_ihl, quote, icmplen, total;
    uint16_t ck;

    if (origlen < IPV4_MIN_HDR || (orig[0] >> 4) != 4)
        return 0;

    orig_ihl = (size_t) (orig[0] & 0x0F) * 4;
    if (orig_ihl < IPV4_MIN_HDR || orig_ihl > origlen)
        return 0;

    /*
     * RFC 792 quotes the original header plus eight bytes, which is
     * enough for the sender to match the message to a connection: for
     * TCP and UDP that covers both ports.
     */
    quote = orig_ihl + 8;
    if (quote > origlen)
        quote = origlen;

    icmplen = 8 + quote;
    total = IPV4_MIN_HDR + icmplen;
    if (total > outcap)
        return 0;

    memset(out, 0, total);

    out[0] = 0x45;
    put16(out + 2, (uint16_t) total);
    out[8] = 64;                        /* TTL      */
    out[9] = 1;                         /* ICMP     */
    put32(out + 12, src_addr);          /* us       */
    put32(out + 16, ipv4_src(orig));    /* whoever sent the big packet */

    ck = checksum(out, IPV4_MIN_HDR);
    put16(out + 10, ck);

    out[20] = ICMP_TYPE_DEST_UNREACH;
    out[21] = ICMP_CODE_FRAG_NEEDED;
    /* 22..23 checksum, 24..25 unused. */

    /*
     * The next-hop MTU, in the second half of what RFC 792 left unused.
     * RFC 1191 defines it, and without it a sender falls back to
     * guessing its way down a table of common MTUs.
     */
    put16(out + 26, next_mtu);

    memcpy(out + 28, orig, quote);

    ck = checksum(out + 20, icmplen);
    put16(out + 22, ck);

    return total;
}

/* ---- recognising the stack's own contradictions ---------------------- */

int icmp_error_from(const uint8_t *pkt, size_t len, uint32_t from_addr,
                    uint32_t *orig_dst, uint8_t *orig_proto)
{
    size_t ihl, orig_off, orig_ihl;
    uint8_t type;

    if (len < IPV4_MIN_HDR || (pkt[0] >> 4) != 4)
        return 0;
    if (pkt[9] != 1)                    /* not ICMP */
        return 0;
    if (ipv4_src(pkt) != from_addr)
        return 0;

    ihl = (size_t) (pkt[0] & 0x0F) * 4;
    if (ihl < IPV4_MIN_HDR || ihl + 8 > len)
        return 0;

    type = pkt[ihl];
    if (type != ICMP_TYPE_DEST_UNREACH && type != ICMP_TYPE_TIME_EXCEEDED)
        return 0;

    /*
     * The quoted original follows the eight-byte ICMP header. It must
     * be a whole IPv4 header for its destination to be readable — a
     * truncated quotation is not worth guessing at.
     */
    orig_off = ihl + 8;
    if (orig_off + IPV4_MIN_HDR > len)
        return 0;
    if ((pkt[orig_off] >> 4) != 4)
        return 0;
    orig_ihl = (size_t) (pkt[orig_off] & 0x0F) * 4;
    if (orig_ihl < IPV4_MIN_HDR || orig_off + orig_ihl > len)
        return 0;

    if (orig_dst != NULL)
        *orig_dst = ipv4_dst(pkt + orig_off);
    if (orig_proto != NULL)
        *orig_proto = pkt[orig_off + 9];
    return 1;
}
