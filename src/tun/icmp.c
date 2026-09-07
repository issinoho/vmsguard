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
    if (type == ICMP_TYPE_DEST_UNREACH) {
        uint8_t code = pkt[ihl + 1];

        /*
         * Routing failures only. Port and protocol unreachable are a
         * host answering about itself, and fragmentation-needed is what
         * this gateway sends on purpose — it captures its own injected
         * packets, so counting those would report the MTU feature
         * working as the stack misbehaving.
         */
        if (code != ICMP_CODE_NET_UNREACH &&
            code != ICMP_CODE_HOST_UNREACH &&
            code != ICMP_CODE_NET_UNKNOWN &&
            code != ICMP_CODE_HOST_UNKNOWN)
            return 0;
    } else if (type != ICMP_TYPE_TIME_EXCEEDED) {
        return 0;
    }

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

/* ---- ICMPv6 ---------------------------------------------------------- */

/*
 * The pseudo-header sum. RFC 4443 section 2.3 defines it as the IPv6
 * source and destination, the ICMPv6 length as 32 bits, three zero
 * bytes and the next-header value -- which is 58 regardless of what the
 * real IPv6 header's Next Header field says, since extension headers do
 * not change what the checksum covers.
 *
 * Accumulated separately from the message rather than by building a
 * scratch buffer: the message can be 1280 bytes and this runs per
 * oversized packet, so there is no reason to copy it.
 */
uint16_t icmp6_checksum(const uint8_t *src, const uint8_t *dst,
                        const uint8_t *msg, size_t msglen)
{
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i < 16; i += 2)
        sum += ((uint32_t) src[i] << 8) | src[i + 1];
    for (i = 0; i < 16; i += 2)
        sum += ((uint32_t) dst[i] << 8) | dst[i + 1];

    sum += (uint32_t) (msglen >> 16) & 0xFFFF;
    sum += (uint32_t) msglen & 0xFFFF;
    sum += IPV6_NEXT_ICMPV6;

    for (i = 0; i + 1 < msglen; i += 2)
        sum += ((uint32_t) msg[i] << 8) | msg[i + 1];
    if (i < msglen)
        sum += (uint32_t) msg[i] << 8;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t) (~sum & 0xFFFF);
}

/*
 * Fill in a fixed IPv6 header. The traffic class and flow label are
 * left zero, which is what a host with nothing to say about either
 * sends.
 */
static void ipv6_header(uint8_t *out, const uint8_t *src, const uint8_t *dst,
                        size_t payload, uint8_t next, uint8_t hop_limit)
{
    memset(out, 0, IPV6_MIN_HDR);
    out[0] = 0x60;                                  /* version 6        */
    put16(out + 4, (uint16_t) payload);             /* payload length   */
    out[6] = next;
    out[7] = hop_limit;
    memcpy(out + 8, src, 16);
    memcpy(out + 24, dst, 16);
}

size_t icmp6_echo_request(uint8_t *out, size_t outcap,
                          const uint8_t *src, const uint8_t *dst,
                          uint16_t id, uint16_t seq)
{
    static const char payload[] = "vmsguard interop probe";
    const size_t paylen = sizeof payload - 1;
    const size_t icmplen = 8 + paylen;
    const size_t total = IPV6_MIN_HDR + icmplen;
    uint16_t ck;

    if (outcap < total)
        return 0;

    ipv6_header(out, src, dst, icmplen, IPV6_NEXT_ICMPV6, 64);

    out[IPV6_MIN_HDR + 0] = ICMP6_TYPE_ECHO_REQUEST;
    out[IPV6_MIN_HDR + 1] = 0;
    out[IPV6_MIN_HDR + 2] = 0;                      /* checksum, below  */
    out[IPV6_MIN_HDR + 3] = 0;
    put16(out + IPV6_MIN_HDR + 4, id);
    put16(out + IPV6_MIN_HDR + 6, seq);
    memcpy(out + IPV6_MIN_HDR + 8, payload, paylen);

    ck = icmp6_checksum(src, dst, out + IPV6_MIN_HDR, icmplen);
    put16(out + IPV6_MIN_HDR + 2, ck);

    return total;
}

int icmp6_is_echo_reply(const uint8_t *pkt, size_t len,
                        uint16_t id, uint16_t seq)
{
    size_t icmplen;

    if (len < IPV6_MIN_HDR + 8 || (pkt[0] >> 4) != 6)
        return 0;
    if (pkt[6] != IPV6_NEXT_ICMPV6)
        return 0;
    if (pkt[IPV6_MIN_HDR] != ICMP6_TYPE_ECHO_REPLY)
        return 0;
    if ((((uint16_t) pkt[IPV6_MIN_HDR + 4] << 8) |
         pkt[IPV6_MIN_HDR + 5]) != id)
        return 0;
    if ((((uint16_t) pkt[IPV6_MIN_HDR + 6] << 8) |
         pkt[IPV6_MIN_HDR + 7]) != seq)
        return 0;

    /*
     * Verify the checksum, which a receiving stack would. Without this
     * the loopback round trip would accept a reply whose checksum was
     * computed wrongly at either end, and the one test that exercises
     * the whole IPv6 path would be unable to fail on the arithmetic
     * that path exists to get right.
     *
     * The length comes from the header, not the buffer: WireGuard pads
     * transport data, and summing the padding rejects a valid reply.
     */
    icmplen = ((size_t) pkt[4] << 8) | pkt[5];
    if (icmplen < 8 || icmplen > len - IPV6_MIN_HDR)
        return 0;
    return icmp6_checksum(pkt + 8, pkt + 24, pkt + IPV6_MIN_HDR,
                          icmplen) == 0;
}

int icmp6_make_echo_reply(uint8_t *pkt, size_t len)
{
    uint8_t tmp[16];
    size_t icmplen;
    uint16_t ck;

    if (len < IPV6_MIN_HDR + 8 || (pkt[0] >> 4) != 6)
        return 0;
    if (pkt[6] != IPV6_NEXT_ICMPV6)
        return 0;
    if (pkt[IPV6_MIN_HDR] != ICMP6_TYPE_ECHO_REQUEST)
        return 0;

    memcpy(tmp, pkt + 8, 16);
    memcpy(pkt + 8, pkt + 24, 16);
    memcpy(pkt + 24, tmp, 16);

    pkt[IPV6_MIN_HDR] = ICMP6_TYPE_ECHO_REPLY;
    pkt[IPV6_MIN_HDR + 2] = 0;
    pkt[IPV6_MIN_HDR + 3] = 0;

    /*
     * The payload length field, not the buffer length: anything past it
     * is WireGuard padding, and including it would produce a checksum
     * the peer rejects. The IPv4 conversion above gets this wrong-way-
     * round protection from ip_len for the same reason.
     */
    icmplen = ((size_t) pkt[4] << 8) | pkt[5];
    if (icmplen > len - IPV6_MIN_HDR)
        icmplen = len - IPV6_MIN_HDR;

    ck = icmp6_checksum(pkt + 8, pkt + 24, pkt + IPV6_MIN_HDR, icmplen);
    put16(pkt + IPV6_MIN_HDR + 2, ck);
    return 1;
}

size_t icmp6_packet_too_big(uint8_t *out, size_t outcap,
                            const uint8_t *src_addr,
                            const uint8_t *orig, size_t origlen,
                            uint32_t mtu)
{
    size_t quote, icmplen, total;
    uint16_t ck;

    if (origlen < IPV6_MIN_HDR || (orig[0] >> 4) != 6)
        return 0;

    /*
     * RFC 4443 section 2.4(c): quote as much of the original as will
     * fit without the error itself exceeding the minimum IPv6 MTU. That
     * minimum is 1280, and every IPv6 node must accept a packet that
     * size, so an error built to it never needs fragmenting on its way
     * back -- which matters here because we could not fragment it.
     */
    quote = origlen;
    if (quote > 1280 - IPV6_MIN_HDR - 8)
        quote = 1280 - IPV6_MIN_HDR - 8;

    icmplen = 8 + quote;
    total = IPV6_MIN_HDR + icmplen;
    if (outcap < total)
        return 0;

    /*
     * Addressed back to the original's source. The hop limit is 64
     * rather than copied from the original: this is a new packet from
     * this hop, not a forward of theirs.
     */
    ipv6_header(out, src_addr, orig + 8, icmplen, IPV6_NEXT_ICMPV6, 64);

    out[IPV6_MIN_HDR + 0] = ICMP6_TYPE_PACKET_TOO_BIG;
    out[IPV6_MIN_HDR + 1] = 0;
    out[IPV6_MIN_HDR + 2] = 0;                      /* checksum, below  */
    out[IPV6_MIN_HDR + 3] = 0;
    put32(out + IPV6_MIN_HDR + 4, mtu);
    memcpy(out + IPV6_MIN_HDR + 8, orig, quote);

    ck = icmp6_checksum(out + 8, out + 24, out + IPV6_MIN_HDR, icmplen);
    put16(out + IPV6_MIN_HDR + 2, ck);

    return total;
}
