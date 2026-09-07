/*
 * ICMP error generation tests — vmsguard
 *
 * A malformed ICMP error is worse than none: the sender ignores it and
 * the transfer still hangs, but now there is traffic suggesting the
 * problem was handled. So the checksums and the quoted original are
 * checked against independent recomputation, and the next-hop MTU is
 * checked to be where RFC 1191 says a sender will look for it.
 */

#include <stdio.h>
#include <string.h>

#include "ethip.h"
#include "icmp.h"

static int failures;
static int checks;

static void check(int cond, const char *what)
{
    checks++;
    if (cond) {
        printf("  ok    %s\n", what);
    } else {
        printf("  FAIL  %s\n", what);
        failures++;
    }
}

static uint16_t sum16(const uint8_t *d, size_t n)
{
    uint32_t s = 0;
    size_t i;

    for (i = 0; i + 1 < n; i += 2)
        s += ((uint32_t) d[i] << 8) | d[i + 1];
    if (i < n)
        s += (uint32_t) d[i] << 8;
    while (s >> 16)
        s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t) (~s & 0xFFFF);
}

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t) (v >> 8);
    p[1] = (uint8_t) (v & 0xFF);
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) v;
}

#define GW_ADDR   0xC0A80050UL   /* 192.168.0.80  */
#define CLIENT    0xC0A800DAUL   /* 192.168.0.218 */
#define FAR       0x01010101UL   /* 1.1.1.1       */

/* A large TCP packet with DF set, as a client doing PMTUD would send. */
static size_t build_big_tcp(uint8_t *p, size_t payload, int df)
{
    size_t total = 20 + 20 + payload;
    size_t i;
    uint8_t hdr[20];

    memset(p, 0, total);
    p[0] = 0x45;
    put16(p + 2, (uint16_t) total);
    put16(p + 4, 0xBEEF);                       /* identification */
    put16(p + 6, df ? IPV4_FLAG_DF : 0);
    p[8] = 64;
    p[9] = 6;                                   /* TCP */
    put32(p + 12, CLIENT);
    put32(p + 16, FAR);
    memcpy(hdr, p, 20);
    hdr[10] = 0;
    hdr[11] = 0;
    put16(p + 10, sum16(hdr, 20));

    put16(p + 20, 54321);                       /* source port */
    put16(p + 22, 443);                         /* dest port   */
    put32(p + 24, 0x11223344);                  /* sequence    */

    for (i = 0; i < payload; i++)
        p[40 + i] = (uint8_t) i;
    return total;
}

static void test_construction(void)
{
    uint8_t orig[1600], err[128], tmp[128];
    size_t olen, elen;

    printf("\nconstruction\n");

    olen = build_big_tcp(orig, 1460, 1);
    check(olen == 1500, "built a 1500-byte original");
    check(ipv4_dont_fragment(orig, olen) == 1, "DF is set on it");

    elen = icmp_frag_needed(err, sizeof err, GW_ADDR, orig, olen, 1420);
    check(elen > 0, "an ICMP error was produced");
    check(elen == 20 + 8 + 20 + 8,
          "length is IP + ICMP + quoted header + 8 bytes");

    check(ipv4_src(err) == GW_ADDR, "sourced from the gateway");
    check(ipv4_dst(err) == CLIENT, "addressed back to the sender");
    check(err[9] == 1, "protocol is ICMP");

    check(err[20] == ICMP_TYPE_DEST_UNREACH && err[21] == ICMP_CODE_FRAG_NEEDED,
          "type 3 code 4, fragmentation needed");
    check(get16(err + 26) == 1420,
          "next-hop MTU is where RFC 1191 says to look");
    check(get16(err + 24) == 0, "the preceding two bytes are left unused");

    /* Checksums, recomputed independently. */
    memcpy(tmp, err, 20);
    tmp[10] = 0;
    tmp[11] = 0;
    check(get16(err + 10) == sum16(tmp, 20), "IP header checksum is correct");

    memcpy(tmp, err + 20, elen - 20);
    tmp[2] = 0;
    tmp[3] = 0;
    check(get16(err + 22) == sum16(tmp, elen - 20),
          "ICMP checksum is correct");
}

static void test_quoted_original(void)
{
    uint8_t orig[1600], err[128];
    size_t olen, elen;

    printf("\nquoted original\n");

    olen = build_big_tcp(orig, 1460, 1);
    elen = icmp_frag_needed(err, sizeof err, GW_ADDR, orig, olen, 1420);

    check(memcmp(err + 28, orig, 20) == 0,
          "the original IP header is quoted verbatim");
    check(get16(err + 28 + 20) == 54321 && get16(err + 28 + 22) == 443,
          "and the first 8 bytes, so both ports are visible");
    check(get16(err + 28 + 4) == 0xBEEF,
          "including the identification field");
    (void) elen;
}

static void test_rejections(void)
{
    uint8_t orig[1600], err[128];
    size_t olen;

    printf("\nrejections\n");

    olen = build_big_tcp(orig, 1460, 0);
    check(ipv4_dont_fragment(orig, olen) == 0,
          "DF clear is reported as such");

    check(icmp_frag_needed(err, 20, GW_ADDR, orig, olen, 1420) == 0,
          "refuses when the output buffer is too small");
    check(icmp_frag_needed(err, sizeof err, GW_ADDR, orig, 10, 1420) == 0,
          "refuses a truncated original");

    orig[0] = 0x65;   /* version 6 */
    check(icmp_frag_needed(err, sizeof err, GW_ADDR, orig, olen, 1420) == 0,
          "refuses a non-IPv4 original");
}

static void test_short_original(void)
{
    uint8_t orig[64], err[128];
    size_t olen, elen;

    printf("\nshort original\n");

    /* An original with fewer than 8 bytes after its header must not be
       read past the end of. */
    olen = build_big_tcp(orig, 0, 1);
    olen = 24;                    /* pretend only 4 bytes of TCP arrived */
    elen = icmp_frag_needed(err, sizeof err, GW_ADDR, orig, olen, 1420);
    check(elen == 20 + 8 + 24, "quotes only what was actually present");
}

/*
 * Recognising the OpenVMS stack contradicting the gateway.
 *
 * The stack sees the same forwarded packets pcap does and, having no
 * route for them, answers the sender with "destination unreachable"
 * while the gateway is tunnelling the very same packet. Nothing can
 * stop it — there is no packet filter on the platform that drops by
 * rule — so the aim is to recognise it precisely enough to report it
 * without crying wolf at every ICMP on the wire.
 */
/* An ICMP error from `src` to `dst` quoting a packet that was headed
   for `orig_dst`. */
static size_t build_icmp_error(uint8_t *p, uint8_t type, uint32_t src,
                               uint32_t dst, uint32_t orig_src,
                               uint32_t orig_dst, uint8_t orig_proto,
                               size_t quote)
{
    size_t total = 20 + 8 + quote;

    memset(p, 0, total);
    p[0] = 0x45;
    p[2] = (uint8_t) (total >> 8);
    p[3] = (uint8_t) (total & 0xFF);
    p[8] = 64;
    p[9] = 1;                       /* ICMP */
    put32(p + 12, src);
    put32(p + 16, dst);

    p[20] = type;
    p[21] = 0;                      /* code: net unreachable */

    /* The quoted original: its own IP header, then whatever fits. */
    if (quote >= 20) {
        p[28] = 0x45;
        p[28 + 8] = 63;
        p[28 + 9] = orig_proto;
        put32(p + 28 + 12, orig_src);
        put32(p + 28 + 16, orig_dst);
    }
    return total;
}

static void test_stack_contradiction(void)
{
    uint8_t p[128];
    size_t len;
    uint32_t dst = 0;
    uint8_t proto = 0;

    printf("\nthe stack answering for traffic we tunnel\n");

    len = build_icmp_error(p, ICMP_TYPE_DEST_UNREACH, GW_ADDR, CLIENT,
                           CLIENT, FAR, 6, 28);
    check(icmp_error_from(p, len, GW_ADDR, &dst, &proto) == 1,
          "an unreachable from our own address is recognised");
    check(dst == FAR,
          "and the quoted header says where the sender was trying to go");
    check(proto == 6, "along with what it was trying to do");

    /*
     * The address test is what keeps this from firing on every ICMP
     * error crossing the segment. An unreachable from a router
     * elsewhere is somebody else's business.
     */
    dst = 0;
    check(icmp_error_from(p, len, 0xC0A80001UL, &dst, &proto) == 0,
          "an error from any other address is not ours to report");

    len = build_icmp_error(p, ICMP_TYPE_TIME_EXCEEDED, GW_ADDR, CLIENT,
                           CLIENT, FAR, 17, 28);
    check(icmp_error_from(p, len, GW_ADDR, &dst, &proto) == 1,
          "time-exceeded counts too: a traceroute reaching us says the"
          " same thing");

    /*
     * Codes matter as much as types. Only a routing failure means the
     * stack could not deliver what we are tunnelling; the rest are the
     * host answering about itself, and one of them is ours.
     */
    len = build_icmp_error(p, ICMP_TYPE_DEST_UNREACH, GW_ADDR, CLIENT,
                           CLIENT, FAR, 6, 28);
    p[21] = ICMP_CODE_HOST_UNREACH;
    check(icmp_error_from(p, len, GW_ADDR, NULL, NULL) == 1,
          "host unreachable is a routing failure");
    p[21] = ICMP_CODE_NET_UNKNOWN;
    check(icmp_error_from(p, len, GW_ADDR, NULL, NULL) == 1,
          "so is an unknown network");

    /*
     * Observed on the target: the OpenVMS box told the LAN router that
     * the OpenVMS box was unreachable, for a closed local UDP port.
     * A correct answer about itself, and nothing to do with the tunnel.
     */
    p[21] = ICMP_CODE_PORT_UNREACH;
    check(icmp_error_from(p, len, GW_ADDR, NULL, NULL) == 0,
          "but a closed port is a host answering about itself");
    p[21] = ICMP_CODE_PROTO_UNREACH;
    check(icmp_error_from(p, len, GW_ADDR, NULL, NULL) == 0,
          "as is an unsupported protocol");

    /*
     * The one that would have hurt most. The gateway injects
     * fragmentation-needed itself and captures its own injected
     * packets, so counting these would report the MTU feature working
     * as the stack misbehaving — and the louder the warning, the worse
     * that is.
     */
    p[21] = ICMP_CODE_FRAG_NEEDED;
    check(icmp_error_from(p, len, GW_ADDR, NULL, NULL) == 0,
          "and fragmentation-needed is ours, never the stack's");

    p[21] = 0;

    /* Echo requests and replies are not errors and quote nothing. */
    len = build_icmp_error(p, 8 /* echo request */, GW_ADDR, CLIENT,
                           CLIENT, FAR, 1, 28);
    check(icmp_error_from(p, len, GW_ADDR, NULL, NULL) == 0,
          "an echo request is not an error message");

    /* A quotation too short to hold an IP header is not worth guessing
       at, and reading past it would be worse than saying nothing. */
    len = build_icmp_error(p, ICMP_TYPE_DEST_UNREACH, GW_ADDR, CLIENT,
                           CLIENT, FAR, 6, 12);
    check(icmp_error_from(p, len, GW_ADDR, NULL, NULL) == 0,
          "a truncated quotation is refused rather than half-read");

    /* Not ICMP at all. */
    len = build_icmp_error(p, ICMP_TYPE_DEST_UNREACH, GW_ADDR, CLIENT,
                           CLIENT, FAR, 6, 28);
    p[9] = 6;
    check(icmp_error_from(p, len, GW_ADDR, NULL, NULL) == 0,
          "and a TCP packet is not an ICMP error however it is shaped");

    check(icmp_error_from(p, 8, GW_ADDR, NULL, NULL) == 0,
          "a runt is refused");
}

/* ---- ICMPv6 ---------------------------------------------------------- */

/*
 * fd00:1234::1 and ::2.
 */
static const uint8_t V6_A[16] = {
    0xfd,0x00,0x12,0x34,0,0,0,0,0,0,0,0,0,0,0,0x01
};
static const uint8_t V6_B[16] = {
    0xfd,0x00,0x12,0x34,0,0,0,0,0,0,0,0,0,0,0,0x02
};

/*
 * The checksums below were computed by a separate implementation
 * written from RFC 4443 section 2.3 and RFC 2460 section 8.1, not by
 * this code. A checksum test that calls the function it is testing to
 * produce the expected value proves only that the function is
 * deterministic, which is the failure mode this project has hit before:
 * a misreading of a specification passes against itself.
 */
static void test_icmp6_checksum(void)
{
    uint8_t pkt[128];
    size_t n;

    printf("\nICMPv6 checksum, against an independent implementation\n");

    n = icmp6_echo_request(pkt, sizeof pkt, V6_A, V6_B, 0x4242, 1);
    check(n == 40 + 8 + 22, "an echo request is header, ICMPv6 and payload");
    check(get16(pkt + 40 + 2) == 0xF456,
          "its checksum matches the reference value");

    /*
     * The standard property: summing a valid message *including* its
     * checksum field yields zero. Independent of the value above, and
     * it catches a pseudo-header assembled in the wrong order that
     * happened to hit the same total.
     */
    check(icmp6_checksum(V6_A, V6_B, pkt + 40, n - 40) == 0,
          "and re-summing a valid message gives zero");

    /* The pseudo-header really is covered: change an address only. */
    {
        uint8_t other[16];
        memcpy(other, V6_B, 16);
        other[15] = 0x03;
        check(icmp6_checksum(V6_A, other, pkt + 40, n - 40) != 0,
              "a different destination changes the sum, so the"
              " pseudo-header is covered");
    }
}

static void test_icmp6_echo(void)
{
    uint8_t pkt[128];
    size_t n;

    printf("\nICMPv6 echo request and reply\n");

    n = icmp6_echo_request(pkt, sizeof pkt, V6_A, V6_B, 0x4242, 1);

    check(pkt[0] >> 4 == 6, "version 6");
    check(get16(pkt + 4) == 30, "payload length excludes the IPv6 header");
    check(pkt[6] == 58, "next header is ICMPv6");
    check(pkt[40] == 128, "type 128, echo request");
    check(memcmp(pkt + 8, V6_A, 16) == 0, "sourced from the first address");
    check(memcmp(pkt + 24, V6_B, 16) == 0, "sent to the second");

    check(icmp6_is_echo_reply(pkt, n, 0x4242, 1) == 0,
          "a request is not mistaken for a reply");

    check(icmp6_make_echo_reply(pkt, n) == 1, "it converts to a reply");
    check(pkt[40] == 129, "type 129, echo reply");
    check(memcmp(pkt + 8, V6_B, 16) == 0, "the addresses are swapped");
    check(memcmp(pkt + 24, V6_A, 16) == 0, "both of them");
    check(get16(pkt + 40 + 2) == 0xF356,
          "the reply's checksum matches the reference value");
    check(icmp6_is_echo_reply(pkt, n, 0x4242, 1) == 1,
          "and it is recognised as the reply to that request");
    check(icmp6_is_echo_reply(pkt, n, 0x4242, 2) == 0,
          "but not as a reply to a different sequence");
    check(icmp6_is_echo_reply(pkt, n, 0x4243, 1) == 0,
          "nor to a different id");

    /* A corrupted reply is refused, so the round trip proves the sum. */
    pkt[40 + 9] ^= 0xFF;
    check(icmp6_is_echo_reply(pkt, n, 0x4242, 1) == 0,
          "a reply whose checksum does not verify is refused");
    pkt[40 + 9] ^= 0xFF;
    check(icmp6_is_echo_reply(pkt, n, 0x4242, 1) == 1,
          "and accepted again once restored");

    /*
     * WireGuard pads transport data, so the buffer is routinely longer
     * than the packet. Summing the padding produces a checksum the peer
     * rejects -- the same bug the IPv4 conversion had to avoid.
     */
    n = icmp6_echo_request(pkt, sizeof pkt, V6_A, V6_B, 0x4242, 1);
    memset(pkt + n, 0xAA, 16);
    check(icmp6_make_echo_reply(pkt, n + 16) == 1,
          "a padded buffer still converts");
    check(get16(pkt + 40 + 2) == 0xF356,
          "and the padding is excluded from the checksum");

    check(icmp6_make_echo_reply(pkt, n) == 0,
          "a reply does not convert again");
}

static void test_icmp6_too_big(void)
{
    uint8_t orig[1500], out[1500];
    size_t n;

    printf("\nICMPv6 Packet Too Big\n");

    memset(orig, 0, sizeof orig);
    orig[0] = 0x60;
    orig[4] = (uint8_t) (1460 >> 8);
    orig[5] = (uint8_t) (1460 & 0xFF);
    orig[6] = 59;                       /* no next header */
    orig[7] = 64;
    memcpy(orig + 8, V6_A, 16);
    memcpy(orig + 24, V6_B, 16);

    n = icmp6_packet_too_big(out, sizeof out, V6_B, orig, 1500, 1380);

    check(n == 1280,
          "the error is built to the minimum IPv6 MTU, so it never"
          " needs fragmenting");
    check(out[40] == 2, "type 2, packet too big");
    check(out[40 + 1] == 0, "code 0");
    check(((uint32_t) out[44] << 24 | (uint32_t) out[45] << 16 |
           (uint32_t) out[46] << 8 | out[47]) == 1380,
          "the MTU is where RFC 4443 says a sender will look");
    check(memcmp(out + 24, V6_A, 16) == 0,
          "addressed back to the original's source");
    check(memcmp(out + 8, V6_B, 16) == 0,
          "sourced from the hop that could not forward");
    check(out[7] == 64,
          "a fresh hop limit, not the original's");
    check(memcmp(out + 48, orig, 1232) == 0,
          "and it quotes the original, as much as fits");
    check(get16(out + 40 + 2) == 0x15BB,
          "its checksum matches the reference value");
    /*
     * Guarded because n is a size_t: a build where this returns 0
     * would make n - 40 an enormous length and kill the process inside
     * the checksum, losing the FAIL line that says which check broke.
     * Found by deliberately breaking the 1280 cap to confirm these
     * tests can fail -- they can, but the first attempt segfaulted
     * instead of reporting.
     */
    check(n >= 40 && icmp6_checksum(out + 8, out + 24, out + 40, n - 40) == 0,
          "and re-summing it gives zero");

    /* A short original is quoted whole rather than padded to 1280. */
    n = icmp6_packet_too_big(out, sizeof out, V6_B, orig, 100, 1380);
    check(n == 40 + 8 + 100, "a short original is quoted whole");
    check(n >= 40 && icmp6_checksum(out + 8, out + 24, out + 40, n - 40) == 0,
          "and that checksum is right too");

    check(icmp6_packet_too_big(out, sizeof out, V6_B, orig, 20, 1380) == 0,
          "a runt original is refused");
    orig[0] = 0x45;
    check(icmp6_packet_too_big(out, sizeof out, V6_B, orig, 1500, 1380) == 0,
          "and an IPv4 packet is not an IPv6 one");
    orig[0] = 0x60;
    check(icmp6_packet_too_big(out, 64, V6_B, orig, 1500, 1380) == 0,
          "a buffer too small to hold it is refused, not overrun");
}

int main(void)
{
    printf("vmsguard ICMP error tests\n");

    test_construction();
    test_quoted_original();
    test_rejections();
    test_short_original();
    test_stack_contradiction();
    test_icmp6_checksum();
    test_icmp6_echo();
    test_icmp6_too_big();

    printf("\n%s — %d checks, %d failure%s\n",
           failures == 0 ? "PASS" : "FAIL",
           checks, failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
