/*
 * Source NAT tests — vmsguard
 *
 * The checksums are the part worth testing hardest. NAT adjusts them
 * incrementally rather than recomputing, because a TCP or UDP checksum
 * covers the whole payload plus a pseudo-header built from the
 * addresses. An adjustment that is subtly wrong produces packets that
 * look perfectly well formed and are silently discarded by the far end.
 *
 * So every translated packet here is checked against a full,
 * independently written recomputation — the same cross-check approach
 * used for the HDLC CRC.
 */

#include <stdio.h>
#include <string.h>

#include "ethip.h"
#include "nat.h"

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

#define TUNNEL_ADDR 0x0A0D7FB1UL   /* 10.13.127.177 */
#define LAN_ADDR    0x0A320032UL   /* 10.50.0.50    */
#define LAN_ADDR2   0x0A320033UL   /* 10.50.0.51    */
#define PEER_ADDR   0x08080808UL   /* 8.8.8.8       */

/* ---- independent checksum implementation, for cross-checking --------- */

static uint16_t sum16(const uint8_t *d, size_t n, uint32_t seed)
{
    uint32_t s = seed;
    size_t i;

    for (i = 0; i + 1 < n; i += 2)
        s += ((uint32_t) d[i] << 8) | d[i + 1];
    if (i < n)
        s += (uint32_t) d[i] << 8;
    while (s >> 16)
        s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t) (~s & 0xFFFF);
}

/* Recompute a TCP/UDP checksum from scratch, pseudo-header included. */
static uint16_t l4_checksum(const uint8_t *pkt, size_t csum_off)
{
    size_t ihl = (size_t) (pkt[0] & 0x0F) * 4;
    size_t total = ((size_t) pkt[2] << 8) | pkt[3];
    size_t l4len = total - ihl;
    uint8_t buf[2048];
    uint32_t seed;
    uint16_t got;

    /* Pseudo-header: source, destination, zero, protocol, length. */
    seed = 0;
    seed += ((uint32_t) pkt[12] << 8) | pkt[13];
    seed += ((uint32_t) pkt[14] << 8) | pkt[15];
    seed += ((uint32_t) pkt[16] << 8) | pkt[17];
    seed += ((uint32_t) pkt[18] << 8) | pkt[19];
    seed += pkt[9];
    seed += (uint32_t) l4len;

    memcpy(buf, pkt + ihl, l4len);
    buf[csum_off] = 0;
    buf[csum_off + 1] = 0;

    got = sum16(buf, l4len, seed);
    return got;
}

static uint16_t icmp_checksum(const uint8_t *pkt)
{
    size_t ihl = (size_t) (pkt[0] & 0x0F) * 4;
    size_t total = ((size_t) pkt[2] << 8) | pkt[3];
    uint8_t buf[2048];

    memcpy(buf, pkt + ihl, total - ihl);
    buf[2] = 0;
    buf[3] = 0;
    return sum16(buf, total - ihl, 0);
}

static uint16_t ip_checksum(const uint8_t *pkt)
{
    size_t ihl = (size_t) (pkt[0] & 0x0F) * 4;
    uint8_t buf[60];

    memcpy(buf, pkt, ihl);
    buf[10] = 0;
    buf[11] = 0;
    return sum16(buf, ihl, 0);
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

/* ---- packet construction --------------------------------------------- */

/* Build a TCP or UDP packet with correct checksums. Returns length. */
static size_t build_l4(uint8_t *p, uint8_t proto, uint32_t src, uint32_t dst,
                       uint16_t sport, uint16_t dport, size_t paylen)
{
    size_t hdr = (proto == 6) ? 20 : 8;
    size_t csum_off = (proto == 6) ? 16 : 6;
    size_t total = 20 + hdr + paylen;
    size_t i;

    memset(p, 0, total);
    p[0] = 0x45;
    put16(p + 2, (uint16_t) total);
    p[8] = 64;
    p[9] = proto;
    put32(p + 12, src);
    put32(p + 16, dst);
    put16(p + 10, ip_checksum(p));

    put16(p + 20, sport);
    put16(p + 22, dport);
    if (proto == 6)
        p[32] = 0x50;          /* data offset: 5 words */
    else
        put16(p + 24, (uint16_t) (hdr + paylen));   /* UDP length */

    for (i = 0; i < paylen; i++)
        p[20 + hdr + i] = (uint8_t) (i * 7 + 1);

    put16(p + 20 + csum_off, l4_checksum(p, csum_off));
    return total;
}

static size_t build_icmp(uint8_t *p, uint32_t src, uint32_t dst,
                         uint8_t type, uint16_t id, uint16_t seq)
{
    size_t total = 20 + 8 + 16;
    size_t i;

    memset(p, 0, total);
    p[0] = 0x45;
    put16(p + 2, (uint16_t) total);
    p[8] = 64;
    p[9] = 1;
    put32(p + 12, src);
    put32(p + 16, dst);
    put16(p + 10, ip_checksum(p));

    p[20] = type;
    put16(p + 24, id);
    put16(p + 26, seq);
    for (i = 0; i < 16; i++)
        p[28 + i] = (uint8_t) (0xA0 + i);

    put16(p + 22, icmp_checksum(p));
    return total;
}

/* Verify every checksum in a packet independently. */
static int checksums_valid(const uint8_t *p)
{
    uint8_t proto = p[9];
    size_t csum_off;

    if (get16(p + 10) != ip_checksum(p))
        return 0;

    if (proto == 1)
        return get16(p + 22) == icmp_checksum(p);

    csum_off = (proto == 6) ? 16 : 6;
    if (proto == 17 && get16(p + 20 + csum_off) == 0)
        return 1;   /* UDP opted out */
    return get16(p + 20 + csum_off) == l4_checksum(p, csum_off);
}

/* ---- tests ------------------------------------------------------------ */

static void test_tcp(void)
{
    struct nat_table t;
    uint8_t pkt[256];
    size_t len;
    uint16_t nat_port;

    printf("\nTCP\n");
    nat_init(&t, TUNNEL_ADDR);

    len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 12345, 443, 40);
    check(checksums_valid(pkt), "constructed packet has valid checksums");

    check(nat_outbound(&t, pkt, len, 1000) == 0, "outbound translated");
    check(ipv4_src(pkt) == TUNNEL_ADDR, "source is now the tunnel address");
    check(ipv4_dst(pkt) == PEER_ADDR, "destination is untouched");
    nat_port = get16(pkt + 20);
    check(nat_port != 12345, "source port was substituted");
    check(checksums_valid(pkt),
          "checksums still valid after translation (vs full recompute)");

    /* The reply, as the far end would send it. */
    {
        uint8_t reply[256];
        size_t rlen = build_l4(reply, 6, PEER_ADDR, TUNNEL_ADDR,
                               443, nat_port, 60);

        check(nat_inbound(&t, reply, rlen, 1100) == 0, "reply matched a mapping");
        check(ipv4_dst(reply) == LAN_ADDR, "destination restored to the client");
        check(get16(reply + 22) == 12345, "destination port restored");
        check(checksums_valid(reply), "reply checksums valid after restore");
    }

    /* Same flow again reuses the mapping rather than allocating. */
    len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 12345, 443, 40);
    check(nat_outbound(&t, pkt, len, 1200) == 0 &&
          get16(pkt + 20) == nat_port,
          "a second packet on the same flow reuses the mapping");
}

static void test_udp(void)
{
    struct nat_table t;
    uint8_t pkt[256];
    size_t len;
    uint16_t nat_port;

    printf("\nUDP\n");
    nat_init(&t, TUNNEL_ADDR);

    len = build_l4(pkt, 17, LAN_ADDR, PEER_ADDR, 5353, 53, 30);
    check(nat_outbound(&t, pkt, len, 1000) == 0, "outbound translated");
    nat_port = get16(pkt + 20);
    check(checksums_valid(pkt), "checksums valid after translation");

    {
        uint8_t reply[256];
        size_t rlen = build_l4(reply, 17, PEER_ADDR, TUNNEL_ADDR,
                               53, nat_port, 80);
        check(nat_inbound(&t, reply, rlen, 1100) == 0 &&
              ipv4_dst(reply) == LAN_ADDR && get16(reply + 22) == 5353,
              "reply restored");
        check(checksums_valid(reply), "reply checksums valid");
    }

    /* A UDP sender may decline to checksum; that must be preserved
       rather than turned into a wrong value. */
    len = build_l4(pkt, 17, LAN_ADDR, PEER_ADDR, 6000, 53, 30);
    put16(pkt + 26, 0);
    check(nat_outbound(&t, pkt, len, 1300) == 0 && get16(pkt + 26) == 0,
          "a zero UDP checksum is left at zero");
}

static void test_icmp(void)
{
    struct nat_table t;
    uint8_t pkt[128];
    size_t len;
    uint16_t nat_id;

    printf("\nICMP echo\n");
    nat_init(&t, TUNNEL_ADDR);

    len = build_icmp(pkt, LAN_ADDR, PEER_ADDR, 8, 0x1234, 1);
    check(checksums_valid(pkt), "constructed echo has valid checksums");

    check(nat_outbound(&t, pkt, len, 1000) == 0, "echo request translated");
    check(ipv4_src(pkt) == TUNNEL_ADDR, "source rewritten");
    nat_id = get16(pkt + 24);
    check(nat_id != 0x1234, "ICMP identifier substituted");
    check(checksums_valid(pkt), "checksums valid after translation");

    {
        uint8_t reply[128];
        size_t rlen = build_icmp(reply, PEER_ADDR, TUNNEL_ADDR, 0, nat_id, 1);
        check(nat_inbound(&t, reply, rlen, 1100) == 0,
              "echo reply matched a mapping");
        check(ipv4_dst(reply) == LAN_ADDR && get16(reply + 24) == 0x1234,
              "address and identifier restored");
        check(checksums_valid(reply), "reply checksums valid");
    }
}

static void test_multiple_clients(void)
{
    struct nat_table t;
    uint8_t a[128], b[128];
    size_t la, lb;
    uint16_t pa, pb;

    printf("\ntwo clients, same source port\n");
    nat_init(&t, TUNNEL_ADDR);

    /* The case that makes port translation necessary rather than
       optional: two clients independently choosing the same port. */
    la = build_l4(a, 6, LAN_ADDR, PEER_ADDR, 40000, 80, 10);
    lb = build_l4(b, 6, LAN_ADDR2, PEER_ADDR, 40000, 80, 10);

    check(nat_outbound(&t, a, la, 1000) == 0, "first client translated");
    check(nat_outbound(&t, b, lb, 1000) == 0, "second client translated");
    pa = get16(a + 20);
    pb = get16(b + 20);
    check(pa != pb, "the two flows got different translated ports");

    {
        uint8_t ra[128], rb[128];
        size_t lra = build_l4(ra, 6, PEER_ADDR, TUNNEL_ADDR, 80, pa, 10);
        size_t lrb = build_l4(rb, 6, PEER_ADDR, TUNNEL_ADDR, 80, pb, 10);

        check(nat_inbound(&t, ra, lra, 1100) == 0 &&
              ipv4_dst(ra) == LAN_ADDR,
              "first reply went to the first client");
        check(nat_inbound(&t, rb, lrb, 1100) == 0 &&
              ipv4_dst(rb) == LAN_ADDR2,
              "second reply went to the second client");
    }
}

static void test_rejections(void)
{
    struct nat_table t;
    uint8_t pkt[128];
    size_t len;

    printf("\nrejections\n");
    nat_init(&t, TUNNEL_ADDR);

    /* Unsolicited inbound traffic has no mapping and must not be
       guessed at. */
    len = build_l4(pkt, 6, PEER_ADDR, TUNNEL_ADDR, 80, 41234, 10);
    check(nat_inbound(&t, pkt, len, 1000) == -1,
          "inbound with no mapping is rejected");

    /* A protocol with no ports cannot be demultiplexed on the way back. */
    len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 1000, 80, 10);
    pkt[9] = 47;   /* GRE */
    put16(pkt + 10, ip_checksum(pkt));
    check(nat_outbound(&t, pkt, len, 1000) == -1,
          "an unsupported protocol is rejected");

    /* ICMP errors embed the original header, which would need
       translating too; not handled, so refused rather than mangled. */
    len = build_icmp(pkt, LAN_ADDR, PEER_ADDR, 3 /* dest unreachable */,
                     0x1234, 1);
    check(nat_outbound(&t, pkt, len, 1000) == -1,
          "a non-echo ICMP type is rejected");

    /* A later fragment has no transport header at all. */
    len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 1000, 80, 10);
    put16(pkt + 6, 0x0001);   /* fragment offset 1 */
    put16(pkt + 10, ip_checksum(pkt));
    check(nat_outbound(&t, pkt, len, 1000) == -1,
          "a non-first fragment is rejected");

    /* Truncated. */
    check(nat_outbound(&t, pkt, 10, 1000) == -1, "a runt packet is rejected");
}

static void test_expiry(void)
{
    struct nat_table t;
    uint8_t pkt[128];
    size_t len;
    uint16_t port;

    printf("\nexpiry\n");
    nat_init(&t, TUNNEL_ADDR);

    len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 1111, 80, 10);
    nat_outbound(&t, pkt, len, 1000);
    port = get16(pkt + 20);
    check(nat_active(&t, 1000) == 1, "one mapping is live");

    {
        uint8_t reply[128];
        size_t rlen = build_l4(reply, 6, PEER_ADDR, TUNNEL_ADDR, 80, port, 10);
        uint64_t late = 1000 + NAT_TIMEOUT_MS + 1;

        check(nat_active(&t, late) == 0, "it has expired by the timeout");
        check(nat_inbound(&t, reply, rlen, late) == -1,
              "and a reply after expiry no longer matches");
    }
}

int main(void)
{
    printf("vmsguard source NAT tests\n");

    test_tcp();
    test_udp();
    test_icmp();
    test_multiple_clients();
    test_rejections();
    test_expiry();

    printf("\n%s — %d checks, %d failure%s\n",
           failures == 0 ? "PASS" : "FAIL",
           checks, failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
