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
    check(nat_inbound(&t, pkt, len, 1000) == NAT_DROP_NO_MAPPING,
          "inbound with no mapping is rejected, and says so");

    /* A protocol with no ports cannot be demultiplexed on the way back. */
    len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 1000, 80, 10);
    pkt[9] = 47;   /* GRE */
    put16(pkt + 10, ip_checksum(pkt));
    check(nat_outbound(&t, pkt, len, 1000) == NAT_DROP_PROTOCOL,
          "an unsupported protocol is rejected, and says so");

    /* ICMP errors embed the original header, which would need
       translating too; not handled, so refused rather than mangled. */
    len = build_icmp(pkt, LAN_ADDR, PEER_ADDR, 3 /* dest unreachable */,
                     0x1234, 1);
    check(nat_outbound(&t, pkt, len, 1000) == NAT_DROP_ICMP_TYPE,
          "a non-echo ICMP type is rejected, and says so");

    /* A later fragment has no transport header at all. */
    len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 1000, 80, 10);
    put16(pkt + 6, 0x0001);   /* fragment offset 1 */
    put16(pkt + 10, ip_checksum(pkt));
    check(nat_outbound(&t, pkt, len, 1000) == NAT_DROP_FRAGMENT,
          "a non-first fragment is rejected as a fragment");

    /*
     * A first fragment could be translated, but its remainder cannot,
     * so forwarding it alone leaves the far end holding an incomplete
     * datagram. Refuse the whole thing.
     */
    len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 1000, 80, 10);
    put16(pkt + 6, 0x2000);   /* More Fragments, offset 0 */
    put16(pkt + 10, ip_checksum(pkt));
    check(nat_outbound(&t, pkt, len, 1000) == NAT_DROP_FRAGMENT,
          "a first fragment with More Fragments set is also a fragment");

    /* But DF, which shares the same field, must not be mistaken for a
       fragment flag. */
    len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 1000, 80, 10);
    put16(pkt + 6, 0x4000);   /* Don't Fragment */
    put16(pkt + 10, ip_checksum(pkt));
    check(nat_outbound(&t, pkt, len, 1000) == NAT_OK,
          "a packet with DF set is translated normally");

    /* Truncated. */
    check(nat_outbound(&t, pkt, 10, 1000) == NAT_DROP_MALFORMED,
          "a runt packet is rejected as malformed");

    /*
     * The reasons are only worth distinguishing if they reach a log
     * line, so every code must name itself, and no two may share a
     * name. Checked by comparison rather than by eye, because a
     * copy-and-paste in the switch would otherwise be invisible.
     */
    {
        static const int codes[] = {
            NAT_OK, NAT_DROP_MALFORMED, NAT_DROP_FRAGMENT,
            NAT_DROP_PROTOCOL, NAT_DROP_ICMP_TYPE,
            NAT_DROP_TABLE_FULL, NAT_DROP_NO_MAPPING
        };
        size_t i, j;
        int named = 1, distinct = 1;

        for (i = 0; i < sizeof codes / sizeof codes[0]; i++) {
            const char *a = nat_reason(codes[i]);
            if (a == NULL || a[0] == '\0' ||
                strcmp(a, nat_reason(999)) == 0)
                named = 0;
            for (j = i + 1; j < sizeof codes / sizeof codes[0]; j++) {
                if (strcmp(a, nat_reason(codes[j])) == 0)
                    distinct = 0;
            }
        }
        check(named, "every reason code has a name of its own");
        check(distinct, "no two reason codes share a name");
        check(strcmp(nat_reason(999), "unknown") == 0,
              "an unrecognised code is named rather than crashing");
    }
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
        uint64_t late = 1000 + NAT_TIMEOUT_TCP_MS + 1;

        check(nat_active(&t, late) == 0, "it has expired by the timeout");
        check(nat_inbound(&t, reply, rlen, late) == NAT_DROP_NO_MAPPING,
              "and a reply after expiry no longer matches");
    }
}

/*
 * A single timeout for every protocol let 856 DNS queries fill all 512
 * entries in one live run, because each query holds a slot for two
 * minutes to cover an exchange that finished in milliseconds. UDP and
 * ICMP now expire in thirty seconds; TCP still gets the two minutes it
 * actually needs.
 */
static void test_protocol_timeouts(void)
{
    struct nat_table t;
    uint8_t tcp[128], udp[128], icmp[128];
    size_t tl, ul, il;
    uint64_t mid, late;

    printf("\nper-protocol timeouts\n");

    check(NAT_TIMEOUT_UDP_MS < NAT_TIMEOUT_TCP_MS,
          "UDP is held for less time than TCP");
    check(nat_timeout_for(6) == NAT_TIMEOUT_TCP_MS, "TCP gets the long one");
    check(nat_timeout_for(17) == NAT_TIMEOUT_UDP_MS, "UDP gets the short one");
    check(nat_timeout_for(1) == NAT_TIMEOUT_UDP_MS,
          "ICMP echo is request-and-reply, so it gets the short one too");

    nat_init(&t, TUNNEL_ADDR);
    tl = build_l4(tcp, 6, LAN_ADDR, PEER_ADDR, 1111, 80, 10);
    ul = build_l4(udp, 17, LAN_ADDR, PEER_ADDR, 2222, 53, 10);
    il = build_icmp(icmp, LAN_ADDR, PEER_ADDR, 8, 0x1234, 1);
    nat_outbound(&t, tcp, tl, 1000);
    nat_outbound(&t, udp, ul, 1000);
    nat_outbound(&t, icmp, il, 1000);
    check(nat_active(&t, 1000) == 3, "three mappings to begin with");

    /* Past the UDP timeout but well inside the TCP one. */
    mid = 1000 + NAT_TIMEOUT_UDP_MS + 1;
    check(nat_active(&t, mid) == 1,
          "the UDP and ICMP mappings are gone, the TCP one is not");

    late = 1000 + NAT_TIMEOUT_TCP_MS + 1;
    check(nat_active(&t, late) == 0, "and the TCP one goes in its own time");
}

/*
 * When every entry is live the least recently used is recycled, which
 * keeps the new flow working at the cost of the old one. That is the
 * right trade, but it happened with no trace at all: a live run ended
 * with 512 of 512 mappings live and nothing to say anything had been
 * thrown away.
 */
static void test_eviction(void)
{
    struct nat_table t;
    uint8_t pkt[128];
    size_t len;
    int i;
    int all_translated = 1;
    uint16_t first_port = 0;

    printf("\neviction under pressure\n");
    nat_init(&t, TUNNEL_ADDR);

    /*
     * Fill every slot, all at the same instant so none can expire.
     * Counted rather than checked one at a time: 512 ok lines would
     * bury everything else in the run.
     */
    for (i = 0; i < NAT_ENTRIES; i++) {
        len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR,
                       (uint16_t) (1024 + i), 80, 10);
        if (nat_outbound(&t, pkt, len, 1000) != NAT_OK)
            all_translated = 0;
        if (i == 0)
            first_port = get16(pkt + 20);
    }
    check(all_translated, "every one of 512 flows is translated");
    check(nat_active(&t, 1000) == NAT_ENTRIES, "the table is full");
    check(t.evicted == 0, "and nothing has been evicted yet");

    /*
     * One more flow, still inside every timeout. It must succeed, and
     * it must say that it cost something.
     */
    len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 9999, 80, 10);
    check(nat_outbound(&t, pkt, len, 1001) == NAT_OK,
          "a further flow is still translated rather than refused");
    check(t.evicted == 1, "and the eviction is counted");
    check(t.dropped_table_full == 0,
          "an eviction is not a drop, and must not be counted as one");
    check(nat_active(&t, 1001) == NAT_ENTRIES,
          "the table is still exactly full, not overfull");

    /* The victim is the oldest, so its reply no longer comes back. */
    {
        uint8_t reply[128];
        size_t rlen = build_l4(reply, 6, PEER_ADDR, TUNNEL_ADDR, 80,
                               first_port, 10);
        check(nat_inbound(&t, reply, rlen, 1001) == NAT_DROP_NO_MAPPING,
              "the recycled flow's reply has nowhere to go");
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
    test_protocol_timeouts();
    test_eviction();

    printf("\n%s — %d checks, %d failure%s\n",
           failures == 0 ? "PASS" : "FAIL",
           checks, failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
