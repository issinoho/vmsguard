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

/* For setup steps whose success is assumed by the check that follows;
   a failure here shows up as that check failing. */
static void check_quiet(int rc)
{
    (void) rc;
}

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

    /*
     * A later fragment whose first fragment was never seen has nothing
     * to inherit. It cannot be translated on its own — there is no
     * transport header in it to read a port from — so it is refused,
     * and the reason says which of the two fragment cases it is.
     */
    len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 1000, 80, 10);
    put16(pkt + 6, 0x0001);   /* fragment offset 1, nothing preceding it */
    put16(pkt + 10, ip_checksum(pkt));
    check(nat_outbound(&t, pkt, len, 1000) == NAT_DROP_FRAG_ORPHAN,
          "an orphaned later fragment is refused, and says why");

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
    check(all_translated, "every one of 2048 flows is translated");
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

/* ---- the hash indices ------------------------------------------------ */

/*
 * The index changes how much work a lookup does and nothing about what
 * it returns, so every other test in this file passes equally well with
 * a linear scan back in place. That is what t.probes and t.lookups are
 * for: they make the work itself observable, and these checks assert a
 * bound on it that a scan of 2048 entries cannot meet.
 *
 * Confirmed to fail without the index: with find_outbound reverted to a
 * scan, the ratio below comes out at 1024 against a limit of 8.
 */
static void test_index(void)
{
    struct nat_table t;
    static uint16_t ports[NAT_ENTRIES];   /* static: too big for a frame */
    uint8_t pkt[128], reply[128];
    size_t len, rlen;
    int i, gen;
    int all_found = 1, all_restored = 1;
    unsigned long probes, lookups, evicted_before;

    printf("\nlookups through the hash indices\n");
    nat_init(&t, TUNNEL_ADDR);

    for (i = 0; i < NAT_ENTRIES; i++) {
        len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR,
                       (uint16_t) (1024 + i), 80, 10);
        check_quiet(nat_outbound(&t, pkt, len, 1000));
        ports[i] = get16(pkt + 20);
    }
    check(nat_active(&t, 1000) == NAT_ENTRIES, "the table is full");

    /*
     * Every flow is looked up again, outbound and in. A wrong chain
     * shows up here as a mapping that cannot be found or one that
     * restores the wrong client, both of which a scan would never do:
     * correctness first, cost second.
     */
    probes = t.probes;
    lookups = t.lookups;

    for (i = 0; i < NAT_ENTRIES; i++) {
        len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR,
                       (uint16_t) (1024 + i), 80, 10);
        if (nat_outbound(&t, pkt, len, 1000) != NAT_OK ||
            get16(pkt + 20) != ports[i])
            all_found = 0;

        rlen = build_l4(reply, 6, PEER_ADDR, TUNNEL_ADDR, 80, ports[i], 10);
        if (nat_inbound(&t, reply, rlen, 1000) != NAT_OK ||
            ipv4_dst(reply) != LAN_ADDR ||
            get16(reply + 22) != (uint16_t) (1024 + i))
            all_restored = 0;
    }
    check(all_found, "all 2048 flows are found again with their own port");
    check(all_restored, "and every reply is restored to the right client");
    check(t.evicted == 0, "no flow was displaced along the way");

    probes = t.probes - probes;
    lookups = t.lookups - lookups;
    check(lookups >= 2 * NAT_ENTRIES, "both directions were measured");
    check(probes / lookups < 8,
          "a lookup in a full table examines a handful of entries, not 2048");

    /*
     * One further flow, with every slot live. This is the case that was
     * worst before indexing: allocating an identifier asks "is this one
     * taken?" per candidate, and each question was a full scan.
     */
    probes = t.probes;
    len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 9999, 80, 10);
    check(nat_outbound(&t, pkt, len, 1001) == NAT_OK,
          "a new flow on a full table is still translated");
    check(t.probes - probes < 64,
          "and allocating its identifier does not scan the table");

    /*
     * Churn. Each generation expires everything and fills the table
     * again, so every slot is reclaimed and relinked repeatedly.
     *
     * This is the check that fails if a reclaimed slot is not unlinked
     * from its old buckets: the stale links stay in the chains, every
     * generation adds another set, and the cost per lookup climbs with
     * them even though the answers stay correct.
     */
    evicted_before = t.evicted;

    for (gen = 1; gen <= 4; gen++) {
        uint64_t now = 1000 + (uint64_t) gen * (NAT_TIMEOUT_TCP_MS + 1000);

        for (i = 0; i < NAT_ENTRIES; i++) {
            len = build_l4(pkt, 6, LAN_ADDR2, PEER_ADDR,
                           (uint16_t) (2048 + i), 443, 10);
            check_quiet(nat_outbound(&t, pkt, len, now));
            ports[i] = get16(pkt + 20);
        }

        probes = t.probes;
        lookups = t.lookups;
        all_restored = 1;
        for (i = 0; i < NAT_ENTRIES; i++) {
            rlen = build_l4(reply, 6, PEER_ADDR, TUNNEL_ADDR, 443,
                            ports[i], 10);
            if (nat_inbound(&t, reply, rlen, now) != NAT_OK ||
                ipv4_dst(reply) != LAN_ADDR2 ||
                get16(reply + 22) != (uint16_t) (2048 + i))
                all_restored = 0;
        }
        probes = t.probes - probes;
        lookups = t.lookups - lookups;

        if (gen == 4) {
            check(all_restored,
                  "after four generations of churn, every reply still lands");
            check(probes / lookups < 8,
                  "and lookups are no dearer than they were in the first");
            check(t.evicted == evicted_before,
                  "an expired table is refilled without evicting anything");
        }
    }
}

/*
 * A chain corrupted into a loop must not hang.
 *
 * This is not hypothetical: deliberately removing the unlink in
 * claim_slot, to confirm the churn checks above could fail, made the
 * suite hang instead of fail. An entry relinked while still in its
 * bucket points at itself, and the walk never ends. In the gateway that
 * is a detached process wedging the tunnel silently, so the walks are
 * bounded and the bound is checked here.
 */
static void test_chain_loop(void)
{
    struct nat_table t;
    uint8_t pkt[128], reply[128];
    size_t len, rlen;
    uint16_t port;
    int i, idx = -1;

    printf("\na chain corrupted into a loop\n");
    nat_init(&t, TUNNEL_ADDR);

    len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 5000, 80, 10);
    check_quiet(nat_outbound(&t, pkt, len, 1000));
    port = get16(pkt + 20);

    for (i = 0; i < NAT_ENTRIES; i++) {
        if (t.entries[i].used)
            idx = i;
    }
    check(idx >= 0, "the flow was recorded somewhere in the table");
    t.entries[idx].next_in = (uint16_t) idx;   /* the loop */

    /*
     * The right identifier but a peer port that matches nothing, so the
     * walk cannot end early on a hit and has to reach the bound.
     */
    rlen = build_l4(reply, 6, PEER_ADDR, TUNNEL_ADDR, 81, port, 10);
    check(nat_inbound(&t, reply, rlen, 1000) == NAT_DROP_NO_MAPPING,
          "a lookup down a looped chain gives up instead of spinning");
    check(t.chain_overruns == 1,
          "and counts it, since only a bug in nat.c can cause it");
}

/* ---- fragmentation --------------------------------------------------- */

/*
 * Split a datagram the way a stack does: the first fragment carries
 * `first_payload` bytes after the IP header and sets More Fragments,
 * the second carries the rest at the corresponding offset. Both keep
 * the datagram's identification. The transport checksum is computed
 * over the whole datagram before splitting and rides in the first
 * fragment, which is exactly why a later fragment has no checksum of
 * its own to adjust.
 */
static void frag_split(const uint8_t *whole, size_t wlen, uint16_t id,
                       size_t first_payload,
                       uint8_t *a, size_t *alen, uint8_t *b, size_t *blen)
{
    size_t ihl = (size_t) (whole[0] & 0x0F) * 4;
    size_t payload = wlen - ihl;
    size_t rest = payload - first_payload;

    memcpy(a, whole, ihl + first_payload);
    put16(a + 2, (uint16_t) (ihl + first_payload));
    put16(a + 4, id);
    put16(a + 6, 0x2000);                      /* More Fragments */
    put16(a + 10, ip_checksum(a));
    *alen = ihl + first_payload;

    memcpy(b, whole, ihl);
    memcpy(b + ihl, whole + ihl + first_payload, rest);
    put16(b + 2, (uint16_t) (ihl + rest));
    put16(b + 4, id);
    put16(b + 6, (uint16_t) (first_payload / 8));   /* offset, no MF */
    put16(b + 10, ip_checksum(b));
    *blen = ihl + rest;
}

/* Put the two back together, as the receiving stack would. */
static size_t frag_join(const uint8_t *a, size_t alen,
                        const uint8_t *b, size_t blen, uint8_t *out)
{
    size_t ihl = (size_t) (a[0] & 0x0F) * 4;
    size_t total = alen + (blen - ihl);

    memcpy(out, a, alen);
    memcpy(out + alen, b + ihl, blen - ihl);
    put16(out + 2, (uint16_t) total);
    put16(out + 6, 0);                 /* no longer a fragment */
    put16(out + 10, ip_checksum(out));
    return total;
}

static void test_fragments(void)
{
    struct nat_table ta, tb;
    uint8_t whole[600], a[600], b[600], joined[600];
    size_t wlen, alen, blen, jlen;

    printf("\nfragmented datagrams\n");

    /*
     * The strongest form of this test: translate the datagram whole in
     * one table, translate it in two fragments in another, reassemble,
     * and require the two results to be identical byte for byte. That
     * checks the addresses, the ports, the IP checksum and the
     * transport checksum all at once, and against a result produced by
     * the path already known to be correct.
     */
    nat_init(&ta, TUNNEL_ADDR);
    nat_init(&tb, TUNNEL_ADDR);

    wlen = build_l4(whole, 17, LAN_ADDR, PEER_ADDR, 4444, 53, 400);
    put16(whole + 4, 0xBEEF);                    /* identification */
    put16(whole + 10, ip_checksum(whole));

    frag_split(whole, wlen, 0xBEEF, 200, a, &alen, b, &blen);

    check(nat_outbound(&tb, a, alen, 1000) == NAT_OK,
          "the first fragment is translated");
    check(nat_outbound(&tb, b, blen, 1000) == NAT_OK,
          "and the later fragment inherits its mapping");
    check(tb.frags_tracked == 1 && tb.frags_inherited == 1,
          "one datagram tracked, one fragment inherited");

    /*
     * The later fragment's own IP header, checked directly.
     *
     * Reassembling and comparing does not reach this: the receiver
     * takes the first fragment's header and only the second's payload,
     * so a wrong address or a stale checksum on the second fragment
     * survives that comparison untouched. It would not survive the
     * network — every hop reads that header, and the WireGuard peer
     * matches its source against AllowedIPs.
     */
    check(ipv4_src(b) == TUNNEL_ADDR,
          "the later fragment's own source is translated too");
    check(get16(b + 10) == ip_checksum(b),
          "and its own IP checksum is recomputed");
    check(get16(b + 6) == (uint16_t) (200 / 8),
          "while its offset is left alone");

    jlen = frag_join(a, alen, b, blen, joined);

    check(nat_outbound(&ta, whole, wlen, 1000) == NAT_OK,
          "the same datagram unfragmented is translated");
    check(jlen == wlen && memcmp(joined, whole, wlen) == 0,
          "reassembling the translated fragments gives the same datagram");

    /* Stated separately, so a failure above says which part broke. */
    check(ipv4_src(joined) == TUNNEL_ADDR, "the source is the tunnel address");
    check(get16(joined + 10) == ip_checksum(joined), "the IP checksum is right");
    check(get16(joined + 26) == l4_checksum(joined, 6),
          "and the UDP checksum still covers the reassembled whole");

    /*
     * Inbound, the reply may fragment too. The first fragment is found
     * by port as usual; the later one inherits the client address.
     */
    {
        struct nat_table t;
        uint8_t reply[600], ra[600], rb[600], rj[600];
        size_t rlen, ralen, rblen, rjlen;
        uint16_t port;

        nat_init(&t, TUNNEL_ADDR);
        wlen = build_l4(whole, 17, LAN_ADDR, PEER_ADDR, 4444, 53, 10);
        check(nat_outbound(&t, whole, wlen, 1000) == NAT_OK,
              "a request goes out to open the mapping");
        port = get16(whole + 20);

        rlen = build_l4(reply, 17, PEER_ADDR, TUNNEL_ADDR, 53, port, 400);
        put16(reply + 4, 0x1234);
        put16(reply + 10, ip_checksum(reply));
        frag_split(reply, rlen, 0x1234, 200, ra, &ralen, rb, &rblen);

        check(nat_inbound(&t, ra, ralen, 1100) == NAT_OK,
              "the reply's first fragment is restored");
        check(nat_inbound(&t, rb, rblen, 1100) == NAT_OK,
              "and its later fragment inherits the client address");
        check(ipv4_dst(rb) == LAN_ADDR,
              "which is written into that fragment's own header");
        check(get16(rb + 10) == ip_checksum(rb),
              "and its own IP checksum recomputed");

        rjlen = frag_join(ra, ralen, rb, rblen, rj);
        check(ipv4_dst(rj) == LAN_ADDR,
              "the reassembled reply is addressed to the client");
        check(get16(rj + 26) == l4_checksum(rj, 6),
              "with a UDP checksum still covering the whole");
        check(rjlen == rlen, "and the length is unchanged");
    }

    /*
     * The association is short-lived: a datagram not reassembled within
     * the timeout is abandoned by the receiver too, so holding the
     * entry longer would only waste it.
     */
    {
        struct nat_table t;
        uint8_t late[600];
        size_t latelen;

        nat_init(&t, TUNNEL_ADDR);
        wlen = build_l4(whole, 17, LAN_ADDR, PEER_ADDR, 4444, 53, 400);
        put16(whole + 4, 0x0BAD);
        put16(whole + 10, ip_checksum(whole));
        frag_split(whole, wlen, 0x0BAD, 200, a, &alen, late, &latelen);

        check(nat_outbound(&t, a, alen, 1000) == NAT_OK,
              "a first fragment is tracked");
        check(nat_outbound(&t, late, latelen,
                           1000 + NAT_FRAG_TIMEOUT_MS + 1)
              == NAT_DROP_FRAG_ORPHAN,
              "but a remainder arriving after the timeout is refused");
    }
}

/*
 * translated counts packets and flows counts mappings. They were the
 * same number for as long as every test flow was a single packet, which
 * made the distinction invisible and let the gateway label a packet
 * count as a flow rate.
 */
static void test_packets_versus_flows(void)
{
    struct nat_table t;
    uint8_t pkt[128];
    size_t len;
    int i;

    printf("\npackets against flows\n");
    nat_init(&t, TUNNEL_ADDR);

    for (i = 0; i < 5; i++) {
        len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 1111, 80, 10);
        check_quiet(nat_outbound(&t, pkt, len, 1000 + (uint64_t) i));
    }
    check(t.translated == 5, "five packets of one flow are five translations");
    check(t.flows == 1, "but only one flow");

    len = build_l4(pkt, 6, LAN_ADDR, PEER_ADDR, 2222, 80, 10);
    check_quiet(nat_outbound(&t, pkt, len, 1000));
    check(t.flows == 2, "a different source port is a second flow");
    check(t.translated == 6, "and a sixth translation");
}

/*
 * Fragments that arrive before the first of their datagram.
 *
 * Outbound this cannot happen — one sender, in-order capture — so it is
 * refused there. Inbound it can, because those fragments crossed the
 * internet inside the tunnel, and dropping one costs the whole
 * datagram when its first fragment is a moment behind it.
 */
static void test_held_fragments(void)
{
    struct nat_table t;
    uint8_t whole[600], a[600], b[600], out[600], req[128];
    size_t wlen, alen, blen, rlen, outlen;
    uint16_t port;

    printf("\nfragments that arrive early\n");
    nat_init(&t, TUNNEL_ADDR);

    /* Open a mapping so the reply has something to come back to. */
    rlen = build_l4(req, 17, LAN_ADDR, PEER_ADDR, 4444, 53, 10);
    check(nat_outbound(&t, req, rlen, 1000) == NAT_OK, "a request goes out");
    port = get16(req + 20);

    wlen = build_l4(whole, 17, PEER_ADDR, TUNNEL_ADDR, 53, port, 400);
    put16(whole + 4, 0x7777);
    put16(whole + 10, ip_checksum(whole));
    frag_split(whole, wlen, 0x7777, 200, a, &alen, b, &blen);

    /* The second fragment first, which is the whole point. */
    check(nat_inbound(&t, b, blen, 1100) == NAT_HELD,
          "a later fragment with no mapping yet is held, not dropped");
    check(t.frags_held == 1, "and counted as held");
    check(t.dropped_frag_orphan == 0, "not as an orphan");
    check(nat_take_held(&t, out, sizeof out, 1100) == 0,
          "nothing can be released while there is still no mapping");

    /* Now the first, which creates the mapping. */
    check(nat_inbound(&t, a, alen, 1100) == NAT_OK,
          "the first fragment then arrives and is translated");

    outlen = nat_take_held(&t, out, sizeof out, 1100);
    check(outlen == blen, "and the held one comes back, whole");
    check(t.frags_released == 1, "counted as released");
    check(ipv4_dst(out) == LAN_ADDR,
          "with the client address written into it");
    check(get16(out + 10) == ip_checksum(out), "and its checksum fixed");
    check(nat_take_held(&t, out, sizeof out, 1100) == 0,
          "and the buffer is then empty");

    /*
     * Reassembling the two must give the same datagram as if they had
     * arrived in order — the holding must not have changed anything
     * except when the packet was handed back.
     */
    {
        uint8_t joined[600];
        size_t jlen = frag_join(a, alen, out, outlen, joined);

        check(get16(joined + 26) == l4_checksum(joined, 6),
              "the reassembled reply still checksums");
        check(jlen == wlen, "and is the length it started as");
    }

    /* Held fragments do not wait for ever. */
    {
        struct nat_table t2;

        nat_init(&t2, TUNNEL_ADDR);
        check(nat_inbound(&t2, b, blen, 1000) == NAT_HELD, "one is held");
        check(nat_take_held(&t2, out, sizeof out,
                            1000 + NAT_FRAG_TIMEOUT_MS + 1) == 0,
              "and is gone once a receiver would have given up reassembling");
        check(t2.dropped_frag_orphan == 1,
              "counted as the orphan it turned out to be");
    }

    /* Outbound never holds: waiting would be waiting for nothing. */
    {
        struct nat_table t3;
        uint8_t o[600], p[600];
        size_t olen, plen;

        nat_init(&t3, TUNNEL_ADDR);
        wlen = build_l4(whole, 17, LAN_ADDR, PEER_ADDR, 4444, 53, 400);
        put16(whole + 4, 0x8888);
        put16(whole + 10, ip_checksum(whole));
        frag_split(whole, wlen, 0x8888, 200, o, &olen, p, &plen);

        check(nat_outbound(&t3, p, plen, 1000) == NAT_DROP_FRAG_ORPHAN,
              "an early later fragment outbound is refused, not held");
        check(t3.frags_held == 0, "and nothing is held");
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
    test_index();
    test_chain_loop();
    test_fragments();
    test_packets_versus_flows();
    test_held_fragments();

    printf("\n%s — %d checks, %d failure%s\n",
           failures == 0 ? "PASS" : "FAIL",
           checks, failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
