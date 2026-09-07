/*
 * Ethernet/IPv4 inspection tests — vmsguard
 *
 * These decide which captured frames get tunnelled, so the failure
 * modes matter: accepting a frame that should be ignored sends a
 * stranger's traffic down the tunnel, and mishandling Ethernet padding
 * corrupts small packets in a way that only shows up for some sizes.
 */

#include <stdio.h>
#include <string.h>

#include "ethip.h"

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

/* Build an Ethernet frame containing an IPv4 packet of total_len,
   padded out to framelen. Returns the frame length used. */
static size_t make_frame(uint8_t *buf, size_t cap,
                         uint16_t ethertype, size_t total_len,
                         size_t framelen)
{
    size_t i;

    if (framelen > cap)
        return 0;
    memset(buf, 0, framelen);

    for (i = 0; i < 6; i++)
        buf[i] = (uint8_t) (0x10 + i);        /* destination MAC */
    for (i = 0; i < 6; i++)
        buf[6 + i] = (uint8_t) (0x20 + i);    /* source MAC */
    buf[12] = (uint8_t) (ethertype >> 8);
    buf[13] = (uint8_t) (ethertype & 0xFF);

    buf[ETH_HDR_LEN + 0] = 0x45;              /* IPv4, IHL 5 */
    buf[ETH_HDR_LEN + 2] = (uint8_t) (total_len >> 8);
    buf[ETH_HDR_LEN + 3] = (uint8_t) (total_len & 0xFF);
    buf[ETH_HDR_LEN + 9] = 1;                 /* ICMP */

    /* 10.0.0.50 -> 10.9.0.5 */
    buf[ETH_HDR_LEN + 12] = 10;
    buf[ETH_HDR_LEN + 13] = 0;
    buf[ETH_HDR_LEN + 14] = 0;
    buf[ETH_HDR_LEN + 15] = 50;
    buf[ETH_HDR_LEN + 16] = 10;
    buf[ETH_HDR_LEN + 17] = 9;
    buf[ETH_HDR_LEN + 18] = 0;
    buf[ETH_HDR_LEN + 19] = 5;

    return framelen;
}

static void test_parse(void)
{
    uint8_t frame[128];
    const uint8_t *ip;
    size_t framelen, iplen = 0;

    printf("\nframe parsing\n");

    framelen = make_frame(frame, sizeof frame, ETH_TYPE_IPV4, 40, 54);
    ip = ethip_ipv4(frame, framelen, &iplen);
    check(ip == frame + ETH_HDR_LEN, "IP header follows the Ethernet header");
    check(iplen == 40, "length comes from the IP header, not the frame");
    check(ipv4_proto(ip) == 1, "protocol byte read correctly");

    /* Not IPv4. */
    framelen = make_frame(frame, sizeof frame, 0x0806 /* ARP */, 40, 54);
    check(ethip_ipv4(frame, framelen, &iplen) == NULL,
          "a non-IPv4 ethertype is rejected");

    /* Too short to hold an IP header at all. */
    check(ethip_ipv4(frame, ETH_HDR_LEN + 4, &iplen) == NULL,
          "a runt frame is rejected");

    /* An IP total length longer than what was captured: a truncated
       capture, which must not be treated as a whole packet. */
    framelen = make_frame(frame, sizeof frame, ETH_TYPE_IPV4, 100, 54);
    check(ethip_ipv4(frame, framelen, &iplen) == NULL,
          "a total length beyond the captured frame is rejected");

    /* An IHL claiming more header than the packet contains. */
    framelen = make_frame(frame, sizeof frame, ETH_TYPE_IPV4, 40, 54);
    frame[ETH_HDR_LEN] = 0x4F;   /* IHL 15 words = 60 bytes > total 40 */
    check(ethip_ipv4(frame, framelen, &iplen) == NULL,
          "an IHL larger than the total length is rejected");

    /* Version 6 in an IPv4 ethertype. */
    framelen = make_frame(frame, sizeof frame, ETH_TYPE_IPV4, 40, 54);
    frame[ETH_HDR_LEN] = 0x65;
    check(ethip_ipv4(frame, framelen, &iplen) == NULL,
          "a version field that is not 4 is rejected");
}

static void test_padding(void)
{
    uint8_t frame[128];
    const uint8_t *ip;
    size_t framelen, iplen = 0;

    printf("\nEthernet padding\n");

    /*
     * A 28-byte IP packet in a frame padded to the 60-byte Ethernet
     * minimum. Reporting 46 bytes here would tunnel 18 bytes of padding
     * as packet data.
     */
    framelen = make_frame(frame, sizeof frame, ETH_TYPE_IPV4, 28, 60);
    ip = ethip_ipv4(frame, framelen, &iplen);
    check(ip != NULL, "a padded minimum-size frame parses");
    check(iplen == 28, "padding is excluded from the reported length");
}

static void test_addresses(void)
{
    uint8_t frame[128];
    const uint8_t *ip;
    size_t framelen, iplen = 0;
    char buf[16];

    printf("\naddresses\n");

    framelen = make_frame(frame, sizeof frame, ETH_TYPE_IPV4, 40, 54);
    ip = ethip_ipv4(frame, framelen, &iplen);

    check(ipv4_src(ip) == 0x0A000032UL, "source address 10.0.0.50");
    check(ipv4_dst(ip) == 0x0A090005UL, "destination address 10.9.0.5");

    ipv4_format(buf, sizeof buf, ipv4_dst(ip));
    check(strcmp(buf, "10.9.0.5") == 0, "formats back to dotted quad");
}

static void test_cidr(void)
{
    uint32_t net = 0, mask = 0;

    printf("\nCIDR parsing\n");

    check(ethip_parse_cidr("10.9.0.0/24", &net, &mask) == 0 &&
          net == 0x0A090000UL && mask == 0xFFFFFF00UL,
          "10.9.0.0/24");

    /* A host bit set in the text should be masked away. */
    check(ethip_parse_cidr("10.9.0.5/24", &net, &mask) == 0 &&
          net == 0x0A090000UL,
          "host bits are masked off the network address");

    check(ethip_parse_cidr("192.168.1.1", &net, &mask) == 0 &&
          mask == 0xFFFFFFFFUL,
          "a bare address is treated as /32");

    check(ethip_parse_cidr("0.0.0.0/0", &net, &mask) == 0 &&
          net == 0 && mask == 0,
          "/0 gives a zero mask rather than undefined shift behaviour");

    check(ethip_parse_cidr("10.9.0.0/33", &net, &mask) != 0,
          "rejects a prefix longer than 32");
    check(ethip_parse_cidr("10.9.0.256/24", &net, &mask) != 0,
          "rejects an octet above 255");
    check(ethip_parse_cidr("not-an-address", &net, &mask) != 0,
          "rejects text that is not an address");
    check(ethip_parse_cidr("10.9.0.0/24junk", &net, &mask) != 0,
          "rejects trailing rubbish");
    check(ethip_parse_cidr(NULL, &net, &mask) != 0, "rejects NULL");
}

static void test_subnet(void)
{
    uint32_t net = 0, mask = 0;

    printf("\nsubnet membership\n");

    ethip_parse_cidr("10.9.0.0/24", &net, &mask);

    check(ipv4_in_subnet(0x0A090005UL, net, mask) == 1,
          "10.9.0.5 is inside 10.9.0.0/24");
    check(ipv4_in_subnet(0x0A090000UL, net, mask) == 1,
          "the network address itself is inside");
    check(ipv4_in_subnet(0x0A0900FFUL, net, mask) == 1,
          "the broadcast address is inside");
    check(ipv4_in_subnet(0x0A0A0005UL, net, mask) == 0,
          "10.10.0.5 is outside");
    check(ipv4_in_subnet(0x0A000032UL, net, mask) == 0,
          "10.0.0.50 is outside");

    ethip_parse_cidr("0.0.0.0/0", &net, &mask);
    check(ipv4_in_subnet(0x08080808UL, net, mask) == 1,
          "everything is inside 0.0.0.0/0");
}

/*
 * Matching an address against a list of subnets, which is what
 * AllowedIPs, --client and --exclude all are.
 */
static void test_in_any(void)
{
    struct ipv4_subnet list[3];

    printf("\naddress against a list of subnets\n");

    check(ipv4_in_any(list, 0, 0x0A000001UL) == 0,
          "an empty list matches nothing, not everything");

    list[0].net  = 0x0A090000UL;   /* 10.9.0.0/24  */
    list[0].mask = 0xFFFFFF00UL;
    list[1].net  = 0xC0A80000UL;   /* 192.168.0.0/16 */
    list[1].mask = 0xFFFF0000UL;

    check(ipv4_in_any(list, 2, 0x0A090005UL), "an address in the first");
    check(ipv4_in_any(list, 2, 0xC0A8007BUL), "an address in the second");
    check(!ipv4_in_any(list, 2, 0x08080808UL), "and one in neither");

    /* The boundary either side of a /24. */
    check(ipv4_in_any(list, 2, 0x0A0900FFUL), "the top of a /24 is inside");
    check(!ipv4_in_any(list, 2, 0x0A090100UL),
          "and the address after it is not");

    /*
     * The default route matches everything, which is what a full
     * tunnel's AllowedIPs is and why it makes the check a formality
     * rather than a restriction.
     */
    list[2].net  = 0;
    list[2].mask = 0;
    check(ipv4_in_any(&list[2], 1, 0x08080808UL),
          "0.0.0.0/0 matches any address");
    check(ipv4_in_any(&list[2], 1, 0),
          "including 0.0.0.0 itself");

    /* A single host. */
    list[0].net  = 0xC0A800DAUL;   /* 192.168.0.218/32 */
    list[0].mask = 0xFFFFFFFFUL;
    check(ipv4_in_any(list, 1, 0xC0A800DAUL), "a /32 matches its own host");
    check(!ipv4_in_any(list, 1, 0xC0A800DBUL), "and not its neighbour");
}

/*
 * Longest-prefix match, which is how a destination is tied to a peer.
 * Getting it wrong does not fail loudly: the packet goes down another
 * peer's tunnel, encrypted to the wrong key, and is discarded at the
 * far end without a word.
 */
static void test_best_match(void)
{
    struct ipv4_subnet list[4];
    uint32_t mask = 0xDEADBEEFUL;

    printf("\nlongest prefix match\n");

    check(!ipv4_best_match(list, 0, 0x0A000001UL, &mask),
          "an empty list matches nothing");

    list[0].net  = 0;              /* 0.0.0.0/0    */
    list[0].mask = 0;
    list[1].net  = 0x0A090000UL;   /* 10.9.0.0/24  */
    list[1].mask = 0xFFFFFF00UL;
    list[2].net  = 0x0A000000UL;   /* 10.0.0.0/8   */
    list[2].mask = 0xFF000000UL;

    check(ipv4_best_match(list, 3, 0x0A090005UL, &mask) && mask == 0xFFFFFF00UL,
          "the /24 wins over the /8 and the default route");
    check(ipv4_best_match(list, 3, 0x0A0A0005UL, &mask) && mask == 0xFF000000UL,
          "an address in the /8 but not the /24 takes the /8");
    check(ipv4_best_match(list, 3, 0x08080808UL, &mask) && mask == 0,
          "and one in neither falls back to the default route");

    /* Order must not matter: the most specific wins wherever it sits. */
    list[0].net  = 0x0A090000UL;
    list[0].mask = 0xFFFFFF00UL;
    list[1].net  = 0;
    list[1].mask = 0;
    check(ipv4_best_match(list, 2, 0x0A090005UL, &mask) && mask == 0xFFFFFF00UL,
          "the specific entry wins when it comes first as well");

    /* A /32 is as specific as it gets. */
    list[2].net  = 0x0A090005UL;
    list[2].mask = 0xFFFFFFFFUL;
    check(ipv4_best_match(list, 3, 0x0A090005UL, &mask) &&
          mask == 0xFFFFFFFFUL,
          "a host route beats the subnet containing it");

    /* Without a default route, an unmatched address matches nothing —
       which is what makes "no peer claims this" expressible. */
    list[0].net  = 0x0A090000UL;
    list[0].mask = 0xFFFFFF00UL;
    check(!ipv4_best_match(list, 1, 0x08080808UL, &mask),
          "no default route means unmatched really is unmatched");
}

/* ---- IPv6 ------------------------------------------------------------ */

static int addr6(const char *text, uint8_t out[16])
{
    uint8_t prefix;
    return ethip_parse_cidr6(text, out, &prefix) == 0;
}

static void test_parse6(void)
{
    uint8_t a[16], p;
    char buf[64];

    printf("\nIPv6 text\n");

    /* The forms AllowedIPs actually contains. */
    check(ethip_parse_cidr6("::/0", a, &p) == 0 && p == 0,
          "the default route");
    check(ethip_parse_cidr6("2001:db8::/32", a, &p) == 0 && p == 32 &&
          a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0d && a[3] == 0xb8 &&
          a[4] == 0,
          "a documentation prefix");
    check(ethip_parse_cidr6("fd00::1", a, &p) == 0 && p == 128 &&
          a[0] == 0xfd && a[15] == 0x01,
          "a bare address is a /128");
    /*
     * fe80::c2a8:ff:fe50:0 is one group before the gap and four after,
     * so the tail sits at groups 4-7 and the zeroes fill 1-3. Written
     * out: fe80:0:0:0:c2a8:00ff:fe50:0000.
     */
    check(ethip_parse_cidr6("fe80::c2a8:ff:fe50:0/64", a, &p) == 0 &&
          p == 64 && a[0] == 0xfe && a[1] == 0x80 &&
          a[2] == 0 && a[7] == 0 &&
          a[8] == 0xc2 && a[9] == 0xa8 && a[11] == 0xff &&
          a[12] == 0xfe && a[13] == 0x50 && a[15] == 0,
          "a link-local with a tail, as the target reported it");

    /* "::" in each position it can occupy. */
    check(ethip_parse_cidr6("::1", a, &p) == 0 && a[15] == 1 && a[0] == 0,
          "leading");
    check(ethip_parse_cidr6("fd00::", a, &p) == 0 && a[0] == 0xfd &&
          a[15] == 0, "trailing");
    check(ethip_parse_cidr6("1:2:3:4:5:6:7:8", a, &p) == 0 &&
          a[1] == 1 && a[15] == 8, "and a full address needing none");

    /* Refusals. Each is a way a config file could be wrong. */
    check(ethip_parse_cidr6("1:2:3:4:5:6:7", a, &p) != 0,
          "too few groups without '::'");
    check(ethip_parse_cidr6("1:2:3:4:5:6:7:8:9", a, &p) != 0,
          "too many groups");
    check(ethip_parse_cidr6("fd00::1::2", a, &p) != 0,
          "two '::' would be ambiguous");
    check(ethip_parse_cidr6("fd00::/129", a, &p) != 0,
          "a prefix longer than 128");
    check(ethip_parse_cidr6("fd00::/", a, &p) != 0, "an empty prefix");
    check(ethip_parse_cidr6("fd00::12345", a, &p) != 0,
          "a group of more than four digits");
    check(ethip_parse_cidr6("::ffff:192.0.2.1", a, &p) != 0,
          "an embedded IPv4 form, which is refused rather than guessed at");
    check(ethip_parse_cidr6("192.0.2.1", a, &p) != 0, "an IPv4 address");
    check(ethip_parse_cidr6("", a, &p) != 0, "nothing at all");

    /* Round trip, including the compression rules. */
    (void) addr6("fe80::c2a8:ff:fe50:0", a);
    ipv6_format(buf, sizeof buf, a);
    check(strcmp(buf, "fe80::c2a8:ff:fe50:0") == 0,
          "formatting compresses the longest run of zeroes");

    (void) addr6("::", a);
    ipv6_format(buf, sizeof buf, a);
    check(strcmp(buf, "::") == 0, "the unspecified address");

    (void) addr6("1:0:0:0:0:0:0:8", a);
    ipv6_format(buf, sizeof buf, a);
    check(strcmp(buf, "1::8") == 0, "a long interior run");

    /*
     * A single zero group is left uncompressed: "::" saves nothing and
     * reads worse, and RFC 5952 says not to.
     */
    (void) addr6("1:0:2:3:4:5:6:7", a);
    ipv6_format(buf, sizeof buf, a);
    check(strcmp(buf, "1:0:2:3:4:5:6:7") == 0,
          "but a single zero group is left alone");
}

static void test_subnet6(void)
{
    struct ipv6_subnet list[3];
    uint8_t a[16], p;

    printf("\nIPv6 prefixes\n");

    (void) ethip_parse_cidr6("2001:db8::/32", list[0].net, &list[0].prefix);
    (void) ethip_parse_cidr6("fd00::/8", list[1].net, &list[1].prefix);

    (void) addr6("2001:db8:1234::1", a);
    check(ipv6_in_subnet(a, list[0].net, list[0].prefix),
          "an address inside a /32");
    (void) addr6("2001:db9::1", a);
    check(!ipv6_in_subnet(a, list[0].net, list[0].prefix),
          "and one just outside it");

    /* A prefix that is not a whole number of bytes is where an
       off-by-one lives, so both sides of /8 are checked. */
    (void) addr6("fdff::1", a);
    check(ipv6_in_subnet(a, list[1].net, list[1].prefix),
          "fd00::/8 covers the whole fd00-fdff range");
    (void) addr6("fe00::1", a);
    check(!ipv6_in_subnet(a, list[1].net, list[1].prefix),
          "and stops at fe00");

    /*
     * A prefix that is not a whole number of bytes, which every case
     * above happens to be. Without one the sub-byte masking is never
     * executed, and removing it entirely passed the whole suite.
     *
     * fc00::/7 is the real example: it is the ULA range, and its
     * boundary falls inside the first byte.
     */
    (void) ethip_parse_cidr6("fc00::/7", list[2].net, &list[2].prefix);
    (void) addr6("fc00::1", a);
    check(ipv6_in_subnet(a, list[2].net, list[2].prefix),
          "fc00::/7 covers fc00");
    (void) addr6("fdff:ffff::1", a);
    check(ipv6_in_subnet(a, list[2].net, list[2].prefix), "and fdff");
    (void) addr6("fe00::1", a);
    check(!ipv6_in_subnet(a, list[2].net, list[2].prefix),
          "and stops before fe00, one bit away");
    (void) addr6("fbff::1", a);
    check(!ipv6_in_subnet(a, list[2].net, list[2].prefix),
          "and does not start before fc00");

    /* A partial byte further in, where the whole-byte compare runs
       first and the mask applies to a later byte. */
    (void) ethip_parse_cidr6("2001:db8:8000::/33", list[2].net,
                             &list[2].prefix);
    (void) addr6("2001:db8:8001::1", a);
    check(ipv6_in_subnet(a, list[2].net, list[2].prefix),
          "a /33 matches inside its half");
    (void) addr6("2001:db8:7fff::1", a);
    check(!ipv6_in_subnet(a, list[2].net, list[2].prefix),
          "and not the half below it");

    /* /0 matches everything, /128 exactly one thing. */
    memset(list[2].net, 0, 16);
    list[2].prefix = 0;
    (void) addr6("2001:4860:4860::8888", a);
    check(ipv6_in_subnet(a, list[2].net, list[2].prefix),
          "::/0 matches any address");

    (void) ethip_parse_cidr6("fd00::1/128", list[2].net, &list[2].prefix);
    (void) addr6("fd00::1", a);
    check(ipv6_in_subnet(a, list[2].net, list[2].prefix), "a /128 matches");
    (void) addr6("fd00::2", a);
    check(!ipv6_in_subnet(a, list[2].net, list[2].prefix),
          "and not its neighbour");

    /* Longest prefix, as for IPv4 and for the same reason. */
    (void) ethip_parse_cidr6("::/0", list[0].net, &list[0].prefix);
    (void) ethip_parse_cidr6("2001:db8::/32", list[1].net, &list[1].prefix);
    (void) ethip_parse_cidr6("2001:db8:1::/48", list[2].net, &list[2].prefix);

    (void) addr6("2001:db8:1::5", a);
    check(ipv6_best_match(list, 3, a, &p) && p == 48,
          "the /48 wins over the /32 and the default route");
    (void) addr6("2001:db8:2::5", a);
    check(ipv6_best_match(list, 3, a, &p) && p == 32,
          "and the /32 when the /48 does not contain it");
    (void) addr6("2600::1", a);
    check(ipv6_best_match(list, 3, a, &p) && p == 0,
          "falling back to ::/0");
    check(!ipv6_best_match(list, 0, a, &p), "an empty list matches nothing");
}

static void test_frame6(void)
{
    uint8_t frame[128];
    const uint8_t *ip;
    size_t iplen = 0;
    uint8_t want[16];

    printf("\nIPv6 in a frame\n");

    memset(frame, 0, sizeof frame);
    frame[12] = 0x86; frame[13] = 0xDD;
    frame[14] = 0x60;                       /* version 6 */
    frame[14 + 4] = 0; frame[14 + 5] = 8;   /* payload length 8 */
    frame[14 + 6] = 58;                     /* ICMPv6 */
    frame[14 + 7] = 64;
    (void) addr6("fd00::1", frame + 14 + 8);
    (void) addr6("fd00::2", frame + 14 + 24);

    ip = ethip_ipv6(frame, sizeof frame, &iplen);
    check(ip != NULL, "an IPv6 frame is recognised");
    check(iplen == 48,
          "and its length comes from the header, not the capture");

    (void) addr6("fd00::1", want);
    check(ip != NULL && memcmp(ipv6_src(ip), want, 16) == 0,
          "the source is where it should be");
    (void) addr6("fd00::2", want);
    check(ip != NULL && memcmp(ipv6_dst(ip), want, 16) == 0,
          "and the destination");

    /* An IPv4 frame must not be taken for one. */
    frame[12] = 0x08; frame[13] = 0x00;
    check(ethip_ipv6(frame, sizeof frame, &iplen) == NULL,
          "an IPv4 frame is not IPv6");

    /* A VLAN tag in front of it, as the IPv4 path allows. */
    memset(frame, 0, sizeof frame);
    frame[12] = 0x81; frame[13] = 0x00;
    frame[16] = 0x86; frame[17] = 0xDD;
    frame[18] = 0x60;
    frame[18 + 5] = 8;
    check(ethip_ipv6(frame, sizeof frame, &iplen) == frame + 18 &&
          iplen == 48, "a VLAN tag is stepped over");

    /* A header claiming more than arrived is refused. */
    memset(frame, 0, sizeof frame);
    frame[12] = 0x86; frame[13] = 0xDD;
    frame[14] = 0x60;
    frame[14 + 4] = 0xFF; frame[14 + 5] = 0xFF;
    check(ethip_ipv6(frame, 80, &iplen) == NULL,
          "a payload length longer than the frame is refused");

    check(!ipv6_looks_valid(frame, 10), "a runt is not a packet");
    frame[14] = 0x45;
    check(!ipv6_looks_valid(frame + 14, 40),
          "and neither is something whose version is 4");
}

int main(void)
{
    printf("vmsguard Ethernet/IPv4 inspection tests\n");

    test_parse();
    test_padding();
    test_addresses();
    test_cidr();
    test_subnet();    test_in_any();
    test_best_match();
    test_parse6();
    test_subnet6();
    test_frame6();


    printf("\n%s — %d checks, %d failure%s\n",
           failures == 0 ? "PASS" : "FAIL",
           checks, failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
