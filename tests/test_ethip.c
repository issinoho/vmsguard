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

int main(void)
{
    printf("vmsguard Ethernet/IPv4 inspection tests\n");

    test_parse();
    test_padding();
    test_addresses();
    test_cidr();
    test_subnet();    test_in_any();
    test_best_match();


    printf("\n%s — %d checks, %d failure%s\n",
           failures == 0 ? "PASS" : "FAIL",
           checks, failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
