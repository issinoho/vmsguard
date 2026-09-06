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

int main(void)
{
    printf("vmsguard Ethernet/IPv4 inspection tests\n");

    test_parse();
    test_padding();
    test_addresses();
    test_cidr();
    test_subnet();

    printf("\n%s — %d checks, %d failure%s\n",
           failures == 0 ? "PASS" : "FAIL",
           checks, failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
