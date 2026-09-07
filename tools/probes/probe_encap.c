/*
 * vmsguard probe: does the stack decapsulate what we inject?
 *
 * A configured tunnel (IT0) exists on this platform -- confirmed
 * 2026-09-07, unlike SLIP and PPP before it. It is a virtual interface
 * that encapsulates IPv4 or IPv6 packets inside an IPv4 datagram, per
 * RFC 2003.
 *
 * That matters because injection here is the hard half. We can put an
 * IPv4 packet on the wire with any header we like (IP_HDRINCL, proven),
 * but we cannot originate IPv6 at all, and cannot suppress a packet the
 * stack decided to send. A tunnel interface might answer both, by
 * letting us hand the stack an encapsulated packet and have it unwrap
 * and deliver the contents itself.
 *
 * So: build a packet, wrap it in an IPv4 header addressed *to this
 * machine* from the tunnel's remote endpoint, and inject it. If the
 * stack recognises it as tunnel traffic it will decapsulate the inner
 * packet and act on it. An inner ICMP echo request is used because the
 * proof is then unambiguous -- a reply comes back to whatever address
 * the inner packet claimed to come from.
 *
 *   probe_encap --tunnel-remote 192.0.2.1 --tunnel-local 192.168.0.80 \
 *               --inner-src 192.168.0.218
 *
 * Then on 192.168.0.218:
 *
 *   sudo tcpdump -ni any icmp and host 192.168.0.80
 *
 * An echo *reply* arriving there proves the whole chain: the injection
 * was accepted, the stack matched it to the tunnel, decapsulated it,
 * and answered the packet inside. Nothing arriving means the stack
 * ignored it, which is the same answer SLIP gave and worth knowing just
 * as quickly.
 *
 * --inner-proto 41 wraps an IPv6 packet instead, which is the case an
 * IPv6 gateway needs; there is nothing to answer it with unless IPv6 is
 * configured, so watch the wire rather than expecting a reply.
 *
 * Needs SYSPRV on OpenVMS, and a tunnel:
 *
 *   $ iptunnel create 192.0.2.1
 *   $ ifconfig "IT0" up
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ethip.h"
#include "rawinject.h"

#define IPPROTO_IPIP_  4     /* IPv4 in IPv4, RFC 2003 */
#define IPPROTO_IPV6_  41    /* IPv6 in IPv4, RFC 4213 */

static unsigned short checksum(const unsigned char *d, size_t n)
{
    unsigned long sum = 0;
    size_t i;

    for (i = 0; i + 1 < n; i += 2)
        sum += (unsigned long) ((d[i] << 8) | d[i + 1]);
    if (i < n)
        sum += (unsigned long) d[i] << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (unsigned short) (~sum & 0xFFFF);
}

static void put32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char) (v >> 24);
    p[1] = (unsigned char) (v >> 16);
    p[2] = (unsigned char) (v >> 8);
    p[3] = (unsigned char) v;
}

/* An ICMP echo request, the thing that answers back. */
static size_t build_inner_v4(unsigned char *p, uint32_t src, uint32_t dst)
{
    unsigned short ck;

    memset(p, 0, 28);
    p[0] = 0x45;
    p[3] = 28;
    p[4] = 0x13; p[5] = 0x37;
    p[8] = 64;
    p[9] = 1;                       /* ICMP */
    put32(p + 12, src);
    put32(p + 16, dst);
    ck = checksum(p, 20);
    p[10] = (unsigned char) (ck >> 8);
    p[11] = (unsigned char) (ck & 0xFF);

    p[20] = 8;                      /* echo request */
    p[24] = 0x42; p[25] = 0x42;
    p[26] = 0x00; p[27] = 0x01;
    ck = checksum(p + 20, 8);
    p[22] = (unsigned char) (ck >> 8);
    p[23] = (unsigned char) (ck & 0xFF);
    return 28;
}

/*
 * ICMPv6's checksum covers a pseudo-header of the addresses, length and
 * next-header value, and is not optional the way ICMPv4's payload
 * checksum can be. Get it wrong and the receiver discards the packet
 * without a word -- which is indistinguishable from the stack refusing
 * to decapsulate, and so would waste the whole test.
 *
 * This is the same routine as probe_inject6, which was cross-checked
 * byte for byte against an independent implementation.
 */
static unsigned short icmp6_checksum(const unsigned char *src,
                                     const unsigned char *dst,
                                     const unsigned char *body, size_t len)
{
    unsigned long sum = 0;
    size_t i;

    for (i = 0; i < 16; i += 2)
        sum += (unsigned long) ((src[i] << 8) | src[i + 1]);
    for (i = 0; i < 16; i += 2)
        sum += (unsigned long) ((dst[i] << 8) | dst[i + 1]);
    sum += (unsigned long) (len >> 16) & 0xFFFF;
    sum += (unsigned long) len & 0xFFFF;
    sum += 58;                                  /* next header: ICMPv6 */

    for (i = 0; i + 1 < len; i += 2)
        sum += (unsigned long) ((body[i] << 8) | body[i + 1]);
    if (i < len)
        sum += (unsigned long) body[i] << 8;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (unsigned short) (~sum & 0xFFFF);
}

/*
 * An IPv6 echo request, properly formed so that a reply is possible and
 * its absence therefore means something.
 */
static size_t build_inner_v6(unsigned char *p, const unsigned char *src,
                             const unsigned char *dst)
{
    unsigned char body[16];
    unsigned short ck;

    memset(body, 0, sizeof body);
    body[0] = 128;                  /* echo request */
    body[4] = 0x42; body[5] = 0x42; /* identifier, as the IPv4 case */
    body[6] = 0x00; body[7] = 0x01; /* sequence */
    memcpy(body + 8, "vmsguard", 8);

    ck = icmp6_checksum(src, dst, body, sizeof body);
    body[2] = (unsigned char) (ck >> 8);
    body[3] = (unsigned char) (ck & 0xFF);

    memset(p, 0, 40);
    p[0] = 0x60;                    /* version 6 */
    p[5] = (unsigned char) sizeof body;
    p[6] = 58;                      /* next header: ICMPv6 */
    p[7] = 64;                      /* hop limit */
    memcpy(p + 8, src, 16);
    memcpy(p + 24, dst, 16);
    memcpy(p + 40, body, sizeof body);
    return 40 + sizeof body;
}

int main(int argc, char **argv)
{
    const char *remote_s = NULL, *local_s = NULL, *inner_s = NULL;
    const char *src6_s = "fd00::1", *dst6_s = "fd00::2";
    unsigned char src6[16], dst6[16];
    uint32_t remote = 0, local = 0, inner = 0, mask;
    unsigned char inner_pkt[96], outer[160];
    struct raw_injector *inj = NULL;
    size_t inner_len, total;
    int proto = IPPROTO_IPIP_;
    unsigned short ck;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--tunnel-remote") == 0 && i + 1 < argc)
            remote_s = argv[++i];
        else if (strcmp(argv[i], "--tunnel-local") == 0 && i + 1 < argc)
            local_s = argv[++i];
        else if (strcmp(argv[i], "--inner-src") == 0 && i + 1 < argc)
            inner_s = argv[++i];
        else if (strcmp(argv[i], "--inner-proto") == 0 && i + 1 < argc)
            proto = atoi(argv[++i]);
        else if (strcmp(argv[i], "--inner-src6") == 0 && i + 1 < argc)
            src6_s = argv[++i];
        else if (strcmp(argv[i], "--inner-dst6") == 0 && i + 1 < argc)
            dst6_s = argv[++i];
        else {
            fprintf(stderr,
"usage: %s --tunnel-remote <ip> --tunnel-local <ip>\n"
"          [--inner-src <ip>] [--inner-proto 4|41]\n"
"\n"
"  --tunnel-remote  the tunnel's far endpoint, as iptunnel was given\n"
"  --tunnel-local   this machine's tunnel endpoint\n"
"  --inner-src      who the inner packet claims to be from; a reply\n"
"                   goes here, so make it something you can watch\n"
"  --inner-proto    4 for IPv4 in IPv4 (default), 41 for IPv6\n"
"  --inner-src6     for proto 41: who the inner IPv6 packet is from\n"
"  --inner-dst6     and who it is to, which should be an address this\n"
"                   machine holds if a reply is wanted\n", argv[0]);
            return 2;
        }
    }
    if (remote_s == NULL || local_s == NULL ||
        ethip_parse_cidr(remote_s, &remote, &mask) != 0 ||
        ethip_parse_cidr(local_s, &local, &mask) != 0) {
        fprintf(stderr, "error: --tunnel-remote and --tunnel-local are"
                        " required\n");
        return 2;
    }
    if (proto == IPPROTO_IPIP_) {
        if (inner_s == NULL || ethip_parse_cidr(inner_s, &inner, &mask) != 0) {
            fprintf(stderr, "error: --inner-src is required for proto 4\n");
            return 2;
        }
    }

    printf("vmsguard encapsulation probe\n");
    printf("  outer : %s -> %s, protocol %d\n", remote_s, local_s, proto);
    if (proto == IPPROTO_IPIP_) {
        printf("  inner : %s -> %s, ICMP echo request\n", inner_s, local_s);
    } else {
        if (inet_pton(AF_INET6, src6_s, src6) != 1 ||
            inet_pton(AF_INET6, dst6_s, dst6) != 1) {
            fprintf(stderr, "error: --inner-src6 and --inner-dst6 must be"
                            " IPv6 addresses\n");
            return 2;
        }
        printf("  inner : %s -> %s, ICMPv6 echo request\n", src6_s, dst6_s);
    }
    printf("\n");

    inner_len = (proto == IPPROTO_IPIP_)
                ? build_inner_v4(inner_pkt, inner, local)
                : build_inner_v6(inner_pkt, src6, dst6);

    /*
     * The outer header. Sourced from the tunnel's remote endpoint and
     * addressed to this machine, because that is what an arriving
     * tunnelled packet looks like and what the stack must match against
     * the tunnel it was told about.
     */
    total = 20 + inner_len;
    memset(outer, 0, 20);
    outer[0] = 0x45;
    outer[2] = (unsigned char) (total >> 8);
    outer[3] = (unsigned char) (total & 0xFF);
    outer[4] = 0x77; outer[5] = 0x01;
    outer[8] = 64;
    outer[9] = (unsigned char) proto;
    put32(outer + 12, remote);
    put32(outer + 16, local);
    ck = checksum(outer, 20);
    outer[10] = (unsigned char) (ck >> 8);
    outer[11] = (unsigned char) (ck & 0xFF);
    memcpy(outer + 20, inner_pkt, inner_len);

    if (raw_injector_open(&inj) != 0) {
        printf("  raw socket: %s\n", raw_injector_error(inj));
        raw_injector_close(inj);
        return 1;
    }
    if (raw_injector_send(inj, outer, total) != 0) {
        printf("  send failed: %s\n", raw_injector_error(inj));
        raw_injector_close(inj);
        return 1;
    }
    raw_injector_close(inj);

    printf("  injected %lu bytes\n\n", (unsigned long) total);
    if (proto == IPPROTO_IPIP_) {
        printf("If the stack decapsulated it, an ICMP echo reply is on its\n"
               "way to %s. Watch there:\n", inner_s);
        printf("  tcpdump -ni any icmp and host %s\n\n", local_s);
        printf("A reply proves the whole chain: injection accepted, packet\n"
               "matched to the tunnel, decapsulated, and answered.\n");
    } else {
        printf("Check IT0's input count either way:\n");
        printf("  netstat -i\n\n");
        printf("A rising Ipkts means the tunnel accepted protocol 41,\n"
               "whether or not IPv6 is configured to do anything with the\n"
               "packet inside. If IPv6 is up and %s is an address this\n"
               "machine holds, an echo reply should also go to %s.\n",
               dst6_s, src6_s);
    }
    printf("\nNothing at all means the stack ignored it, which is the same\n"
           "answer SLIP gave and worth having just as quickly.\n");
    return 0;
}
