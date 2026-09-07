/*
 * vmsguard probe: raw-socket IPv6 injection
 *
 * Answers one question before anything is built on the answer: can this
 * system put an IPv6 packet on the wire with a source address it does
 * not own?
 *
 * The gateway needs exactly that. A packet arriving through the tunnel
 * is addressed to a LAN client and sourced from somewhere on the far
 * side, and injecting it means writing a header we did not get to
 * choose the source of. For IPv4 that is IP_HDRINCL, which is proven
 * working here. IPv6 has no equivalent that is portable:
 *
 *   - Linux has no IPV6_HDRINCL at all. The kernel builds the IPv6
 *     header, taking the source from the socket's binding, so a source
 *     you do not own cannot be sent. Layer 2 (AF_PACKET) is the escape,
 *     and OpenVMS has no AF_PACKET.
 *   - The BSDs did have IPV6_HDRINCL and mostly removed it, directing
 *     callers at ancillary data instead, which still will not let you
 *     forge a source.
 *   - What VSI TCP/IP Services does is unknown, and a declaration in a
 *     header would prove nothing anyway: pcap_sendpacket is declared on
 *     this system and returns "socket is not connected".
 *
 * So this probe tries each mechanism in turn and says which, if any,
 * actually put bytes on the wire. It writes an ICMPv6 echo request,
 * because a reply is proof the receiver accepted it as well formed.
 *
 *   probe_inject6 --src fd00::1 --dst fd00::2
 *
 * Then on the destination host:
 *
 *   sudo tcpdump -ni any icmp6 and host fd00::1
 *
 * Seeing the request arrive proves injection works. Nothing arriving,
 * with the probe reporting a successful send, means the stack accepted
 * the write and dropped the packet -- which is the failure mode that
 * cost this project a week over SLIP, and the reason for watching the
 * wire rather than trusting a return code.
 *
 * Needs SYSPRV on OpenVMS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* ---- the packet ------------------------------------------------------ */

/*
 * ICMPv6's checksum covers a pseudo-header of the addresses, length and
 * next-header value. Unlike ICMPv4 it is not optional, so this has to be
 * right or the receiver discards the packet without a word.
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

static size_t build_echo(unsigned char *out, const unsigned char *src,
                         const unsigned char *dst, int with_header)
{
    unsigned char body[16];
    unsigned short ck;
    size_t n = 0;

    memset(body, 0, sizeof body);
    body[0] = 128;                  /* echo request */
    body[1] = 0;                    /* code */
    body[4] = 0x42; body[5] = 0x42; /* identifier */
    body[6] = 0x00; body[7] = 0x01; /* sequence */
    memcpy(body + 8, "vmsguard", 8);

    ck = icmp6_checksum(src, dst, body, sizeof body);
    body[2] = (unsigned char) (ck >> 8);
    body[3] = (unsigned char) (ck & 0xFF);

    if (with_header) {
        out[0] = 0x60;              /* version 6, no traffic class */
        out[1] = 0; out[2] = 0; out[3] = 0;
        out[4] = 0;
        out[5] = (unsigned char) sizeof body;   /* payload length */
        out[6] = 58;                            /* next header: ICMPv6 */
        out[7] = 64;                            /* hop limit */
        memcpy(out + 8, src, 16);
        memcpy(out + 24, dst, 16);
        n = 40;
    }
    memcpy(out + n, body, sizeof body);
    return n + sizeof body;
}

/* ---- the attempts ---------------------------------------------------- */

static int report(const char *what, int ok, const char *detail)
{
    printf("  %-34s %s%s%s\n", what, ok ? "yes" : "no",
           detail != NULL ? " -- " : "", detail != NULL ? detail : "");
    return ok;
}

int main(int argc, char **argv)
{
    const char *src_s = NULL, *dst_s = NULL;
    unsigned char src[16], dst[16];
    unsigned char pkt[128];
    struct sockaddr_in6 to;
    size_t len;
    int fd;
    int any = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--src") == 0 && i + 1 < argc)
            src_s = argv[++i];
        else if (strcmp(argv[i], "--dst") == 0 && i + 1 < argc)
            dst_s = argv[++i];
        else {
            fprintf(stderr, "usage: %s --src <ipv6> --dst <ipv6>\n", argv[0]);
            return 2;
        }
    }
    if (src_s == NULL || dst_s == NULL) {
        fprintf(stderr, "usage: %s --src <ipv6> --dst <ipv6>\n", argv[0]);
        fprintf(stderr, "\n--src should be an address this machine does"
                        " NOT own: forging it is the\nwhole question.\n");
        return 2;
    }
    if (inet_pton(AF_INET6, src_s, src) != 1 ||
        inet_pton(AF_INET6, dst_s, dst) != 1) {
        fprintf(stderr, "error: --src and --dst must be IPv6 addresses\n");
        return 2;
    }

    printf("vmsguard IPv6 injection probe\n");
    printf("  source      : %s  (forged; not this machine's)\n", src_s);
    printf("  destination : %s\n\n", dst_s);

    memset(&to, 0, sizeof to);
    to.sin6_family = AF_INET6;
    memcpy(&to.sin6_addr, dst, 16);

    /* 1. Does a raw IPv6 socket open at all? */
    fd = socket(AF_INET6, SOCK_RAW, 58 /* IPPROTO_ICMPV6 */);
    if (fd < 0) {
        report("raw IPv6 socket opens", 0, strerror(errno));
        printf("\nWithout this nothing else is possible. If the error is a"
               " privilege\nfailure, try again with SYSPRV.\n");
        return 1;
    }
    report("raw IPv6 socket opens", 1, NULL);

    /*
     * 2. IPV6_HDRINCL, if this system has it. Defined nowhere on Linux;
     *    present on some BSDs. If it sets, the header we build is the
     *    header that goes out, and a forged source is possible.
     */
#ifdef IPV6_HDRINCL
    {
        int on = 1;

        if (setsockopt(fd, IPPROTO_IPV6, IPV6_HDRINCL,
                       (void *) &on, sizeof on) == 0) {
            report("IPV6_HDRINCL accepted", 1, NULL);
            len = build_echo(pkt, src, dst, 1);
            if (sendto(fd, pkt, len, 0, (struct sockaddr *) &to,
                       sizeof to) == (long) len) {
                any = report("  and a forged packet sends", 1,
                             "watch the wire to be sure");
            } else {
                report("  and a forged packet sends", 0, strerror(errno));
            }
        } else {
            report("IPV6_HDRINCL accepted", 0, strerror(errno));
        }
    }
#else
    report("IPV6_HDRINCL declared", 0, "not defined in the headers");
#endif

    /*
     * 3. Without a header-include option the kernel builds the header
     *    and takes the source from the socket. Binding to an address we
     *    do not own should fail, and if it does, a forged source is
     *    simply not available this way -- which is the answer, not a
     *    setback.
     */
    {
        struct sockaddr_in6 from;

        memset(&from, 0, sizeof from);
        from.sin6_family = AF_INET6;
        memcpy(&from.sin6_addr, src, 16);

        if (bind(fd, (struct sockaddr *) &from, sizeof from) == 0)
            report("binding to the forged source", 1,
                   "unexpected; the stack may not be checking");
        else
            report("binding to the forged source", 0, strerror(errno));
    }

    /*
     * 4. And the ordinary case, for comparison: a packet from whatever
     *    address the stack picks. If this works and the forged one does
     *    not, IPv6 forwarding is possible only for traffic we source
     *    ourselves -- not for a gateway.
     */
    close(fd);
    fd = socket(AF_INET6, SOCK_RAW, 58);
    if (fd >= 0) {
        len = build_echo(pkt, src, dst, 0);
        if (sendto(fd, pkt, len, 0, (struct sockaddr *) &to,
                   sizeof to) == (long) len)
            report("unforged packet sends", 1, NULL);
        else
            report("unforged packet sends", 0, strerror(errno));
        close(fd);
    }

    printf("\n");
    if (any) {
        printf("A forged source went out. Confirm it arrived:\n");
        printf("  tcpdump -ni any icmp6 and host %s\n", src_s);
        printf("\nIf nothing arrives, the stack accepted the write and\n"
               "discarded the packet, which is not the same as working.\n");
    } else {
        printf("No mechanism here can send with a source this machine does\n"
               "not own. An IPv6 gateway would need one -- see\n"
               "docs/research/driver-feasibility.md, which records the same\n"
               "conclusion for IPv4 pcap injection.\n");
    }
    return any ? 0 : 1;
}
