/*
 * vmsguard probe: raw-socket IPv4 injection
 *
 * Tests IP_HDRINCL in isolation — the one mechanism the gateway needs
 * that has not been shown to work end to end. The socket is known to
 * open; whether a packet written to it actually reaches the wire is a
 * separate question.
 *
 * Testing it inside the gateway would need a LAN host and a WireGuard
 * peer on separate machines, because a host that is both will deliver
 * the reply locally instead of sending it back through the tunnel. This
 * probe avoids the topology entirely: it injects one ICMP echo request
 * with addresses of your choosing and leaves verification to whatever
 * is watching the network.
 *
 *   probe_inject --src 192.168.0.80 --dst 192.168.0.131
 *
 * Then on the destination host:
 *
 *   sudo tcpdump -ni any icmp and host 192.168.0.80
 *
 * Seeing the echo request arrive proves injection works. A reply is a
 * bonus — it means the receiver accepted the packet as well formed.
 *
 * Needs SYSPRV on OpenVMS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ethip.h"
#include "rawinject.h"

static unsigned short inet_checksum(const unsigned char *data, size_t len)
{
    unsigned long sum = 0;
    size_t i;

    for (i = 0; i + 1 < len; i += 2)
        sum += ((unsigned long) data[i] << 8) | (unsigned long) data[i + 1];
    if (i < len)
        sum += (unsigned long) data[i] << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (unsigned short) (~sum & 0xFFFF);
}

/* Build an ICMP echo request. Returns the total length. */
static size_t build_echo(unsigned char *out, unsigned long src,
                         unsigned long dst, unsigned short id,
                         unsigned short seq)
{
    static const char payload[] = "vmsguard inject probe";
    const size_t paylen = sizeof payload - 1;
    const size_t icmplen = 8 + paylen;
    const size_t total = 20 + icmplen;
    unsigned short ck;

    memset(out, 0, total);

    out[0] = 0x45;                          /* IPv4, IHL 5 */
    out[2] = (unsigned char) (total >> 8);
    out[3] = (unsigned char) (total & 0xFF);
    out[4] = (unsigned char) (id >> 8);
    out[5] = (unsigned char) (id & 0xFF);
    out[8] = 64;                            /* TTL  */
    out[9] = 1;                             /* ICMP */

    out[12] = (unsigned char) ((src >> 24) & 0xFF);
    out[13] = (unsigned char) ((src >> 16) & 0xFF);
    out[14] = (unsigned char) ((src >> 8) & 0xFF);
    out[15] = (unsigned char) (src & 0xFF);
    out[16] = (unsigned char) ((dst >> 24) & 0xFF);
    out[17] = (unsigned char) ((dst >> 16) & 0xFF);
    out[18] = (unsigned char) ((dst >> 8) & 0xFF);
    out[19] = (unsigned char) (dst & 0xFF);

    ck = inet_checksum(out, 20);
    out[10] = (unsigned char) (ck >> 8);
    out[11] = (unsigned char) (ck & 0xFF);

    out[20] = 8;                            /* echo request */
    out[24] = (unsigned char) (id >> 8);
    out[25] = (unsigned char) (id & 0xFF);
    out[26] = (unsigned char) (seq >> 8);
    out[27] = (unsigned char) (seq & 0xFF);
    memcpy(out + 28, payload, paylen);

    ck = inet_checksum(out + 20, icmplen);
    out[22] = (unsigned char) (ck >> 8);
    out[23] = (unsigned char) (ck & 0xFF);

    return total;
}

int main(int argc, char **argv)
{
    struct raw_injector *inj = NULL;
    unsigned char pkt[128];
    unsigned long src_net = 0, dst_net = 0, mask;
    const char *src_arg = NULL, *dst_arg = NULL;
    char abuf[16], bbuf[16];
    size_t len;
    int count = 3;
    int i;
    int sent = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--src") == 0 && i + 1 < argc)
            src_arg = argv[++i];
        else if (strcmp(argv[i], "--dst") == 0 && i + 1 < argc)
            dst_arg = argv[++i];
        else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc)
            count = atoi(argv[++i]);
        else {
            fprintf(stderr,
                "usage: %s --src <ip> --dst <ip> [--count <n>]\n"
                "\n"
                "Injects ICMP echo requests with a raw socket, to test\n"
                "IP_HDRINCL. Watch for them on the destination with\n"
                "  sudo tcpdump -ni any icmp and host <src>\n",
                argv[0]);
            return 2;
        }
    }

    if (src_arg == NULL || dst_arg == NULL) {
        fprintf(stderr, "error: --src and --dst are both required\n");
        return 2;
    }

    {
        uint32_t n, m;
        if (ethip_parse_cidr(src_arg, &n, &m) != 0 || m != 0xFFFFFFFFUL) {
            fprintf(stderr, "error: --src must be a plain IPv4 address\n");
            return 2;
        }
        src_net = n;
        if (ethip_parse_cidr(dst_arg, &n, &m) != 0 || m != 0xFFFFFFFFUL) {
            fprintf(stderr, "error: --dst must be a plain IPv4 address\n");
            return 2;
        }
        dst_net = n;
        mask = m;
        (void) mask;
    }

    printf("vmsguard injection probe\n");
    ipv4_format(abuf, sizeof abuf, (uint32_t) src_net);
    ipv4_format(bbuf, sizeof bbuf, (uint32_t) dst_net);
    printf("  %s -> %s, %d packet%s\n\n", abuf, bbuf,
           count, count == 1 ? "" : "s");

    if (raw_injector_open(&inj) != 0) {
        fprintf(stderr, "  FAIL  %s\n", raw_injector_error(inj));
        raw_injector_close(inj);
        return 1;
    }
    printf("  ok    raw socket open with IP_HDRINCL\n");

    for (i = 0; i < count; i++) {
        len = build_echo(pkt, src_net, dst_net, 0x7601,
                         (unsigned short) (i + 1));
        if (raw_injector_send(inj, pkt, len) == 0) {
            printf("  ok    injected %lu bytes, seq %d\n",
                   (unsigned long) len, i + 1);
            sent++;
        } else {
            printf("  FAIL  %s\n", raw_injector_error(inj));
        }
    }

    printf("\n%d of %d injected\n", sent, count);
    if (sent > 0)
        printf("Check the destination for arrival — sendto succeeding\n"
               "means the stack accepted the packet, not that it left.\n");

    raw_injector_close(inj);
    return sent == count ? 0 : 1;
}
