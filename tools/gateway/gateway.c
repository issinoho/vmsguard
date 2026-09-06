/*
 * vmsguard gateway
 *
 * Forwards traffic for a subnet through a WireGuard tunnel, with
 * OpenVMS as the gateway rather than the originating host.
 *
 * The client shape — traffic originating on this box — needs a TUN
 * device to claim outbound packets, and OpenVMS has nothing that can.
 * See docs/research/slip-tunnel.md for how that was established.
 *
 * The gateway shape has no such problem. Packets being forwarded were
 * never ours, so there is no plaintext original to suppress: we capture
 * a copy, tunnel it, and the stack drops the original because it has no
 * route for the destination.
 *
 *   LAN host --> [ pcap capture ] --> encrypt --> UDP --> peer
 *   LAN host <-- [ raw socket   ] <-- decrypt <-- UDP <-- peer
 *
 * Capture is layer 2 because pcap is what OpenVMS offers. Injection is
 * layer 3 because pcap_sendpacket does not work there, and because a
 * decrypted packet is destined for an ordinary host the stack can
 * already route to.
 *
 * See docs/gateway.md.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* <pcap.h> uses struct timeval without defining it; see the note in
   tools/probes/probe_pcap.c. */
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#ifndef __VMS
#  include <sys/time.h>
#endif

/* VSI C upcases external names; the pcap image exports them as-is. */
#ifdef __VMS
#  pragma names save
#  pragma names as_is
#endif
#include <pcap.h>
#ifdef __VMS
#  pragma names restore
#endif

#include "ethip.h"
#include "rawinject.h"
#include "wg_client.h"
#include "wg_key.h"
#include "wg_platform.h"

/*
 * pcap's read timeout, in milliseconds. The loop alternates between
 * waiting on pcap and polling the tunnel socket, so this also bounds
 * how long an inbound packet can sit before being injected.
 *
 * pcap_get_selectable_fd would allow polling both together, but it is
 * not certain to exist in the OpenVMS port, and an undefined symbol
 * there is only a link *warning* — it would build and then fail at
 * run time. Alternating costs a little latency and cannot break that
 * way.
 */
#define PCAP_TIMEOUT_MS 50

struct stats {
    unsigned long captured;
    unsigned long tunnelled;
    unsigned long received;
    unsigned long injected;
    unsigned long dropped;
};

static void usage(const char *argv0)
{
    fprintf(stderr,
"usage: %s --key <base64> --peer-key <base64> --endpoint <host:port>\n"
"          --interface <name> --tunnel-subnet <cidr>\n"
"          [--psk <base64>] [--listen-port <n>] [--verbose]\n"
"\n"
"  --key            our private key, base64\n"
"  --peer-key       the peer's public key, base64\n"
"  --endpoint       the peer's UDP endpoint, e.g. 192.0.2.1:51820\n"
"  --interface      LAN interface to capture on, e.g. IE0\n"
"  --tunnel-subnet  traffic for this subnet is tunnelled,\n"
"                   e.g. 10.9.0.0/24\n"
"  --psk            optional preshared key, base64\n"
"  --listen-port    local UDP port (default: any)\n"
"\n"
"LAN hosts must route the tunnel subnet via this machine. Needs\n"
"privilege for both packet capture and raw sockets (SYSPRV on\n"
"OpenVMS).\n", argv0);
}

static int read_key(uint8_t key[WG_KEY_LEN], const char *arg,
                    const char *what)
{
    if (wg_key_from_base64(key, arg) != 0) {
        fprintf(stderr, "error: %s is not a valid base64 key\n", what);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct wg_client client;
    struct wg_endpoint endpoint;
    struct raw_injector *inj = NULL;
    struct stats st;
    pcap_t *pc = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint8_t privkey[WG_KEY_LEN], peerkey[WG_KEY_LEN], psk[WG_KEY_LEN];
    uint8_t *pskp = NULL;
    uint32_t tun_net = 0, tun_mask = 0;
    const char *endpoint_arg = NULL, *ifname = NULL, *subnet_arg = NULL;
    const char *colon;
    char host[128], b64[WG_KEY_B64_LEN], abuf[16], bbuf[16];
    int have_key = 0, have_peer = 0, verbose = 0;
    uint16_t listen_port = 0, peer_port;
    int i;

    memset(&st, 0, sizeof st);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            if (read_key(privkey, argv[++i], "--key") != 0)
                return 2;
            have_key = 1;
        } else if (strcmp(argv[i], "--peer-key") == 0 && i + 1 < argc) {
            if (read_key(peerkey, argv[++i], "--peer-key") != 0)
                return 2;
            have_peer = 1;
        } else if (strcmp(argv[i], "--psk") == 0 && i + 1 < argc) {
            if (read_key(psk, argv[++i], "--psk") != 0)
                return 2;
            pskp = psk;
        } else if (strcmp(argv[i], "--endpoint") == 0 && i + 1 < argc) {
            endpoint_arg = argv[++i];
        } else if (strcmp(argv[i], "--interface") == 0 && i + 1 < argc) {
            ifname = argv[++i];
        } else if (strcmp(argv[i], "--tunnel-subnet") == 0 && i + 1 < argc) {
            subnet_arg = argv[++i];
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            listen_port = (uint16_t) atoi(argv[++i]);
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!have_key || !have_peer || endpoint_arg == NULL ||
        ifname == NULL || subnet_arg == NULL) {
        usage(argv[0]);
        return 2;
    }

    if (ethip_parse_cidr(subnet_arg, &tun_net, &tun_mask) != 0) {
        fprintf(stderr, "error: --tunnel-subnet '%s' is not valid CIDR\n",
                subnet_arg);
        return 2;
    }

    colon = strrchr(endpoint_arg, ':');
    if (colon == NULL || (size_t) (colon - endpoint_arg) >= sizeof host) {
        fprintf(stderr, "error: --endpoint must be host:port\n");
        return 2;
    }
    memcpy(host, endpoint_arg, (size_t) (colon - endpoint_arg));
    host[colon - endpoint_arg] = '\0';
    peer_port = (uint16_t) atoi(colon + 1);
    if (peer_port == 0) {
        fprintf(stderr, "error: invalid port in --endpoint\n");
        return 2;
    }
    if (wg_endpoint_resolve(&endpoint, host, peer_port) != 0) {
        fprintf(stderr, "error: could not resolve '%s'\n", host);
        return 1;
    }

    printf("vmsguard gateway\n");

    /* ---- the tunnel ---- */

    if (wg_client_init(&client, privkey, peerkey, pskp, &endpoint,
                       listen_port) != 0) {
        fprintf(stderr, "error: %s\n", client.error);
        return 1;
    }

    wg_key_to_base64(b64, client.local.static_public);
    printf("  our public key : %s\n", b64);
    ipv4_format(abuf, sizeof abuf, tun_net);
    ipv4_format(bbuf, sizeof bbuf, tun_mask);
    printf("  tunnel subnet  : %s mask %s\n", abuf, bbuf);
    printf("  capturing on   : %s\n", ifname);
    printf("\n");

    /* ---- capture ---- */

    errbuf[0] = '\0';
    pc = pcap_open_live(ifname, 65535, 1, PCAP_TIMEOUT_MS, errbuf);
    if (pc == NULL) {
        fprintf(stderr, "error: pcap_open_live(%s): %s\n", ifname, errbuf);
        fprintf(stderr, "       packet capture needs privilege\n");
        wg_client_close(&client);
        return 1;
    }
    if (pcap_datalink(pc) != DLT_EN10MB) {
        fprintf(stderr, "error: %s is link type %d, not Ethernet\n",
                ifname, pcap_datalink(pc));
        pcap_close(pc);
        wg_client_close(&client);
        return 1;
    }

    /* ---- injection ---- */

    if (raw_injector_open(&inj) != 0) {
        fprintf(stderr, "error: %s\n", raw_injector_error(inj));
        raw_injector_close(inj);
        pcap_close(pc);
        wg_client_close(&client);
        return 1;
    }

    /* ---- handshake ---- */

    printf("handshake with the peer\n");
    if (wg_client_handshake(&client, 3, 5000) != 0) {
        fprintf(stderr, "error: %s\n", client.error);
        raw_injector_close(inj);
        pcap_close(pc);
        wg_client_close(&client);
        return 1;
    }
    printf("  established\n\n");
    printf("forwarding. Ctrl-Y or Ctrl-C to stop.\n\n");
    fflush(stdout);

    /* ---- the loop ---- */

    for (;;) {
        struct pcap_pkthdr *hdr = NULL;
        const unsigned char *frame = NULL;
        uint8_t plain[WG_MAX_PACKET];
        size_t plainlen = 0;
        int rc;

        /* Outbound: capture, filter, tunnel. */
        rc = pcap_next_ex(pc, &hdr, &frame);
        if (rc == 1) {
            const uint8_t *ip;
            size_t iplen = 0;

            ip = ethip_ipv4((const uint8_t *) frame, hdr->caplen, &iplen);
            if (ip != NULL && ipv4_in_subnet(ipv4_dst(ip),
                                             tun_net, tun_mask)) {
                st.captured++;
                if (wg_client_send(&client, ip, iplen) == 0) {
                    st.tunnelled++;
                    if (verbose) {
                        ipv4_format(abuf, sizeof abuf, ipv4_src(ip));
                        ipv4_format(bbuf, sizeof bbuf, ipv4_dst(ip));
                        printf("out %s -> %s  proto %u  %lu bytes\n",
                               abuf, bbuf, (unsigned) ipv4_proto(ip),
                               (unsigned long) iplen);
                        fflush(stdout);
                    }
                } else {
                    st.dropped++;
                }
            }
        } else if (rc < 0) {
            fprintf(stderr, "capture error: %s\n", pcap_geterr(pc));
            break;
        }

        /* Inbound: decrypt and put it back on the LAN. Zero timeout,
           because pcap_next_ex above already did the waiting. */
        rc = wg_client_recv(&client, plain, sizeof plain, &plainlen, 0);
        if (rc == WG_SOCK_OK && plainlen >= IPV4_MIN_HDR) {
            size_t iplen = ((size_t) plain[2] << 8) | plain[3];

            st.received++;

            /*
             * Trust the packet's own length rather than the decrypted
             * size: WireGuard pads plaintext to a 16-byte boundary, and
             * injecting that padding would corrupt the packet.
             */
            if (iplen >= IPV4_MIN_HDR && iplen <= plainlen) {
                if (raw_injector_send(inj, plain, iplen) == 0) {
                    st.injected++;
                    if (verbose) {
                        ipv4_format(abuf, sizeof abuf, ipv4_src(plain));
                        ipv4_format(bbuf, sizeof bbuf, ipv4_dst(plain));
                        printf("in  %s -> %s  proto %u  %lu bytes\n",
                               abuf, bbuf, (unsigned) ipv4_proto(plain),
                               (unsigned long) iplen);
                        fflush(stdout);
                    }
                } else {
                    st.dropped++;
                    if (verbose) {
                        printf("inject failed: %s\n",
                               raw_injector_error(inj));
                        fflush(stdout);
                    }
                }
            } else {
                st.dropped++;
            }
        } else if (rc == WG_SOCK_ERROR) {
            fprintf(stderr, "tunnel receive error\n");
            break;
        }
    }

    printf("\ncaptured %lu, tunnelled %lu, received %lu, injected %lu,"
           " dropped %lu\n",
           st.captured, st.tunnelled, st.received, st.injected, st.dropped);

    raw_injector_close(inj);
    pcap_close(pc);
    wg_client_close(&client);
    return 0;
}
