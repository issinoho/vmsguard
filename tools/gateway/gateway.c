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
#include "icmp.h"
#include "nat.h"
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

/* Plenty for a gateway serving a handful of hosts. */
#define MAX_CLIENTS 16

struct client_filter {
    uint32_t net;
    uint32_t mask;
};

struct stats {
    unsigned long captured;
    unsigned long tunnelled;
    unsigned long received;
    unsigned long injected;
    unsigned long dropped;
    unsigned long too_big;
    unsigned long icmp_sent;
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
"  --tunnel-address the address the peer assigned us, e.g.\n"
"                   10.13.127.177. Enables source NAT: outbound\n"
"                   packets are rewritten to come from it, and replies\n"
"                   translated back. Required by commercial providers,\n"
"                   which accept only their assigned address as a\n"
"                   source\n"
"  --exclude        never tunnel traffic to this destination subnet.\n"
"                   Repeatable. Required when the tunnel subnet is\n"
"                   wider than /8: a full tunnel otherwise matches\n"
"                   local destinations too, sending LAN traffic to the\n"
"                   far end. Give it your local network\n"
"  --client         only forward for this source address or subnet.\n"
"                   Repeatable. Required when the tunnel subnet is\n"
"                   wider than /8, because packet capture is\n"
"                   promiscuous and an unfiltered wide subnet would\n"
"                   tunnel other machines' traffic\n"
"  --psk            optional preshared key, base64\n"
"  --listen-port    local UDP port (default: any)\n"
"  --tunnel-mtu     largest inner packet the tunnel carries. Default\n"
"                   1420, which is 1500 less WireGuard, UDP and outer\n"
"                   IP headers. Set it from the provider's config: a\n"
"                   larger packet with DF set is answered with ICMP\n"
"                   fragmentation-needed so the sender adapts\n"
"  --keepalive      seconds between keepalives when otherwise idle,\n"
"                   as PersistentKeepalive in a provider config.\n"
"                   0 disables, which is the default\n"
"\n"
"LAN hosts must route the tunnel subnet via this machine. Needs\n"
"privilege for both packet capture and raw sockets (SYSPRV on\n"
"OpenVMS).\n", argv0);
}

/*
 * Match a requested interface name against what pcap reports, ignoring
 * case, and return the name pcap actually uses.
 *
 * DCL lowercases unquoted arguments to a foreign command, so
 * "--interface IE0" arrives as "ie0" while pcap knows the device as
 * "IE0" — and pcap_open_live is case-sensitive, so it fails with "no
 * such device or address". Rather than require quoting, resolve the
 * name here and report what was found.
 *
 * Returns 0 on success, with the resolved name copied into out.
 */
static int resolve_interface(char *out, size_t cap, const char *want)
{
    pcap_if_t *devs = NULL, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int found = 0;

    errbuf[0] = '\0';
    if (pcap_findalldevs(&devs, errbuf) != 0 || devs == NULL) {
        fprintf(stderr, "error: pcap_findalldevs: %s\n",
                errbuf[0] != '\0' ? errbuf : "no devices");
        return -1;
    }

    for (d = devs; d != NULL; d = d->next) {
        const char *a = d->name;
        const char *b = want;
        while (*a != '\0' && *b != '\0') {
            int ca = (*a >= 'A' && *a <= 'Z') ? *a - 'A' + 'a' : *a;
            int cb = (*b >= 'A' && *b <= 'Z') ? *b - 'A' + 'a' : *b;
            if (ca != cb)
                break;
            a++;
            b++;
        }
        if (*a == '\0' && *b == '\0') {
            snprintf(out, cap, "%s", d->name);
            found = 1;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "error: no interface matching '%s'. Available:\n",
                want);
        for (d = devs; d != NULL; d = d->next)
            fprintf(stderr, "         %s\n", d->name);
    }

    pcap_freealldevs(devs);
    return found ? 0 : -1;
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
    struct client_filter clients[MAX_CLIENTS];
    int nclients = 0;
    struct client_filter excludes[MAX_CLIENTS];
    int nexcludes = 0;
    struct nat_table nat;
    uint32_t tunnel_addr = 0, tunnel_addr_mask = 0;
    int use_nat = 0;
    const char *endpoint_arg = NULL, *ifname = NULL, *subnet_arg = NULL;
    const char *colon;
    char host[128], b64[WG_KEY_B64_LEN], abuf[16], bbuf[16];
    char realif[64];
    int have_key = 0, have_peer = 0, verbose = 0;
    int keepalive_s = 0;
    int tunnel_mtu = 1420;
    struct wg_endpoint local_ep;
    uint32_t gw_addr = 0;
    int have_gw_addr = 0;
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
        } else if (strcmp(argv[i], "--tunnel-address") == 0 && i + 1 < argc) {
            if (ethip_parse_cidr(argv[++i], &tunnel_addr,
                                 &tunnel_addr_mask) != 0 ||
                tunnel_addr_mask != 0xFFFFFFFFUL) {
                fprintf(stderr,
                        "error: --tunnel-address must be a plain address\n");
                return 2;
            }
            use_nat = 1;
        } else if (strcmp(argv[i], "--exclude") == 0 && i + 1 < argc) {
            if (nexcludes >= MAX_CLIENTS) {
                fprintf(stderr, "error: at most %d --exclude entries\n",
                        MAX_CLIENTS);
                return 2;
            }
            if (ethip_parse_cidr(argv[++i], &excludes[nexcludes].net,
                                 &excludes[nexcludes].mask) != 0) {
                fprintf(stderr, "error: --exclude '%s' is not valid CIDR\n",
                        argv[i]);
                return 2;
            }
            nexcludes++;
        } else if (strcmp(argv[i], "--client") == 0 && i + 1 < argc) {
            if (nclients >= MAX_CLIENTS) {
                fprintf(stderr, "error: at most %d --client entries\n",
                        MAX_CLIENTS);
                return 2;
            }
            if (ethip_parse_cidr(argv[++i], &clients[nclients].net,
                                 &clients[nclients].mask) != 0) {
                fprintf(stderr, "error: --client '%s' is not valid CIDR\n",
                        argv[i]);
                return 2;
            }
            nclients++;
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            listen_port = (uint16_t) atoi(argv[++i]);
        } else if (strcmp(argv[i], "--tunnel-mtu") == 0 && i + 1 < argc) {
            tunnel_mtu = atoi(argv[++i]);
            if (tunnel_mtu < 576 || tunnel_mtu > 1500) {
                fprintf(stderr,
                        "error: --tunnel-mtu must be between 576 and 1500\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--keepalive") == 0 && i + 1 < argc) {
            keepalive_s = atoi(argv[++i]);
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

    /*
     * Packet capture is promiscuous: every frame on the segment is
     * visible, not just those addressed to this machine. A narrow
     * tunnel subnet is self-limiting, but a wide one would match
     * traffic between machines that have nothing to do with vmsguard
     * and tunnel it to the far end.
     *
     * So a wide subnet requires an explicit list of hosts to forward
     * for. /8 is the cut-off: anything broader is almost certainly a
     * full tunnel, where this matters most.
     */
    if (tun_mask < 0xFF000000UL && nclients == 0) {
        fprintf(stderr,
            "error: --tunnel-subnet %s is wider than /8, so --client is\n"
            "       required. Capture is promiscuous, and without a source\n"
            "       filter this would tunnel other machines' traffic.\n",
            subnet_arg);
        return 2;
    }

    /*
     * A full tunnel matches local destinations as readily as remote
     * ones, so without exclusions it forwards a client's LAN traffic —
     * its own conversations with hosts on this segment, this machine
     * included — out to the far end. A real VPN client avoids this
     * because its routing table holds a more specific route for the
     * local subnet; there is no equivalent here, so it has to be said
     * explicitly.
     */
    if (tun_mask < 0xFF000000UL && nexcludes == 0) {
        fprintf(stderr,
            "error: --tunnel-subnet %s is wider than /8, so --exclude is\n"
            "       required. Without it, traffic to local destinations is\n"
            "       tunnelled too — including conversations with this\n"
            "       machine. Pass your local network, e.g.\n"
            "         --exclude 192.168.0.0/24\n",
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
    if (use_nat) {
        ipv4_format(abuf, sizeof abuf, tunnel_addr);
        printf("  source NAT to  : %s\n", abuf);
    } else {
        printf("  source NAT     : off\n");
    }
    if (nclients == 0) {
        printf("  forwarding for : any source\n");
    } else {
        for (i = 0; i < nclients; i++) {
            ipv4_format(abuf, sizeof abuf, clients[i].net);
            ipv4_format(bbuf, sizeof bbuf, clients[i].mask);
            printf("  forwarding for : %s mask %s\n", abuf, bbuf);
        }
    }
    for (i = 0; i < nexcludes; i++) {
        ipv4_format(abuf, sizeof abuf, excludes[i].net);
        ipv4_format(bbuf, sizeof bbuf, excludes[i].mask);
        printf("  excluding      : %s mask %s\n", abuf, bbuf);
    }

    /* ---- capture ---- */

    if (resolve_interface(realif, sizeof realif, ifname) != 0) {
        wg_client_close(&client);
        return 1;
    }
    printf("  capturing on   : %s\n", realif);
    printf("\n");

    errbuf[0] = '\0';
    pc = pcap_open_live(realif, 65535, 1, PCAP_TIMEOUT_MS, errbuf);
    if (pc == NULL) {
        fprintf(stderr, "error: pcap_open_live(%s): %s\n", realif, errbuf);
        fprintf(stderr, "       packet capture needs privilege\n");
        wg_client_close(&client);
        return 1;
    }
    if (pcap_datalink(pc) != DLT_EN10MB) {
        fprintf(stderr, "error: %s is link type %d, not Ethernet\n",
                realif, pcap_datalink(pc));
        pcap_close(pc);
        wg_client_close(&client);
        return 1;
    }

    nat_init(&nat, tunnel_addr);

    /*
     * ICMP errors have to come from an address the client recognises as
     * the hop that dropped its packet. Ask the routing table which of
     * our addresses faces the peer; that is the one a LAN client sees
     * us as.
     */
    if (wg_local_address_for(&endpoint, &local_ep) == 0 &&
        local_ep.family == WG_AF_INET) {
        gw_addr = ((uint32_t) local_ep.addr[0] << 24) |
                  ((uint32_t) local_ep.addr[1] << 16) |
                  ((uint32_t) local_ep.addr[2] << 8) |
                  (uint32_t) local_ep.addr[3];
        have_gw_addr = 1;
        ipv4_format(abuf, sizeof abuf, gw_addr);
        printf("  our address    : %s\n", abuf);
    } else {
        printf("  our address    : unknown, so oversized packets will be\n"
               "                   dropped without an ICMP reply\n");
    }
    printf("  tunnel MTU     : %d\n\n", tunnel_mtu);

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
    if (keepalive_s > 0) {
        client.keepalive_interval_ms = (uint64_t) keepalive_s * 1000;
        printf("  established, keepalive every %d s\n\n", keepalive_s);
    } else {
        printf("  established\n\n");
    }
    printf("forwarding. Ctrl-Y or Ctrl-C to stop.\n\n");
    fflush(stdout);

    /* ---- the loop ---- */

    for (;;) {
        struct pcap_pkthdr *hdr = NULL;
        const unsigned char *frame = NULL;
        uint8_t plain[WG_MAX_PACKET];
        uint8_t natbuf[WG_MAX_PACKET];
        size_t plainlen = 0;
        int rc;

        /* Outbound: capture, filter, tunnel. */
        rc = pcap_next_ex(pc, &hdr, &frame);
        if (rc == 1) {
            const uint8_t *ip;
            size_t iplen = 0;

            ip = ethip_ipv4((const uint8_t *) frame, hdr->caplen, &iplen);

            /*
             * Never tunnel our own encrypted traffic. With a wide
             * tunnel subnet the outer packets heading to the peer would
             * otherwise match and be re-tunnelled, recursively.
             */
            if (ip != NULL && endpoint.family == WG_AF_INET &&
                memcmp(ip + 16, endpoint.addr, 4) == 0)
                ip = NULL;

            /*
             * Never tunnel to a destination that was excluded, nor to
             * multicast or broadcast — neither has any meaning at the
             * far end of a point-to-point tunnel.
             */
            if (ip != NULL) {
                uint32_t d = ipv4_dst(ip);
                int j;

                if ((d & 0xF0000000UL) == 0xE0000000UL ||   /* 224/4     */
                    d == 0xFFFFFFFFUL ||                    /* broadcast */
                    d == 0) {
                    ip = NULL;
                }
                for (j = 0; ip != NULL && j < nexcludes; j++) {
                    if (ipv4_in_subnet(d, excludes[j].net, excludes[j].mask))
                        ip = NULL;
                }
            }

            /* Only forward for hosts we were told to serve. */
            if (ip != NULL && nclients > 0) {
                int j, allowed = 0;
                for (j = 0; j < nclients; j++) {
                    if (ipv4_in_subnet(ipv4_src(ip), clients[j].net,
                                       clients[j].mask)) {
                        allowed = 1;
                        break;
                    }
                }
                if (!allowed)
                    ip = NULL;
            }

            if (ip != NULL && ipv4_in_subnet(ipv4_dst(ip),
                                             tun_net, tun_mask)) {
                st.captured++;

                /*
                 * Too large for the tunnel. Tell the sender rather than
                 * dropping in silence: without the ICMP its path-MTU
                 * discovery never learns, and the symptom is small
                 * requests working while transfers hang.
                 */
                if (iplen > (size_t) tunnel_mtu) {
                    st.too_big++;
                    if (have_gw_addr && ipv4_dont_fragment(ip, iplen)) {
                        uint8_t err[128];
                        size_t elen = icmp_frag_needed(err, sizeof err,
                                                       gw_addr, ip, iplen,
                                                       (uint16_t) tunnel_mtu);
                        if (elen > 0 &&
                            raw_injector_send(inj, err, elen) == 0) {
                            st.icmp_sent++;
                            if (verbose) {
                                ipv4_format(abuf, sizeof abuf, ipv4_src(ip));
                                printf("big %lu bytes from %s, told to use"
                                       " %d\n", (unsigned long) iplen,
                                       abuf, tunnel_mtu);
                                fflush(stdout);
                            }
                        }
                    }
                    goto after_out;
                }

                /*
                 * Translation needs a writable copy: the capture buffer
                 * belongs to pcap and the same frame may be handed back
                 * on the next call.
                 */
                if (use_nat) {
                    if (iplen > sizeof natbuf) {
                        st.dropped++;
                        goto after_out;
                    }
                    memcpy(natbuf, ip, iplen);
                    if (nat_outbound(&nat, natbuf, iplen,
                                     wg_time_ms()) != 0) {
                        /* Untranslatable: sending it anyway would leak
                           the client's address and be discarded by the
                           peer regardless. */
                        st.dropped++;
                        goto after_out;
                    }
                    ip = natbuf;
                }

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
after_out:
            ;
        } else if (rc < 0) {
            fprintf(stderr, "capture error: %s\n", pcap_geterr(pc));
            break;
        }

        /* Keepalives and rekeying are time-driven, so an idle tunnel
           still needs the clock looked at. */
        (void) wg_client_tick(&client);

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
                if (use_nat &&
                    nat_inbound(&nat, plain, iplen, wg_time_ms()) != 0) {
                    /* No mapping: unsolicited, or the flow expired. */
                    st.dropped++;
                } else if (raw_injector_send(inj, plain, iplen) == 0) {
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
    if (st.too_big > 0)
        printf("oversized: %lu, of which %lu answered with ICMP"
               " fragmentation-needed\n", st.too_big, st.icmp_sent);
    if (use_nat)
        printf("NAT: %lu translated, %lu restored, %d mappings live,"
               " dropped %lu unsupported / %lu unmatched / %lu table-full\n",
               nat.translated, nat.restored, nat_active(&nat, wg_time_ms()),
               nat.dropped_unsupported, nat.dropped_no_mapping,
               nat.dropped_table_full);

    raw_injector_close(inj);
    pcap_close(pc);
    wg_client_close(&client);
    return 0;
}
