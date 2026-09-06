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

#include <signal.h>
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
#include "wg_conf.h"
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

/*
 * The forwarding loop runs until it is interrupted, so the summary
 * after it used to be reachable only by an error breaking out. In
 * practice every run ends at the keyboard, which meant every run threw
 * its counters away — and the counters are how a run is judged.
 *
 * The two interrupt keys need different treatment, because they are not
 * the same kind of event:
 *
 *   Ctrl-C raises SIGINT. A handler sets a flag and the loop leaves by
 *   its own front door, so the capture and the tunnel socket are closed
 *   in order rather than by image rundown.
 *
 *   Ctrl-Y on OpenVMS belongs to DCL, not to us; no handler in this
 *   image will ever see it. What it does do is run the image down as
 *   soon as the next DCL command is typed, and rundown calls exit
 *   handlers — so the summary is registered with atexit() as well.
 *   (Ctrl-Y followed by STOP skips exit handlers by design. Nothing
 *   here can change that, and the manual is explicit about it.)
 *
 * atexit is therefore the route both keys share, and anything it prints
 * has to outlive main's frame. That is why the counters and the NAT
 * table are file scope: not convenience, correctness.
 */
/*
 * File scope for the same reason as the counters: print_summary runs
 * from atexit, after main has returned, so anything it reads must
 * outlive main's frame. wg_client_close releases the socket but leaves
 * the struct readable, which is all the summary needs.
 */
static struct wg_client client;

static struct stats     st;
static struct nat_table nat;
static int              use_nat;
static uint64_t         started_ms;

static volatile sig_atomic_t stop_requested;

static void on_interrupt(int sig)
{
    (void) sig;
    stop_requested = 1;

    /*
     * Nothing else happens here. A handler may portably touch only a
     * volatile sig_atomic_t, and the disposition is deliberately left
     * reset to the default: a second Ctrl-C then terminates outright,
     * which is the escape hatch if the loop is ever wedged.
     */
}

/*
 * One line for a packet we refused.
 *
 * A live run against a provider ended with "dropped 2 unsupported" and
 * nothing whatever to say what those two had been — every packet in the
 * log was ordinary UDP. A count you cannot explain is barely better
 * than no count, so under --verbose each refusal now names itself.
 *
 * Direction is spelled the same way as the forwarding lines, so the
 * three read as one column.
 */
static void log_drop(const char *dir, const uint8_t *ip, size_t iplen,
                     const char *why)
{
    char abuf[32], bbuf[32];

    ipv4_format(abuf, sizeof abuf, ipv4_src(ip));
    ipv4_format(bbuf, sizeof bbuf, ipv4_dst(ip));
    printf("%s %s -> %s  proto %u  %lu bytes  DROPPED: %s\n",
           dir, abuf, bbuf, (unsigned) ipv4_proto(ip),
           (unsigned long) iplen, why);
    fflush(stdout);
}

/*
 * A duration a person can read at a glance. Seconds with one decimal
 * below a minute, minutes and seconds above it — "ran for 3600.0 s" is
 * technically correct and useless.
 *
 * Integer arithmetic throughout, like the rest of the project; there is
 * no reason to pull floating point in for one decimal place.
 */
static void format_duration(char *out, size_t cap, uint64_t ms)
{
    unsigned long secs = (unsigned long) (ms / 1000);

    if (secs < 60)
        snprintf(out, cap, "%lu.%lu s", secs,
                 (unsigned long) ((ms % 1000) / 100));
    else
        snprintf(out, cap, "%lum %lus", secs / 60, secs % 60);
}

static void print_summary(void)
{
    uint64_t elapsed = 0;
    char dur[32];

    /*
     * How long the run lasted, because without it none of the rest can
     * be read. "296 of 512 mappings live" means the timeouts are doing
     * their job if the run was twenty seconds and that they are not if
     * it was ten minutes, and the summary gave no way to tell which.
     */
    if (started_ms != 0)
        elapsed = wg_time_ms() - started_ms;

    format_duration(dur, sizeof dur, elapsed);
    printf("\nran for %s\n", dur);

    printf("captured %lu, tunnelled %lu, received %lu, injected %lu,"
           " dropped %lu\n",
           st.captured, st.tunnelled, st.received, st.injected, st.dropped);
    if (st.too_big > 0)
        printf("oversized: %lu, of which %lu answered with ICMP"
               " fragmentation-needed\n", st.too_big, st.icmp_sent);
    /*
     * Only mentioned when it happened. A peer that never moved is the
     * normal case and needs no line; one that did explains why the
     * endpoint in the header is no longer where packets are going.
     */
    if (client.roams > 0) {
        char epbuf[80];

        wg_endpoint_format(epbuf, sizeof epbuf, &client.endpoint);
        printf("peer roamed %lu time%s; last seen at %s\n",
               client.roams, client.roams == 1 ? "" : "s", epbuf);
    }
    if (client.cookies_received > 0)
        printf("answered %lu cookie challenge%s from a loaded peer\n",
               client.cookies_received,
               client.cookies_received == 1 ? "" : "s");

    if (use_nat) {
        printf("NAT: %lu translated, %lu restored, %d of %d mappings live,"
               " dropped %lu unsupported / %lu unmatched / %lu table-full"
               " / %lu orphan fragments\n",
               nat.translated, nat.restored, nat_active(&nat, wg_time_ms()),
               NAT_ENTRIES, nat.dropped_unsupported, nat.dropped_no_mapping,
               nat.dropped_table_full, nat.dropped_frag_orphan);
        if (nat.frags_tracked > 0)
            printf("     %lu fragmented datagram%s, %lu later fragment%s"
                   " carried on the first one's mapping\n",
                   nat.frags_tracked, nat.frags_tracked == 1 ? "" : "s",
                   nat.frags_inherited,
                   nat.frags_inherited == 1 ? "" : "s");
        /*
         * A rate turns the live count into something judgeable: with a
         * 30-second UDP timeout, a table holding roughly half a minute
         * of flows is behaving, and one holding far more is not.
         */
        /*
         * nat.flows, not nat.translated: the latter counts packets, so
         * a single long TCP connection would report as thousands of
         * flows and make the table look under far more pressure than it
         * is. Mappings are what fill the table, so mappings are what
         * the rate has to be about.
         */
        if (elapsed > 0)
            printf("     %lu new flow%s over the run, %lu per minute\n",
                   nat.flows, nat.flows == 1 ? "" : "s",
                   (unsigned long) ((uint64_t) nat.flows * 60000ULL
                                    / elapsed));
        /*
         * Only mentioned when it happened, because when it has, some
         * flow was broken without any other trace of it.
         */
        if (nat.evicted > 0)
            printf("     %lu live mapping%s recycled to make room; a flow"
                   " that quiet may have stopped working\n",
                   nat.evicted, nat.evicted == 1 ? " was" : "s were");
    }
    fflush(stdout);
}

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
"  --config         take PrivateKey, PublicKey, PresharedKey, Endpoint,\n"
"                   Address, AllowedIPs, MTU, PersistentKeepalive and\n"
"                   ListenPort from a wg-quick config file, so a\n"
"                   provider's .conf can be used as it arrives. Any\n"
"                   flag given as well overrides the file\n"
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

/*
 * Load a config file into memory. Kept here rather than in wg_conf.c so
 * the parser stays free of I/O and compiles on OpenVMS with the rest of
 * src/proto.
 *
 * Returns the length read, or -1 with a message printed.
 */
static long read_file(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    size_t n;

    if (f == NULL) {
        fprintf(stderr, "error: cannot open %s\n", path);
        return -1;
    }
    n = fread(buf, 1, cap - 1, f);
    if (ferror(f)) {
        fprintf(stderr, "error: cannot read %s\n", path);
        fclose(f);
        return -1;
    }
    /*
     * A file that exactly fills the buffer may have more behind it, and
     * a config silently truncated mid-key is worse than one refused.
     */
    if (n == cap - 1 && fgetc(f) != EOF) {
        fprintf(stderr, "error: %s is too large to be a WireGuard config\n",
                path);
        fclose(f);
        return -1;
    }
    fclose(f);
    buf[n] = '\0';
    return (long) n;
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
    struct wg_endpoint endpoint;
    struct raw_injector *inj = NULL;
    pcap_t *pc = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint8_t privkey[WG_KEY_LEN], peerkey[WG_KEY_LEN], psk[WG_KEY_LEN];
    uint8_t *pskp = NULL;
    uint32_t tun_net = 0, tun_mask = 0;
    struct client_filter clients[MAX_CLIENTS];
    int nclients = 0;
    struct client_filter excludes[MAX_CLIENTS];
    int nexcludes = 0;
    uint32_t tunnel_addr = 0, tunnel_addr_mask = 0;
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

    /*
     * --config first, in a pass of its own, so that the ordinary flag
     * loop below overwrites whatever the file supplied regardless of
     * where on the command line it appeared. A flag the operator typed
     * beats a file they may not have written.
     */
    for (i = 1; i < argc; i++) {
        struct wg_conf conf;
        char text[8192];
        long n;

        if (strcmp(argv[i], "--config") != 0 || i + 1 >= argc)
            continue;

        n = read_file(argv[i + 1], text, sizeof text);
        if (n < 0)
            return 1;
        if (wg_conf_parse(&conf, text, (size_t) n) != 0) {
            fprintf(stderr, "error: %s: %s\n", argv[i + 1], conf.error);
            return 2;
        }

        if (conf.have_private_key) {
            memcpy(privkey, conf.private_key, WG_KEY_LEN);
            have_key = 1;
        }
        if (conf.have_public_key) {
            memcpy(peerkey, conf.public_key, WG_KEY_LEN);
            have_peer = 1;
        }
        if (conf.have_preshared_key) {
            memcpy(psk, conf.preshared_key, WG_KEY_LEN);
            pskp = psk;
        }
        if (conf.have_endpoint)
            endpoint_arg = conf.endpoint;
        if (conf.n_allowed > 0)
            subnet_arg = conf.allowed[0];
        if (conf.mtu > 0)
            tunnel_mtu = conf.mtu;
        if (conf.keepalive > 0)
            keepalive_s = conf.keepalive;
        if (conf.listen_port > 0)
            listen_port = (uint16_t) conf.listen_port;

        if (conf.have_address) {
            if (ethip_parse_cidr(conf.address, &tunnel_addr,
                                 &tunnel_addr_mask) != 0 ||
                tunnel_addr_mask != 0xFFFFFFFFUL) {
                fprintf(stderr, "error: %s: Address '%s' is not usable\n",
                        argv[i + 1], conf.address);
                return 2;
            }
            use_nat = 1;
        }

        printf("read %s\n", argv[i + 1]);

        /*
         * Say what was not acted on. A config is written for wg-quick,
         * which does more than we do, and appearing to have honoured a
         * line we ignored is how an operator ends up debugging the
         * wrong thing.
         */
        if (conf.saw_dns)
            printf("  note: DNS is for the machines behind the gateway to\n"
                   "        set for themselves; it is not applied here\n");
        if (conf.n_allowed > 1) {
            int k;
            printf("  note: only the first AllowedIPs entry is used as the\n"
                   "        tunnel subnet; ignoring");
            for (k = 1; k < conf.n_allowed; k++)
                printf(" %s", conf.allowed[k]);
            printf("\n");
        }
        printf("  note: --interface is not in a config file and must still\n"
               "        be given, as must --client and --exclude for a\n"
               "        full tunnel\n\n");

        /* Scrub: the private key was in this buffer. */
        memset(text, 0, sizeof text);
        memset(&conf, 0, sizeof conf);
        i++;
    }

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            i++;                    /* already handled above */
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
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

    /* Armed only now, so that a failure before this point exits without
       printing a summary of a run that never started. */
    (void) signal(SIGINT, on_interrupt);
#ifdef SIGTERM
    (void) signal(SIGTERM, on_interrupt);
#endif
    (void) atexit(print_summary);

    started_ms = wg_time_ms();

    /* ---- the loop ---- */

    for (;;) {
        struct pcap_pkthdr *hdr = NULL;
        const unsigned char *frame = NULL;
        uint8_t plain[WG_MAX_PACKET];
        uint8_t natbuf[WG_MAX_PACKET];
        size_t plainlen = 0;
        int rc;

        if (stop_requested)
            break;

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
                    int told = 0;

                    st.too_big++;
                    if (have_gw_addr && ipv4_dont_fragment(ip, iplen)) {
                        uint8_t err[128];
                        size_t elen = icmp_frag_needed(err, sizeof err,
                                                       gw_addr, ip, iplen,
                                                       (uint16_t) tunnel_mtu);
                        if (elen > 0 &&
                            raw_injector_send(inj, err, elen) == 0) {
                            st.icmp_sent++;
                            told = 1;
                            if (verbose) {
                                ipv4_format(abuf, sizeof abuf, ipv4_src(ip));
                                printf("big %lu bytes from %s, told to use"
                                       " %d\n", (unsigned long) iplen,
                                       abuf, tunnel_mtu);
                                fflush(stdout);
                            }
                        }
                    }
                    /*
                     * An oversized packet we could not answer is the
                     * silent failure the ICMP exists to prevent, so say
                     * so rather than letting it vanish into a counter.
                     * Without DF the sender is entitled to expect us to
                     * fragment, and we do not.
                     */
                    if (!told && verbose)
                        log_drop("out", ip, iplen,
                                 ipv4_dont_fragment(ip, iplen)
                                 ? "too big, and no ICMP could be sent"
                                 : "too big, and DF is not set");
                    goto after_out;
                }

                /*
                 * Translation needs a writable copy: the capture buffer
                 * belongs to pcap and the same frame may be handed back
                 * on the next call.
                 */
                if (use_nat) {
                    int nrc;

                    if (iplen > sizeof natbuf) {
                        st.dropped++;
                        if (verbose)
                            log_drop("out", ip, iplen,
                                     "larger than the translation buffer");
                        goto after_out;
                    }
                    memcpy(natbuf, ip, iplen);
                    nrc = nat_outbound(&nat, natbuf, iplen, wg_time_ms());
                    if (nrc != NAT_OK) {
                        /* Untranslatable: sending it anyway would leak
                           the client's address and be discarded by the
                           peer regardless. */
                        st.dropped++;
                        if (verbose)
                            log_drop("out", ip, iplen, nat_reason(nrc));
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
                    if (verbose)
                        log_drop("out", ip, iplen, "tunnel send failed");
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
                int nrc = NAT_OK;

                if (use_nat)
                    nrc = nat_inbound(&nat, plain, iplen, wg_time_ms());

                if (nrc != NAT_OK) {
                    /* No mapping: unsolicited, or the flow expired. */
                    st.dropped++;
                    if (verbose)
                        log_drop("in ", plain, iplen, nat_reason(nrc));
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
                if (verbose) {
                    printf("in  decrypted %lu bytes claiming an IP length"
                           " of %lu  DROPPED: malformed\n",
                           (unsigned long) plainlen, (unsigned long) iplen);
                    fflush(stdout);
                }
            }
        } else if (rc == WG_SOCK_ERROR) {
            fprintf(stderr, "tunnel receive error\n");
            break;
        }
    }

    if (stop_requested)
        printf("\ninterrupted");

    /* The summary itself is printed by print_summary, registered with
       atexit above, so that it appears whichever way we leave. */

    raw_injector_close(inj);
    pcap_close(pc);
    wg_client_close(&client);
    return 0;
}
