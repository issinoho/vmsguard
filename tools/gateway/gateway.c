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
#include <stdarg.h>
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

#include "encap.h"
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

struct stats {
    unsigned long captured;
    unsigned long tunnelled;
    unsigned long received;
    unsigned long injected;
    unsigned long dropped;
    unsigned long too_big;
    unsigned long icmp_sent;
    unsigned long stack_unreach;

    /* Drops, by cause. The total on its own says a run lost something
       without saying what, which for an unattended run is the only
       part that matters. */
    unsigned long drop_send;
    unsigned long drop_inject;
    unsigned long drop_malformed;
    unsigned long drop_oversize;
    unsigned long drop_not_allowed;
    unsigned long drop_no_encap;
    unsigned long v6_captured;
    unsigned long v6_injected;

    /*
     * The longest a single pass of the forwarding loop has taken.
     *
     * Rekeying used to block the loop for up to five seconds waiting
     * for a handshake, and a two-hour run measured that happening
     * twice. Now that it does not, this is how to tell: the figure
     * should stay at the pcap read timeout and never approach a
     * handshake timeout.
     */
    unsigned long max_stall_ms;
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
/*
 * One tunnel: a peer, and the addresses that belong to it.
 *
 * Several are possible, and they are not variants of one another --
 * each has its own keys, endpoint, session and timers. AllowedIPs is
 * what ties a packet to a tunnel, in both directions: it decides which
 * peer an outbound packet is sent to, and what an inbound one from that
 * peer is permitted to claim to be.
 *
 * The client library needs no changes for this. Each tunnel holds a
 * complete wg_client with its own UDP socket, which costs a socket per
 * peer and buys complete independence -- a peer that stops answering,
 * roams, or is rekeying affects nothing but itself.
 */
struct tunnel {
    struct wg_client   client;
    struct ipv4_subnet allowed[MAX_CLIENTS];
    int                nallowed;
    struct ipv6_subnet allowed6[MAX_CLIENTS];
    int                nallowed6;
    char               label[80];     /* the endpoint, for the log */
};

static struct tunnel tunnels[WG_CONF_MAX_PEERS];
static int           ntunnels;

/*
 * Peers as the config file gave them, copied out of struct wg_conf
 * before it is scrubbed. Command-line flags override the first of
 * these; the rest are configurable only from a file, because a command
 * line has no way to say where one peer ends and the next begins
 * without inventing a syntax for it.
 */
static struct wg_conf_peer conf_peers[WG_CONF_MAX_PEERS];
static int                 n_conf_peers;

static struct stats     st;
static struct nat_table nat;
static int              use_nat;
static uint64_t         started_ms;

/*
 * Running with nobody watching.
 *
 * A detached process has no terminal, so Ctrl-C is not available to
 * stop it and there is nothing to read its output. Three things follow:
 * the output goes to a file, the log has to say something between
 * starting and stopping or there is no way to tell a working gateway
 * from a wedged one, and there must be some way to ask it to stop that
 * still runs the shutdown path.
 *
 * Stopping by deleting the process would work but skips the exit
 * handler, and with it the summary — which is the one part of a long
 * run worth keeping.
 */
/*
 * IPv6 forwarding, which works by a route this platform provides and
 * most do not.
 *
 * A decrypted IPv6 packet cannot be put on the LAN directly: the stack
 * will not let a program originate one with a source address it does
 * not own, and there is no IPV6_HDRINCL to ask with. What it will do is
 * accept an IPv4 packet addressed to itself carrying an IPv6 one
 * inside, unwrap it, and route the contents natively -- if a configured
 * tunnel interface exists to match it against.
 *
 * So these are that tunnel's endpoints, and without them IPv6 is simply
 * not forwarded. Confirmed working on the target before any of this was
 * written; see docs/research/driver-feasibility.md.
 */
static uint32_t encap_local;
static uint32_t encap_remote;
static int      encap_ready;
static uint16_t encap_id;

/*
 * The address an ICMPv6 Packet Too Big claims to come from.
 *
 * The IPv4 side learns its equivalent from the socket, because the
 * gateway necessarily has an IPv4 address to reach its peer with. There
 * is no such guarantee for IPv6 -- the machine may have no IPv6 address
 * at all, and the tunnel's own is link-local, which is the wrong scope
 * for an error going to a client that is not on link. So it is asked
 * for rather than guessed, and without it the message is not sent and
 * the gateway says so.
 */
static uint8_t gw_addr6[16];
static int     have_gw_addr6;

static const char *stop_file;
static const char *log_file;
static uint64_t    status_interval_ms;

static volatile sig_atomic_t stop_requested;
static int stopped_by_file;

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
/*
 * Whether an address is one of our peers' endpoints.
 *
 * Our own encrypted traffic must never be captured and tunnelled again:
 * with a wide AllowedIPs the outer packets match, and each pass wraps
 * them once more. Every peer has to be checked, not just the one the
 * packet would otherwise go to.
 */
static int is_peer_endpoint(uint32_t d)
{
    int i;

    for (i = 0; i < ntunnels; i++) {
        const struct wg_endpoint *e = &tunnels[i].client.endpoint;
        uint32_t a;

        if (e->family != WG_AF_INET)
            continue;
        a = ((uint32_t) e->addr[0] << 24) | ((uint32_t) e->addr[1] << 16) |
            ((uint32_t) e->addr[2] << 8) | (uint32_t) e->addr[3];
        if (d == a)
            return 1;
    }
    return 0;
}

/*
 * Whether a packet addressed here is one the gateway would tunnel,
 * ignoring the tunnel subnet itself: not excluded, not multicast or
 * broadcast, and not the peer's own endpoint.
 *
 * The forwarding path makes these same judgements inline. They are
 * gathered here because the ICMP check needs to ask the same question
 * about an address it has read out of a quoted header rather than off
 * a captured packet.
 */
static int would_tunnel_to(uint32_t d, const struct ipv4_subnet *excludes,
                           int nexcludes)
{
    if ((d & 0xF0000000UL) == 0xE0000000UL || d == 0xFFFFFFFFUL || d == 0)
        return 0;
    if (is_peer_endpoint(d))
        return 0;
    return !ipv4_in_any(excludes, nexcludes, d);
}

/* Whether an address is one of the sources we forward for. With no
   --client given the gateway serves any source, so anything counts. */
static int is_a_client(uint32_t a, const struct ipv4_subnet *clients,
                       int nclients)
{
    /* No --client given means the gateway serves any source. */
    return nclients == 0 || ipv4_in_any(clients, nclients, a);
}

/*
 * All output, to the terminal or to the log.
 *
 * When a log file is named it is opened, appended to and closed for
 * every line. That looks wasteful and is the only approach that works
 * here.
 *
 * The obvious design -- redirect stdout once and leave it open -- fails
 * on OpenVMS, where the C RTL opens files for exclusive access, so
 * nothing can read the log while the gateway holds it:
 *
 *   %TYPE-W-OPENIN, error opening ...VMSGUARD.LOG;1 as input
 *   -RMS-E-FLK, file currently locked by another user
 *
 * A log nobody can read while the process is running is not a log, and
 * watching it is the entire reason a detached process writes one.
 *
 * Sharing can be asked for -- fopen takes optional RMS attributes -- but
 * only outside strict standard mode, and this is built with
 * /STANDARD=C99 on purpose. Under it, both the variadic fopen and
 * fileno are hidden:
 *
 *   %CC-E-TOOMANYARGS, ... "fopen" expects 2 arguments, but 3 supplied
 *   %CC-I-IMPLICITFUNC, ... "fileno" is implicitly declared
 *
 * Weakening the standard for one convenience is a bad trade -- the flag
 * is what keeps C11 from creeping in -- so the file is simply not held
 * open. At a status line every five minutes the cost is nothing.
 * --verbose with --log is the exception, an open and close per packet,
 * and it is a debugging combination rather than how this runs.
 */
/*
 * Errors go here too, rather than to stderr. One destination is the
 * point: a detached gateway's diagnostics belong in the same file, in
 * order, as everything else it said. The cost is that redirecting
 * stderr alone no longer captures them.
 */
static void emit(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (log_file != NULL) {
        FILE *f = fopen(log_file, "a");

        if (f != NULL) {
            vfprintf(f, fmt, ap);
            fclose(f);            /* closed at once: that is the point */
        }
    } else {
        vprintf(fmt, ap);
        /*
         * Flushed every line. Without a log file this still ends up in
         * a batch log when detached, and that is fully buffered — the
         * output would appear in minute-long bursts, which is exactly
         * wrong for something being watched.
         */
        fflush(stdout);
    }
    va_end(ap);
}

/*
 * Local time as HH:MM:SS. A log without times is nearly useless for a
 * process that has been up for days — "when did it last rekey" is the
 * whole question, and the counters alone cannot answer it.
 */
static const char *stamp(void)
{
    static char buf[16];
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);

    if (tm == NULL || strftime(buf, sizeof buf, "%H:%M:%S", tm) == 0)
        snprintf(buf, sizeof buf, "--:--:--");
    return buf;
}

/*
 * Why packets were dropped, appended to a line that has just said how
 * many. Only non-zero causes appear: a run that lost one packet should
 * say which kind, not recite six zeroes.
 *
 * The NAT counters are read straight from the table rather than
 * duplicated, so they cannot drift from what NAT itself believes.
 */
static void emit_drop_causes(void)
{
    if (st.dropped == 0)
        return;

    emit(" (");
    if (use_nat) {
        if (nat.dropped_unsupported > 0)
            emit("unsupported %lu ", nat.dropped_unsupported);
        if (nat.dropped_no_mapping > 0)
            emit("unmatched %lu ", nat.dropped_no_mapping);
        if (nat.dropped_table_full > 0)
            emit("table-full %lu ", nat.dropped_table_full);
        if (nat.dropped_frag_orphan > 0)
            emit("orphan-fragment %lu ", nat.dropped_frag_orphan);
    }
    if (st.drop_send > 0)
        emit("send-failed %lu ", st.drop_send);
    if (st.drop_inject > 0)
        emit("inject-failed %lu ", st.drop_inject);
    if (st.drop_malformed > 0)
        emit("malformed %lu ", st.drop_malformed);
    if (st.drop_oversize > 0)
        emit("too-big-to-translate %lu ", st.drop_oversize);
    if (st.drop_not_allowed > 0)
        emit("outside-allowedips %lu ", st.drop_not_allowed);
    if (st.drop_no_encap > 0)
        emit("ipv6-with-no-tunnel %lu ", st.drop_no_encap);
    emit(")");
}

/*
 * One line, periodically, so the log shows the thing is alive and what
 * it has been doing. Deliberately the same figures as the exit summary,
 * so a reader learns one format rather than two, and so a run that ends
 * badly still has its last known state on record.
 */
/*
 * Inbound packets the tunnel received and could not use, totalled
 * across peers. Each was a silent `continue` until a live run stalled
 * for forty seconds while every counter here read zero.
 */
static unsigned long tunnel_rx_discards(void)
{
    unsigned long n = 0;
    int t;

    for (t = 0; t < ntunnels; t++) {
        const struct wg_client *c = &tunnels[t].client;
        n += c->rx_malformed + c->rx_unknown_keypair +
             c->rx_decrypt_failed + c->rx_replayed;
    }
    return n;
}

static void emit_rx_discards(void)
{
    unsigned long malformed = 0, unknown = 0, bad = 0, replayed = 0;
    int t;

    for (t = 0; t < ntunnels; t++) {
        const struct wg_client *c = &tunnels[t].client;
        malformed += c->rx_malformed;
        unknown   += c->rx_unknown_keypair;
        bad       += c->rx_decrypt_failed;
        replayed  += c->rx_replayed;
    }
    if (malformed > 0)
        emit(" malformed %lu", malformed);
    if (unknown > 0)
        emit(" unknown-session %lu", unknown);
    if (bad > 0)
        emit(" undecryptable %lu", bad);
    if (replayed > 0)
        emit(" replayed %lu", replayed);
}

static void log_status(int nat_live)
{
    unsigned long rekeys = 0, failed = 0, roams = 0;
    unsigned long discards;
    int t;

    for (t = 0; t < ntunnels; t++) {
        rekeys += tunnels[t].client.rekeys;
        failed += tunnels[t].client.rekeys_failed;
        roams  += tunnels[t].client.roams;
    }

    emit("%s  up, %lu captured / %lu tunnelled / %lu injected,"
         " %lu dropped",
         stamp(), st.captured, st.tunnelled, st.injected, st.dropped);
    emit_drop_causes();
    emit(", %lu rekey%s", rekeys, rekeys == 1 ? "" : "s");
    /*
     * Printed on the status line rather than only in the summary: the
     * question it answers -- are packets arriving and being discarded?
     * -- is asked while a run is stalling, not afterwards.
     */
    discards = tunnel_rx_discards();
    if (discards > 0) {
        emit(", %lu tunnel discard%s:", discards, discards == 1 ? "" : "s");
        emit_rx_discards();
    }
    if (nat_live >= 0)
        emit(", %d mappings", nat_live);
    if (failed > 0)
        emit(", %lu FAILED rekey%s", failed, failed == 1 ? "" : "s");
    if (roams > 0)
        emit(", %lu roam%s", roams, roams == 1 ? "" : "s");
    /*
     * The longest single pass through the loop. Anything near a
     * handshake timeout means forwarding stopped while a rekey waited,
     * which is the thing that was supposed to have been fixed.
     */
    emit(", worst pass %lums", st.max_stall_ms);
    emit("\n");

    /*
     * A per-tunnel line only when there is more than one, and only for
     * the tunnel with something to say. With a single peer the totals
     * above already are that peer, and repeating them would be noise in
     * a log that may run for days.
     */
    if (ntunnels > 1) {
        for (t = 0; t < ntunnels; t++) {
            const struct wg_client *c = &tunnels[t].client;

            if (c->rekeys_failed == 0 && c->roams == 0)
                continue;
            emit("%s    %s: %lu rekeys, %lu failed, %lu roams\n",
                 stamp(), tunnels[t].label, c->rekeys,
                 c->rekeys_failed, c->roams);
        }
    }
}

/*
 * Bring up one tunnel and add it to the list.
 *
 * Returns 0, or -1 with the reason already reported.
 */
static int open_tunnel(const uint8_t *privkey, const uint8_t *peerkey,
                       const uint8_t *psk, const char *host, uint16_t port,
                       const struct wg_endpoint *ep, uint16_t listen_port,
                       const struct ipv4_subnet *allowed, int nallowed,
                       const struct ipv6_subnet *allowed6, int nallowed6,
                       int keepalive_s)
{
    struct tunnel *t;

    if (ntunnels >= WG_CONF_MAX_PEERS) {
        emit("error: at most %d peers\n", WG_CONF_MAX_PEERS);
        return -1;
    }
    t = &tunnels[ntunnels];

    if (wg_client_init(&t->client, privkey, peerkey, psk, ep,
                       listen_port) != 0) {
        emit("error: %s\n", t->client.error);
        return -1;
    }

    /*
     * Remember the endpoint as written, so that if the peer stops
     * answering the name can be looked up again. Roaming handles a peer
     * that moves and keeps talking; only this handles one that goes
     * quiet and comes back somewhere else, which is what a provider
     * retiring a server looks like.
     */
    wg_client_set_endpoint_name(&t->client, host, port);

    if (keepalive_s > 0)
        t->client.keepalive_interval_ms = (uint64_t) keepalive_s * 1000;

    memcpy(t->allowed, allowed, (size_t) nallowed * sizeof allowed[0]);
    t->nallowed = nallowed;
    if (nallowed6 > 0)
        memcpy(t->allowed6, allowed6,
               (size_t) nallowed6 * sizeof allowed6[0]);
    t->nallowed6 = nallowed6;
    snprintf(t->label, sizeof t->label, "%s:%u", host, (unsigned) port);

    ntunnels++;
    return 0;
}

/*
 * Which tunnel a destination belongs to, by longest prefix -- the same
 * rule a routing table uses, and the same one WireGuard uses to pick a
 * peer. A more specific AllowedIPs entry wins over a less specific one,
 * so a peer holding 10.9.0.0/24 takes that traffic even when another
 * holds 0.0.0.0/0.
 *
 * Returns the index, or -1 if no peer claims the address.
 */
static void close_tunnels(void)
{
    int i;

    for (i = 0; i < ntunnels; i++)
        wg_client_close(&tunnels[i].client);
}

static int tunnel_for(uint32_t dst)
{
    int best = -1;
    uint32_t best_mask = 0;
    int i;

    for (i = 0; i < ntunnels; i++) {
        uint32_t m;

        if (!ipv4_best_match(tunnels[i].allowed, tunnels[i].nallowed,
                             dst, &m))
            continue;
        if (best < 0 || m > best_mask) {
            best = i;
            best_mask = m;
        }
    }
    return best;
}

/* As tunnel_for, over IPv6 prefixes. */
static int tunnel_for6(const uint8_t *dst)
{
    int best = -1;
    uint8_t best_prefix = 0;
    int i;

    for (i = 0; i < ntunnels; i++) {
        uint8_t p;

        if (!ipv6_best_match(tunnels[i].allowed6, tunnels[i].nallowed6,
                             dst, &p))
            continue;
        if (best < 0 || p > best_prefix) {
            best = i;
            best_prefix = p;
        }
    }
    return best;
}

/*
 * Outbound IPv6: filter, choose a tunnel, encrypt, send.
 *
 * Separate from the IPv4 path rather than merged into it. They share
 * the shape and none of the details -- no NAT, since there is no NAT66
 * and a site-to-site link does not want one; no fragmentation, since
 * IPv6 routers do not fragment; and a different address type
 * throughout. Interleaving the two would make both harder to read for
 * the sake of a few lines.
 */
static void forward_outbound6(const uint8_t *ip, size_t iplen,
                              const struct ipv6_subnet *clients6,
                              int nclients6,
                              const struct ipv6_subnet *excludes6,
                              int nexcludes6, int tunnel_mtu,
                              struct raw_injector *inj, int verbose)
{
    char s6[48], d6[48];
    int t;

    /* Never tunnel to somewhere excluded, nor to multicast, which has
       no meaning at the far end of a point-to-point tunnel. */
    if (ipv6_dst(ip)[0] == 0xFF)
        return;
    if (ipv6_in_any(excludes6, nexcludes6, ipv6_dst(ip)))
        return;

    /* Only for hosts we were told to serve. An empty list means any. */
    if (nclients6 > 0 && !ipv6_in_any(clients6, nclients6, ipv6_src(ip)))
        return;

    t = tunnel_for6(ipv6_dst(ip));
    if (t < 0)
        return;

    st.captured++;
    st.v6_captured++;

    /*
     * Too large for the tunnel. An IPv6 router may not fragment, so
     * where IPv4 could pass this on in pieces, here the sender is the
     * only thing that can act -- and it only acts if told. Without the
     * ICMPv6 a large flow does not slow down, it stops.
     *
     * The error goes back the way inbound IPv6 does: wrapped in
     * protocol 41 and injected, letting the stack decapsulate it and
     * route the ICMPv6 inside to the client. There is no IPV6_HDRINCL
     * on this platform to put it on the LAN directly, and this is the
     * same mechanism deliver_inbound() already relies on -- the stack
     * was seen to route a decapsulated inner packet onward when
     * probe_encap's echo request was answered.
     */
    if (iplen > (size_t) tunnel_mtu) {
        int told = 0;

        st.too_big++;
        if (encap_ready && have_gw_addr6) {
            uint8_t err[1280], wrapped[1280 + IPV4_MIN_HDR];
            size_t elen = icmp6_packet_too_big(err, sizeof err,
                                               gw_addr6, ip, iplen,
                                               (uint32_t) tunnel_mtu);
            if (elen > 0) {
                size_t n = ip4_encap(wrapped, sizeof wrapped, encap_remote,
                                     encap_local, ENCAP_PROTO_IPV6,
                                     encap_id++, err, elen);
                if (n > 0 && raw_injector_send(inj, wrapped, n) == 0) {
                    st.icmp_sent++;
                    told = 1;
                    if (verbose) {
                        ipv6_format(s6, sizeof s6, ipv6_src(ip));
                        emit("big %lu bytes from %s, told to use %d\n",
                             (unsigned long) iplen, s6, tunnel_mtu);
                    }
                }
            }
        }
        /*
         * Unanswered, this is the silent stall the message exists to
         * prevent, so it is named rather than left in a counter.
         */
        if (!told && verbose) {
            ipv6_format(s6, sizeof s6, ipv6_src(ip));
            emit("big %lu bytes from %s: DROPPED, and no ICMPv6 Packet Too"
                 " Big could be sent%s\n", (unsigned long) iplen, s6,
                 !encap_ready ? " (no --encap-local/--encap-remote)"
                              : !have_gw_addr6 ? " (no --gateway-ip6)" : "");
        }
        st.dropped++;
        return;
    }

    if (wg_client_send(&tunnels[t].client, ip, iplen) == 0) {
        st.tunnelled++;
        if (verbose) {
            ipv6_format(s6, sizeof s6, ipv6_src(ip));
            ipv6_format(d6, sizeof d6, ipv6_dst(ip));
            emit("out %s -> %s  next-header %u  %lu bytes\n",
                 s6, d6, (unsigned) ip[6], (unsigned long) iplen);
        }
    } else {
        st.dropped++;
        st.drop_send++;
    }
}

/*
 * Whether the operator has asked us to stop.
 *
 * A file, because it is the one signalling mechanism available from
 * DCL, from a shell, and from a script, without knowing the process id
 * or holding any privilege beyond writing to a directory. It is removed
 * once seen so that a restart does not stop immediately.
 */
static int stop_requested_by_file(void)
{
    FILE *f;

    if (stop_file == NULL)
        return 0;
    f = fopen(stop_file, "r");
    if (f == NULL)
        return 0;
    fclose(f);
    (void) remove(stop_file);
    return 1;
}

static void log_drop(const char *dir, const uint8_t *ip, size_t iplen,
                     const char *why)
{
    char abuf[32], bbuf[32];

    ipv4_format(abuf, sizeof abuf, ipv4_src(ip));
    ipv4_format(bbuf, sizeof bbuf, ipv4_dst(ip));
    emit("%s %s -> %s  proto %u  %lu bytes  DROPPED: %s\n",
           dir, abuf, bbuf, (unsigned) ipv4_proto(ip),
           (unsigned long) iplen, why);
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

/*
 * Deliver one decrypted packet from `t` onto the LAN.
 *
 * Split out of the loop because it now runs once per tunnel: inlining
 * it would have put the whole of it inside two nested loops, and the
 * cryptokey check in the middle reads as a guard rather than a filter
 * only when it is at the top of a function.
 */
static void deliver_inbound(struct tunnel *t, uint8_t *plain,
                            size_t plainlen, struct raw_injector *inj,
                            int verbose)
{
    size_t iplen = ((size_t) plain[2] << 8) | plain[3];
    char abuf[16], bbuf[16];

    st.received++;

    /*
     * IPv6, which takes a different road onto the LAN. It cannot be
     * injected as it stands -- the stack will not originate a packet
     * from an address we do not hold -- so it is wrapped in IPv4 and
     * addressed to this machine, which unwraps it and routes it
     * natively. Everything the tunnel needs is in the outer header.
     */
    if (ipv6_looks_valid(plain, plainlen)) {
        uint8_t wrapped[WG_MAX_PACKET];
        char s6[48], d6[48];
        size_t v6len = IPV6_MIN_HDR +
                       (((size_t) plain[4] << 8) | plain[5]);
        size_t n;

        if (!encap_ready) {
            st.dropped++;
            st.drop_no_encap++;
            return;
        }
        /* Cryptokey routing applies exactly as it does to IPv4. */
        if (!ipv6_in_any(t->allowed6, t->nallowed6, ipv6_src(plain))) {
            st.dropped++;
            st.drop_not_allowed++;
            if (verbose) {
                ipv6_format(s6, sizeof s6, ipv6_src(plain));
                emit("in  %s  DROPPED: source outside the peer's"
                     " AllowedIPs\n", s6);
            }
            return;
        }

        n = ip4_encap(wrapped, sizeof wrapped, encap_remote, encap_local,
                      ENCAP_PROTO_IPV6, encap_id++, plain, v6len);
        if (n == 0 || raw_injector_send(inj, wrapped, n) != 0) {
            st.dropped++;
            st.drop_inject++;
            if (verbose)
                emit("in  IPv6 %lu bytes  DROPPED: %s\n",
                     (unsigned long) v6len,
                     n == 0 ? "would not encapsulate"
                            : raw_injector_error(inj));
            return;
        }
        st.injected++;
        st.v6_injected++;
        if (verbose) {
            ipv6_format(s6, sizeof s6, ipv6_src(plain));
            ipv6_format(d6, sizeof d6, ipv6_dst(plain));
            emit("in  %s -> %s  next-header %u  %lu bytes  (via %s)\n",
                 s6, d6, (unsigned) plain[6], (unsigned long) v6len,
                 "the tunnel interface");
        }
        return;
    }

    /*
     * Trust the packet's own length rather than the decrypted
     * size: WireGuard pads plaintext to a 16-byte boundary, and
     * injecting that padding would corrupt the packet.
     */
    if (iplen >= IPV4_MIN_HDR && iplen <= plainlen) {
        int nrc = NAT_OK;

        /*
         * Cryptokey routing, the inbound half.
         *
         * Decryption proves the packet came from the peer. It
         * says nothing about what the peer may claim to *be*,
         * and WireGuard's central idea is that those are the
         * same question: a peer may only source addresses
         * inside its AllowedIPs. Without this a peer -- or
         * anyone who has taken it over -- could inject packets
         * onto the LAN bearing any source address at all.
         *
         * Checked on the packet as decrypted, before NAT
         * rewrites anything: what is being validated is what
         * the peer sent, not what we made of it.
         *
         * With a full tunnel the list is 0.0.0.0/0 and this
         * permits everything, which is correct rather than
         * pointless -- that configuration really does authorise
         * the peer to send as anyone.
         */
        if (!ipv4_in_any(t->allowed, t->nallowed, ipv4_src(plain))) {
            st.dropped++;
            st.drop_not_allowed++;
            if (verbose)
                log_drop("in ", plain, iplen,
                         "source outside the peer's AllowedIPs");
            return;
        }

        if (use_nat)
            nrc = nat_inbound(&nat, plain, iplen, wg_time_ms());

        if (nrc == NAT_HELD) {
            /*
             * A fragment that overtook the first of its
             * datagram inside the tunnel. Not sent and not
             * lost: it comes back out of nat_take_held once the
             * first arrives, a moment later.
             */
            if (verbose)
                log_drop("in ", plain, iplen, nat_reason(nrc));
        } else if (nrc != NAT_OK) {
            /* No mapping: unsolicited, or the flow expired. */
            st.dropped++;
            if (verbose)
                log_drop("in ", plain, iplen, nat_reason(nrc));
        } else if (raw_injector_send(inj, plain, iplen) == 0) {
            st.injected++;
            if (verbose) {
                ipv4_format(abuf, sizeof abuf, ipv4_src(plain));
                ipv4_format(bbuf, sizeof bbuf, ipv4_dst(plain));
                emit("in  %s -> %s  proto %u  %lu bytes\n",
                       abuf, bbuf, (unsigned) ipv4_proto(plain),
                       (unsigned long) iplen);
            }
        } else {
            st.dropped++;
            st.drop_inject++;
            if (verbose) {
                emit("inject failed: %s\n",
                       raw_injector_error(inj));
            }
        }
        /*
         * A first fragment has just created a mapping, so any
         * fragment held waiting for one can go now. Drained
         * here rather than at the top of the loop so it happens
         * immediately, while the datagram is still worth
         * reassembling at the far end.
         */
        if (use_nat) {
            uint8_t held[WG_MAX_PACKET];
            size_t heldlen;

            while ((heldlen = nat_take_held(&nat, held, sizeof held,
                                            wg_time_ms())) > 0) {
                if (raw_injector_send(inj, held, heldlen) == 0) {
                    st.injected++;
                    if (verbose) {
                        ipv4_format(abuf, sizeof abuf,
                                    ipv4_src(held));
                        ipv4_format(bbuf, sizeof bbuf,
                                    ipv4_dst(held));
                        emit("in  %s -> %s  proto %u  %lu bytes"
                               "  (was held)\n", abuf, bbuf,
                               (unsigned) ipv4_proto(held),
                               (unsigned long) heldlen);
                    }
                } else {
                    st.dropped++;
                }
            }
        }
    } else {
        st.dropped++;
        st.drop_malformed++;
        if (verbose) {
            emit("in  decrypted %lu bytes claiming an IP length"
                 " of %lu  DROPPED: malformed\n",
                 (unsigned long) plainlen, (unsigned long) iplen);
        }
    }
}

static void print_summary(void)
{
    uint64_t elapsed = 0;
    char dur[32];
    int t;

    /*
     * How long the run lasted, because without it none of the rest can
     * be read. "296 of 512 mappings live" means the timeouts are doing
     * their job if the run was twenty seconds and that they are not if
     * it was ten minutes, and the summary gave no way to tell which.
     */
    if (started_ms != 0)
        elapsed = wg_time_ms() - started_ms;

    format_duration(dur, sizeof dur, elapsed);
    emit("\nran for %s\n", dur);

    emit("captured %lu, tunnelled %lu, received %lu, injected %lu,"
         " dropped %lu",
         st.captured, st.tunnelled, st.received, st.injected, st.dropped);
    emit_drop_causes();
    emit("\n");
    emit("longest single pass through the forwarding loop: %lums\n",
         st.max_stall_ms);
    /*
     * Loud, because this one silently breaks connections that would
     * otherwise have worked, and the fix is a one-line setting on the
     * OpenVMS box rather than anything in this program.
     */
    if (st.stack_unreach > 0)
        emit("WARNING: the OpenVMS stack sent %lu ICMP unreachable%s to"
               " clients about\n"
               "         destinations this gateway was tunnelling. Those"
               " senders were told\n"
               "         the traffic failed while it was in fact"
               " working. See the ICMP\n"
               "         unreachables section of docs/gateway.md — IP"
               " forwarding should\n"
               "         be disabled on this machine.\n",
               st.stack_unreach, st.stack_unreach == 1 ? "" : "s");
    if (st.too_big > 0)
        emit("oversized: %lu, of which %lu answered with ICMP"
               " fragmentation-needed\n", st.too_big, st.icmp_sent);
    /*
     * Only mentioned when it happened. A peer that never moved is the
     * normal case and needs no line; one that did explains why the
     * endpoint in the header is no longer where packets are going.
     */
    for (t = 0; t < ntunnels; t++) {
        const struct wg_client *c = &tunnels[t].client;

        if (c->roams > 0) {
            char epbuf[80];

            wg_endpoint_format(epbuf, sizeof epbuf, &c->endpoint);
            emit("%s: roamed %lu time%s; last seen at %s\n",
                 tunnels[t].label, c->roams,
                 c->roams == 1 ? "" : "s", epbuf);
        }
    }
    /*
     * Always printed, even at zero. A run shorter than the rekey
     * interval and a run whose rekeys silently failed look identical
     * otherwise, and the difference is the whole question when a
     * session dies after a few minutes.
     */
    for (t = 0; t < ntunnels; t++) {
        const struct wg_client *c = &tunnels[t].client;

        emit("%s: rekeys %lu succeeded, %lu failed",
             tunnels[t].label, c->rekeys, c->rekeys_failed);
        if (c->peer_handshakes > 0)
            emit("; the peer started %lu of its own", c->peer_handshakes);
        if (c->cookies_received > 0)
            emit("; answered %lu cookie challenge%s", c->cookies_received,
                 c->cookies_received == 1 ? "" : "s");
        emit("\n");

        /*
         * Always named individually here, unlike on the status line.
         * "unknown-session" in particular says the peer was sending
         * under a session we no longer held, which is a rekey fault
         * and not a network one -- and is invisible without this.
         */
        if (c->rx_malformed + c->rx_unknown_keypair +
            c->rx_decrypt_failed + c->rx_replayed > 0) {
            emit("%s: tunnel packets discarded --"
                 " %lu malformed, %lu unknown session,"
                 " %lu undecryptable, %lu replayed\n",
                 tunnels[t].label, c->rx_malformed, c->rx_unknown_keypair,
                 c->rx_decrypt_failed, c->rx_replayed);
        }
    }

    if (use_nat) {
        emit("NAT: %lu translated, %lu restored, %d of %d mappings live,"
               " dropped %lu unsupported / %lu unmatched / %lu table-full"
               " / %lu orphan fragments\n",
               nat.translated, nat.restored, nat_active(&nat, wg_time_ms()),
               NAT_ENTRIES, nat.dropped_unsupported, nat.dropped_no_mapping,
               nat.dropped_table_full, nat.dropped_frag_orphan);
        if (nat.frags_tracked > 0) {
            emit("     %lu fragmented datagram%s, %lu later fragment%s"
                   " carried on the first one's mapping\n",
                   nat.frags_tracked, nat.frags_tracked == 1 ? "" : "s",
                   nat.frags_inherited,
                   nat.frags_inherited == 1 ? "" : "s");
            if (nat.frags_held > 0)
                emit("     %lu arrived before their first fragment and"
                       " were held; %lu released\n",
                       nat.frags_held, nat.frags_released);
        }
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
            emit("     %lu new flow%s over the run, %lu per minute\n",
                   nat.flows, nat.flows == 1 ? "" : "s",
                   (unsigned long) ((uint64_t) nat.flows * 60000ULL
                                    / elapsed));
        /*
         * Only mentioned when it happened, because when it has, some
         * flow was broken without any other trace of it.
         */
        if (nat.evicted > 0)
            emit("     %lu live mapping%s recycled to make room; a flow"
                   " that quiet may have stopped working\n",
                   nat.evicted, nat.evicted == 1 ? " was" : "s were");
        /*
         * Only a bug in nat.c can produce this, so it says so plainly
         * rather than leaving a bare number to be interpreted as some
         * network condition. Nothing here can be done about it at run
         * time; the value is in it being visible at all.
         */
        if (nat.chain_overruns > 0)
            emit("     %lu corrupt lookup chain%s abandoned — a defect in"
                   " the NAT index, please report it\n",
                   nat.chain_overruns,
                   nat.chain_overruns == 1 ? "" : "s");
    }
}

static void usage(const char *argv0)
{
    emit("usage: %s --key <base64> --peer-key <base64> --endpoint <host:port>\n"
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
"                   flag given as well overrides the first peer.\n"
"                   Several [Peer] sections are supported and are\n"
"                   the only way to configure more than one: a\n"
"                   command line cannot say where one peer ends\n"
"                   and the next begins\n"
"  --log            append all output to this file, for a process\n"
"                   with no terminal. Opened before anything is\n"
"                   printed, so startup errors land in it too\n"
"  --status         seconds between status lines in the log.\n"
"                   Default 300 with --log, off without: a log\n"
"                   that says nothing between starting and\n"
"                   stopping cannot distinguish working from\n"
"                   wedged\n"
"  --stop-file      exit cleanly, writing the summary, when this\n"
"                   file appears. The way to stop a detached\n"
"                   process without deleting it, which would skip\n"
"                   the summary. Removed once seen\n");
    /*
     * Split here deliberately. C99 only requires a compiler to support
     * a 4095-character string literal, and VSI C is the ceiling this
     * project builds to -- one continuous usage text had grown past
     * that and gcc warned. Two calls cost nothing and the limit stops
     * being something to remember.
     */
    emit(
"  --encap-local    this machine's end of an OpenVMS configured\n"
"                   tunnel (iptunnel create), and\n"
"  --encap-remote   the far end of it. Both are needed to forward\n"
"                   IPv6: a decrypted IPv6 packet cannot be put on\n"
"                   the LAN directly, so it is wrapped in IPv4 and\n"
"                   handed to the stack, which unwraps and routes\n"
"                   it. Without them IPv6 is captured and dropped\n"
"  --gateway-ip6    an IPv6 address of this machine, used as the\n"
"                   source of ICMPv6 Packet Too Big. IPv6 routers\n"
"                   may not fragment, so an oversized packet stalls\n"
"                   the sender unless it is told. Without this the\n"
"                   packet is dropped and counted instead\n"
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
        emit("error: pcap_findalldevs: %s\n",
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
        emit("error: no interface matching '%s'. Available:\n",
                want);
        for (d = devs; d != NULL; d = d->next)
            emit("         %s\n", d->name);
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
        emit("error: cannot open %s\n", path);
        return -1;
    }
    n = fread(buf, 1, cap - 1, f);
    if (ferror(f)) {
        emit("error: cannot read %s\n", path);
        fclose(f);
        return -1;
    }
    /*
     * A file that exactly fills the buffer may have more behind it, and
     * a config silently truncated mid-key is worse than one refused.
     */
    if (n == cap - 1 && fgetc(f) != EOF) {
        emit("error: %s is too large to be a WireGuard config\n",
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
        emit("error: %s is not a valid base64 key\n", what);
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
    struct ipv4_subnet allowed[MAX_CLIENTS];
    int nallowed = 0;
    struct ipv6_subnet allowed6[MAX_CLIENTS];
    int nallowed6 = 0;
    struct ipv4_subnet clients[MAX_CLIENTS];
    int nclients = 0;
    struct ipv4_subnet excludes[MAX_CLIENTS];
    int nexcludes = 0;
    struct ipv6_subnet clients6[MAX_CLIENTS];
    int nclients6 = 0;
    struct ipv6_subnet excludes6[MAX_CLIENTS];
    int nexcludes6 = 0;
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
    int status_given = 0;
    uint64_t last_status_ms = 0;
    uint64_t last_tick_ms = 0;
    uint64_t last_pass_ms = 0;
    int i;

    memset(&st, 0, sizeof st);

    /*
     * --log before anything else, including --config.
     *
     * A detached process has no terminal, so any output produced before
     * the redirect is simply lost — and that included the config file's
     * own diagnostics. A config that failed to parse would have
     * reported the reason to nobody and exited, leaving an empty log
     * and no explanation.
     */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--log") != 0 || i + 1 >= argc)
            continue;
        log_file = argv[i + 1];

        /*
         * Opened once here purely to fail early: a log that cannot be
         * written is worth refusing to start over, rather than
         * discovering hours later that nothing was recorded.
         */
        {
            FILE *f = fopen(log_file, "a");

            if (f == NULL) {
                log_file = NULL;
                emit("error: cannot open log file %s\n", argv[i + 1]);
                return 1;
            }
            fclose(f);
        }
        emit("\n%s  ---- vmsguard gateway starting ----\n", stamp());
        break;
    }

    /*
     * --config next, in a pass of its own, so that the ordinary flag
     * loop below overwrites whatever the file supplied regardless of
     * where on the command line it appeared. A flag the operator typed
     * beats a file they may not have written.
     */
    for (i = 1; i < argc; i++) {
        struct wg_conf conf;
        char text[8192];
        long n;

        /*
         * Values taken from the file are copied into these rather than
         * pointed at inside conf, which is scoped to this loop and
         * scrubbed at the end of it. Pointing at conf left endpoint_arg
         * and subnet_arg addressing memory that had been zeroed to
         * clear the private key, so the gateway refused its own config
         * with "--tunnel-subnet '' is not valid CIDR".
         */
        static char conf_endpoint[WG_CONF_ENDPOINT_LEN];
        static char conf_subnet[WG_CONF_CIDR_LEN];

        if (strcmp(argv[i], "--config") != 0 || i + 1 >= argc)
            continue;

        n = read_file(argv[i + 1], text, sizeof text);
        if (n < 0)
            return 1;
        if (wg_conf_parse(&conf, text, (size_t) n) != 0) {
            emit("error: %s: %s\n", argv[i + 1], conf.error);
            return 2;
        }

        if (conf.have_private_key) {
            memcpy(privkey, conf.private_key, WG_KEY_LEN);
            have_key = 1;
        }
        /*
         * Copied out before the struct is scrubbed at the end of this
         * loop -- the same trap that once left --tunnel-subnet pointing
         * at zeroed memory.
         */
        memcpy(conf_peers, conf.peers, sizeof conf_peers);
        n_conf_peers = conf.n_peers;

        /*
         * The first peer also fills the single-peer variables, so that
         * a flag given as well still overrides it and every existing
         * check still applies. Peers beyond the first are used as they
         * came from the file.
         */
        if (n_conf_peers > 0) {
            const struct wg_conf_peer *p0 = &conf_peers[0];

            if (p0->have_public_key) {
                memcpy(peerkey, p0->public_key, WG_KEY_LEN);
                have_peer = 1;
            }
            if (p0->have_preshared_key) {
                memcpy(psk, p0->preshared_key, WG_KEY_LEN);
                pskp = psk;
            }
            if (p0->have_endpoint) {
                snprintf(conf_endpoint, sizeof conf_endpoint, "%s",
                         p0->endpoint);
                endpoint_arg = conf_endpoint;
            }
            if (p0->n_allowed > 0) {
                int k;

                /*
                 * Every entry, not just the first. AllowedIPs is a list
                 * in WireGuard and means two things at once: what may
                 * be sent to this peer, and what it may claim to be.
                 * Using one of several would quietly narrow both.
                 */
                snprintf(conf_subnet, sizeof conf_subnet, "%s",
                         p0->allowed[0]);
                subnet_arg = conf_subnet;
                nallowed = 0;
                nallowed6 = 0;
                for (k = 0; k < p0->n_allowed; k++) {
                    if (nallowed < MAX_CLIENTS &&
                        ethip_parse_cidr(p0->allowed[k],
                                         &allowed[nallowed].net,
                                         &allowed[nallowed].mask) == 0) {
                        nallowed++;
                    } else if (nallowed6 < MAX_CLIENTS &&
                               ethip_parse_cidr6(p0->allowed[k],
                                                 allowed6[nallowed6].net,
                                                 &allowed6[nallowed6].prefix)
                               == 0) {
                        nallowed6++;
                    } else {
                        emit("error: %s: AllowedIPs '%s' is not valid"
                             " CIDR\n", argv[i + 1], p0->allowed[k]);
                        return 2;
                    }
                }
            }
            if (p0->keepalive > 0)
                keepalive_s = p0->keepalive;
        }
        if (conf.mtu > 0)
            tunnel_mtu = conf.mtu;
        if (conf.listen_port > 0)
            listen_port = (uint16_t) conf.listen_port;

        if (conf.have_address) {
            if (ethip_parse_cidr(conf.address, &tunnel_addr,
                                 &tunnel_addr_mask) != 0 ||
                tunnel_addr_mask != 0xFFFFFFFFUL) {
                emit("error: %s: Address '%s' is not usable\n",
                        argv[i + 1], conf.address);
                return 2;
            }
            use_nat = 1;
        }

        emit("read %s\n", argv[i + 1]);

        /*
         * Say what was not acted on. A config is written for wg-quick,
         * which does more than we do, and appearing to have honoured a
         * line we ignored is how an operator ends up debugging the
         * wrong thing.
         */
        if (conf.saw_dns)
            emit("  note: DNS is for the machines behind the gateway to\n"
                   "        set for themselves; it is not applied here\n");

        emit("  note: --interface is not in a config file and must still\n"
               "        be given, as must --client and --exclude for a\n"
               "        full tunnel\n\n");

        /*
         * Scrub: the private key was in both of these.
         *
         * wg_zero rather than memset, because a memset over a local
         * about to go out of scope is a dead store and the compiler is
         * entitled to remove it — GCC at -O2 does, so this scrub was
         * not happening at all on the reference build. OPENSSL_cleanse
         * exists precisely to be unremovable.
         */
        wg_zero(text, sizeof text);
        wg_zero(&conf, sizeof conf);   /* conf_peers already copied */
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
            nallowed = 0;       /* a flag replaces the file's list */
        } else if (strcmp(argv[i], "--tunnel-address") == 0 && i + 1 < argc) {
            if (ethip_parse_cidr(argv[++i], &tunnel_addr,
                                 &tunnel_addr_mask) != 0 ||
                tunnel_addr_mask != 0xFFFFFFFFUL) {
                emit("error: --tunnel-address must be a plain address\n");
                return 2;
            }
            use_nat = 1;
        } else if (strcmp(argv[i], "--exclude") == 0 && i + 1 < argc) {
            if (nexcludes >= MAX_CLIENTS) {
                emit("error: at most %d --exclude entries\n",
                        MAX_CLIENTS);
                return 2;
            }
            i++;
            if (ethip_parse_cidr(argv[i], &excludes[nexcludes].net,
                                 &excludes[nexcludes].mask) == 0) {
                nexcludes++;
            } else if (nexcludes6 < MAX_CLIENTS &&
                       ethip_parse_cidr6(argv[i], excludes6[nexcludes6].net,
                                         &excludes6[nexcludes6].prefix)
                       == 0) {
                nexcludes6++;
            } else {
                emit("error: --exclude '%s' is not valid CIDR\n", argv[i]);
                return 2;
            }
        } else if (strcmp(argv[i], "--client") == 0 && i + 1 < argc) {
            if (nclients >= MAX_CLIENTS) {
                emit("error: at most %d --client entries\n",
                        MAX_CLIENTS);
                return 2;
            }
            /*
             * IPv4 or IPv6, decided by which parser accepts it, so a
             * dual-stack client is two --client entries and not a
             * different flag.
             */
            i++;
            if (ethip_parse_cidr(argv[i], &clients[nclients].net,
                                 &clients[nclients].mask) == 0) {
                nclients++;
            } else if (nclients6 < MAX_CLIENTS &&
                       ethip_parse_cidr6(argv[i], clients6[nclients6].net,
                                         &clients6[nclients6].prefix) == 0) {
                nclients6++;
            } else {
                emit("error: --client '%s' is not valid CIDR\n", argv[i]);
                return 2;
            }
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            listen_port = (uint16_t) atoi(argv[++i]);
        } else if (strcmp(argv[i], "--tunnel-mtu") == 0 && i + 1 < argc) {
            tunnel_mtu = atoi(argv[++i]);
            if (tunnel_mtu < 576 || tunnel_mtu > 1500) {
                emit("error: --tunnel-mtu must be between 576 and 1500\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--keepalive") == 0 && i + 1 < argc) {
            keepalive_s = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            i++;                    /* already acted on, above */
        } else if (strcmp(argv[i], "--stop-file") == 0 && i + 1 < argc) {
            stop_file = argv[++i];
        } else if (strcmp(argv[i], "--status") == 0 && i + 1 < argc) {
            status_interval_ms = (uint64_t) atoi(argv[++i]) * 1000;
            status_given = 1;
        } else if (strcmp(argv[i], "--gateway-ip6") == 0 && i + 1 < argc) {
            uint8_t plen;
            if (ethip_parse_cidr6(argv[++i], gw_addr6, &plen) != 0 ||
                plen != 128) {
                emit("error: --gateway-ip6 must be a plain address\n");
                return 2;
            }
            have_gw_addr6 = 1;
        } else if (strcmp(argv[i], "--encap-local") == 0 && i + 1 < argc) {
            uint32_t m;
            if (ethip_parse_cidr(argv[++i], &encap_local, &m) != 0 ||
                m != 0xFFFFFFFFUL) {
                emit("error: --encap-local must be a plain address\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--encap-remote") == 0 && i + 1 < argc) {
            uint32_t m;
            if (ethip_parse_cidr(argv[++i], &encap_remote, &m) != 0 ||
                m != 0xFFFFFFFFUL) {
                emit("error: --encap-remote must be a plain address\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    /*
     * A log nobody is watching needs to say something periodically, so
     * logging turns status lines on unless a rate was given explicitly.
     */
    if (log_file != NULL && !status_given)
        status_interval_ms = 300000;

    if (!have_key || !have_peer || endpoint_arg == NULL ||
        ifname == NULL || subnet_arg == NULL) {
        usage(argv[0]);
        return 2;
    }

    if (nallowed == 0 && nallowed6 == 0 && subnet_arg != NULL) {
        if (ethip_parse_cidr(subnet_arg, &allowed[0].net,
                             &allowed[0].mask) == 0)
            nallowed = 1;
        else if (ethip_parse_cidr6(subnet_arg, allowed6[0].net,
                                   &allowed6[0].prefix) == 0)
            nallowed6 = 1;
    }

    if (nallowed == 0 && nallowed6 == 0) {
        emit("error: --tunnel-subnet '%s' is not valid CIDR\n",
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
    if (nallowed > 0 && allowed[0].mask < 0xFF000000UL &&
        nclients == 0 && nclients6 == 0) {
        emit("error: --tunnel-subnet %s is wider than /8, so --client is\n"
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
    if (nallowed > 0 && allowed[0].mask < 0xFF000000UL &&
        nexcludes == 0 && nexcludes6 == 0) {
        emit("error: --tunnel-subnet %s is wider than /8, so --exclude is\n"
            "       required. Without it, traffic to local destinations is\n"
            "       tunnelled too — including conversations with this\n"
            "       machine. Pass your local network, e.g.\n"
            "         --exclude 192.168.0.0/24\n",
            subnet_arg);
        return 2;
    }

    colon = strrchr(endpoint_arg, ':');
    if (colon == NULL || (size_t) (colon - endpoint_arg) >= sizeof host) {
        emit("error: --endpoint must be host:port\n");
        return 2;
    }
    memcpy(host, endpoint_arg, (size_t) (colon - endpoint_arg));
    host[colon - endpoint_arg] = '\0';
    peer_port = (uint16_t) atoi(colon + 1);
    if (peer_port == 0) {
        emit("error: invalid port in --endpoint\n");
        return 2;
    }
    if (wg_endpoint_resolve(&endpoint, host, peer_port) != 0) {
        emit("error: could not resolve '%s'\n", host);
        return 1;
    }

    emit("vmsguard gateway\n");

    /* ---- the tunnels ---- */

    /*
     * Peer 0 from the flags as merged above, and any further peers
     * exactly as the config file gave them.
     */
    if (open_tunnel(privkey, peerkey, pskp, host, peer_port, &endpoint,
                    listen_port, allowed, nallowed, allowed6, nallowed6,
                    keepalive_s) != 0)
        return 1;

    for (i = 1; i < n_conf_peers; i++) {
        const struct wg_conf_peer *pr = &conf_peers[i];
        struct ipv4_subnet pa[MAX_CLIENTS];
        struct ipv6_subnet pa6[MAX_CLIENTS];
        struct wg_endpoint pe;
        char phost[128];
        uint16_t pport;
        int npa = 0, npa6 = 0, k;
        char *pc;

        if (!pr->have_public_key || !pr->have_endpoint) {
            emit("error: peer %d has no %s\n", i + 1,
                 pr->have_public_key ? "Endpoint" : "PublicKey");
            return 2;
        }
        for (k = 0; k < pr->n_allowed; k++) {
            if (npa < MAX_CLIENTS &&
                ethip_parse_cidr(pr->allowed[k], &pa[npa].net,
                                 &pa[npa].mask) == 0) {
                npa++;
            } else if (npa6 < MAX_CLIENTS &&
                       ethip_parse_cidr6(pr->allowed[k], pa6[npa6].net,
                                         &pa6[npa6].prefix) == 0) {
                npa6++;
            } else {
                emit("error: peer %d: AllowedIPs '%s' is not valid CIDR\n",
                     i + 1, pr->allowed[k]);
                return 2;
            }
        }
        if (npa == 0 && npa6 == 0) {
            emit("error: peer %d has no AllowedIPs, so nothing would ever"
                 " be sent to it\n", i + 1);
            return 2;
        }

        snprintf(phost, sizeof phost, "%s", pr->endpoint);
        pc = strrchr(phost, ':');
        if (pc == NULL) {
            emit("error: peer %d: Endpoint must be host:port\n", i + 1);
            return 2;
        }
        *pc = '\0';
        pport = (uint16_t) atoi(pc + 1);
        if (pport == 0 || wg_endpoint_resolve(&pe, phost, pport) != 0) {
            emit("error: peer %d: cannot resolve '%s'\n", i + 1, phost);
            return 1;
        }

        /*
         * Port 0 for every peer after the first: they each need their
         * own socket, and only one of them can have the configured
         * listen port.
         */
        if (open_tunnel(privkey, pr->public_key,
                        pr->have_preshared_key ? pr->preshared_key : NULL,
                        phost, pport, &pe, 0, pa, npa, pa6, npa6,
                        pr->keepalive) != 0)
            return 1;
    }

    wg_key_to_base64(b64, tunnels[0].client.local.static_public);
    emit("  our public key : %s\n", b64);

    /*
     * Named AllowedIPs rather than "tunnel subnet", because it is both:
     * what gets sent to a peer, and what that peer is permitted to
     * claim as a source.
     */
    {
        int t, k;

        for (t = 0; t < ntunnels; t++) {
            for (k = 0; k < tunnels[t].nallowed; k++) {
                ipv4_format(abuf, sizeof abuf, tunnels[t].allowed[k].net);
                ipv4_format(bbuf, sizeof bbuf, tunnels[t].allowed[k].mask);
                emit("  %-15s: %s mask %s%s%s\n",
                     k == 0 ? "allowed-ips" : "",
                     abuf, bbuf,
                     (k == 0 && ntunnels > 1) ? "  via " : "",
                     (k == 0 && ntunnels > 1) ? tunnels[t].label : "");
            }
            for (k = 0; k < tunnels[t].nallowed6; k++) {
                int first = (k == 0 && tunnels[t].nallowed == 0);
                char n6[48];

                ipv6_format(n6, sizeof n6, tunnels[t].allowed6[k].net);
                emit("  %-15s: %s/%u%s%s\n",
                     first ? "allowed-ips" : "",
                     n6, (unsigned) tunnels[t].allowed6[k].prefix,
                     (first && ntunnels > 1) ? "  via " : "",
                     (first && ntunnels > 1) ? tunnels[t].label : "");
            }
        }
    }
    encap_ready = (encap_local != 0 && encap_remote != 0);
    {
        int any6 = 0, k;

        for (k = 0; k < ntunnels; k++)
            any6 += tunnels[k].nallowed6;

        if (encap_ready) {
            ipv4_format(abuf, sizeof abuf, encap_remote);
            ipv4_format(bbuf, sizeof bbuf, encap_local);
            emit("  ipv6 return    : a configured tunnel, %s -> %s\n",
                 abuf, bbuf);
            if (have_gw_addr6) {
                char g6[46];
                ipv6_format(g6, sizeof g6, gw_addr6);
                emit("  icmpv6 from    : %s\n", g6);
            } else {
                /*
                 * Not fatal, but a large IPv6 flow will stall with
                 * nothing to explain it, so it is said once here
                 * rather than only in the summary afterwards.
                 */
                emit("  icmpv6 from    : nothing. --gateway-ip6 was not"
                     " given, so an\n"
                     "                   oversized IPv6 packet is dropped"
                     " without telling\n"
                     "                   the sender, and large flows will"
                     " stall\n");
            }
        } else if (any6 > 0) {
            /*
             * AllowedIPs names IPv6 prefixes but there is nowhere to
             * put a decrypted IPv6 packet. Said at startup rather than
             * left to be discovered as traffic that goes out and never
             * comes back.
             */
            emit("  ipv6 return    : NOTHING. --encap-local and"
                 " --encap-remote were not\n"
                 "                   given, so inbound IPv6 will be"
                 " dropped. Create a\n"
                 "                   tunnel with iptunnel and name its"
                 " two ends.\n");
        }
    }

    if (use_nat) {
        ipv4_format(abuf, sizeof abuf, tunnel_addr);
        emit("  source NAT to  : %s\n", abuf);
    } else {
        emit("  source NAT     : off\n");
    }
    if (nclients == 0) {
        emit("  forwarding for : any source\n");
    } else {
        for (i = 0; i < nclients; i++) {
            ipv4_format(abuf, sizeof abuf, clients[i].net);
            ipv4_format(bbuf, sizeof bbuf, clients[i].mask);
            emit("  forwarding for : %s mask %s\n", abuf, bbuf);
        }
    }
    for (i = 0; i < nexcludes; i++) {
        ipv4_format(abuf, sizeof abuf, excludes[i].net);
        ipv4_format(bbuf, sizeof bbuf, excludes[i].mask);
        emit("  excluding      : %s mask %s\n", abuf, bbuf);
    }

    /* ---- capture ---- */

    if (resolve_interface(realif, sizeof realif, ifname) != 0) {
        close_tunnels();
        return 1;
    }
    /*
     * Source NAT rewrites every outbound packet to one address and
     * demultiplexes the replies from a single table. With two peers
     * that table cannot say which tunnel a reply came back through, so
     * the restoration would be a guess. Refused rather than guessed.
     *
     * It is also not what multi-peer is for: source NAT exists because
     * a commercial provider accepts only its own assigned address, and
     * a site-to-site link between networks you control does not need
     * it.
     */
    if (use_nat && ntunnels > 1) {
        emit("error: source NAT works with one peer only. This config has"
             " %d.\n"
             "       --tunnel-address rewrites every outbound packet to a"
             " single\n"
             "       address and restores replies from one table, which"
             " cannot say\n"
             "       which tunnel a reply arrived through.\n", ntunnels);
        close_tunnels();
        return 2;
    }

    emit("  capturing on   : %s\n", realif);
    emit("\n");

    errbuf[0] = '\0';
    pc = pcap_open_live(realif, 65535, 1, PCAP_TIMEOUT_MS, errbuf);
    if (pc == NULL) {
        emit("error: pcap_open_live(%s): %s\n", realif, errbuf);
        emit("       packet capture needs privilege\n");
        close_tunnels();
        return 1;
    }
    if (pcap_datalink(pc) != DLT_EN10MB) {
        emit("error: %s is link type %d, not Ethernet\n",
                realif, pcap_datalink(pc));
        pcap_close(pc);
        close_tunnels();
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
        emit("  our address    : %s\n", abuf);
    } else {
        emit("  our address    : unknown, so oversized packets will be\n"
               "                   dropped without an ICMP reply\n");
    }
    emit("  tunnel MTU     : %d\n\n", tunnel_mtu);

    /* ---- injection ---- */

    if (raw_injector_open(&inj) != 0) {
        emit("error: %s\n", raw_injector_error(inj));
        raw_injector_close(inj);
        pcap_close(pc);
        close_tunnels();
        return 1;
    }

    /* ---- handshake ---- */

    /*
     * Every peer, and all of them must come up. A gateway that starts
     * with one of three tunnels working would forward a third of the
     * traffic and drop the rest, which is harder to diagnose than not
     * starting at all.
     */
    for (i = 0; i < ntunnels; i++) {
        emit("handshake with %s\n", tunnels[i].label);
        if (wg_client_handshake(&tunnels[i].client, 3, 5000) != 0) {
            emit("error: %s: %s\n", tunnels[i].label,
                 tunnels[i].client.error);
            raw_injector_close(inj);
            pcap_close(pc);
            close_tunnels();
            return 1;
        }
        if (tunnels[i].client.keepalive_interval_ms > 0)
            emit("  established, keepalive every %lu s\n",
                 (unsigned long)
                 (tunnels[i].client.keepalive_interval_ms / 1000));
        else
            emit("  established\n");
    }
    emit("\n");
    /*
     * A detached process has no terminal to press Ctrl-C at, so saying
     * so in its log is worse than saying nothing — it names the one
     * thing the reader cannot do.
     */
    if (stop_file != NULL)
        emit("forwarding. To stop:  CREATE %s\n\n", stop_file);
    else
        emit("forwarding. Ctrl-Y or Ctrl-C to stop.\n\n");

    /* Armed only now, so that a failure before this point exits without
       printing a summary of a run that never started. */
    (void) signal(SIGINT, on_interrupt);
#ifdef SIGTERM
    (void) signal(SIGTERM, on_interrupt);
#endif
    (void) atexit(print_summary);

    started_ms = wg_time_ms();
    last_status_ms = started_ms;
    last_tick_ms = started_ms;

    /* ---- the loop ---- */

    for (;;) {
        struct pcap_pkthdr *hdr = NULL;
        const unsigned char *frame = NULL;
        uint8_t plain[WG_MAX_PACKET];
        uint8_t natbuf[WG_MAX_PACKET];
        size_t plainlen = 0;
        int rc, t;

        if (stop_requested)
            break;

        /*
         * Both checked on the same tick, once a second at most: neither
         * is urgent, and a stat() plus a clock read for every captured
         * packet would be a real cost on a busy segment.
         */
        {
            uint64_t now = wg_time_ms();

            /*
             * How long the previous pass took. Measured rather than
             * assumed: it is the only evidence that a change made to
             * stop the loop stalling actually stopped it.
             */
            if (last_pass_ms != 0) {
                uint64_t took = now - last_pass_ms;

                if (took > st.max_stall_ms)
                    st.max_stall_ms = (unsigned long) took;
            }
            last_pass_ms = now;

            if (now - last_tick_ms >= 1000) {
                last_tick_ms = now;

                if (stop_requested_by_file()) {
                    emit("%s  stop file seen; shutting down\n", stamp());
                    stopped_by_file = 1;
                    break;
                }
                if (status_interval_ms > 0 &&
                    now - last_status_ms >= status_interval_ms) {
                    last_status_ms = now;
                    log_status(use_nat ? nat_active(&nat, now) : -1);
                }
            }
        }

        /* Outbound: capture, filter, tunnel. */
        rc = pcap_next_ex(pc, &hdr, &frame);
        if (rc == 1) {
            const uint8_t *ip;
            size_t iplen = 0;

            ip = ethip_ipv4((const uint8_t *) frame, hdr->caplen, &iplen);

            /*
             * IPv6 needs no tunnel interface on the way out: a frame
             * from the client is captured like any other, and what
             * leaves is a WireGuard datagram. Only the return direction
             * needs the stack's help.
             */
            if (ip == NULL) {
                const uint8_t *ip6;
                size_t v6len = 0;

                ip6 = ethip_ipv6((const uint8_t *) frame, hdr->caplen,
                                 &v6len);
                if (ip6 != NULL)
                    forward_outbound6(ip6, v6len, clients6, nclients6,
                                      excludes6, nexcludes6, tunnel_mtu,
                                      inj, verbose);
            }

            /*
             * Before any filtering: the OpenVMS stack sees these same
             * forwarded packets and, having no route for them, may
             * answer the sender "destination unreachable" while we are
             * tunnelling the very same packet. The sender believes the
             * ICMP — a TCP connect fails outright rather than waiting
             * for the reply already on its way.
             *
             * Nothing here can stop it: there is no packet filter on
             * this platform that drops by rule, which is the same fact
             * that makes the gateway shape necessary in the first
             * place. What we can do is notice, so this shows up as a
             * known problem with a documented fix rather than as
             * connections that fail for no visible reason.
             *
             * Checked here rather than below because the message is
             * addressed to the client on the local segment, so every
             * filter that follows would discard it.
             */
            if (ip != NULL && have_gw_addr) {
                uint32_t orig_dst = 0;
                uint8_t orig_proto = 0;

                /*
                 * "Is the quoted destination in the tunnel subnet?" is
                 * no test at all under a full tunnel, where every
                 * address is. The question is whether it is a packet we
                 * would actually have tunnelled, which means applying
                 * the same exclusions and client filter the forwarding
                 * path applies — and requiring the complaint to be
                 * addressed to a client we forward for, since a
                 * complaint to anyone else is not about our traffic.
                 *
                 * Without this the first live run reported the stack
                 * telling the LAN router that the OpenVMS box itself
                 * was unreachable, which is an ordinary answer about a
                 * closed local port and nothing whatever to do with the
                 * tunnel.
                 */
                if (icmp_error_from(ip, iplen, gw_addr, &orig_dst,
                                    &orig_proto) &&
                    tunnel_for(orig_dst) >= 0 &&
                    would_tunnel_to(orig_dst, excludes, nexcludes) &&
                    is_a_client(ipv4_dst(ip), clients, nclients)) {
                    st.stack_unreach++;
                    if (verbose) {
                        ipv4_format(abuf, sizeof abuf, ipv4_dst(ip));
                        ipv4_format(bbuf, sizeof bbuf, orig_dst);
                        emit("STACK: told %s that %s is unreachable,"
                               " proto %u — we are tunnelling it\n",
                               abuf, bbuf, (unsigned) orig_proto);
                    }
                }
            }

            /*
             * Never tunnel our own encrypted traffic. With a wide
             * tunnel subnet the outer packets heading to the peer would
             * otherwise match and be re-tunnelled, recursively.
             */
            if (ip != NULL && is_peer_endpoint(ipv4_dst(ip)))
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

            t = (ip != NULL) ? tunnel_for(ipv4_dst(ip)) : -1;
            if (t >= 0) {
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
                                emit("big %lu bytes from %s, told to use"
                                       " %d\n", (unsigned long) iplen,
                                       abuf, tunnel_mtu);
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
                        st.drop_oversize++;
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

                if (wg_client_send(&tunnels[t].client, ip, iplen) == 0) {
                    st.tunnelled++;
                    if (verbose) {
                        ipv4_format(abuf, sizeof abuf, ipv4_src(ip));
                        ipv4_format(bbuf, sizeof bbuf, ipv4_dst(ip));
                        emit("out %s -> %s  proto %u  %lu bytes\n",
                               abuf, bbuf, (unsigned) ipv4_proto(ip),
                               (unsigned long) iplen);
                    }
                } else {
                    st.dropped++;
                    st.drop_send++;
                    if (verbose)
                        log_drop("out", ip, iplen, "tunnel send failed");
                }
            }
after_out:
            ;
        } else if (rc < 0) {
            emit("capture error: %s\n", pcap_geterr(pc));
            break;
        }

        /*
         * Keepalives and rekeying are time-driven, and each tunnel
         * keeps its own clock: an idle one still ages out.
         */
        for (t = 0; t < ntunnels; t++)
            (void) wg_client_tick(&tunnels[t].client);

        /*
         * Inbound, every tunnel. Zero timeout on each, because
         * pcap_next_ex above already did the waiting -- polling them in
         * turn costs a syscall apiece and keeps one busy peer from
         * starving the others.
         */
        for (t = 0; t < ntunnels; t++) {
            rc = wg_client_recv(&tunnels[t].client, plain, sizeof plain,
                                &plainlen, 0);
            if (rc == WG_SOCK_ERROR) {
                emit("%s: tunnel receive error\n", tunnels[t].label);
                goto done;
            }
            if (rc != WG_SOCK_OK || plainlen < IPV4_MIN_HDR)
                continue;
            deliver_inbound(&tunnels[t], plain, plainlen, inj, verbose);
        }
    }
done:

    if (stopped_by_file)
        emit("\nstopped on request");
    else if (stop_requested)
        emit("\ninterrupted");

    /* The summary itself is printed by print_summary, registered with
       atexit above, so that it appears whichever way we leave. */

    raw_injector_close(inj);
    pcap_close(pc);
    close_tunnels();
    return 0;
}
