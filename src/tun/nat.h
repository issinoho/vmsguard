/*
 * Source NAT with connection tracking — vmsguard
 *
 * A commercial VPN provider assigns one tunnel address and their
 * cryptokey routing accepts nothing else as a source. Forwarding a LAN
 * client's packet unchanged means the far end decrypts it, finds a
 * source outside what our key permits, and discards it.
 *
 * So outbound packets are rewritten to appear to come from the assigned
 * address, and replies are translated back. That needs state: a table
 * mapping each translated flow to the client it belongs to.
 *
 * This is ordinary NAPT — the same thing any consumer VPN router does —
 * over TCP, UDP and ICMP echo. Anything else is dropped, since without
 * ports there is nothing to demultiplex replies on.
 *
 * Fragmented datagrams are handled by having later fragments inherit
 * the first fragment's decision; see the fragment tracking below.
 *
 * Pure logic over packet buffers: no allocation, no I/O, no platform
 * dependency, so it is tested on Linux rather than only on OpenVMS.
 */

#ifndef VMSGUARD_NAT_H
#define VMSGUARD_NAT_H

#include <stddef.h>
#include <stdint.h>

/*
 * How many flows can be tracked at once.
 *
 * The table needs to hold one timeout window's worth of flows at the
 * peak rate. A measured run against a provider reached 749 new flows a
 * minute, which at the 30-second UDP timeout is around 375 live — three
 * quarters of the 512 this used to be. That is not a failure, since a
 * full table recycles its least recently used entry rather than
 * refusing anything, but the entry it recycles is by definition the
 * quietest, and the quietest flow is the idle TCP connection someone
 * cares about.
 *
 * 2048 is four times the measured peak requirement.
 *
 * Lookups are through the hash indices below rather than a scan of this
 * array, so the size can grow again without the per-packet cost growing
 * with it.
 */
#define NAT_ENTRIES 2048

/*
 * Hash indices over the entry table.
 *
 * Every packet has to find its mapping, and finding it by walking all
 * NAT_ENTRIES was affordable only because encrypting the same packet
 * costs more. Port allocation was the part that did not stay
 * affordable: allocate_id asks "is this identifier taken?" for each
 * candidate, and answering that by a scan made a new flow cost up to
 * NAT_ENTRIES * NAT_PORT_COUNT comparisons on a full table.
 *
 * Two chains, because the two lookups have different keys:
 *
 *   out — (proto, lan_addr, lan_id, peer_addr, peer_id), the whole
 *         five-tuple as it arrives from the client
 *   in  — (proto, nat_id) alone, deliberately not the full inbound key:
 *         the bucket then holds every mapping using that identifier,
 *         which is exactly the question port allocation asks, and an
 *         inbound lookup filters the same chain on the peer.
 *
 * Chains are singly linked through indices in the entries themselves,
 * so the table stays one flat struct with no allocation — a
 * requirement here, not a preference.
 *
 * An entry's keys never change once it is linked: a mapping's nat_id is
 * fixed at creation and only last_used_ms is touched afterwards. So
 * linking happens at creation and unlinking when a slot is reclaimed,
 * and nothing has to be moved between buckets in between.
 *
 * Power of two so the fold is a mask, and twice NAT_ENTRIES so a full
 * table still averages a chain of two.
 */
#define NAT_BUCKETS 4096
#define NAT_NIL     0xFFFF   /* end of chain; also "not linked" */

/*
 * Ports handed out for translated flows. Above the ephemeral range most
 * systems use, to reduce the chance of colliding with something the
 * OpenVMS box itself originates.
 */
#define NAT_PORT_BASE 40000
#define NAT_PORT_COUNT 20000

/*
 * How long an idle mapping is kept, by protocol.
 *
 * A single timeout for everything was wrong in a way a live run made
 * plain: 856 DNS queries filled all 512 entries, because each query
 * takes a fresh source port and then holds its slot for the full two
 * minutes despite the exchange being over in milliseconds.
 *
 * UDP and ICMP echo are request-and-reply, so a mapping is dead almost
 * as soon as the reply arrives, and 30 seconds is generous. TCP is the
 * one that genuinely needs the long timeout — a connection can sit idle
 * between keystrokes and must still be there afterwards — so it keeps
 * two minutes.
 *
 * This is what consumer NAT routers do, and for the same reason.
 */
#define NAT_TIMEOUT_TCP_MS 120000UL
#define NAT_TIMEOUT_UDP_MS  30000UL

/*
 * Fragment tracking.
 *
 * Only the first fragment of a datagram carries a transport header, so
 * only it can be looked up by port. Later fragments have nothing but an
 * IP header, and the sole thing tying them to their datagram is the
 * identification field.
 *
 * So the first fragment records what its later fragments should have
 * done to them, and they inherit it. A later fragment needs only its
 * address rewritten — the ports live in the first fragment and are
 * translated there, and the transport checksum covers the reassembled
 * whole and is likewise adjusted there.
 *
 * Few datagrams fragment, and those that do are reassembled or
 * discarded within seconds, so the table is small and the timeout
 * short. RFC 791 allows a reassembly timeout as low as 15 seconds;
 * 30 matches what common stacks actually use.
 */
#define NAT_FRAGS            64
#define NAT_FRAG_TIMEOUT_MS  30000UL

/*
 * Fragments that arrive before the first fragment of their datagram.
 *
 * Outbound this cannot happen: one sender emits its fragments in order
 * and pcap hands them over in capture order. Inbound it can, because
 * those fragments crossed the internet inside the tunnel, and UDP
 * datagrams are reordered by real networks routinely.
 *
 * Such a fragment cannot be translated when it arrives — there is no
 * mapping yet — but its first fragment is almost certainly microseconds
 * behind it, so it is held rather than dropped and released once the
 * mapping exists. Four is generous: it is per datagram in flight, not
 * per fragment, and a datagram fragmented into more pieces than that
 * while also arriving out of order is not a case worth carrying memory
 * for.
 */
#define NAT_HELD_MAX 4
#define NAT_HELD_MTU 1600

struct nat_held {
    uint8_t  pkt[NAT_HELD_MTU];
    size_t   len;
    uint64_t held_ms;
    int      used;
};

/* Which address field a later fragment inherits a rewrite of. */
#define NAT_FRAG_SRC 0   /* outbound: source becomes the tunnel address */
#define NAT_FRAG_DST 1   /* inbound: destination becomes the client     */

struct nat_frag {
    uint32_t src;           /* keyed on the addresses as they arrive,   */
    uint32_t dst;           /* before any translation                   */
    uint32_t replacement;   /* what to write into the chosen field      */
    uint16_t ip_id;
    uint8_t  proto;
    uint8_t  field;         /* NAT_FRAG_SRC or NAT_FRAG_DST             */
    uint8_t  used;
    uint64_t last_used_ms;
};

struct nat_entry {
    uint32_t lan_addr;      /* the client's real address        */
    uint32_t peer_addr;     /* the far end                      */
    uint16_t lan_id;        /* client's source port, or ICMP id */
    uint16_t peer_id;       /* far end's port, 0 for ICMP       */
    uint16_t nat_id;        /* what we substitute               */
    uint8_t  proto;
    uint8_t  used;
    uint16_t next_out;      /* chain links, NAT_NIL at the end  */
    uint16_t next_in;
    uint64_t last_used_ms;
};

struct nat_table {
    struct nat_entry entries[NAT_ENTRIES];
    struct nat_frag  frags[NAT_FRAGS];
    struct nat_held  held[NAT_HELD_MAX];
    uint16_t bucket_out[NAT_BUCKETS];
    uint16_t bucket_in[NAT_BUCKETS];
    uint32_t tunnel_addr;   /* the address the provider assigned us */
    uint16_t next_port;
    /* Counters, for reporting. */
    unsigned long translated;   /* packets, not flows */
    unsigned long flows;        /* mappings created: what fills the table */
    unsigned long frags_tracked;
    unsigned long frags_inherited;
    unsigned long restored;
    unsigned long dropped_unsupported;
    unsigned long dropped_no_mapping;
    unsigned long dropped_table_full;
    unsigned long dropped_frag_orphan;
    unsigned long frags_held;      /* set aside to wait for a first */
    unsigned long frags_released;  /* and translated once it arrived */
    /*
     * Mappings recycled while still live, because every entry was in
     * use. Not a drop — the new flow works — but the evicted one is
     * silently broken, which for a quiet TCP connection means it dies
     * with nothing anywhere to say why. Worth watching.
     */
    unsigned long evicted;
    /*
     * Entries examined by a lookup, and lookups made.
     *
     * Here because the index is otherwise untestable: it changes how
     * much work a lookup does and nothing about what it returns, so
     * every test of behaviour passes just as well with the scan back.
     * These two make the work itself observable, and tests/test_nat.c
     * asserts a bound on the ratio that a linear scan cannot meet.
     *
     * They also answer the operational question directly, if the
     * gateway is ever pushed hard enough to ask it.
     */
    unsigned long probes;
    unsigned long lookups;
    /*
     * Chain walks abandoned for running longer than the table is big.
     *
     * That can only happen if a chain has been corrupted into a loop,
     * which is one missing unlink away: relinking an entry that is
     * still in its bucket points it at itself. Deliberately introducing
     * that bug made the test suite hang rather than fail, which is the
     * same thing the gateway would do — detached, on a machine with no
     * debugger to attach, wedging the tunnel with nothing in the log.
     *
     * So every walk is bounded, and a walk that hits the bound gives up
     * and counts it. The mapping is then missed, which costs a packet
     * or a flow; the alternative costs the whole gateway. Non-zero here
     * means a bug in this file, not a network condition.
     */
    unsigned long chain_overruns;
};

/* How long a mapping for this protocol is kept once idle. */
unsigned long nat_timeout_for(uint8_t proto);

/*
 * Why a packet could not be translated.
 *
 * The counters above say how many were refused; these say what any one
 * of them was, which is what a log line needs. A live run refusing two
 * packets an hour tells you nothing useful until it can name them.
 *
 * Negative, so that the existing "non-zero means refused" tests in
 * callers keep working, and so that NAT_DROP_MALFORMED stays -1 — the
 * value the functions returned for every refusal before they could
 * distinguish one from another.
 */
#define NAT_OK                0
#define NAT_DROP_MALFORMED  (-1)   /* truncated, or not IPv4          */
#define NAT_DROP_FRAGMENT   (-2)   /* any fragment of a datagram      */
#define NAT_DROP_PROTOCOL   (-3)   /* not TCP, UDP or ICMP            */
#define NAT_DROP_ICMP_TYPE  (-4)   /* ICMP, but not echo              */
#define NAT_DROP_TABLE_FULL (-5)   /* no free entry, or no free port  */
#define NAT_DROP_NO_MAPPING (-6)   /* inbound, matching nothing       */
#define NAT_DROP_FRAG_ORPHAN (-7)  /* later fragment, first never seen */
#define NAT_HELD             (-8)  /* set aside; not sent, not lost     */

/* A short phrase for a reason code, suitable for a log line. Never
   returns NULL, so it can be used directly in a format string. */
const char *nat_reason(int code);

/* tunnel_addr is in host order, as ipv4_dst returns. */
void nat_init(struct nat_table *t, uint32_t tunnel_addr);

/*
 * Rewrite an outbound packet in place so it appears to originate from
 * the tunnel address, creating or refreshing a mapping.
 *
 * Returns NAT_OK, or one of the negative NAT_DROP_* codes saying why
 * the packet cannot be translated. A rejected packet must not be sent:
 * it would be discarded by the far end anyway, and would leak the
 * client's address in doing so.
 */
int nat_outbound(struct nat_table *t, uint8_t *pkt, size_t len,
                 uint64_t now_ms);

/*
 * Rewrite an inbound packet in place, restoring the original client
 * address and port from the mapping.
 *
 * Returns NAT_OK, or a negative NAT_DROP_* code. NAT_DROP_NO_MAPPING is
 * the normal fate of unsolicited inbound traffic and is not a fault.
 */
int nat_inbound(struct nat_table *t, uint8_t *pkt, size_t len,
                uint64_t now_ms);

/*
 * Take one held fragment that can now be translated, writing it to
 * `out` and returning its length; 0 when there are none.
 *
 * Call it in a loop after any successful nat_inbound, and send whatever
 * it hands back the same way an ordinary translated packet is sent. A
 * caller that never calls it does not lose correctness, only the held
 * fragments, which expire on their own — but the datagram they belong
 * to is then unreassemblable at the far end, so it is worth calling.
 */
size_t nat_take_held(struct nat_table *t, uint8_t *out, size_t cap,
                     uint64_t now_ms);

/* Number of live mappings, for reporting. */
int nat_active(const struct nat_table *t, uint64_t now_ms);

#endif /* VMSGUARD_NAT_H */
