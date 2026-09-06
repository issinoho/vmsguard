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
 * Pure logic over packet buffers: no allocation, no I/O, no platform
 * dependency, so it is tested on Linux rather than only on OpenVMS.
 */

#ifndef VMSGUARD_NAT_H
#define VMSGUARD_NAT_H

#include <stddef.h>
#include <stdint.h>

/* Enough for a small site; the table is scanned linearly. */
#define NAT_ENTRIES 512

/*
 * Ports handed out for translated flows. Above the ephemeral range most
 * systems use, to reduce the chance of colliding with something the
 * OpenVMS box itself originates.
 */
#define NAT_PORT_BASE 40000
#define NAT_PORT_COUNT 20000

/* How long an idle mapping is kept. Long enough for a quiet TCP
   connection to resume, short enough that the table recycles. */
#define NAT_TIMEOUT_MS 120000UL

struct nat_entry {
    uint32_t lan_addr;      /* the client's real address        */
    uint32_t peer_addr;     /* the far end                      */
    uint16_t lan_id;        /* client's source port, or ICMP id */
    uint16_t peer_id;       /* far end's port, 0 for ICMP       */
    uint16_t nat_id;        /* what we substitute               */
    uint8_t  proto;
    uint8_t  used;
    uint64_t last_used_ms;
};

struct nat_table {
    struct nat_entry entries[NAT_ENTRIES];
    uint32_t tunnel_addr;   /* the address the provider assigned us */
    uint16_t next_port;
    /* Counters, for reporting. */
    unsigned long translated;
    unsigned long restored;
    unsigned long dropped_unsupported;
    unsigned long dropped_no_mapping;
    unsigned long dropped_table_full;
};

/* tunnel_addr is in host order, as ipv4_dst returns. */
void nat_init(struct nat_table *t, uint32_t tunnel_addr);

/*
 * Rewrite an outbound packet in place so it appears to originate from
 * the tunnel address, creating or refreshing a mapping.
 *
 * Returns 0 on success, -1 if the packet cannot be translated — an
 * unsupported protocol, a malformed header, or a full table. A rejected
 * packet must not be sent: it would be discarded by the far end anyway,
 * and would leak the client's address in doing so.
 */
int nat_outbound(struct nat_table *t, uint8_t *pkt, size_t len,
                 uint64_t now_ms);

/*
 * Rewrite an inbound packet in place, restoring the original client
 * address and port from the mapping.
 *
 * Returns 0 on success, -1 if no mapping matches, which is the normal
 * fate of unsolicited inbound traffic.
 */
int nat_inbound(struct nat_table *t, uint8_t *pkt, size_t len,
                uint64_t now_ms);

/* Number of live mappings, for reporting. */
int nat_active(const struct nat_table *t, uint64_t now_ms);

#endif /* VMSGUARD_NAT_H */
