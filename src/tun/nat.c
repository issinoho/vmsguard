/*
 * Source NAT with connection tracking — vmsguard
 */

#include <string.h>

#include "ethip.h"
#include "nat.h"

#define IPPROTO_ICMP_ 1
#define IPPROTO_TCP_  6
#define IPPROTO_UDP_  17

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0

/* ---- byte access ----------------------------------------------------- */

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t) (v >> 8);
    p[1] = (uint8_t) (v & 0xFF);
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) ((v >> 24) & 0xFF);
    p[1] = (uint8_t) ((v >> 16) & 0xFF);
    p[2] = (uint8_t) ((v >> 8) & 0xFF);
    p[3] = (uint8_t) (v & 0xFF);
}

/* ---- checksums ------------------------------------------------------- */

static uint16_t checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i + 1 < len; i += 2)
        sum += ((uint32_t) data[i] << 8) | data[i + 1];
    if (i < len)
        sum += (uint32_t) data[i] << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t) (~sum & 0xFFFF);
}

/*
 * Incremental checksum update, RFC 1624 equation 3:
 *
 *     HC' = ~(~HC + ~m + m')
 *
 * Used rather than recomputing because a TCP or UDP checksum covers the
 * whole payload plus a pseudo-header built from the addresses. Adjusting
 * for the words that actually changed is both cheaper and independent of
 * how much payload follows.
 */
static uint16_t csum_adjust(uint16_t sum, uint16_t old_word, uint16_t new_word)
{
    uint32_t s = (uint32_t) ((~sum) & 0xFFFF) +
                 (uint32_t) ((~old_word) & 0xFFFF) +
                 (uint32_t) new_word;

    while (s >> 16)
        s = (s & 0xFFFF) + (s >> 16);
    return (uint16_t) (~s & 0xFFFF);
}

/* Adjust for a 32-bit address change, which is two 16-bit words. */
static uint16_t csum_adjust32(uint16_t sum, uint32_t old_val, uint32_t new_val)
{
    sum = csum_adjust(sum, (uint16_t) (old_val >> 16),
                      (uint16_t) (new_val >> 16));
    sum = csum_adjust(sum, (uint16_t) (old_val & 0xFFFF),
                      (uint16_t) (new_val & 0xFFFF));
    return sum;
}

static void ip_checksum_fix(uint8_t *ip, size_t ihl)
{
    uint16_t ck;

    ip[10] = 0;
    ip[11] = 0;
    ck = checksum(ip, ihl);
    put16(ip + 10, ck);
}

/* ---- packet inspection ----------------------------------------------- */

/*
 * Locate the transport header and the fields NAT needs to touch.
 *
 * `id_off` is where the identifier we translate lives — the source or
 * destination port for TCP and UDP, the ICMP identifier for echo.
 * `csum_off` is that protocol's checksum.
 *
 * Returns 0 on success, -1 if the packet is not something we can
 * translate.
 */
struct pkt_view {
    size_t   ihl;
    uint8_t  proto;
    uint8_t *l4;
    size_t   l4len;
    size_t   csum_off;      /* offset within l4 */
    int      csum_covers_addrs;  /* TCP/UDP pseudo-header includes them */
    int      is_icmp_echo;
};

static int inspect(uint8_t *pkt, size_t len, struct pkt_view *v)
{
    size_t total;

    if (len < IPV4_MIN_HDR || (pkt[0] >> 4) != 4)
        return -1;

    v->ihl = (size_t) (pkt[0] & 0x0F) * 4;
    if (v->ihl < IPV4_MIN_HDR || v->ihl > len)
        return -1;

    total = (size_t) get16(pkt + 2);
    if (total > len || total < v->ihl)
        return -1;

    /*
     * A fragment other than the first has no transport header to
     * translate, and NAT cannot reassemble here. Refuse rather than
     * corrupt it.
     */
    if ((get16(pkt + 6) & 0x1FFF) != 0)
        return -1;

    v->proto = pkt[9];
    v->l4 = pkt + v->ihl;
    v->l4len = total - v->ihl;
    v->is_icmp_echo = 0;

    switch (v->proto) {
    case IPPROTO_TCP_:
        if (v->l4len < 20)
            return -1;
        v->csum_off = 16;
        v->csum_covers_addrs = 1;
        return 0;
    case IPPROTO_UDP_:
        if (v->l4len < 8)
            return -1;
        v->csum_off = 6;
        v->csum_covers_addrs = 1;
        return 0;
    case IPPROTO_ICMP_:
        if (v->l4len < 8)
            return -1;
        if (v->l4[0] != ICMP_ECHO_REQUEST && v->l4[0] != ICMP_ECHO_REPLY)
            return -1;   /* errors carry an embedded header; not handled */
        v->csum_off = 2;
        v->csum_covers_addrs = 0;   /* ICMP has no pseudo-header */
        v->is_icmp_echo = 1;
        return 0;
    default:
        return -1;
    }
}

/* ---- table ----------------------------------------------------------- */

void nat_init(struct nat_table *t, uint32_t tunnel_addr)
{
    memset(t, 0, sizeof *t);
    t->tunnel_addr = tunnel_addr;
    t->next_port = 0;
}

static int expired(const struct nat_entry *e, uint64_t now_ms)
{
    return now_ms - e->last_used_ms > NAT_TIMEOUT_MS;
}

int nat_active(const struct nat_table *t, uint64_t now_ms)
{
    int i, n = 0;

    for (i = 0; i < NAT_ENTRIES; i++) {
        if (t->entries[i].used && !expired(&t->entries[i], now_ms))
            n++;
    }
    return n;
}

/* Is this translated identifier already in use for a different flow? */
static int port_taken(const struct nat_table *t, uint8_t proto, uint16_t id,
                      uint64_t now_ms)
{
    int i;

    for (i = 0; i < NAT_ENTRIES; i++) {
        const struct nat_entry *e = &t->entries[i];
        if (e->used && !expired(e, now_ms) &&
            e->proto == proto && e->nat_id == id)
            return 1;
    }
    return 0;
}

static struct nat_entry *find_outbound(struct nat_table *t, uint8_t proto,
                                       uint32_t lan_addr, uint16_t lan_id,
                                       uint32_t peer_addr, uint16_t peer_id,
                                       uint64_t now_ms)
{
    int i;

    for (i = 0; i < NAT_ENTRIES; i++) {
        struct nat_entry *e = &t->entries[i];
        if (e->used && !expired(e, now_ms) &&
            e->proto == proto && e->lan_addr == lan_addr &&
            e->lan_id == lan_id && e->peer_addr == peer_addr &&
            e->peer_id == peer_id)
            return e;
    }
    return NULL;
}

static struct nat_entry *find_inbound(struct nat_table *t, uint8_t proto,
                                      uint16_t nat_id, uint32_t peer_addr,
                                      uint16_t peer_id, uint64_t now_ms)
{
    int i;

    for (i = 0; i < NAT_ENTRIES; i++) {
        struct nat_entry *e = &t->entries[i];
        if (e->used && !expired(e, now_ms) &&
            e->proto == proto && e->nat_id == nat_id &&
            e->peer_addr == peer_addr && e->peer_id == peer_id)
            return e;
    }
    return NULL;
}

/* A free slot, or the least recently used one if none is free. */
static struct nat_entry *claim_slot(struct nat_table *t, uint64_t now_ms)
{
    struct nat_entry *oldest = NULL;
    int i;

    for (i = 0; i < NAT_ENTRIES; i++) {
        struct nat_entry *e = &t->entries[i];
        if (!e->used || expired(e, now_ms))
            return e;
        if (oldest == NULL || e->last_used_ms < oldest->last_used_ms)
            oldest = e;
    }
    return oldest;
}

static int allocate_id(struct nat_table *t, uint8_t proto, uint64_t now_ms,
                       uint16_t *out)
{
    int tries;

    for (tries = 0; tries < NAT_PORT_COUNT; tries++) {
        uint16_t id = (uint16_t) (NAT_PORT_BASE +
                                  (t->next_port % NAT_PORT_COUNT));
        t->next_port = (uint16_t) ((t->next_port + 1) % NAT_PORT_COUNT);
        if (!port_taken(t, proto, id, now_ms)) {
            *out = id;
            return 0;
        }
    }
    return -1;
}

/* ---- translation ----------------------------------------------------- */

int nat_outbound(struct nat_table *t, uint8_t *pkt, size_t len,
                 uint64_t now_ms)
{
    struct pkt_view v;
    struct nat_entry *e;
    uint32_t lan_addr, peer_addr;
    uint16_t lan_id, peer_id, nat_id, csum;

    if (inspect(pkt, len, &v) != 0) {
        t->dropped_unsupported++;
        return -1;
    }

    lan_addr = ipv4_src(pkt);
    peer_addr = ipv4_dst(pkt);

    if (v.is_icmp_echo) {
        lan_id = get16(v.l4 + 4);   /* ICMP identifier */
        peer_id = 0;
    } else {
        lan_id = get16(v.l4);       /* source port */
        peer_id = get16(v.l4 + 2);  /* destination port */
    }

    e = find_outbound(t, v.proto, lan_addr, lan_id, peer_addr, peer_id,
                      now_ms);
    if (e == NULL) {
        if (allocate_id(t, v.proto, now_ms, &nat_id) != 0) {
            t->dropped_table_full++;
            return -1;
        }
        e = claim_slot(t, now_ms);
        if (e == NULL) {
            t->dropped_table_full++;
            return -1;
        }
        e->proto = v.proto;
        e->lan_addr = lan_addr;
        e->lan_id = lan_id;
        e->peer_addr = peer_addr;
        e->peer_id = peer_id;
        e->nat_id = nat_id;
        e->used = 1;
    }
    e->last_used_ms = now_ms;

    /* Transport checksum first, while the old values are still in the
       packet to adjust away from. */
    csum = get16(v.l4 + v.csum_off);

    /*
     * A UDP checksum of zero means the sender did not compute one, and
     * it must stay zero rather than becoming a wrong value.
     */
    if (!(v.proto == IPPROTO_UDP_ && csum == 0)) {
        if (v.csum_covers_addrs)
            csum = csum_adjust32(csum, lan_addr, t->tunnel_addr);
        csum = csum_adjust(csum, e->lan_id, e->nat_id);

        /* Zero is reserved in UDP for "no checksum", so a computed zero
           is transmitted as the equivalent 0xFFFF. */
        if (v.proto == IPPROTO_UDP_ && csum == 0)
            csum = 0xFFFF;
        put16(v.l4 + v.csum_off, csum);
    }

    if (v.is_icmp_echo)
        put16(v.l4 + 4, e->nat_id);
    else
        put16(v.l4, e->nat_id);

    put32(pkt + 12, t->tunnel_addr);
    ip_checksum_fix(pkt, v.ihl);

    t->translated++;
    return 0;
}

int nat_inbound(struct nat_table *t, uint8_t *pkt, size_t len,
                uint64_t now_ms)
{
    struct pkt_view v;
    struct nat_entry *e;
    uint32_t peer_addr;
    uint16_t nat_id, peer_id, csum;

    if (inspect(pkt, len, &v) != 0) {
        t->dropped_unsupported++;
        return -1;
    }

    peer_addr = ipv4_src(pkt);

    if (v.is_icmp_echo) {
        nat_id = get16(v.l4 + 4);
        peer_id = 0;
    } else {
        nat_id = get16(v.l4 + 2);   /* destination port is ours */
        peer_id = get16(v.l4);      /* source port is theirs    */
    }

    e = find_inbound(t, v.proto, nat_id, peer_addr, peer_id, now_ms);
    if (e == NULL) {
        t->dropped_no_mapping++;
        return -1;
    }
    e->last_used_ms = now_ms;

    csum = get16(v.l4 + v.csum_off);

    if (!(v.proto == IPPROTO_UDP_ && csum == 0)) {
        if (v.csum_covers_addrs)
            csum = csum_adjust32(csum, t->tunnel_addr, e->lan_addr);
        csum = csum_adjust(csum, e->nat_id, e->lan_id);
        if (v.proto == IPPROTO_UDP_ && csum == 0)
            csum = 0xFFFF;
        put16(v.l4 + v.csum_off, csum);
    }

    if (v.is_icmp_echo)
        put16(v.l4 + 4, e->lan_id);
    else
        put16(v.l4 + 2, e->lan_id);

    put32(pkt + 16, e->lan_addr);
    ip_checksum_fix(pkt, v.ihl);

    t->restored++;
    return 0;
}
