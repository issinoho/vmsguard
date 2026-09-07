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
    int      is_first_frag;      /* offset 0 with More Fragments set     */
    int      is_later_frag;      /* nonzero offset: no transport header  */
};

/*
 * Returns NAT_OK, or the NAT_DROP_* code saying why not. The reason
 * matters as much as the refusal: a run that quietly declines a couple
 * of packets is impossible to explain from a counter alone.
 */
static int inspect(uint8_t *pkt, size_t len, struct pkt_view *v)
{
    size_t total;

    if (len < IPV4_MIN_HDR || (pkt[0] >> 4) != 4)
        return NAT_DROP_MALFORMED;

    v->ihl = (size_t) (pkt[0] & 0x0F) * 4;
    if (v->ihl < IPV4_MIN_HDR || v->ihl > len)
        return NAT_DROP_MALFORMED;

    total = (size_t) get16(pkt + 2);
    if (total > len || total < v->ihl)
        return NAT_DROP_MALFORMED;

    /*
     * Classify the fragment. The 0x2000 bit is More Fragments; the low
     * 13 bits are the offset. DF, at 0x4000, shares the field and must
     * not be mistaken for either.
     *
     * These used to be refused outright, first fragments included,
     * because translating a first fragment while dropping its remainder
     * leaves the far end holding an incomplete datagram. That was the
     * right call while later fragments could not be translated at all.
     * Now they can — by inheriting the first fragment's mapping — so
     * the whole datagram goes through and the reason for refusing the
     * first one has gone with it.
     */
    {
        uint16_t frag = get16(pkt + 6);

        v->is_later_frag = (frag & 0x1FFF) != 0;
        v->is_first_frag = !v->is_later_frag && (frag & 0x2000) != 0;
    }

    v->proto = pkt[9];
    v->l4 = pkt + v->ihl;
    v->l4len = total - v->ihl;
    v->is_icmp_echo = 0;

    /*
     * A later fragment has no transport header at all — not a truncated
     * one, none — so there is nothing here to parse and no protocol
     * check to make. It is translated by inheriting its datagram's
     * mapping instead. Note that v->l4 is meaningless in this case and
     * callers must branch before touching it.
     */
    if (v->is_later_frag)
        return NAT_OK;

    switch (v->proto) {
    case IPPROTO_TCP_:
        if (v->l4len < 20)
            return NAT_DROP_MALFORMED;
        v->csum_off = 16;
        v->csum_covers_addrs = 1;
        return NAT_OK;
    case IPPROTO_UDP_:
        if (v->l4len < 8)
            return NAT_DROP_MALFORMED;
        v->csum_off = 6;
        v->csum_covers_addrs = 1;
        return NAT_OK;
    case IPPROTO_ICMP_:
        if (v->l4len < 8)
            return NAT_DROP_MALFORMED;
        if (v->l4[0] != ICMP_ECHO_REQUEST && v->l4[0] != ICMP_ECHO_REPLY)
            return NAT_DROP_ICMP_TYPE;   /* errors carry an embedded
                                            header; not handled */
        v->csum_off = 2;
        v->csum_covers_addrs = 0;   /* ICMP has no pseudo-header */
        v->is_icmp_echo = 1;
        return NAT_OK;
    default:
        return NAT_DROP_PROTOCOL;
    }
}

const char *nat_reason(int code)
{
    switch (code) {
    case NAT_OK:                return "translated";
    case NAT_DROP_MALFORMED:    return "malformed header";
    case NAT_DROP_FRAGMENT:     return "fragment";
    case NAT_DROP_PROTOCOL:     return "unsupported protocol";
    case NAT_DROP_ICMP_TYPE:    return "ICMP, but not echo";
    case NAT_DROP_TABLE_FULL:   return "NAT table full";
    case NAT_DROP_NO_MAPPING:   return "no matching mapping";
    case NAT_DROP_FRAG_ORPHAN:  return "later fragment, first one never seen";
    case NAT_HELD:              return "held, waiting for its first fragment";
    default:                    return "unknown";
    }
}

/* ---- table ----------------------------------------------------------- */

void nat_init(struct nat_table *t, uint32_t tunnel_addr)
{
    memset(t, 0, sizeof *t);
    t->tunnel_addr = tunnel_addr;
    t->next_port = 0;
}

unsigned long nat_timeout_for(uint8_t proto)
{
    return (proto == IPPROTO_TCP_) ? NAT_TIMEOUT_TCP_MS
                                   : NAT_TIMEOUT_UDP_MS;
}

static int expired(const struct nat_entry *e, uint64_t now_ms)
{
    return now_ms - e->last_used_ms > nat_timeout_for(e->proto);
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

    /*
     * Every entry is live, so the least recently used is recycled and
     * whatever flow owned it stops working. Preferable to refusing the
     * new flow, but it is a real loss and used to happen invisibly:
     * count it so the summary can say it happened.
     */
    t->evicted++;
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

/* ---- fragment tracking ------------------------------------------------ */


static int frag_expired(const struct nat_frag *f, uint64_t now_ms)
{
    return now_ms - f->last_used_ms > NAT_FRAG_TIMEOUT_MS;
}

static struct nat_frag *frag_find(struct nat_table *t, uint32_t src,
                                  uint32_t dst, uint8_t proto, uint16_t id,
                                  uint64_t now_ms)
{
    int i;

    for (i = 0; i < NAT_FRAGS; i++) {
        struct nat_frag *f = &t->frags[i];
        if (f->used && !frag_expired(f, now_ms) &&
            f->src == src && f->dst == dst &&
            f->proto == proto && f->ip_id == id)
            return f;
    }
    return NULL;
}

/*
 * Record what this datagram's later fragments should inherit.
 *
 * Returns 0, or -1 if there is no room. The caller must treat that as a
 * refusal of the *first* fragment rather than forwarding it anyway: the
 * remainder would arrive with nothing to match against and be dropped,
 * which is the incomplete-datagram problem all over again.
 */
static int frag_remember(struct nat_table *t, uint32_t src, uint32_t dst,
                         uint8_t proto, uint16_t id, uint32_t replacement,
                         uint8_t field, uint64_t now_ms)
{
    struct nat_frag *f = frag_find(t, src, dst, proto, id, now_ms);
    int fresh = 0;
    int i;

    if (f == NULL) {
        for (i = 0; i < NAT_FRAGS; i++) {
            if (!t->frags[i].used || frag_expired(&t->frags[i], now_ms)) {
                f = &t->frags[i];
                fresh = 1;
                break;
            }
        }
    }
    if (f == NULL)
        return -1;

    f->src = src;
    f->dst = dst;
    f->proto = proto;
    f->ip_id = id;
    f->replacement = replacement;
    f->field = field;
    f->used = 1;
    f->last_used_ms = now_ms;
    if (fresh)
        t->frags_tracked++;
    return 0;
}

/*
 * Set a fragment aside until its first fragment turns up.
 *
 * Returns 0 if it was held. Failure means there is no room, and the
 * caller should treat it as the drop it would otherwise have been:
 * holding is an improvement on dropping, never a requirement.
 */
static int frag_hold(struct nat_table *t, const uint8_t *pkt, size_t len,
                     uint64_t now_ms)
{
    int i;

    if (len > NAT_HELD_MTU)
        return -1;

    for (i = 0; i < NAT_HELD_MAX; i++) {
        struct nat_held *h = &t->held[i];

        /* A slot whose fragment has waited longer than a receiver would
           spend reassembling is free: that datagram is lost either way. */
        if (h->used && now_ms - h->held_ms > NAT_FRAG_TIMEOUT_MS) {
            h->used = 0;
            t->dropped_frag_orphan++;
        }
        if (!h->used) {
            memcpy(h->pkt, pkt, len);
            h->len = len;
            h->held_ms = now_ms;
            h->used = 1;
            t->frags_held++;
            return 0;
        }
    }
    return -1;
}

/*
 * Translate a later fragment: rewrite the one address its datagram's
 * first fragment established, and fix the IP header checksum. There is
 * no transport header here and so no transport checksum to touch — that
 * one covers the reassembled datagram and was adjusted on the first
 * fragment.
 */
static int translate_later_fragment(struct nat_table *t, uint8_t *pkt,
                                    size_t len, const struct pkt_view *v,
                                    uint64_t now_ms, int may_hold)
{
    struct nat_frag *f;

    f = frag_find(t, ipv4_src(pkt), ipv4_dst(pkt), v->proto,
                  get16(pkt + 4), now_ms);
    if (f == NULL) {
        /*
         * Either the first fragment was refused, in which case nothing
         * will ever make this translatable, or it has not arrived yet.
         * The two are indistinguishable here, so inbound the fragment
         * is held for a moment on the chance that it is the second: a
         * datagram reordered inside the tunnel is common enough, and
         * dropping this would cost the whole datagram.
         */
        if (may_hold && frag_hold(t, pkt, len, now_ms) == 0)
            return NAT_HELD;

        t->dropped_frag_orphan++;
        return NAT_DROP_FRAG_ORPHAN;
    }
    f->last_used_ms = now_ms;

    put32(pkt + (f->field == NAT_FRAG_SRC ? 12 : 16), f->replacement);
    ip_checksum_fix(pkt, v->ihl);

    t->frags_inherited++;
    return NAT_OK;
}

/* ---- translation ----------------------------------------------------- */

int nat_outbound(struct nat_table *t, uint8_t *pkt, size_t len,
                 uint64_t now_ms)
{
    struct pkt_view v;
    struct nat_entry *e;
    uint32_t lan_addr, peer_addr;
    uint16_t lan_id, peer_id, nat_id, csum;
    int rc;

    rc = inspect(pkt, len, &v);
    if (rc != NAT_OK) {
        t->dropped_unsupported++;
        return rc;
    }

    if (v.is_later_frag) {
        /*
         * Never held outbound. One sender emits its fragments in order
         * and pcap delivers them in capture order, so a later fragment
         * with no mapping means the first was refused — waiting for it
         * would be waiting for something that is not coming.
         */
        rc = translate_later_fragment(t, pkt, len, &v, now_ms, 0);
        if (rc == NAT_OK)
            t->translated++;
        return rc;
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
            return NAT_DROP_TABLE_FULL;
        }
        e = claim_slot(t, now_ms);
        if (e == NULL) {
            t->dropped_table_full++;
            return NAT_DROP_TABLE_FULL;
        }
        e->proto = v.proto;
        e->lan_addr = lan_addr;
        e->lan_id = lan_id;
        e->peer_addr = peer_addr;
        e->peer_id = peer_id;
        e->nat_id = nat_id;
        e->used = 1;
        t->flows++;
    }
    e->last_used_ms = now_ms;

    /*
     * Note what the later fragments must inherit, before the packet is
     * touched — so that running out of room refuses the datagram rather
     * than emitting a translated first fragment its remainder can never
     * follow.
     */
    if (v.is_first_frag &&
        frag_remember(t, lan_addr, peer_addr, v.proto, get16(pkt + 4),
                      t->tunnel_addr, NAT_FRAG_SRC, now_ms) != 0) {
        t->dropped_table_full++;
        return NAT_DROP_TABLE_FULL;
    }

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
    return NAT_OK;
}

int nat_inbound(struct nat_table *t, uint8_t *pkt, size_t len,
                uint64_t now_ms)
{
    struct pkt_view v;
    struct nat_entry *e;
    uint32_t peer_addr;
    uint16_t nat_id, peer_id, csum;
    int rc;

    rc = inspect(pkt, len, &v);
    if (rc != NAT_OK) {
        t->dropped_unsupported++;
        return rc;
    }

    if (v.is_later_frag) {
        rc = translate_later_fragment(t, pkt, len, &v, now_ms, 1);
        if (rc == NAT_OK)
            t->restored++;
        return rc;
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
        return NAT_DROP_NO_MAPPING;
    }
    e->last_used_ms = now_ms;

    /* As outbound: recorded against the addresses as they arrived, and
       before the packet is modified. */
    if (v.is_first_frag &&
        frag_remember(t, peer_addr, ipv4_dst(pkt), v.proto, get16(pkt + 4),
                      e->lan_addr, NAT_FRAG_DST, now_ms) != 0) {
        t->dropped_table_full++;
        return NAT_DROP_TABLE_FULL;
    }

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
    return NAT_OK;
}

size_t nat_take_held(struct nat_table *t, uint8_t *out, size_t cap,
                     uint64_t now_ms)
{
    int i;

    for (i = 0; i < NAT_HELD_MAX; i++) {
        struct nat_held *h = &t->held[i];
        struct pkt_view v;

        if (!h->used)
            continue;

        if (now_ms - h->held_ms > NAT_FRAG_TIMEOUT_MS) {
            h->used = 0;
            t->dropped_frag_orphan++;
            continue;
        }
        if (h->len > cap)
            continue;

        /*
         * Re-inspected rather than trusted: it was a valid later
         * fragment when it went in, but reading it back through the
         * same check is cheaper than proving that stays true.
         */
        if (inspect(h->pkt, h->len, &v) != NAT_OK || !v.is_later_frag) {
            h->used = 0;
            t->dropped_frag_orphan++;
            continue;
        }

        /* may_hold is 0: a held fragment must not be held again, or a
           full buffer would shuffle rather than drain. */
        if (translate_later_fragment(t, h->pkt, h->len, &v, now_ms, 0)
            != NAT_OK)
            continue;   /* still no mapping; leave it to wait or expire */

        memcpy(out, h->pkt, h->len);
        h->used = 0;
        t->frags_released++;
        t->restored++;
        return h->len;
    }
    return 0;
}
