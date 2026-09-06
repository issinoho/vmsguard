/*
 * ICMP error generation — vmsguard
 *
 * A tunnel carries less than the LAN it forwards for: every packet
 * gains 60 bytes of WireGuard, UDP and outer IP headers. A client
 * sending 1500 bytes produces 1560 on the wire, which the path to the
 * peer will not carry.
 *
 * Silently dropping those is the worst outcome — small requests succeed
 * and large transfers hang, with nothing to explain why. The remedy is
 * the one routers have always used: reply with ICMP "fragmentation
 * needed", carrying the MTU that would have worked, and let the
 * sender's path-MTU discovery adjust.
 *
 * Pure construction over byte buffers, so it is tested rather than
 * merely written.
 */

#ifndef VMSGUARD_ICMP_H
#define VMSGUARD_ICMP_H

#include <stddef.h>
#include <stdint.h>

#define ICMP_TYPE_DEST_UNREACH   3
#define ICMP_CODE_FRAG_NEEDED    4

/* The IP flag meaning the sender forbids fragmentation. */
#define IPV4_FLAG_DF 0x4000

/*
 * Build an ICMP fragmentation-needed message about `orig`, addressed
 * back to whoever sent it.
 *
 * `src_addr` is the address the message should appear to come from —
 * the gateway's own, since it is the hop that could not forward.
 * `next_mtu` is the largest packet that would have fitted, which is
 * what RFC 1191 path-MTU discovery reads.
 *
 * The quoted original is its IP header plus the first 8 bytes that
 * follow, which is enough for the sender to identify the connection.
 *
 * Returns the length written, or 0 if outcap is too small or the
 * original is unusable.
 */
size_t icmp_frag_needed(uint8_t *out, size_t outcap, uint32_t src_addr,
                        const uint8_t *orig, size_t origlen,
                        uint16_t next_mtu);

/* Whether a packet forbids fragmentation. */
int ipv4_dont_fragment(const uint8_t *pkt, size_t len);

#endif /* VMSGUARD_ICMP_H */
