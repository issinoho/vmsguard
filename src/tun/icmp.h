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

/* ---- recognising the stack's own contradictions ---------------------- */

#define ICMP_TYPE_TIME_EXCEEDED  11

/*
 * Destination-unreachable codes.
 *
 * Only some of these mean "I could not route this". Port and protocol
 * unreachable are a host answering about *itself* and are perfectly
 * ordinary; fragmentation-needed is the message this gateway generates
 * on purpose, and reporting our own as the stack contradicting us would
 * be worse than saying nothing.
 */
#define ICMP_CODE_NET_UNREACH      0
#define ICMP_CODE_HOST_UNREACH     1
#define ICMP_CODE_PROTO_UNREACH    2
#define ICMP_CODE_PORT_UNREACH     3
#define ICMP_CODE_NET_UNKNOWN      6
#define ICMP_CODE_HOST_UNKNOWN     7

/*
 * Whether `pkt` is an ICMP error message sent *by* `from_addr`, and if
 * so what it was complaining about.
 *
 * The gateway needs this because OpenVMS has no packet filter that can
 * drop by rule, so the stack sees the same forwarded packets we capture
 * and, finding no route for them, may answer the sender with
 * "destination unreachable" while we are quietly tunnelling the very
 * same packet. The sender is then told two contradictory things, and
 * the ICMP usually wins: a TCP connect fails outright rather than
 * waiting for the reply that is on its way.
 *
 * Nothing here can stop the stack doing it. What this makes possible is
 * seeing it happen, which is the difference between a puzzling
 * intermittent failure and a known one with a documented fix.
 *
 * An ICMP error quotes the header of the packet it is about, so the
 * destination the sender was trying to reach is recoverable — that is
 * what makes the detection precise rather than a guess based on seeing
 * any ICMP at all. orig_dst and orig_proto are filled in from that
 * quoted header; either pointer may be NULL.
 *
 * Only errors that mean a *routing* failure count: net and host
 * unreachable, net and host unknown, and time exceeded. Port and
 * protocol unreachable are the host answering about itself and are
 * normal. Fragmentation-needed is excluded above all, because this
 * gateway generates those itself and captures its own injected packets
 * — reporting them would turn a working feature into a warning.
 *
 * The caller must still decide whether the quoted destination is one it
 * would have tunnelled. That cannot be answered here: with a full
 * tunnel every address is nominally in the tunnel subnet, and only the
 * caller knows its exclusions.
 *
 * Returns 1 if this is such an error, 0 otherwise.
 */
int icmp_error_from(const uint8_t *pkt, size_t len, uint32_t from_addr,
                    uint32_t *orig_dst, uint8_t *orig_proto);

/* ---- ICMPv6 ---------------------------------------------------------- */

/*
 * IPv6's equivalents, which are not quite a rename of the above.
 *
 * Two differences matter. A router may not fragment an IPv6 packet at
 * all, so where IPv4 has "fragmentation needed" as advice IPv6 has
 * "packet too big" as the only way the transfer can proceed: without it
 * a large flow does not degrade, it stops. And every ICMPv6 checksum
 * covers a pseudo-header of the addresses, the payload length and the
 * next-header value, so it cannot be computed from the message alone
 * the way ICMPv4's can -- which is why these take the addresses even
 * where the message itself does not need them.
 */

#define ICMP6_TYPE_PACKET_TOO_BIG   2
#define ICMP6_TYPE_ECHO_REQUEST   128
#define ICMP6_TYPE_ECHO_REPLY     129

#define IPV6_NEXT_ICMPV6 58

/*
 * The ICMPv6 checksum over `msg`, with the pseudo-header RFC 4443
 * section 2.3 requires: 16-byte source and destination, the message
 * length as 32 bits, and the next-header value.
 *
 * Exposed rather than kept private because the responder converts an
 * echo request in place and needs the same sum over a buffer it already
 * holds.
 */
uint16_t icmp6_checksum(const uint8_t *src, const uint8_t *dst,
                        const uint8_t *msg, size_t msglen);

/*
 * Build an ICMPv6 echo request inside an IPv6 packet, from `src` to
 * `dst`. Returns the total length written, or 0 if outcap is too small.
 */
size_t icmp6_echo_request(uint8_t *out, size_t outcap,
                          const uint8_t *src, const uint8_t *dst,
                          uint16_t id, uint16_t seq);

/*
 * Whether `pkt` is an ICMPv6 echo reply carrying this id and sequence.
 */
int icmp6_is_echo_reply(const uint8_t *pkt, size_t len,
                        uint16_t id, uint16_t seq);

/*
 * Turn an ICMPv6 echo request into a reply in place: swap the
 * addresses, change the type, recompute the checksum. Returns 1 if it
 * was converted, 0 if it was not an echo request.
 */
int icmp6_make_echo_reply(uint8_t *pkt, size_t len);

/*
 * Build an ICMPv6 Packet Too Big about `orig`, addressed back to
 * whoever sent it, from `src_addr` -- the gateway's own address, since
 * it is the hop that could not forward.
 *
 * `mtu` is the largest packet that would have fitted. RFC 4443 asks
 * that as much of the original be quoted as fits in 1280 bytes without
 * exceeding the minimum IPv6 MTU, so that the error itself never needs
 * fragmenting.
 *
 * Returns the length written, or 0 if outcap is too small or the
 * original is not a usable IPv6 packet.
 */
size_t icmp6_packet_too_big(uint8_t *out, size_t outcap,
                            const uint8_t *src_addr,
                            const uint8_t *orig, size_t origlen,
                            uint32_t mtu);

#endif /* VMSGUARD_ICMP_H */
