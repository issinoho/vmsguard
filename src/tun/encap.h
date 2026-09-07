/*
 * IP-in-IP encapsulation — vmsguard
 *
 * RFC 2003: an IPv4 header wrapped around another packet, with the
 * protocol field saying what is inside. Protocol 4 for IPv4, 41 for
 * IPv6.
 *
 * This exists because of what the OpenVMS stack will and will not do.
 * It will not let a program originate a packet with a source address it
 * does not own, which is what forwarding IPv6 onto the LAN requires,
 * and there is no IPV6_HDRINCL to ask it with. What it *will* do is
 * accept an encapsulated packet addressed to itself, unwrap it, and
 * route the contents as though they had arrived from elsewhere —
 * confirmed on the target, counters and an echo reply both.
 *
 * So an inbound IPv6 packet is wrapped here, injected with the IPv4
 * raw socket that is already proven, and delivered by the stack. See
 * docs/research/driver-feasibility.md.
 *
 * Pure construction over byte buffers, so it is tested rather than
 * merely written.
 */

#ifndef VMSGUARD_ENCAP_H
#define VMSGUARD_ENCAP_H

#include <stddef.h>
#include <stdint.h>

#define ENCAP_PROTO_IPV4 4    /* IPv4 in IPv4, RFC 2003 */
#define ENCAP_PROTO_IPV6 41   /* IPv6 in IPv4, RFC 4213 */

/*
 * Wrap `inner` in an IPv4 header from `src` to `dst`, protocol `proto`.
 *
 * `src` should be the tunnel's remote endpoint and `dst` its local one:
 * the packet has to look like one arriving from the far side, because
 * that is what the stack matches against the tunnel it was told about.
 *
 * `id` goes in the identification field. It should differ between
 * packets — a receiver reassembling fragments keys on it, and repeating
 * one invites two unrelated datagrams being spliced together. Passed in
 * rather than counted here so the caller keeps that decision visible.
 *
 * Returns the total length written, or 0 if it would not fit or the
 * inner packet is implausible.
 */
size_t ip4_encap(uint8_t *out, size_t cap, uint32_t src, uint32_t dst,
                 uint8_t proto, uint16_t id,
                 const uint8_t *inner, size_t innerlen);

#endif /* VMSGUARD_ENCAP_H */
