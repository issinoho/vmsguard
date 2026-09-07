/*
 * Ethernet and IPv4 header inspection — vmsguard
 *
 * The gateway captures Ethernet frames with pcap and has to decide,
 * for each one, whether it is an IPv4 packet this host should tunnel.
 * That decision is pure arithmetic over a byte buffer, so it lives here
 * where it can be tested on any platform, rather than inside the pcap
 * loop where it could only be exercised on OpenVMS.
 *
 * Nothing here allocates or does I/O.
 */

#ifndef VMSGUARD_ETHIP_H
#define VMSGUARD_ETHIP_H

#include <stddef.h>
#include <stdint.h>

#define ETH_HDR_LEN     14
#define ETH_TYPE_IPV4   0x0800

#define IPV4_MIN_HDR    20

/*
 * Locate the IPv4 packet inside an Ethernet frame.
 *
 * Returns a pointer to the start of the IP header and writes its length
 * to iplen, or NULL if the frame is not IPv4, is truncated, or carries
 * an IP header that disagrees with the captured length.
 *
 * The returned length is the IP total length, which may be shorter than
 * the captured frame: Ethernet pads small frames, and that padding must
 * not be tunnelled as though it were part of the packet.
 */
const uint8_t *ethip_ipv4(const uint8_t *frame, size_t framelen,
                          size_t *iplen);

/* Source and destination addresses, in network order. Both assume a
   packet already validated by ethip_ipv4. */
uint32_t ipv4_src(const uint8_t *ip);
uint32_t ipv4_dst(const uint8_t *ip);

/* Protocol byte, e.g. 1 for ICMP, 6 TCP, 17 UDP. */
uint8_t ipv4_proto(const uint8_t *ip);

/*
 * Whether an address falls inside a subnet. All three arguments are in
 * network order, as ipv4_dst returns and ethip_parse_cidr produces.
 */
int ipv4_in_subnet(uint32_t addr, uint32_t network, uint32_t mask);

/*
 * A list of subnets, and whether an address falls in any of them.
 *
 * WireGuard's AllowedIPs is a list, and so are the gateway's --client
 * and --exclude. All three were being walked by hand, in near-identical
 * loops, none of them tested. An empty list matches nothing, which is
 * the right answer for "is this address permitted" and the reason
 * callers that mean "no restriction" have to say so themselves.
 */
struct ipv4_subnet {
    uint32_t net;
    uint32_t mask;
};

int ipv4_in_any(const struct ipv4_subnet *list, int n, uint32_t addr);

/*
 * The most specific subnet in the list that contains `addr`.
 *
 * Returns 1 and writes that entry's mask to *mask, or 0 if none
 * matches. Longest prefix wins, which is what a routing table does and
 * what WireGuard does to choose a peer: a peer holding 10.9.0.0/24 must
 * take that traffic even when another holds 0.0.0.0/0.
 *
 * A longer prefix is a numerically larger mask, so the comparison is
 * just `>`. That is only true because masks are contiguous, which
 * ethip_parse_cidr guarantees by construction.
 */
int ipv4_best_match(const struct ipv4_subnet *list, int n, uint32_t addr,
                    uint32_t *mask);

/*
 * Parse "10.9.0.0/24" into a network address and mask, both in network
 * order. A missing prefix length is treated as /32.
 *
 * Returns 0 on success, -1 if the text is not a valid CIDR block. The
 * network address is masked, so "10.9.0.5/24" yields 10.9.0.0.
 */
int ethip_parse_cidr(const char *text, uint32_t *network, uint32_t *mask);

/* Format an address as dotted quad. out needs 16 bytes. */
void ipv4_format(char *out, size_t cap, uint32_t addr);

#endif /* VMSGUARD_ETHIP_H */
