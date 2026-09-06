/*
 * Raw-socket IPv4 injection — vmsguard
 *
 * The write half of the gateway. Decrypted packets coming out of the
 * tunnel are put back on the local network with SOCK_RAW and
 * IP_HDRINCL, so the IP header we already hold is transmitted as-is
 * and the stack routes on it.
 *
 * pcap would have been the obvious counterpart to capture, but its
 * pcap_sendpacket is non-functional on OpenVMS ("socket is not
 * connected"). Raw sockets are the better choice anyway: injection at
 * layer 3 needs no Ethernet framing, no destination MAC and no ARP,
 * because the destination is an ordinary host the stack already knows
 * how to reach.
 *
 * Confirmed on OpenVMS: SOCK_RAW opens. The Sockets API manual says
 * this needs SYSPRV.
 */

#ifndef VMSGUARD_RAWINJECT_H
#define VMSGUARD_RAWINJECT_H

#include <stddef.h>
#include <stdint.h>

struct raw_injector;

/*
 * Open a raw socket for injecting complete IPv4 packets. Returns 0 on
 * success, -1 on failure — most often a privilege problem.
 */
int raw_injector_open(struct raw_injector **inj);

void raw_injector_close(struct raw_injector *inj);

/*
 * Transmit one complete IPv4 packet, header included. The destination
 * is taken from the packet's own header, so the caller does not supply
 * one separately.
 *
 * Returns 0 on success, -1 on failure.
 */
int raw_injector_send(struct raw_injector *inj,
                      const uint8_t *packet, size_t len);

/* Last error as text, for reporting. Never NULL. */
const char *raw_injector_error(const struct raw_injector *inj);

#endif /* VMSGUARD_RAWINJECT_H */
