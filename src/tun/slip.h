/*
 * SLIP framing (RFC 1055) — vmsguard
 *
 * OpenVMS has no TUN device, but it does have SLIP, and SLIP runs over
 * "any standard OpenVMS terminal device" — including, we hope, a
 * pseudo-terminal created with PTD$CREATE. If that holds, a userspace
 * process can hold the master side and act as the far end of a
 * point-to-point IP link, which is functionally what a TUN device
 * provides. See docs/research/slip-tunnel.md.
 *
 * This module is the framing half of that, and is deliberately free of
 * any VMS dependency so it can be tested on Linux.
 *
 * The encoding is simple: END terminates a datagram, and END or ESC
 * appearing in the data are escaped.
 *
 *     END       0xC0    ->  ESC ESC_END
 *     ESC       0xDB    ->  ESC ESC_ESC
 */

#ifndef VMSGUARD_SLIP_H
#define VMSGUARD_SLIP_H

#include <stddef.h>
#include <stdint.h>

#define SLIP_END      0xC0
#define SLIP_ESC      0xDB
#define SLIP_ESC_END  0xDC
#define SLIP_ESC_ESC  0xDD

/*
 * VSI TCP/IP Services accepts and sends at most 1006-byte datagrams on
 * a SLIP line (Management guide, section 3.1.3), so that is the MTU of
 * any tunnel built this way.
 */
#define SLIP_MTU 1006

/*
 * Encode one datagram. Writes a leading END as well as a trailing one:
 * RFC 1055 suggests this so that any line noise before the packet is
 * discarded as an empty frame rather than corrupting it.
 *
 * Worst case output is 2 * inlen + 2 bytes, when every byte needs
 * escaping. Returns the number of bytes written, or 0 if outcap is too
 * small — never a partial frame.
 */
size_t slip_encode(uint8_t *out, size_t outcap,
                   const uint8_t *in, size_t inlen);

/*
 * Streaming decoder, because bytes arrive from a terminal device in
 * arbitrary chunks rather than one datagram at a time.
 */
struct slip_decoder {
    uint8_t buf[SLIP_MTU];
    size_t  len;
    int     escaped;
    int     overflowed;   /* current frame exceeded the MTU */
    int     complete;     /* buf holds a packet the caller may not have
                             consumed yet; cleared on the next call */
};

void slip_decoder_init(struct slip_decoder *d);

/*
 * Feed one byte. Returns 1 when a complete, non-empty datagram is
 * available in d->buf with length d->len; the caller should consume it
 * before feeding more bytes. Returns 0 otherwise.
 *
 * Empty frames — two ENDs in a row, or leading line noise — are
 * silently discarded rather than reported, as are frames that overran
 * the MTU, since a truncated IP packet is worse than a dropped one.
 */
int slip_decode_byte(struct slip_decoder *d, uint8_t c);

#endif /* VMSGUARD_SLIP_H */
