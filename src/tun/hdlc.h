/*
 * PPP HDLC-like framing (RFC 1662) — vmsguard
 *
 * SLIP turned out to have no driver on OpenVMS x86-64, but PPP does,
 * and TCPIP SET INTERFACE PP0 against a pseudoterminal creates a real
 * interface. PPP needs rather more than SLIP did: HDLC framing with a
 * CRC, then LCP to bring the link up and IPCP to agree addresses,
 * before it will carry IP at all.
 *
 * This is the framing layer. Like slip.c it has no VMS dependency, so
 * it can be tested here rather than on the target.
 *
 * A frame on the wire:
 *
 *     7E | FF | 03 | protocol (2) | information | FCS (2) | 7E
 *
 * with 0x7E and 0x7D escaped as 0x7D followed by the byte XOR 0x20.
 * The FCS is the RFC 1662 16-bit CRC over everything between the
 * flags, before escaping.
 */

#ifndef VMSGUARD_HDLC_H
#define VMSGUARD_HDLC_H

#include <stddef.h>
#include <stdint.h>

#define HDLC_FLAG      0x7E
#define HDLC_ESC       0x7D
#define HDLC_XOR       0x20

#define HDLC_ADDRESS   0xFF   /* "all stations" */
#define HDLC_CONTROL   0x03   /* unnumbered information */

/* PPP protocol numbers we care about. */
#define PPP_PROTO_IP   0x0021
#define PPP_PROTO_IPCP 0x8021
#define PPP_PROTO_LCP  0xC021

/*
 * RFC 1662 leaves the maximum receive unit negotiable; 1500 is the
 * default and the OpenVMS PP0 interface reported an MTU of 1496.
 */
#define HDLC_MRU 1500

/* The FCS of a correctly received frame, including its own FCS. */
#define HDLC_GOOD_FCS 0xF0B8

/* Running FCS-16 over a buffer. Start from 0xFFFF. */
uint16_t hdlc_fcs(uint16_t fcs, const uint8_t *data, size_t len);

/*
 * Build a complete frame: flags, address, control, protocol, the
 * payload, and the FCS, with escaping applied.
 *
 * Worst case output is 2 * (payload + 6) + 2 bytes. Returns bytes
 * written, or 0 if outcap is too small — never a partial frame.
 */
size_t hdlc_encode(uint8_t *out, size_t outcap,
                   uint16_t protocol, const uint8_t *payload, size_t len);

/* Streaming decoder, for bytes arriving from a terminal device. */
struct hdlc_decoder {
    uint8_t  buf[HDLC_MRU + 8];
    size_t   len;
    int      escaped;
    int      overflowed;
    int      complete;
    /* Set when a frame is complete: the protocol field, and the
       payload within buf. */
    uint16_t protocol;
    size_t   payload_off;
    size_t   payload_len;
};

void hdlc_decoder_init(struct hdlc_decoder *d);

/*
 * Feed one byte. Returns 1 when a complete frame with a valid FCS is
 * available, with d->protocol set and the payload at
 * d->buf + d->payload_off for d->payload_len bytes.
 *
 * Frames that are empty, too short, oversized, or fail the FCS check
 * are discarded silently — on a real line these are ordinary events,
 * not errors worth reporting to the caller.
 */
int hdlc_decode_byte(struct hdlc_decoder *d, uint8_t c);

#endif /* VMSGUARD_HDLC_H */
