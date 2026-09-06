/*
 * PPP HDLC-like framing (RFC 1662) — vmsguard
 */

#include <string.h>

#include "hdlc.h"

/*
 * FCS-16 table from RFC 1662, appendix C. The polynomial is x^16 +
 * x^12 + x^5 + 1, used in its reversed form 0x8408.
 */
static const uint16_t fcstab[256] = {
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

uint16_t hdlc_fcs(uint16_t fcs, const uint8_t *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        fcs = (uint16_t) ((fcs >> 8) ^ fcstab[(fcs ^ data[i]) & 0xFF]);
    return fcs;
}

/* Append one byte, escaping it if the framing requires. */
static size_t put_escaped(uint8_t *out, size_t o, size_t outcap, uint8_t c)
{
    if (c == HDLC_FLAG || c == HDLC_ESC) {
        if (o + 2 > outcap)
            return 0;
        out[o++] = HDLC_ESC;
        out[o++] = (uint8_t) (c ^ HDLC_XOR);
    } else {
        if (o + 1 > outcap)
            return 0;
        out[o++] = c;
    }
    return o;
}

size_t hdlc_encode(uint8_t *out, size_t outcap,
                   uint16_t protocol, const uint8_t *payload, size_t len)
{
    uint8_t header[4];
    uint16_t fcs;
    size_t o = 0;
    size_t i;

    /* Worst case: every byte of header, payload and FCS escaped, plus
       two flags. Refuse rather than emit a partial frame. */
    if (outcap < 2 * (len + 6) + 2)
        return 0;

    header[0] = HDLC_ADDRESS;
    header[1] = HDLC_CONTROL;
    header[2] = (uint8_t) (protocol >> 8);
    header[3] = (uint8_t) (protocol & 0xFF);

    fcs = hdlc_fcs(0xFFFF, header, sizeof header);
    fcs = hdlc_fcs(fcs, payload, len);
    fcs ^= 0xFFFF;

    out[o++] = HDLC_FLAG;

    for (i = 0; i < sizeof header; i++) {
        o = put_escaped(out, o, outcap, header[i]);
        if (o == 0)
            return 0;
    }
    for (i = 0; i < len; i++) {
        o = put_escaped(out, o, outcap, payload[i]);
        if (o == 0)
            return 0;
    }

    /* FCS goes out low byte first. */
    o = put_escaped(out, o, outcap, (uint8_t) (fcs & 0xFF));
    if (o == 0)
        return 0;
    o = put_escaped(out, o, outcap, (uint8_t) (fcs >> 8));
    if (o == 0)
        return 0;

    if (o + 1 > outcap)
        return 0;
    out[o++] = HDLC_FLAG;
    return o;
}

void hdlc_decoder_init(struct hdlc_decoder *d)
{
    memset(d, 0, sizeof *d);
}

int hdlc_decode_byte(struct hdlc_decoder *d, uint8_t c)
{
    /* Clear the frame the previous call delivered before accumulating
       anything more. */
    if (d->complete) {
        d->complete = 0;
        d->len = 0;
    }

    if (c == HDLC_FLAG) {
        size_t len = d->len;
        int bad = d->overflowed;

        d->escaped = 0;
        d->overflowed = 0;

        /* Back-to-back flags, or noise: not an error. A valid frame is
           at least address, control, protocol and FCS. */
        if (bad || len < 6) {
            d->len = 0;
            return 0;
        }

        /* A correct frame, FCS included, checksums to a fixed value. */
        if (hdlc_fcs(0xFFFF, d->buf, len) != HDLC_GOOD_FCS) {
            d->len = 0;
            return 0;
        }

        d->protocol    = (uint16_t) (((uint16_t) d->buf[2] << 8) | d->buf[3]);
        d->payload_off = 4;
        d->payload_len = len - 4 - 2;   /* strip header and FCS */
        d->complete    = 1;
        return 1;
    }

    if (d->escaped) {
        d->escaped = 0;
        c = (uint8_t) (c ^ HDLC_XOR);
    } else if (c == HDLC_ESC) {
        d->escaped = 1;
        return 0;
    }

    if (d->len >= sizeof d->buf) {
        d->overflowed = 1;
        return 0;
    }

    d->buf[d->len++] = c;
    return 0;
}
