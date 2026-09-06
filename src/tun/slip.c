/*
 * SLIP framing (RFC 1055) — vmsguard
 */

#include <string.h>

#include "slip.h"

size_t slip_encode(uint8_t *out, size_t outcap,
                   const uint8_t *in, size_t inlen)
{
    size_t o = 0;
    size_t i;

    /* Refuse rather than truncate: a half-written frame would be
       decoded as a corrupt packet at the far end. */
    if (outcap < 2 * inlen + 2)
        return 0;

    out[o++] = SLIP_END;

    for (i = 0; i < inlen; i++) {
        switch (in[i]) {
        case SLIP_END:
            out[o++] = SLIP_ESC;
            out[o++] = SLIP_ESC_END;
            break;
        case SLIP_ESC:
            out[o++] = SLIP_ESC;
            out[o++] = SLIP_ESC_ESC;
            break;
        default:
            out[o++] = in[i];
            break;
        }
    }

    out[o++] = SLIP_END;
    return o;
}

void slip_decoder_init(struct slip_decoder *d)
{
    memset(d, 0, sizeof *d);
}

int slip_decode_byte(struct slip_decoder *d, uint8_t c)
{
    /*
     * The previous call delivered a packet, which the caller has now
     * had its chance to consume. Clear it before accumulating anything
     * further — otherwise the delivered bytes stay in the buffer, the
     * next END reports them a second time, and the following datagram
     * is appended to them.
     */
    if (d->complete) {
        d->complete = 0;
        d->len = 0;
    }

    if (c == SLIP_END) {
        int overflowed = d->overflowed;
        size_t len = d->len;

        d->escaped = 0;
        d->overflowed = 0;

        /* An empty frame is the leading END of the next datagram, or
           noise before one. Neither is an error. */
        if (len == 0 || overflowed) {
            d->len = 0;
            return 0;
        }

        d->complete = 1;
        return 1;
    }

    if (d->escaped) {
        d->escaped = 0;
        /*
         * RFC 1055 leaves the meaning of any other byte after ESC
         * undefined. Treating it as a literal is the conventional
         * choice and keeps a single corrupted byte from discarding an
         * otherwise intact packet.
         */
        if (c == SLIP_ESC_END)
            c = SLIP_END;
        else if (c == SLIP_ESC_ESC)
            c = SLIP_ESC;
    } else if (c == SLIP_ESC) {
        d->escaped = 1;
        return 0;
    }

    if (d->len >= sizeof d->buf) {
        /* Remember the overrun so the whole frame is dropped at the
           next END, rather than delivering a truncated IP packet. */
        d->overflowed = 1;
        return 0;
    }

    d->buf[d->len++] = c;
    return 0;
}
