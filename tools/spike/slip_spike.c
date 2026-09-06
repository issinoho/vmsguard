/*
 * SLIP-over-pseudoterminal spike — vmsguard, OpenVMS only
 *
 * Answers the question that decides whether a transparent tunnel on
 * OpenVMS is reachable in userspace: will SLIP attach to a PTD$-created
 * pseudoterminal?
 *
 * If it will, a SLIP interface backed by this process is functionally a
 * TUN device — the stack gets a real point-to-point interface to route
 * at, and traffic sent to it is *claimed* rather than copied, which is
 * the problem the pcap approach could never solve. See
 * docs/research/slip-tunnel.md.
 *
 * Direction, from I/O User's Reference Manual chapter 6: this program
 * is the "control connection". What the SLIP driver writes to FTAn: we
 * read with PTD$READW; what we write with PTD$WRITE appears to SLIP as
 * if typed at the terminal. Reads are outbound packets, writes inbound.
 *
 * Two things about PTD$ I/O buffers, both from Appendix D and both
 * easy to get wrong:
 *
 *   - readbuf and wrtbuf must lie inside the address range handed to
 *     PTD$CREATE as inadr. A buffer anywhere else — the stack, say —
 *     returns SS$_ACCVIO.
 *
 *   - Those arguments point at an I/O status longword, not at the data.
 *     "The first character position in an I/O buffer to receive all
 *     output is this address plus 4." The status longword follows the
 *     usual IOSB layout, so the low word is a condition value and the
 *     high word the transfer count — which is how the byte count comes
 *     back, there being no separate IOSB argument.
 */

#ifndef __VMS
#error "This spike is OpenVMS-only; it uses the PTD$ control connection routines."
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dvidef.h>
#include <ssdef.h>
#include <starlet.h>

#include "slip.h"

/*
 * PTD$CREATE, PTD$READW, PTD$WRITE and PTD$DELETE are declared in
 * <starlet.h>. For reference, their argument lists:
 *
 *   PTD$CREATE chan [,acmode] [,charbuff] [,bufflen] [,astadr]
 *              [,astprm] [,ast_acmode], inadr
 *   PTD$READW  [efn], chan [,astadr] [,astprm] readbuf, readbuf_len
 *   PTD$WRITE  chan [,astadr] [,astprm] wrtbuf, wrtbuf_len
 *              [,echobuf] [,echobuf_len]
 *   PTD$DELETE chan
 */

/* Pagelets for $EXPREG. Generous: the range must hold both buffers. */
#define IO_PAGES       32

#define IOSB_LEN       4          /* status longword ahead of the data */
#define READ_DATA_MAX  512
#define WRITE_DATA_MAX (2 * SLIP_MTU + 2)

/* ---- helpers --------------------------------------------------------- */

static int vms_ok(unsigned int status, const char *what)
{
    /* VMS condition values indicate success with the low bit set. */
    if (status & 1)
        return 1;
    fprintf(stderr, "%s failed, status = %%X%08X\n", what, status);
    if (status == SS$_ACCVIO)
        fprintf(stderr, "  (SS$_ACCVIO — a PTD$ buffer must lie inside the\n"
                        "   address range given to PTD$CREATE as inadr)\n");
    return 0;
}

static unsigned short inet_checksum(const unsigned char *data, size_t len)
{
    unsigned long sum = 0;
    size_t i;

    for (i = 0; i + 1 < len; i += 2)
        sum += ((unsigned long) data[i] << 8) | (unsigned long) data[i + 1];
    if (i < len)
        sum += (unsigned long) data[i] << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (unsigned short) (~sum & 0xFFFF);
}

static void describe_ip(const unsigned char *p, size_t len)
{
    size_t ihl;

    if (len < 20) {
        printf("    (too short for IPv4)\n");
        return;
    }
    if ((p[0] >> 4) != 4) {
        printf("    (not IPv4: version %u)\n", (unsigned) (p[0] >> 4));
        return;
    }
    ihl = (size_t) (p[0] & 0x0F) * 4;

    printf("    IPv4 %u.%u.%u.%u -> %u.%u.%u.%u  proto %u  total len %u\n",
           p[12], p[13], p[14], p[15], p[16], p[17], p[18], p[19],
           (unsigned) p[9],
           (unsigned) (((unsigned) p[2] << 8) | p[3]));

    if (p[9] == 1 && len >= ihl + 8) {
        unsigned t = p[ihl];
        const char *kind = (t == 8) ? "echo request"
                         : (t == 0) ? "echo reply" : "other";
        printf("    ICMP %s (type %u), id %u seq %u\n", kind, t,
               (unsigned) (((unsigned) p[ihl + 4] << 8) | p[ihl + 5]),
               (unsigned) (((unsigned) p[ihl + 6] << 8) | p[ihl + 7]));
    }
}

static void hexdump(const unsigned char *p, size_t len)
{
    size_t i;

    printf("    ");
    for (i = 0; i < len && i < 48; i++) {
        if (i > 0 && i % 16 == 0)
            printf("\n    ");
        printf("%02x ", p[i]);
    }
    if (len > 48)
        printf("...");
    printf("\n");
}

/* Convert an echo request into a reply in place. Returns 1 if done. */
static int make_echo_reply(unsigned char *pkt, size_t len)
{
    unsigned char tmp[4];
    size_t ihl, icmplen;
    unsigned short ck;

    if (len < 20 || (pkt[0] >> 4) != 4)
        return 0;
    ihl = (size_t) (pkt[0] & 0x0F) * 4;
    if (ihl < 20 || len < ihl + 8 || pkt[9] != 1 || pkt[ihl] != 8)
        return 0;

    memcpy(tmp, pkt + 12, 4);
    memcpy(pkt + 12, pkt + 16, 4);
    memcpy(pkt + 16, tmp, 4);

    pkt[10] = pkt[11] = 0;
    ck = inet_checksum(pkt, ihl);
    pkt[10] = (unsigned char) (ck >> 8);
    pkt[11] = (unsigned char) (ck & 0xFF);

    pkt[ihl] = 0;                       /* echo reply */
    pkt[ihl + 2] = pkt[ihl + 3] = 0;

    icmplen = ((size_t) pkt[2] << 8) | pkt[3];
    if (icmplen > len || icmplen < ihl)
        icmplen = len;
    icmplen -= ihl;

    ck = inet_checksum(pkt + ihl, icmplen);
    pkt[ihl + 2] = (unsigned char) (ck >> 8);
    pkt[ihl + 3] = (unsigned char) (ck & 0xFF);
    return 1;
}

/* ---- main ------------------------------------------------------------ */

int main(int argc, char **argv)
{
    unsigned int inadr[2];
    unsigned int status;
    unsigned short pt_chan = 0;
    char devname[64];
    const char *devshort;
    unsigned short devname_len = 0;
    struct {
        unsigned short  buflen;
        unsigned short  itmcod;
        void           *bufadr;
        unsigned short *retlen;
    } itmlst[2];
    struct slip_decoder dec;
    unsigned char *iobase, *rbuf, *wbuf;
    size_t iolen, needed;
    unsigned long packets = 0, replies = 0, bytes = 0, reads = 0;
    int quiet = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quiet") == 0)
            quiet = 1;
    }

    printf("vmsguard SLIP-over-pseudoterminal spike\n\n");

    /*
     * PTD$CREATE needs a page-aligned address range, and every PTD$ I/O
     * buffer must sit inside it. $EXPREG returns exactly the two-longword
     * start/end format inadr expects.
     */
    status = sys$expreg(IO_PAGES, inadr, 0, 0);
    if (!vms_ok(status, "sys$expreg"))
        return 1;

    iobase = (unsigned char *) inadr[0];
    iolen  = (size_t) (inadr[1] - inadr[0] + 1);

    needed = (IOSB_LEN + READ_DATA_MAX) + (IOSB_LEN + WRITE_DATA_MAX);
    if (iolen < needed) {
        fprintf(stderr, "$EXPREG gave %lu bytes, need %lu; raise IO_PAGES\n",
                (unsigned long) iolen, (unsigned long) needed);
        return 1;
    }

    rbuf = iobase;
    wbuf = iobase + IOSB_LEN + READ_DATA_MAX;

    status = PTD$CREATE(&pt_chan, 0, NULL, 0, NULL, 0, 0, inadr);
    if (!vms_ok(status, "PTD$CREATE")) {
        fprintf(stderr, "\nThis may need privileges. Try from a suitably\n"
                        "privileged account before concluding the driver\n"
                        "is unavailable.\n");
        return 1;
    }

    /* Recover the FTAn: name — that is what TCPIP SET INTERFACE needs. */
    itmlst[0].buflen = (unsigned short) (sizeof devname - 1);
    itmlst[0].itmcod = DVI$_DEVNAM;
    itmlst[0].bufadr = devname;
    itmlst[0].retlen = &devname_len;
    memset(&itmlst[1], 0, sizeof itmlst[1]);

    status = sys$getdviw(0, pt_chan, NULL, itmlst, NULL, NULL, 0, 0);
    if (!vms_ok(status, "sys$getdviw")) {
        PTD$DELETE(pt_chan);
        return 1;
    }
    if (devname_len >= sizeof devname)
        devname_len = sizeof devname - 1;
    devname[devname_len] = '\0';

    /* $GETDVI returns the unambiguous form, with a leading underscore.
       DCL takes it either way, but the plain name reads better. */
    devshort = (devname[0] == '_') ? devname + 1 : devname;

    printf("pseudoterminal created: %s\n", devname);
    printf("I/O buffer range: %%X%08X..%%X%08X (%lu bytes)\n\n",
           inadr[0], inadr[1], (unsigned long) iolen);

    printf("From another session, attach SLIP to it:\n\n");
    printf("  $ TCPIP SET INTERFACE SL0 /HOST=10.9.0.2 -\n");
    printf("        /NETWORK_MASK=255.255.255.0 -\n");
    printf("        /SERIAL_DEVICE=%s\n\n", devshort);
    printf("If accepted, generate traffic from a third session:\n\n");
    printf("  $ TCPIP PING 10.9.0.1\n\n");
    printf("Waiting for data. Ctrl-Y to stop.\n\n");
    fflush(stdout);

    slip_decoder_init(&dec);

    for (;;) {
        unsigned int iosb;
        unsigned int io_status, n;
        unsigned char *data;
        size_t k;

        memset(rbuf, 0, IOSB_LEN);
        status = PTD$READW(0, pt_chan, NULL, 0, rbuf, READ_DATA_MAX);
        if (!vms_ok(status, "PTD$READW"))
            break;

        /* Standard IOSB first longword: condition value in the low
           word, transfer count in the high word. */
        memcpy(&iosb, rbuf, sizeof iosb);
        io_status = iosb & 0xFFFF;
        n         = (iosb >> 16) & 0xFFFF;
        data      = rbuf + IOSB_LEN;
        reads++;

        /* Print the raw status for the first few reads: the layout is
           inferred from the usual IOSB convention rather than stated
           in the manual, so it is worth being able to check it. */
        if (reads <= 3)
            printf("[read %lu: iosb=%%X%08X status=%u count=%u]\n",
                   reads, iosb, io_status, n);

        if (n > READ_DATA_MAX) {
            printf("implausible count %u; the status longword layout is\n"
                   "not what was assumed. Raw iosb = %%X%08X\n", n, iosb);
            break;
        }
        if (n == 0)
            continue;
        bytes += n;

        for (k = 0; k < n; k++) {
            if (!slip_decode_byte(&dec, data[k]))
                continue;

            packets++;
            printf("packet %lu: %lu bytes (after %lu raw bytes)\n",
                   packets, (unsigned long) dec.len, bytes);
            if (!quiet) {
                describe_ip(dec.buf, dec.len);
                hexdump(dec.buf, dec.len);
            }

            if (make_echo_reply(dec.buf, dec.len)) {
                size_t enclen = slip_encode(wbuf + IOSB_LEN, WRITE_DATA_MAX,
                                            dec.buf, dec.len);
                if (enclen > 0) {
                    memset(wbuf, 0, IOSB_LEN);
                    status = PTD$WRITE(pt_chan, NULL, 0, wbuf,
                                       (unsigned int) enclen, NULL, 0);
                    if (status & 1) {
                        replies++;
                        printf("    -> echo reply written (%lu total)\n",
                               replies);
                    } else {
                        printf("    -> PTD$WRITE failed, %%X%08X\n", status);
                    }
                }
            }
            fflush(stdout);
        }
    }

    printf("\n%lu read%s, %lu byte%s, %lu packet%s decoded, %lu repl%s sent\n",
           reads, reads == 1 ? "" : "s",
           bytes, bytes == 1 ? "" : "s",
           packets, packets == 1 ? "" : "s",
           replies, replies == 1 ? "y" : "ies");

    PTD$DELETE(pt_chan);
    return 0;
}
