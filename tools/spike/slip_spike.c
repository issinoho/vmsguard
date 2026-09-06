/*
 * SLIP-over-pseudoterminal spike — vmsguard, OpenVMS only
 *
 * Answers the one question that decides whether a transparent tunnel on
 * OpenVMS is achievable in userspace: will SLIP attach to a
 * PTD$-created pseudoterminal?
 *
 * If it does, a SLIP interface backed by this process is functionally a
 * TUN device — the stack gets a real point-to-point interface to route
 * at, and traffic sent to it is *claimed* rather than copied, which is
 * the problem the pcap approach could never solve. See
 * docs/research/slip-tunnel.md.
 *
 * What it does:
 *   1. Creates a pseudoterminal and reports its FTAn: device name.
 *   2. Waits while you attach SLIP to that device from another session.
 *   3. Reads what the SLIP driver writes, decodes the framing, and
 *      reports the IP packets it finds.
 *   4. Answers ICMP echo requests, so a successful ping proves both
 *      directions.
 *
 * UNTESTED — written from the I/O User's Reference Manual, Appendix D,
 * and never run. Expect to iterate.
 *
 * Direction, from chapter 6: this program is the "control connection".
 * What the SLIP driver writes to FTAn: we read with PTD$READW; what we
 * write with PTD$WRITE appears to SLIP as if typed at the terminal. So
 * reads are outbound packets, writes are inbound ones.
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
 * The PTD$ routines have no header. Declared from the manual:
 *
 *   PTD$CREATE chan [,acmode] [,charbuff] [,bufflen] [,astadr]
 *              [,astprm] [,ast_acmode], inadr
 *   PTD$READW  [efn], chan [,astadr] [,astprm] readbuf, readbuf_len
 *   PTD$WRITE  chan [,astadr] [,astprm] wrtbuf, wrtbuf_len
 *              [,echobuf] [,echobuf_len]
 *   PTD$DELETE chan
 *
 * Uppercase, because the linker symbols are uppercase and VSI C does
 * not necessarily upcase external names.
 */
extern unsigned int PTD$CREATE(unsigned short *chan, unsigned int acmode,
                               void *charbuff, unsigned short bufflen,
                               void *astadr, unsigned int astprm,
                               unsigned int ast_acmode, unsigned int *inadr);
extern unsigned int PTD$READW(unsigned int efn, unsigned short chan,
                              void *astadr, unsigned int astprm,
                              void *readbuf, unsigned int readbuf_len);
extern unsigned int PTD$WRITE(unsigned short chan, void *astadr,
                              unsigned int astprm,
                              void *wrtbuf, unsigned int wrtbuf_len,
                              void *echobuf, unsigned int echobuf_len);
extern unsigned int PTD$DELETE(unsigned short chan);

#define IO_PAGES 4

/* ---- helpers --------------------------------------------------------- */

static int vms_ok(unsigned int status, const char *what)
{
    /* VMS condition values indicate success with the low bit set. */
    if (status & 1)
        return 1;
    fprintf(stderr, "%s failed, status = %%X%08X\n", what, status);
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
    unsigned short devname_len = 0;
    struct {
        unsigned short  buflen;
        unsigned short  itmcod;
        void           *bufadr;
        unsigned short *retlen;
    } itmlst[2];
    struct slip_decoder dec;
    unsigned char encbuf[2 * SLIP_MTU + 2];
    unsigned char c;
    unsigned long packets = 0, replies = 0, bytes = 0;
    int quiet = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quiet") == 0)
            quiet = 1;
    }

    printf("vmsguard SLIP-over-pseudoterminal spike\n\n");

    /*
     * PTD$CREATE requires a page-aligned address range for its I/O
     * buffers. $EXPREG returns precisely that format: a two-longword
     * array holding the start and end addresses of newly created pages.
     */
    status = sys$expreg(IO_PAGES, inadr, 0, 0);
    if (!vms_ok(status, "sys$expreg"))
        return 1;

    status = PTD$CREATE(&pt_chan, 0, NULL, 0, NULL, 0, 0, inadr);
    if (!vms_ok(status, "PTD$CREATE")) {
        fprintf(stderr, "\nThis may need privileges. Try from a suitably\n"
                        "privileged account before concluding the driver\n"
                        "is unavailable.\n");
        return 1;
    }

    /* Recover the FTAn: name from the channel — that is what has to be
       handed to TCPIP SET INTERFACE. */
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

    printf("pseudoterminal created: %s\n\n", devname);
    printf("From another session, attach SLIP to it:\n\n");
    printf("  $ TCPIP SET INTERFACE SL0 /HOST=10.9.0.2 -\n");
    printf("        /NETWORK_MASK=255.255.255.0 -\n");
    printf("        /SERIAL_DEVICE=%s\n\n", devname);
    printf("If accepted, generate traffic from a third session:\n\n");
    printf("  $ TCPIP PING 10.9.0.1\n\n");
    printf("Waiting for data. Ctrl-Y to stop.\n\n");
    fflush(stdout);

    slip_decoder_init(&dec);

    /*
     * One byte per read, deliberately.
     *
     * PTD$READ and PTD$READW take six arguments and no IOSB, and the
     * manual does not say how the byte count is reported — only that a
     * read completes with at least one character and at most
     * readbuf_len. Asking for exactly one byte makes the count
     * unambiguous without depending on undocumented behaviour.
     *
     * This is a system call per byte, which is fine for a spike whose
     * job is to answer a yes/no question, and is worth revisiting if
     * this becomes the basis of a real interface.
     *
     * Caveat: the manual notes a rare case where a read completes with
     * zero bytes. That is indistinguishable from reading a genuine
     * 0x00, so an occasional spurious zero could corrupt a frame. It
     * would show up as a malformed IP header in the output rather than
     * passing silently.
     */
    for (;;) {
        c = 0;
        status = PTD$READW(0, pt_chan, NULL, 0, &c, 1);
        if (!vms_ok(status, "PTD$READW"))
            break;
        bytes++;

        if (!slip_decode_byte(&dec, c))
            continue;

        packets++;
        printf("packet %lu: %lu bytes (after %lu raw bytes)\n",
               packets, (unsigned long) dec.len, bytes);
        if (!quiet) {
            describe_ip(dec.buf, dec.len);
            hexdump(dec.buf, dec.len);
        }

        if (make_echo_reply(dec.buf, dec.len)) {
            size_t enclen = slip_encode(encbuf, sizeof encbuf,
                                        dec.buf, dec.len);
            if (enclen > 0) {
                status = PTD$WRITE(pt_chan, NULL, 0, encbuf,
                                   (unsigned int) enclen, NULL, 0);
                if (status & 1) {
                    replies++;
                    printf("    -> echo reply written (%lu total)\n", replies);
                } else {
                    printf("    -> PTD$WRITE failed, %%X%08X\n", status);
                }
            }
        }
        fflush(stdout);
    }

    printf("\n%lu byte%s read, %lu packet%s decoded, %lu repl%s sent\n",
           bytes, bytes == 1 ? "" : "s",
           packets, packets == 1 ? "" : "s",
           replies, replies == 1 ? "y" : "ies");

    PTD$DELETE(pt_chan);
    return 0;
}
