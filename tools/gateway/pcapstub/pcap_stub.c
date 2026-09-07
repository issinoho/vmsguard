/*
 * A stub libpcap, for running the gateway on a machine that has none.
 *
 * The gateway only ever captures on OpenVMS, so nothing here linked it
 * and nothing here ran it. That left every part of it outside packet
 * handling — argument parsing, config loading, the header it prints —
 * exercised for the first time on a machine three round trips away.
 *
 * It cost one. Values read from a config file were left pointing into a
 * struct that was scrubbed when it went out of scope, so the gateway
 * refused its own config with "--tunnel-subnet '' is not valid CIDR".
 * A syntax check cannot see a lifetime bug; running it can.
 *
 * So: one advertised device, and a capture that declines to open. The
 * gateway gets as far as printing everything it derived from its
 * arguments and then exits, which is exactly the part worth checking
 * here. Anything past pcap_open_live needs a real network and belongs
 * on the target.
 */

#include <stdio.h>
#include <string.h>
#include <sys/time.h>   /* struct timeval, which pcap.h uses and does not define */

#include "pcap.h"

/* Named to match what the OpenVMS box calls its interface, so the test
   drives the same case-folding path a real invocation does. */
static pcap_if_t stub_device = { NULL, (char *) "IE0", NULL, NULL, 0 };

int pcap_findalldevs(pcap_if_t **alldevs, char *errbuf)
{
    (void) errbuf;
    *alldevs = &stub_device;
    return 0;
}

void pcap_freealldevs(pcap_if_t *alldevs)
{
    (void) alldevs;
}

/*
 * Opening succeeds, so the run reaches the rest of the header — "our
 * address" and the tunnel MTU, both worth checking and both printed
 * after this point. It stops instead at the raw socket a moment later,
 * which needs privilege and so declines by itself. Run as root it would
 * get as far as a handshake against an unroutable test address and
 * spend fifteen seconds failing at it, which is slow but not wrong.
 */
static int stub_handle;

pcap_t *pcap_open_live(const char *device, int snaplen, int promisc,
                       int to_ms, char *errbuf)
{
    (void) device; (void) snaplen; (void) promisc; (void) to_ms;
    (void) errbuf;
    return (pcap_t *) &stub_handle;
}

void pcap_close(pcap_t *p) { (void) p; }
int pcap_datalink(pcap_t *p) { (void) p; return DLT_EN10MB; }
char *pcap_geterr(pcap_t *p) { (void) p; return (char *) "stub libpcap"; }

int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **hdr,
                 const unsigned char **data)
{
    (void) p; (void) hdr; (void) data;
    return -1;
}
