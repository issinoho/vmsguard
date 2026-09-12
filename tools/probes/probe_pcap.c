/*
 * vmsguard probe: libpcap capture and injection
 *
 * TCPIP$LIBPCAP_SHR.EXE ships with VSI TCP/IP Services and the header
 * declares pcap_sendpacket, so capture and injection both appear to be
 * available. This determines whether they actually work, which decides
 * whether the Phase 2 transparent-tunnel architecture is worth pursuing
 * without a kernel driver.
 *
 * This probe does NOT prove a tunnel is feasible even if it passes. pcap
 * observes copies of packets rather than claiming them, so the unsolved
 * problem — suppressing the plaintext original on the outbound path —
 * remains open regardless of the result here. See
 * docs/research/driver-feasibility.md.
 *
 * Injection test uses EtherType 0x88B5, which IEEE reserves for local
 * experimental use, addressed to an all-zero destination. It is inert:
 * nothing on the network is expected to act on it.
 *
 * Usage: probe_pcap [interface [filter]]
 *   With no argument, uses the first non-loopback device pcap reports.
 *   The filter is an ordinary pcap expression, e.g. "host 10.99.0.2".
 *
 * The filter exists to answer a question lengths cannot: a handle
 * opened on a configured tunnel captures the Ethernet's frames, so on
 * a busy segment the first frames to arrive are always the LAN's, and
 * the tunnel's own traffic could be behind thousands of them. A filter
 * naming the tunnel's addresses says whether it is there at all.
 *
 * C99. Build instructions in README.md. Almost certainly needs
 * privileges to open a live capture handle.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * <pcap.h> uses struct timeval in struct pcap_pkthdr without defining
 * it, so it must already be complete by the time pcap.h is read, or
 * VSI C reports %CC-E-INCOMPMEM on the member.
 *
 * Which header supplies it varies: glibc puts it in <sys/time.h>, and
 * on OpenVMS it is reached through the socket headers rather than
 * <time.h>. Including the plausible set is cheaper than being precise,
 * and none of them costs anything here.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#ifndef __VMS
#  include <sys/time.h>
#endif

/*
 * VSI C upcases external names by default, so calls come out as
 * PCAP_OPEN_LIVE and friends. TCPIP$LIBPCAP_SHR is a port of a C
 * library and exports them in their original lower case, so the two do
 * not meet and the link reports every pcap symbol undefined.
 *
 * "#pragma names as_is" around the header keeps the case of everything
 * it declares. The save/restore pair confines that to pcap, leaving
 * the C RTL calls elsewhere in this file on the default setting.
 */
#ifdef __VMS
#  pragma names save
#  pragma names as_is
#endif

#include <pcap.h>

#ifdef __VMS
#  pragma names restore
#endif

/*
 * PCAP_NETMASK_UNKNOWN arrived in libpcap 1.1 and the image on OpenVMS
 * reports 0.9.4, so it cannot be relied on. Zero is what callers passed
 * before it existed and means the same thing to pcap_compile: the mask
 * is only consulted for the "broadcast" keyword, which no filter here
 * uses.
 */
#ifndef PCAP_NETMASK_UNKNOWN
#  define PCAP_NETMASK_UNKNOWN 0
#endif

/*
 * Show the head of a captured frame.
 *
 * Lengths alone cannot say *which interface* a frame came from, and
 * that turned out to matter: opening a configured tunnel by name
 * succeeded and immediately captured frames, on an interface whose
 * packet counters were zero. Either the counters lie or the capture is
 * coming from somewhere else, and the first bytes settle it — a frame
 * off the LAN starts with real MAC addresses and an ethertype, while
 * anything off a tunnel should start with an IP header (0x45 for the
 * usual IPv4, or 0x6x for IPv6).
 */
static void dump_head(const unsigned char *p, unsigned len)
{
    unsigned n = len < 34 ? len : 34;
    unsigned i;

    printf("        ");
    for (i = 0; i < n; i++) {
        printf("%02x", p[i]);
        if ((i % 4) == 3)
            printf(" ");
    }
    printf("\n");

    /*
     * Interpret it both ways rather than assuming which is right: as
     * an Ethernet header, and as a bare IP header.
     */
    if (len >= 14) {
        printf("        as ethernet: dst %02x:%02x:%02x:%02x:%02x:%02x"
               " src %02x:%02x:%02x:%02x:%02x:%02x type %02x%02x\n",
               p[0], p[1], p[2], p[3], p[4], p[5],
               p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13]);
    }
    if (len >= 20 && (p[0] >> 4) == 4) {
        printf("        as bare IPv4: %u.%u.%u.%u -> %u.%u.%u.%u"
               " proto %u\n",
               p[12], p[13], p[14], p[15],
               p[16], p[17], p[18], p[19], p[9]);
    } else if (len >= 40 && (p[0] >> 4) == 6) {
        printf("        as bare IPv6: next header %u\n", p[6]);
    } else {
        printf("        (does not begin with an IP version nibble)\n");
    }
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs = NULL, *d = NULL;
    const char *ifname = NULL;
    pcap_t *h = NULL;
    struct pcap_pkthdr *hdr = NULL;
    const unsigned char *data = NULL;
    unsigned char frame[60];
    const char *filter = NULL;
    struct bpf_program prog;
    int rc;
    int captured = 0;
    int i;

    printf("vmsguard pcap probe\n");
    printf("  library: %s\n\n", pcap_lib_version());

    /* --- enumerate --- */

    errbuf[0] = '\0';
    if (pcap_findalldevs(&devs, errbuf) != 0) {
        printf("  FAIL  pcap_findalldevs: %s\n", errbuf);
        return 1;
    }
    if (devs == NULL) {
        printf("  FAIL  pcap_findalldevs returned no devices\n");
        printf("  note  usually means insufficient privilege\n");
        return 1;
    }

    printf("  devices:\n");
    for (d = devs; d != NULL; d = d->next) {
        printf("    %-12s %s\n", d->name,
               d->description != NULL ? d->description : "");
        if (ifname == NULL && (d->flags & PCAP_IF_LOOPBACK) == 0)
            ifname = d->name;
    }
    printf("\n");

    if (argc > 1)
        ifname = argv[1];
    if (argc > 2)
        filter = argv[2];
    if (ifname == NULL)
        ifname = devs->name;

    /* --- open live --- */

    errbuf[0] = '\0';
    h = pcap_open_live(ifname, 65535, 1 /* promiscuous */, 1000, errbuf);
    if (h == NULL) {
        printf("  FAIL  pcap_open_live(%s): %s\n", ifname, errbuf);
        printf("  note  likely a privilege issue; retry with elevated\n");
        printf("        privileges before concluding it is unsupported\n");
        pcap_freealldevs(devs);
        return 1;
    }
    printf("  ok    pcap_open_live(%s)\n", ifname);
    printf("  note  link type %d (%s)\n", pcap_datalink(h),
           pcap_datalink_val_to_name(pcap_datalink(h)));

    /* --- optional filter --- */

    if (filter != NULL) {
        /*
         * The netmask is only used to decide what "broadcast" means in
         * an expression; none of ours says that, and an unknown mask
         * is the honest value for an interface whose mask we have not
         * asked for.
         */
        /*
         * The cast is for libpcap 0.9.4, whose pcap_compile takes a
         * plain char * — const arrived later. VSI C reports the
         * mismatch as %CC-W-NOTCONSTQUAL, which is a *warning*, and the
         * link then reports %ILINK-W-COMPWARN, which is also a warning:
         * on VMS that combination builds an image and says nothing
         * useful. pcap_compile does not modify the string.
         */
        if (pcap_compile(h, &prog, (char *) filter, 1,
                         PCAP_NETMASK_UNKNOWN) != 0) {
            printf("  FAIL  pcap_compile(%s): %s\n", filter, pcap_geterr(h));
            pcap_close(h);
            pcap_freealldevs(devs);
            return 1;
        }
        if (pcap_setfilter(h, &prog) != 0) {
            printf("  FAIL  pcap_setfilter: %s\n", pcap_geterr(h));
            pcap_freecode(&prog);
            pcap_close(h);
            pcap_freealldevs(devs);
            return 1;
        }
        pcap_freecode(&prog);
        printf("  ok    filter set: %s\n", filter);
    }

    /* --- capture: a few packets, or time out --- */

    for (i = 0; i < 20 && captured < 3; i++) {
        rc = pcap_next_ex(h, &hdr, &data);
        if (rc == 1) {
            captured++;
            printf("  ok    captured frame, %u bytes on the wire\n", hdr->len);
            dump_head(data, hdr->caplen);
        } else if (rc < 0) {
            printf("  FAIL  pcap_next_ex: %s\n", pcap_geterr(h));
            break;
        }
        /* rc == 0 is a timeout; keep trying */
    }
    if (captured == 0) {
        if (filter != NULL)
            printf("  note  no frames matched the filter. On an interface\n"
                   "        known to be carrying matching traffic, that is\n"
                   "        a result: this handle is not capturing it\n");
        else
            printf("  note  no frames captured — the link may simply be"
                   " idle,\n"
                   "        so this is inconclusive rather than a failure\n");
    }

    /* --- injection: the decisive test --- */

    memset(frame, 0, sizeof frame);
    /* dst 00:00:00:00:00:00, src locally-administered, inert ethertype */
    frame[6] = 0x02;
    frame[12] = 0x88;
    frame[13] = 0xB5;
    memcpy(frame + 14, "vmsguard probe", 14);

    if (pcap_sendpacket(h, frame, (int) sizeof frame) == 0) {
        printf("  ok    pcap_sendpacket accepted a %d-byte frame\n",
               (int) sizeof frame);
        printf("\nINJECTION AVAILABLE\n");
    } else {
        printf("  FAIL  pcap_sendpacket: %s\n", pcap_geterr(h));
        printf("\nINJECTION UNAVAILABLE — capture-only\n");
    }

    pcap_close(h);
    pcap_freealldevs(devs);
    return 0;
}
