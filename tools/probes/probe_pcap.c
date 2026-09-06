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
 * Usage: probe_pcap [interface]
 *   With no argument, uses the first non-loopback device pcap reports.
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

#include <pcap.h>

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs = NULL, *d = NULL;
    const char *ifname = NULL;
    pcap_t *h = NULL;
    struct pcap_pkthdr *hdr = NULL;
    const unsigned char *data = NULL;
    unsigned char frame[60];
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

    /* --- capture: a few packets, or time out --- */

    for (i = 0; i < 20 && captured < 3; i++) {
        rc = pcap_next_ex(h, &hdr, &data);
        if (rc == 1) {
            captured++;
            printf("  ok    captured frame, %u bytes on the wire\n", hdr->len);
        } else if (rc < 0) {
            printf("  FAIL  pcap_next_ex: %s\n", pcap_geterr(h));
            break;
        }
        /* rc == 0 is a timeout; keep trying */
    }
    if (captured == 0)
        printf("  note  no frames captured — the link may simply be idle,\n"
               "        so this is inconclusive rather than a failure\n");

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
