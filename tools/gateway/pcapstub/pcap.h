/*
 * A stub <pcap.h> — vmsguard
 *
 * Not for linking. It exists so gateway.c can be compiled for its
 * diagnostics on a machine with no libpcap headers installed, which is
 * the normal case here and was the case on the development host.
 *
 * The gateway only ever *runs* on OpenVMS, so without this the file was
 * never put through -std=c99 -pedantic -Wall -Wextra at all, and a
 * missing semicolon cost a round trip to a machine we cannot reach.
 * That is the most expensive way to find one.
 *
 * It declares exactly what gateway.c uses and nothing else. Because it
 * is only ever a syntax check, drift from the real header is harmless:
 * anything that matters shows up when the OpenVMS build compiles
 * against the genuine article. If libpcap's headers are installed,
 * compile against those instead — put their include path first.
 */

#ifndef VMSGUARD_STUB_PCAP_H
#define VMSGUARD_STUB_PCAP_H

#define PCAP_ERRBUF_SIZE 256
#define DLT_EN10MB       1

typedef struct pcap pcap_t;

struct pcap_pkthdr {
    struct timeval ts;
    unsigned int   caplen;
    unsigned int   len;
};

typedef struct pcap_if {
    struct pcap_if *next;
    char           *name;
    char           *description;
    void           *addresses;
    unsigned int    flags;
} pcap_if_t;

int      pcap_findalldevs(pcap_if_t **alldevs, char *errbuf);
void     pcap_freealldevs(pcap_if_t *alldevs);
pcap_t  *pcap_open_live(const char *device, int snaplen, int promisc,
                        int to_ms, char *errbuf);
void     pcap_close(pcap_t *p);
int      pcap_datalink(pcap_t *p);
char    *pcap_geterr(pcap_t *p);
int      pcap_next_ex(pcap_t *p, struct pcap_pkthdr **hdr,
                      const unsigned char **data);

/*
 * Used by tools/probes/probe_pcap.c rather than by the gateway. They
 * are declared here so that probe can be syntax-checked on Linux too:
 * it is built only on OpenVMS, so without these every change to it
 * went to the target unchecked, and one duly arrived with an
 * unbuildable line in it.
 */
#define PCAP_IF_LOOPBACK 0x00000001
const char *pcap_lib_version(void);
const char *pcap_datalink_val_to_name(int dlt);
int         pcap_sendpacket(pcap_t *p, const unsigned char *buf, int size);

#endif /* VMSGUARD_STUB_PCAP_H */
