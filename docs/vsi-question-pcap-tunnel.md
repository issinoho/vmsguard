# A pcap handle opened on a configured tunnel captures the Ethernet

A question for VSI about `TCPIP$LIBPCAP_SHR` on OpenVMS x86-64.

Drafted 2026-09-12. Everything below was observed on the system
described; nothing is inferred from documentation.

## Summary

`pcap_open_live()` on a configured tunnel interface (`ITn`, created by
`iptunnel create`) succeeds and reports link type 1 (EN10MB). The
handle then delivers the **Ethernet interface's** frames, and none of
the tunnel's, while the tunnel is demonstrably carrying traffic.

The concern is not that tunnel capture is unavailable. It is that the
call **succeeds** and returns a different interface's traffic, so a
program has no way to detect that it is not capturing what it asked
for.

Two smaller matters found alongside this one are reported separately,
since neither depends on it:
[`vsi-question-pcap-ipv4-address.md`](vsi-question-pcap-ipv4-address.md)
and [`vsi-question-ifconfig-netmask.md`](vsi-question-ifconfig-netmask.md).

## Environment

| | |
| --- | --- |
| Operating system | VSI OpenVMS x86-64 V9.2-3 |
| libpcap | `pcap_lib_version()` reports `libpcap version 0.9.4` |
| Shareable image | `TCPIP$LIBPCAP_SHR` |
| LAN device | `EIA0`, `i82540 KVM`, 1 Gb full duplex |
| TCP/IP interface | `IE0`, 192.168.0.80/24 |

The test program runs with privileges sufficient to open a live capture
on `IE0`, which works correctly.

## The observation

A tunnel to a real, reachable host on the LAN, so that its encapsulated
packets must cross the Ethernet:

```
$ iptunnel create 192.168.0.131
IT3  iftype IFT_IPV4 (208) src 192.168.0.80 dst 192.168.0.131

$ ifconfig "IT3" 10.98.0.1 10.98.0.2 netmask 255.255.255.0 up

$ netstat -rn
10.98.0/24       10.98.0.1          U           1        0  IT3
10.98.0.1        10.98.0.1          UHL         0        0  IT3
```

Traffic is then sent through it with `ping 10.98.0.5` — an address that
is neither this machine's nor the tunnel peer's, so the stack cannot
answer it locally and has to encapsulate and transmit.

Two capture handles, differing only in the interface named, running
against that same traffic.

**On `IE0`, filter `ip proto 4`.** The encapsulated packets, captured:

```
4074e05fc300 aa0004000104 0800 45 00 0068 e6f5 4000 ff 04 1278 c0a80050 c0a80083
dst 192.168.0.131's MAC    IPv4  len 104         TTL  proto 4   .0.80 -> .0.131
src EIA0                                              IP-in-IP
```

**On `IT3`, filter `host 10.98.0.5`.** Nothing:

```
  ok    pcap_open_live(IT3)
  note  link type 1 (EN10MB)
  ok    filter set: host 10.98.0.5
  note  no frames matched the filter
```

**And the interface counters show the traffic went through the tunnel:**

```
IT3   1280  <Link>      x86vms                    0     0        8     0     0
IT3   1280  10.98.0     10.98.0.1                 0     0        8     0     0
```

Eight packets out of `IT3`, eight encapsulated packets on the Ethernet
at the same moment, and nothing at all from a handle opened on `IT3`.

Note `tcpdump: Filtering in user process`, printed when a filter is
set: this libpcap filters in the application rather than in the kernel,
so the filter is applied to whatever the handle has already delivered
and cannot be what hid the traffic.

### The same handle, unfiltered, delivers the Ethernet's frames

The complementary observation, on an earlier tunnel. With no filter
set, a handle opened on `IT2` returned three frames immediately, of
which the first was:

```
9c31c37a4eb1 aa0004000104 0800 4500006cea42400080068ea7 c0a80050 c0a80001
^ dst          ^ src        ^ IPv4                        ^ src    ^ dst
  router         EIA0's own MAC                             .0.80    .0.1
```

The source MAC address is `EIA0`'s own hardware address and the IP
addresses are the LAN's — this is the machine's own TCP traffic to its
router. `IT2` was at `Ipkts 0 Opkts 0` throughout, with nothing routed
through it.

A tunnel interface cannot emit a frame bearing the Ethernet
controller's MAC address. Taken with the filtered result above, the two
say the handle is bound to the Ethernet regardless of which interface
was named when it was opened.

## Minimal program

```c
#include <stdio.h>
#include <pcap.h>

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *hdr;
    const unsigned char *data;
    pcap_t *h;
    int i, rc;

    h = pcap_open_live(argv[1], 65535, 1, 1000, errbuf);
    if (h == NULL) {
        printf("pcap_open_live(%s): %s\n", argv[1], errbuf);
        return 1;
    }
    printf("open %s, link type %d\n", argv[1], pcap_datalink(h));

    for (i = 0; i < 20; i++) {
        rc = pcap_next_ex(h, &hdr, &data);
        if (rc == 1) {
            unsigned j;
            printf("%u bytes:", hdr->len);
            for (j = 0; j < 20 && j < hdr->caplen; j++)
                printf(" %02x", data[j]);
            printf("\n");
        }
    }
    pcap_close(h);
    return 0;
}
```

On OpenVMS the pcap declarations need `#pragma names as_is` around the
`#include <pcap.h>`, since the shareable image exports them in lower
case.

## What would resolve it

Either behaviour would be workable:

- **Capture the interface that was asked for.**
- **Fail on open** for an interface that cannot be captured.

The present behaviour is the one that cannot be worked with, because a
program cannot detect it: a capture loop receives plausible frames and
reports success while observing a different interface entirely.

## What we have not established

Stated so that nothing above is read as a stronger claim than it is:

- Whether the handle is bound specifically to `EIA0`, or is receiving
  from all LAN devices. This system has exactly one, so the two cannot
  be distinguished here.
- Whether `pcap_sendpacket()` behaves differently on such a handle. It
  fails on `IE0` with `send: socket is not connected`, and fails
  identically on a tunnel handle.
- Whether any of this differs on Alpha or IA-64. Everything here is
  x86-64.

## Why it matters to us

We are building a WireGuard implementation for OpenVMS. Its working
form is a gateway: it captures LAN traffic with pcap, encrypts it, and
forwards it, and that part works well on x86-64.

The form we cannot build is a client for the OpenVMS machine itself,
which needs to observe what the stack emits on a tunnel interface.
`iptunnel` supplies everything else it needs — we have confirmed that
the stack decapsulates packets injected into `ITn` and acts on them,
and that it encapsulates and transmits what is routed into `ITn` — so
capture on `ITn` is the single remaining piece.
