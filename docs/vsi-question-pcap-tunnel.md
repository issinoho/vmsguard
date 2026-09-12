# A pcap handle opened on a configured tunnel captures the Ethernet

A question for VSI about `TCPIP$LIBPCAP_SHR` on OpenVMS x86-64.

Drafted 2026-09-12. Everything below was observed on the system
described; nothing is inferred from documentation.

## Summary

`pcap_open_live()` on a configured tunnel interface (`ITn`, created by
`iptunnel create`) succeeds, reports link type 1 (EN10MB), and then
delivers frames belonging to the Ethernet interface `IE0` — including
frames whose source MAC address is the Ethernet controller's own, while
the tunnel's own packet counters remain at zero.

The concern is not that tunnel capture is unavailable. It is that the
call **succeeds** and returns another interface's traffic, so a program
cannot tell from any return value that it is not capturing what it
asked for.

There is a second, smaller question about an IPv4 address being
required before libpcap will list or open an interface at all.

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

## Reproducing it

Create a tunnel, bring it up, and give it an IPv4 address:

```
$ iptunnel create 192.0.2.2
IT2  iftype IFT_IPV4 (208) src 192.168.0.80 dst 192.0.2.2

$ ifconfig "IT2" up
$ ifconfig "IT2" 10.99.0.1 10.99.0.2
%TCPIP-I-FSIPADDRUP, IT2 10.99.0.1 primary active on node X86VMS, interface IT2
```

`netstat -i` then shows the tunnel up, addressed, and carrying nothing:

```
Name  Mtu   Network     Address               Ipkts Ierrs    Opkts Oerrs  Coll
IE0   1500  <Link>      aa:00:04:00:01:04  28326389     0  3522363     6     0
IE0   1500  192.168.0   X86VMS             28326389     0  3522363     6     0
IT2   1280  <Link>      x86vms                    0     0        0     0     0
IT2   1280  10          10.99.0.1                 0     0        0     0     0
```

Nothing is routed through `IT2`, and its destination `192.0.2.2` is a
documentation address that is not reachable. The interface is idle by
construction.

### Minimal program

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

## What happens

`pcap_open_live("IT2", ...)` succeeds. `pcap_datalink()` returns 1,
EN10MB. The frames that arrive are Ethernet frames from the LAN:

```
9c31c37a4eb1 aa0004000104 0800 4500006cea42400080068ea7 c0a80050 c0a80001
^ dst        ^ src        ^ IPv4                        ^ src    ^ dst
  router       EIA0's own MAC                             .0.80    .0.1
```

That is the machine's own TCP traffic to 192.168.0.1, captured from the
Ethernet, from a handle opened on `IT2`. Three consecutive frames were
all of this kind, arriving immediately, while `IT2` remained at
`Ipkts 0 Opkts 0`.

Expected instead: either frames belonging to `IT2` — which would be
bare IP, not EN10MB, and of which there would be none on an idle
tunnel — or a failure on open saying that this interface cannot be
captured.

## The smaller question: the IPv4 address requirement

The same program against the same tunnel in other states:

| interface | state | result |
| --- | --- | --- |
| `IT0` | does not exist | `no such device or address` |
| `IT2` | up, no address | `can't assign requested address` |
| `IT1` | up, IPv6 link-local address only | `can't assign requested address` |
| `IT2` | up, 10.99.0.1 | opens (and see above) |

`pcap_findalldevs()` behaves the same way: it lists `IE0` and `LO0`
only, until the tunnel is given an IPv4 address, at which point `IT2`
appears in the list as well.

Is it intended that an interface with only an IPv6 address is invisible
to `pcap_findalldevs()` and cannot be opened? On a dual-stack or
IPv6-only configuration that would leave interfaces uncapturable with
no indication of why, and `can't assign requested address` does not
suggest "this interface has no IPv4 address" to a caller.

## What we have not established

Stated so that nothing here is read as a stronger claim than it is:

- Whether the handle is bound specifically to `EIA0`, or is receiving
  from all LAN devices. This system has exactly one, so the two cannot
  be distinguished here.
- Whether traffic actually routed through `ITn` would also appear on
  such a handle, in addition to the Ethernet's. See below.
- Whether `pcap_sendpacket()` behaves any differently on such a handle.
  It fails on `IE0` with `send: socket is not connected`, and fails
  identically on `IT2`.

## With traffic actually on the tunnel

The first tests were run on an idle tunnel, which invites the obvious
objection: of course nothing of the tunnel's was seen. This run removes
it.

**Result: the tunnel's handle sees none of the tunnel's traffic**, while
the same traffic is demonstrably on the wire at that moment.

The arrangement removes the objections the earlier attempts invited. The
tunnel's remote endpoint is a real, reachable host on the LAN, so the
encapsulated packets must cross the Ethernet. The address pinged,
`10.98.0.5`, is neither this machine's nor the tunnel peer's, so the
stack cannot answer it locally and has to encapsulate and transmit.

```
$ iptunnel create 192.168.0.131
IT3  iftype IFT_IPV4 (208) src 192.168.0.80 dst 192.168.0.131
$ ifconfig "IT3" 10.98.0.1 10.98.0.2 netmask 255.255.255.0 up
```

Two captures, same traffic, differing only in the interface named:

**On `IE0`, filter `ip proto 4`** — the encapsulated packets, captured:

```
4074e05fc300 aa0004000104 0800 45 00 0068 e6f5 4000 ff 04 1278 c0a80050 c0a80083
dst 192.168.0.131's MAC    IPv4  len 104         TTL  proto 4   .0.80 -> .0.131
src EIA0                                              IP-in-IP
```

**On `IT3`, filter `host 10.98.0.5`** — nothing:

```
  ok    pcap_open_live(IT3)
  note  link type 1 (EN10MB)
  ok    filter set: host 10.98.0.5
  note  no frames matched the filter
```

And the interface counters confirm the traffic went through the tunnel:

```
IT3   1280  <Link>      x86vms                    0     0        8     0     0
IT3   1280  10.98.0     10.98.0.1                 0     0        8     0     0
```

Eight packets out of `IT3`, eight encapsulated packets on the Ethernet,
nothing at all from a handle opened on `IT3`.

Note also `tcpdump: Filtering in user process` on setting a filter:
this libpcap filters in the application rather than in the kernel, so
the filter is applied to whatever the handle has already delivered and
cannot be what hides the traffic.

Taken with the earlier result — that an unfiltered handle on a tunnel
delivers frames carrying `EIA0`'s own MAC address — the two together
say the handle is bound to the Ethernet regardless of the interface
named when it was opened.

### Routing into the tunnel — answered, and the answer is the netmask

Included because it explains the failed run above, and because the
behaviour on the way to it looks like something worth knowing.

`ifconfig "IT2" 10.99.0.1 10.99.0.2` configures the addresses and
creates **no route**, which is what made the run above meaningless.
Adding a netmask and `up` in the same command installs the interface
route:

```
$ ifconfig "IT2" 10.99.0.1 10.99.0.2 netmask 255.255.255.0 up

$ netstat -rn
10.99.0/24       10.99.0.1          U           1        0  IT2
10.99.0.1        10.99.0.1          UHL         0        0  IT2
```

The intermediate attempt is the part that may be a defect. With a host
netmask — the natural choice for a point-to-point tunnel — the command
is refused **and the existing address is deleted**:

```
$ ifconfig "IT2" 10.99.0.1 10.99.0.2 netmask 255.255.255.255 up
%TCPIP-I-FSIPADDRDEL, IT2 10.99.0.1 primary address removed from node
host address is zero when ipaddr=10.99.0.1 netmask:255.255.255.255
```

The interface is left with no address at all, rather than with the
configuration it had before the rejected command. A program
reconfiguring an interface cannot treat a failed `ifconfig` as a no-op,
and the message arrives on the terminal rather than as a status.

## Why it matters to us

We are building a WireGuard implementation for OpenVMS. Its working
form is a gateway: it captures LAN traffic with pcap, encrypts it, and
forwards it, and that part works well on x86-64.

The form we cannot build is a client for the OpenVMS machine itself,
which needs to observe what the stack emits on a tunnel interface.
`iptunnel` supplies everything else it needs — we have confirmed that
the stack decapsulates packets injected into `ITn`, acts on them, and
routes the replies — so capture on `ITn` is the single remaining
piece.

Either behaviour would let us proceed:

- **Capture the interface that was asked for.** This is what we would
  build on.
- **Fail on open** for an interface that cannot be captured. Less
  useful, but honest, and we would stop pursuing the approach rather
  than build on a handle that appears to work.

The present behaviour is the one we cannot work with, because a program
cannot detect it. A capture loop receives plausible frames and reports
success while observing a different interface entirely.
