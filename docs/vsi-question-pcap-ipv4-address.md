# libpcap does not see an interface that has no IPv4 address

A question for VSI about `TCPIP$LIBPCAP_SHR` on OpenVMS x86-64.

Drafted 2026-09-12. Everything below was observed on the system
described; nothing is inferred from documentation.

## Summary

An interface with no IPv4 address — including one carrying only an IPv6
address — is absent from `pcap_findalldevs()` and cannot be opened by
name. `pcap_open_live()` fails with `can't assign requested address`,
which does not suggest the cause.

Giving the same interface an IPv4 address makes it both appear in the
device list and open successfully.

Is that intended? On a dual-stack or IPv6-only configuration it leaves
interfaces uncapturable with nothing to say why.

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

The same program against configured tunnel interfaces (`iptunnel
create`) in four states:

| interface | state | `pcap_open_live()` |
| --- | --- | --- |
| `IT0` | does not exist | `no such device or address` |
| `IT2` | up, no address | `can't assign requested address` |
| `IT1` | up, IPv6 link-local address only | `can't assign requested address` |
| `IT2` | addressed `10.99.0.1` | succeeds |

`pcap_findalldevs()` tracks the same condition. Before the address is
assigned it lists two devices:

```
  devices:
    IE0
    LO0
```

After `ifconfig "IT2" 10.99.0.1 10.99.0.2`, the same call lists three:

```
  devices:
    IE0
    IT2
    LO0
```

Being `UP` is not part of it. An interface that is down but addressed
still opens, and still appears.

`IT1` is the interesting row: it is up and has an address — a link-local
IPv6 address, `fe80::c2a8:ff:fe50:0` — and is treated exactly like an
interface with no address at all.

## Why the error matters as much as the behaviour

If this is intended, the diagnostic is still misleading.
`can't assign requested address` is `EADDRNOTAVAIL`, which a caller
reads as a problem with an address it supplied — but `pcap_open_live()`
takes no address, and the caller supplied only an interface name. There
is nothing in the message to suggest "this interface has no IPv4
address", which is what we eventually established by elimination.

An error naming the actual condition would have saved that work, and
would save it for anyone capturing on an IPv6-only interface.

## Minimal program

```c
#include <stdio.h>
#include <pcap.h>

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs, *d;
    pcap_t *h;

    if (pcap_findalldevs(&devs, errbuf) == 0) {
        for (d = devs; d != NULL; d = d->next)
            printf("device: %s\n", d->name);
    }

    h = pcap_open_live(argv[1], 65535, 1, 1000, errbuf);
    if (h == NULL) {
        printf("pcap_open_live(%s): %s\n", argv[1], errbuf);
        return 1;
    }
    printf("open %s, link type %d\n", argv[1], pcap_datalink(h));
    pcap_close(h);
    return 0;
}
```

On OpenVMS the pcap declarations need `#pragma names as_is` around the
`#include <pcap.h>`, since the shareable image exports them in lower
case.

## What we have not established

- Whether a LAN device with only an IPv6 address behaves the same way.
  The interfaces tested here are configured tunnels, because that is
  what we had that could be given one address family and not the other.
- Whether any of this differs on Alpha or IA-64. Everything here is
  x86-64.

## Related

A separate report covers what happens once such an interface does open:
the handle delivers the Ethernet's frames rather than the interface's.
See [`vsi-question-pcap-tunnel.md`](vsi-question-pcap-tunnel.md).
