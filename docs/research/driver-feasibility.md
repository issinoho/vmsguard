# Kernel driver / virtual NIC feasibility (tracking document)

## Status: not started — this is a feasibility investigation, not committed work

> **`slip-tunnel.md` is now closed.** SLIP has no driver on OpenVMS
> x86-64, and PPP — which does have one — requires a modem-controlled
> dialup line that a `PTD$` pseudoterminal cannot provide. The
> serial-line route to a virtual interface is ruled out, which makes the
> material below the live option again.

Per the project plan, the MVP (Phase 1) does not require a kernel-mode
virtual network interface: it proves out WireGuard protocol/crypto
correctness against a real peer using plain UDP sockets, without needing to
carry real routed IP traffic. This document tracks the *separate* question
of how vmsguard could eventually present itself as a transparent OS-level
network interface, the way WireGuard does via TUN on Linux.

## Why this is hard on OpenVMS

- **Confirmed 2026-09-06**: there is no TUN/TAP device. The C RTL header
  library on the target system contains no `TUN`, `TAP`, or `IF_TUN` module
  (see `data/decc_headers.txt`). This was previously inferred from absent
  documentation; it is now established from the system itself.
- OpenVMS's own **PEDRIVER** proves a kernel-mode virtual LAN adapter is
  architecturally possible (it's used for Cluster-over-IP communication),
  but it's a VSI-internal driver, not a public API or template.
- Public documentation for writing OpenVMS device drivers is sparse even for
  Itanium and essentially absent for x86-64 in public sources.
- There are also **no BSD routing sockets** (no `net/route.h` equivalent), so
  even with a way to move packets, installing routes has to go through the
  TCP/IP management interface or DCL rather than a routing socket.

## Lead: libpcap is present

The target system's C RTL header library ships **`PCAP` and `PCAP-BPF`**.
libpcap being available means OpenVMS x86-64 has some BPF-style packet
capture facility, which is the most promising lead found so far for the
packet-interception half of the problem.

What this could mean, in descending order of usefulness:

1. **If libpcap here supports injection** (`pcap_inject` /
   `pcap_sendpacket`), then capture + inject together might approximate a
   TUN device closely enough for a transparent tunnel entirely in
   userspace — no kernel driver. This would be the single best outcome for
   the project and is the first thing to test.
2. **If it captures but cannot inject**, it still gives a read path, and the
   write path would need another mechanism (raw sockets, or a driver).
3. **If it's a stub or a thin shim over something VMS-specific**, it may not
   help at all.

### Confirmed 2026-09-06: capture *and* injection are both declared

Extracting the `PCAP` module from `SYS$LIBRARY:DECC$RTLDEF.TLB` shows:

```
pcap_t *pcap_open_live(const char *, int, int, int, char *);
        pcap_next(pcap_t *, struct pcap_pkthdr *);
int     pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);
int     pcap_sendpacket(pcap_t *p, u_char *buf, int size);
```

- **Injection is available** via `pcap_sendpacket`. (The BSD-spelled
  `pcap_inject` is *not* declared — only the WinPcap-origin
  `pcap_sendpacket` spelling. Functionally equivalent for our purposes.)
- There is a real implementation behind the header:
  `SYS$COMMON:[SYSLIB]TCPIP$LIBPCAP_SHR.EXE`. The `TCPIP$` prefix is strong
  evidence this ships as a component of VSI TCP/IP Services rather than
  being an orphaned third-party port — i.e. it's a supported part of the
  stack.

### What this does and does not get us

This is the best news the project has had, but it must not be over-read.
libpcap is **not** a TUN device, and the gap between them is where the real
work now sits.

What we get:
- A read path: observe frames on a real interface.
- A write path: inject frames onto a real interface.

What we do not get, and this is the crux:
- **No virtual interface exists to route to.** Without a TUN device and
  without routing sockets, there is no "wg0" for the OpenVMS routing table
  to point at. Route-based traffic steering — the normal way WireGuard is
  used — has no obvious mechanism here.
- **pcap observes copies; it does not claim traffic.** Packets captured on
  an interface are still processed by the real stack. For an
  originating-host tunnel you must *suppress* the plaintext original, or it
  goes out in the clear alongside the encrypted copy. pcap alone cannot
  suppress.

### Better injection path: raw sockets with IP_HDRINCL

The Sockets API manual (see `tcpip-stack.md`) shows `SOCK_RAW` is supported
with SYSPRV privilege, and `IP_HDRINCL` lets the application build the
entire IP header for datagrams sent on a raw socket.

This is a **better write path than pcap** for our purposes:

| | pcap | raw socket + IP_HDRINCL |
| --- | --- | --- |
| Layer | 2 (Ethernet frames) | 3 (IP packets) |
| Must handle MAC/ARP | yes | no |
| Must handle framing | yes | no |
| Privilege | likely equivalent | SYSPRV |

WireGuard's payload is IP packets, so injecting at layer 3 skips a whole
class of Ethernet bookkeeping. pcap remains interesting for the *capture*
side; raw sockets look like the right answer for *inject*.

Also confirmed available and relevant: `SIOCADDRT`/`SIOCDELRT` for
programmatic route manipulation, and the full set of interface ioctls
including point-to-point destination address (`SIOCSIFDSTADDR`) and MTU
(`SIOCSIPMTU`).

### The architecture this suggests, and its open question

Capture + suppress + inject:
1. Capture outbound packets bound for the tunnel subnet with pcap.
2. Suppress the originals so the real stack doesn't also transmit them —
   **this is the unsolved piece**. It would need a packet-filter/firewall
   facility in VSI TCP/IP Services capable of dropping by rule, working
   alongside pcap capture.
3. Encrypt, send over the WireGuard UDP socket as normal.
4. On receive, decrypt and `pcap_sendpacket` the plaintext frame back onto
   the local interface for the stack to pick up.

Layer-2 details make this fiddly regardless: MTU, checksum offload, and ARP
all have to be handled by hand, because we'd be working with Ethernet
frames rather than IP packets as a TUN device would give us.

**Next question to answer**: does VSI TCP/IP Services have a packet
filtering facility that can drop outbound packets by rule? If yes, the
driverless transparent tunnel becomes genuinely plausible. If no, step 2 has
no mechanism and we're back to either a driver or the proxy fallback.

The Sockets API manual contains **no packet filtering facility** — its only
"filter" is ICMPv6 type filtering on raw sockets, which selects what your
own socket receives and cannot drop traffic system-wide. This does not rule
filtering out: it is a *programming* manual, and VSI TCP/IP Services is
known to have packet filtering configured through management commands. The
place to look next is the **Management guide**, not the programming one.

Summary of where the three steps stand, after testing on the target:

| Step | Status |
| --- | --- |
| Capture | **Works** — pcap 0.9.4 captures LAN frames at EN10MB |
| **Suppress** | **Unsolved — why the client shape is abandoned** |
| Inject via pcap | **Broken** — `pcap_sendpacket` returns "socket is not connected" |
| Inject via raw socket | Documented, not yet tested |

The gateway shape in `docs/gateway.md` avoids the suppression step
entirely and injects at layer 3, so the pcap send failure does not
affect it.

### A case where suppression isn't needed

If OpenVMS acts as a **gateway forwarding traffic for other hosts** rather
than tunnelling traffic that originates on the box itself, the suppression
problem largely dissolves — capture and inject on a forwarding path is much
more natural. This is out of scope for the client-only MVP, but it's worth
noting that the gateway shape is *easier* here than the client shape, which
is the opposite of the usual situation.

## What would need to be answered

- [ ] Does VSI offer a Driver Development Kit (DDK) for OpenVMS x86-64, and
      under what terms (support contract tier, NDA, cost)?
- [ ] Does the user's existing VSI license/support entitlement include
      access to driver development documentation or the DDK?
- [ ] Is there a lighter-weight integration point short of a full driver —
      e.g. a documented packet-filter/BPF-like hook in VSI TCP/IP Services,
      or an existing third-party (MultiNet/TCPware) mechanism for injecting
      packets — that could stand in for a TUN device without kernel driver
      development?
- [ ] If a driver truly is required, what's the realistic effort/timeline,
      and does it make sense to pursue vs. staying at the userspace-proxy
      integration model longer-term?

## Fallback if a driver is impractical

A userspace proxy model: the Phase 1 protocol core (already implemented and
interop-tested against a real WireGuard peer) sits behind a local
SOCKS/HTTP proxy or an explicit port-forwarding configuration, rather than a
transparent whole-OS tunnel. This trades transparency for being achievable
entirely in userspace, with no kernel driver dependency.

## Next steps

1. Contact VSI (via the user's support channel) with the specific question:
   "Is there a supported way to implement a virtual network interface
   (TUN/TAP-equivalent) on OpenVMS x86-64 for a third-party application,
   and if so, what documentation/DDK access is required?"
2. Record the answer here along with any docs/links VSI provides.
3. Revisit this document once Phase 1 (protocol MVP) is working, to decide
   whether to invest in the driver path or settle on the proxy fallback.
