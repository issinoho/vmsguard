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


## IPv6 injection: confirmed impossible (2026-09-07)

Probed before any IPv6 code was written, with `probe_inject6`:

```
  raw IPv6 socket opens              yes
  IPV6_HDRINCL declared              no -- not defined in the headers
  binding to the forged source       no -- can't assign requested address
  unforged packet sends              no -- no route to host
```

**Established.** A raw IPv6 socket opens, so the family is supported.
There is no `IPV6_HDRINCL`, so the header cannot be supplied by the
caller and the stack builds it. Binding to an address this machine does
not own is refused with `EADDRNOTAVAIL`, so the source cannot be claimed
that way either. Between them those are the only two portable
mechanisms, and neither is available.

**Not established.** The last line is inconclusive about the platform:
`fd00::2` simply has no route from that machine, so it says nothing
about whether raw IPv6 sending works to a destination that does. It does
not need to — a gateway that can only send as itself cannot forward.

### What this means

Forwarding *is* putting a packet on the wire with a source you do not
own. Outbound needs no injection at all: the packet is captured with
pcap and leaves through the WireGuard UDP socket. It is the return
direction, decrypted and put back on the LAN addressed to the client,
that requires it — and there is no way to do it for IPv6.

So IPv6 through the gateway is blocked by exactly the same missing
facility as the transparent client shape: no way to originate a packet
the stack did not address. That was already the conclusion for pcap
injection (`pcap_sendpacket` returns "socket is not connected") and for
the absence of any packet filter that drops by rule.

The three now have one cause between them, which makes the case to VSI a
single request rather than three: **a way for a user-mode program to
present packets to, and receive packets from, the IP stack as an
interface.** A TUN device answers all three at once.

### Not tried

`IPV6_HDRINCL` might exist numerically without a header definition, as
options occasionally do. Guessing a value was deliberately not
attempted: setting an unknown socket option is not a probe, it is
setting an unknown socket option. That question belongs to VSI, who know
what the number is.


## A lead worth probing: configured tunnels (ITn)

Found in the VSI *Guide to IPv6*, section 4.1.2, while confirming the
absence of `IPV6_HDRINCL`. **Not verified on the target.** Recorded here
because it may reopen more than one settled question, and because a
documented facility on this platform has twice turned out not to exist.

VSI TCP/IP Services documents an `iptunnel` command that creates a
**virtual interface, `ITn`**:

```
$ iptunnel create [-I int-name] [v4-dest] [v4-src]
$ ifconfig "IT0" ipv6 up
$ iptunnel show tunnel
$ iptunnel delete tunnel
```

"A configured tunnel is created as a virtual interface (ITn)... an IPv4
configured tunnel encapsulates IPv4 **or IPv6** packets in an IPv4
packet." The reference given is RFC 2003, IP-in-IP encapsulation.

### Why it matters for IPv6 through the gateway

The blocker is the *return* direction. An IPv6 packet arriving through
the WireGuard tunnel has to be put on the LAN addressed to the client,
and there is no way to originate IPv6 with a source we do not own.

A configured tunnel could supply one, without needing to forge anything:

1. Wrap the decrypted IPv6 packet in an IPv4 header, protocol 41, from
   the tunnel's remote endpoint to its local one.
2. Inject that with `IP_HDRINCL`, **which is proven working here**.
3. The stack receives it on `ITn`, decapsulates, and forwards the IPv6
   packet to the client natively.

Every primitive in that chain is already demonstrated except the
existence of `ITn` itself. Outbound needs no tunnel at all — an IPv6
frame from the client is captured by pcap the same way an IPv4 one is.

Nothing is forged and nothing leaks: the injection is addressed to this
machine, and what leaves the box afterwards is the stack's own natively
routed IPv6.

### Why it might matter more than that

The client shape was abandoned because a packet originating on this
machine cannot be suppressed — the stack sends it in the clear while we
separately tunnel a copy. Routing traffic at an `ITn` interface would
mean the stack *encapsulates* it instead, and there is then no plaintext
original: only an encapsulated one addressed to the tunnel endpoint,
which we capture.

**With a serious caveat.** RFC 2003 encapsulation is not encryption. The
encapsulated packet still goes out on the wire to the tunnel
destination, so unless that destination is this machine, the inner
packet is readable by anything on the segment. Whether it can be pointed
at the local box, and whether pcap can then capture it, is unknown and
is the question to settle before treating this as a route to the client
shape at all.

### Confirmed to exist (2026-09-07)

Unlike SLIP and PPP before it, this one is real:

```
$ iptunnel create 192.0.2.1
IT0  iftype IFT_IPV4 (208) src 192.168.0.80 dst 192.0.2.1

$ ifconfig -a
IT0: flags=4c2<BROADCAST,RUNNING,NOARP,MULTICAST>
     192.168.0.80 --> 192.0.2.1

$ iptunnel show it0
interface IT0 src 192.168.0.80 dst 192.0.2.1 gate 192.168.0.1
```

The interface is created and `RUNNING`. `iptunnel help` gives the real
syntax, which the manual's examples obscure:

```
create  [-I <intf-name>] [-V <ipversion>] <tunnel-dst> [tunnel-src]
delete  <intf-name>
show    <intf-name>
```

**`gate 192.168.0.1` is the significant part.** The stack has already
resolved a next hop for tunnelled packets — the LAN router. So an
encapsulated packet is a real frame on a real interface, which means
pcap can capture it. It also means it leaves the machine, which is the
whole of the caveat below.

### Confirmed to decapsulate (2026-09-07)

With `IT0` up, one injected packet and one counted:

```
$ ifconfig "IT0" up
$ ifconfig "IT0"
IT0: flags=4c3<UP,BROADCAST,RUNNING,NOARP,MULTICAST>
     192.168.0.80 --> 192.0.2.1

$ netstat -i          (before)
IT0   1280  <Link>  x86vms   0 ...

$ PENC --tunnel-remote 192.0.2.1 --tunnel-local 192.168.0.80 \
       --inner-src 192.168.0.218
  injected 48 bytes

$ netstat -i          (after)
IT0   1280  <Link>  x86vms   1 ...
```

`Ipkts` went from 0 to 1. That establishes three things at once, none of
which was known before:

- a raw socket can hand this stack a packet **addressed to itself**, and
  it reaches the local input path rather than leaving on the wire;
- the stack **matches an injected packet to a configured tunnel**;
- and receives it on that interface, which is decapsulation.

The interface had to be brought up first. `iptunnel create` leaves it
`RUNNING` but not `UP`, which `netstat -i` marks with a `*` and which
made an earlier run of this same probe read as a flat no.

And the inner packet was **acted upon**. On 192.168.0.218:

```
16:59:24.944270 enp0s25 In  IP 192.168.0.80 > 192.168.0.218:
                              ICMP echo reply, id 16962, seq 1, length 8
```

`id 16962` is `0x4242`, the identifier `probe_encap` writes, so this is
that packet and not a coincidence. `.218` never sent a request: the only
way an echo *reply* reaches it is that the OpenVMS stack unwrapped what
we injected, treated the ICMP inside as an arriving packet, answered it,
and routed the answer out `IE0`.

The complete chain, then, is proven end to end: inject to ourselves →
local input path → matched to the tunnel → decapsulated → **inner packet
delivered to the stack** → answered → routed out.

Worth recording that the expected obstacle did not appear. The inner
source, `192.168.0.218`, is directly connected on `IE0`, and a packet
bearing it while arriving on `IT0` looks spoofed; a reverse-path check
would have dropped it. There is evidently no such check here, which is
convenient and worth knowing rather than relying on.

### What this changes

The client shape was abandoned, and IPv6 forwarding declared impossible,
for the same reason: this machine cannot originate a packet the stack
did not address. That is still true. What has changed is that it no
longer has to — the stack can be *given* a packet and made to process
it as though it had arrived from elsewhere.

For an IPv6 gateway that is the whole of the missing half. Wrap the
decrypted IPv6 packet in an IPv4 protocol-41 header addressed to this
machine, inject it, and the stack unwraps and routes it natively. No
address is forged, and nothing leaves the box in the clear.

The client shape is a further step and still has the caveat below: its
*outbound* direction needs the encapsulated packet captured, and
`gate 192.168.0.1` says that frame goes to the router.

But the inbound half of the client shape is the same mechanism just
demonstrated, and it is the half that was thought impossible. What
remains is a question about capture and leakage, not about whether the
stack will accept what we give it.

### What is still unknown

Creation is not operation. Two questions remain, and they are
independent:

1. **Does the stack decapsulate a packet we inject?** `probe_encap`
   answers this: it wraps an ICMP echo request in an IPv4 protocol-4
   header addressed to this machine from the tunnel's remote endpoint
   and injects it with `IP_HDRINCL`. If the stack matches it to `IT0`,
   unwraps it and answers, a reply arrives at whatever address the
   inner packet claimed to be from. That is the mechanism an IPv6
   gateway needs, with protocol 41 instead of 4.

2. **Can the encapsulated output be captured without leaking it?** For
   the client shape the stack would encapsulate our own outbound
   traffic, and we would capture and encrypt it. But `gate` says that
   frame goes to the router, so the inner packet is on the segment in
   the clear. Pointing the tunnel at this machine, or at an address
   whose next hop goes nowhere, might avoid that — and might equally
   stop the frame being emitted at all, which would stop pcap seeing
   it. Nothing here settles it.

The first question is worth answering on its own: it unblocks IPv6
through the gateway, where nothing is leaked because the injection is
addressed to this machine and what leaves afterwards is natively routed.

### Probing it

The command's existence is the first question, and DCL answers it:

```
$ ifconfig -a
$ iptunnel create 192.0.2.1
$ ifconfig -a
$ iptunnel show tunnel
```

`192.0.2.1` is TEST-NET-1 and routes nowhere, so a tunnel to it moves no
traffic. If `IT0` appears in the second `ifconfig -a`, the facility is
real and worth pursuing. If `iptunnel` is not a command, or it succeeds
and creates nothing, this joins SLIP in the settled list — `SET
INTERFACE SL0` also returned success and created nothing.

To undo:

```
$ ifconfig "IT0" down
$ iptunnel delete tunnel
```
