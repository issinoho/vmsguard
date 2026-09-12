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

**Confirmed on a second architecture, 2026-09-12.** `probe_pcap` on
OpenVMS V8.4-2L3 Itanium (TCP/IP Services V6.0-31) captures on `WE1` at
EN10MB and fails `pcap_sendpacket` with the same "socket is not
connected". `probe_sockets` there opens `SOCK_RAW` successfully, so the
raw-socket injection path the gateway actually uses is available on both.

Both machines report `libpcap version 0.9.4`, so this is one pcap
implementation seen twice rather than two builds agreeing — weaker
evidence than two versions would be, but it does rule out the failure
being specific to the x86-64 port.

Device naming differs and matters for `--interface`: the Itanium machine
presents `WE1` where the x86-64 one presents `IE0`. Its pcap also
enumerates `LO0`, which the x86-64 listing does not show.

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

`tunnel` there is the manual's placeholder for the interface name, not
a keyword: `iptunnel show IT3` works and `iptunnel show tunnel` returns
`invalid argument`. Obvious once seen, and duly typed literally on
2026-09-12.

**A tunnel cannot be deleted while it still has an address**, and
`ifconfig down` does not remove one. Bringing an interface down drops
its routes and leaves the address assigned, and `iptunnel delete` then
fails with `SIOCIPTUNNEL delete: mount device busy` — which does not
suggest an address is the reason. The full sequence is:

```
$ ifconfig "IT3" delete     ! removes the address
$ iptunnel delete IT3
interface IT3 deleted
```

This matters to the client shape rather than being housekeeping: a
client creates a tunnel at startup and removes it at shutdown, so a
teardown that quietly leaves the interface behind would leak one `ITn`
per run until the system is rebooted.

It is the **IPv4** address specifically that holds the device. Deleting
an IPv6-only tunnel's address failed outright —

```
%TCPIP-E-FSDELIFADDR, IT1 :C2A8:00FF:FE50:0000 could not delete address
```

— and `iptunnel delete IT1` succeeded regardless. So a teardown should
attempt the address deletion and carry on rather than treating its
failure as fatal.

That is the second thing today to distinguish an interface's IPv4
address from its IPv6 one: libpcap will not list or open an interface
without the former either. Both look like the same registration being
keyed on IPv4.

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

### Protocol 41 too (2026-09-07)

The same probe with `--inner-proto 41`, carrying an ICMPv6 echo request:

```
$ netstat -i          IT0 ... 1
$ PENC --tunnel-remote 192.0.2.1 --tunnel-local 192.168.0.80 \
       --inner-proto 41
  injected 76 bytes
$ netstat -i          IT0 ... 2
```

**With IPv6 not configured on the system at all.** The tunnel matches on
the outer IPv4 header and receives the packet before anything looks at
what is inside, so the encapsulation path is protocol-agnostic: IPv4 in
IPv4 and IPv6 in IPv4 are accepted alike.

### And the IPv6 round trip completes (2026-09-07)

IPv6 needed no system reconfiguration at all. One line brings it up on
the tunnel:

```
$ ifconfig "IT0" ipv6 up
%TCPIP-I-FSIPADDRUP, IT0 :C2A8:00FF:FE50:0000 primary active

$ ifconfig "IT0"
IT0: flags=4c3<UP,BROADCAST,RUNNING,NOARP,MULTICAST>
    *inet6 fe80::c2a8:ff:fe50:0
     192.168.0.80 --> 192.0.2.1
```

Then an ICMPv6 echo request **to that address**, from a link-local peer
reachable only through the tunnel:

```
$ netstat -i          IT0 ... Ipkts 2   Opkts 3
$ PENC --tunnel-remote 192.0.2.1 --tunnel-local 192.168.0.80 \
       --inner-proto 41 --inner-src6 fe80::1 \
       --inner-dst6 fe80::c2a8:ff:fe50:0
$ netstat -i          IT0 ... Ipkts 3   Opkts 4
```

**Both counters moved.** `fe80::1` is on-link only via `IT0`, so a reply
can leave by no other route. The stack therefore received our injected
packet, decapsulated it, processed the IPv6 packet inside, generated a
reply, and re-encapsulated that reply in IPv4 on the way out.

That is every element of an IPv6 gateway's inbound path, demonstrated:

| | |
| --- | --- |
| A virtual interface exists | `IT0`, `RUNNING` |
| An injected packet reaches our own input path | yes |
| The stack matches it to the tunnel | protocol 4 and 41 alike |
| It decapsulates | `Ipkts` |
| It acts on the inner packet | the IPv4 echo reply, and this |
| It routes the result back out | `Opkts` |

Nothing in the chain is forged. The injection is addressed to this
machine, and what leaves afterwards is the stack's own routing.

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

### The client shape: narrowed, not solved (2026-09-07)

Its inbound half is exactly what was demonstrated above. Its outbound
half needs the encapsulated frame captured, and pcap cannot see the
tunnel interface:

```
$ ppcap
  devices:
    IE0
    LO0
  FAIL  pcap_sendpacket: send: socket is not connected
```

`IT0` is absent, though it was up and carrying traffic at the time. So
capture would have to happen on `IE0`, where the encapsulated frame goes
— and `gate 192.168.0.1` means that frame is a real Ethernet frame on
the segment, carrying the inner packet **unencrypted**. Capturing it
works; the plaintext copy travelling to the router alongside is the
problem.

That is a genuinely different obstacle from the one that stopped this
before. The old one was that the stack could not be handed a packet, and
it is gone. The new one is that the stack's *output* cannot be observed
without also being transmitted.

**A tunnel cannot terminate locally**, which was the one way round it:

```
$ iptunnel create 127.0.0.1
iptunnel: SIOCIPTUNNEL create: invalid argument

$ iptunnel create 192.168.0.80
iptunnel: SIOCIPTUNNEL create: invalid argument

$ iptunnel create 192.0.2.2
IT1  iftype IFT_IPV4 (208) src 192.168.0.80 dst 192.0.2.2
```

Creation plainly works — the third succeeded — so it is local
destinations specifically that are refused, both loopback and the
machine's own LAN address. Sending the encapsulated packets over
loopback, where pcap can see them and the LAN cannot, is therefore not
available.

The destination must be remote, so the encapsulated frame must go to the
wire, so the inner packet is on the segment in the clear. There is no
configuration of this mechanism that avoids it.

(`pcap_sendpacket` still fails, unchanged, which confirms the earlier
finding rather than revisiting it.)

### Where this leaves the client shape

Blocked, for a different and much smaller reason than before.

| | |
| --- | --- |
| Hand the stack a packet to deliver | **solved** — inject to a tunnel |
| Suppress the plaintext original | **solved** — routing at `ITn` encapsulates it instead |
| Observe what the stack emits | **blocked** — see the correction below |

The third is the whole of what remains, and it is a narrow, concrete
thing to ask VSI for: a way to read what a tunnel interface emits. Not
a new subsystem — a capture hook on an interface that already exists
and already works.

**The reason recorded here was wrong**, though the row is still
blocked. It said pcap cannot see `ITn`. In fact pcap lists and opens a
tunnel that has an IPv4 address, and then delivers `IE0`'s traffic from
the handle. Tested 2026-09-12; the detail is at the end of this
document.

Worth stating plainly what changed today. The client shape was abandoned
because a packet originating on this machine could not be suppressed;
that is now solved, by a facility already shipping. What replaced it is
a gap in observability rather than in capability.

### Four manuals read against this, and what they settle (2026-09-12)

Neither moves the blocked row. Recorded so the same ground is not
covered twice.

**VSI OpenVMS LAN Driver Tracing Guide.** LAN drivers keep their own
trace buffer below pcap, and LANCP writes it out as a pcap file. That is
a genuinely useful second view of the wire — see
[`../gateway.md`](../gateway.md) — but it is a property of **LAN
devices**, addressed as `EIA0`. A configured tunnel is not a LAN device
and has no LAN driver to trace, so this is the same layer pcap already
sees, reached by a different route.

Confirmed on the machine rather than left at the manual, 2026-09-12.
`LANCP SHOW CONFIGURATION` lists one device, `EIA0`, and
`SHOW DEVICE/TRACE/HEADER` — which applies to all devices — reports
trace data for that one and nothing else. No `IT` device appears in
either. The LAN layer does not know tunnel interfaces exist, which is
the same boundary pcap ran into, and the two are now known to be the
same boundary rather than assumed to be.

**VSI OpenVMS x86-64 Driver Developer Guide for the I/O Buffer
Descriptor.** Concerns how a driver maps a user buffer for DMA: the
`SVAPTE/BOFF/BCNT` triplet and the DIOBM are gone on x86-64, replaced by
an IOBD holding a list of physical Extents. A pseudo-NIC has no DMA
engine, so none of it applies to anything we would write.

One thing in it is worth keeping anyway, because it invalidates
reference material rather than adding any: **all IRP SVAPTE-related
symbols are undefined on x86-64**. Every driver example in the pre-x86
*Writing OpenVMS Device Drivers* material uses `IRP$L_SVAPTE`. If the
driver route is ever reopened, those examples are stale in a way that
reads as a missing symbol rather than as a design change.

**VSI TCP/IP Services Sockets API and System Services Programming.**
Two things, one of which reopens nothing and one of which is a gap in
our own testing.

It **confirms the IPv6 injection finding and makes it permanent**. The
absence of `IPV6_HDRINCL` is not an omission in VSI's implementation:
the manual's own comparison table says IPv4 raw sockets "send and
receive complete packets" and IPv6 raw sockets do not, using ancillary
data for header fields instead. That is RFC 3542, which replaced header
inclusion outright. There is no version of this API where the option
appears, so `probe_inject6`'s result stands for good rather than
pending a newer release.

It also documents `SIOCGIFCONF` — the stack's own interface list —
as an ioctl and as a `$QIO` `IO$_SENSEMODE`, which is a different list
from the one libpcap enumerates. Which raises the gap:

**We never tried opening `IT0` by name.** Every record here says
`pcap_findalldevs` does not *list* it, and the conclusion drawn was
that pcap cannot see it. Those are two different mechanisms, and on
several platforms libpcap enumerates a restricted set while still
opening any name handed to it.

That test was run, and the answer is below.

### pcap and `ITn`: it opens, and it captures the wrong interface

Run 2026-09-12. The reason for reopening was the above: the conclusion
rested on enumeration alone and `pcap_open_live("IT0")` had never been
called.

The errors move as the interface gains configuration:

| interface | state | `pcap_open_live` |
| --- | --- | --- |
| `IT0` | does not exist | no such device or address |
| `IT2` | up, no address | can't assign requested address |
| `IT1` | up, IPv6 address only | can't assign requested address |
| `IT2` | up, `10.99.0.1` | **succeeds**, and `findalldevs` lists it |

So libpcap here wants an **IPv4** address on an interface before it will
touch it, and every tunnel tested before today was IPv6-only. Even the
enumeration finding was an artefact of that: an IPv4-addressed tunnel
appears in the device list.

The address is the whole of the requirement. A later run opened `IT2`
successfully while it was **down** and while `findalldevs` was once
again listing only `IE0` and `LO0` — being up, and being listed, are
neither of them necessary.

**But the handle captures `IE0`.** The open reports link type 1
(EN10MB), which a tunnel carrying bare IP cannot be, and the frames are
plainly the LAN's:

```
9c31c37a4eb1 aa0004000104 0800 4500006c...06...c0a80050 c0a80001
dst router   src EIA0      IP        TCP  192.168.0.80 -> 192.168.0.1
```

The source MAC is `EIA0`'s own, the addresses are the LAN's, and `IT2`
had `Ipkts 0 Opkts 0` with nothing routed through it at the time. This
is the box's own SSH traffic, captured from the Ethernet while we asked
for a tunnel.

That is worse than the refusal it replaces. A refusal is honest; this
looks like success — a handle opens, a link type is reported, frames
arrive — and the client's outbound half could have been built on it
before anyone noticed the frames were the wrong interface's.

**The client shape stays blocked, and the ask to VSI is now sharper.**
It is not "make `ITn` visible to pcap": `ITn` can be listed and opened
today. It is that **a handle opened on a non-LAN interface delivers the
LAN device's traffic instead of that interface's**, silently. Whether
the fix is real capture on tunnel interfaces or an honest error on
open, the current behaviour cannot be built on either way.

Injection is unchanged — `pcap_sendpacket` still returns "socket is not
connected" — so that finding stands exactly as recorded.

### The tunnel's outbound half works (2026-09-12)

Established on the way to the above, and new. Everything demonstrated
on the 7th was *inbound*: a packet injected into `ITn` was decapsulated
and acted upon. Nothing had ever been sent *out* through a tunnel.

Two things were missing. A tunnel needs a **netmask** to get a route —
`ifconfig "IT3" 10.98.0.1 10.98.0.2` alone configures addresses and
creates nothing, while adding `netmask 255.255.255.0 up` installs both
the interface and host routes. And the destination has to be past the
tunnel peer: **pinging the peer address is answered locally**, in under
a millisecond, by our own address, so nothing leaves the machine.

With a tunnel to a real host and a ping to `10.98.0.5`, `Opkts` moved
0 → 8 and the encapsulated packets were captured on `IE0`:

```
4074e05fc300 aa0004000104 0800 45 00 0068 e6f5 4000 ff 04 1278 c0a80050 c0a80083
                                                        proto 4   .0.80 -> .0.131
```

So the stack encapsulates and transmits for us, and both halves of a
configured tunnel are now demonstrated rather than one.

It also confirms the leak by observation rather than by reasoning. That
frame's payload is the inner packet **in the clear**, on the segment,
addressed to the tunnel's remote endpoint. A client that routed traffic
into `ITn` and captured the result on `IE0` would be transmitting
everything it meant to encrypt, exactly as this document has claimed
since the 7th — now seen rather than argued.

**OpenVMS VAX Device Support Manual (1994, VAX V6.1).** Superseded for
this target and not useful. It is MACRO-32 throughout, and its
mechanics are VAX-specific: VAXBI, VMEbus, Q-bus and UNIBUS adapters,
and the `SVAPTE/BOFF/BCNT` buffer mapping the IOBD guide above says is
undefined on x86-64 — 41 occurrences of it here. There is no LAN driver
chapter, no VCI, and its only "pseudo" references are VAXBI pseudo CSR
addressing rather than software-only devices. The class/port design it
describes, which is the nearest thing in it to a pseudo-NIC, carries an
explicit warning that there are "no supported methods for implementing
the class/port design in a non-Digital-supplied device driver".

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
