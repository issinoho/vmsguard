# Kernel driver / virtual NIC feasibility (tracking document)

## Status: not started — this is a feasibility investigation, not committed work

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

Note the caveat: `PCAP-BPF` is libpcap's *own bundled* header defining filter
program structures. Its presence does not prove a writable
`/dev/bpf`-equivalent exists underneath, nor that capture works on this
platform's interfaces. This needs testing, not inference.

**Next action on this lead**: extract the `PCAP` header from
`SYS$LIBRARY:DECC$RTLDEF.TLB` and check which functions are actually
declared — specifically `pcap_inject`, `pcap_sendpacket`, `pcap_open_live`,
and `pcap_set_immediate_mode`. Then check `SYS$SHARE:` for the corresponding
shareable image to confirm there's an implementation behind the header.

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
