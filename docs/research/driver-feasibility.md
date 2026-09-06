# Kernel driver / virtual NIC feasibility (tracking document)

## Status: not started — this is a feasibility investigation, not committed work

Per the project plan, the MVP (Phase 1) does not require a kernel-mode
virtual network interface: it proves out WireGuard protocol/crypto
correctness against a real peer using plain UDP sockets, without needing to
carry real routed IP traffic. This document tracks the *separate* question
of how vmsguard could eventually present itself as a transparent OS-level
network interface, the way WireGuard does via TUN on Linux.

## Why this is hard on OpenVMS

- No publicly documented TUN/TAP-equivalent pseudo-device facility exists on
  OpenVMS for third-party use.
- OpenVMS's own **PEDRIVER** proves a kernel-mode virtual LAN adapter is
  architecturally possible (it's used for Cluster-over-IP communication),
  but it's a VSI-internal driver, not a public API or template.
- Public documentation for writing OpenVMS device drivers is sparse even for
  Itanium and essentially absent for x86-64 in public sources.

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
