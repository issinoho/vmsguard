# OpenVMS x86-64 TCP/IP stack

Findings from public sources (2025-2026); several key questions could not be
verified because VSI's primary documentation hosts (`docs.vmssoftware.com`,
`vmssoftware.com`, `wiki.vmssoftware.com`) were unreachable from the research
environment used for this document. These need to be confirmed from the
target system or VSI's support portal.

## What we know

- **VSI TCP/IP Services** is VSI's own TCP/IP stack for OpenVMS (Alpha,
  Itanium, VAX historically; now x86-64), offering both a Berkeley Sockets
  API and native OpenVMS system-service based network programming.
- Multiple TCP/IP stacks can be installed and switched via
  `SYS$MANAGER:IP$SET_STACK` — VSI TCP/IP, MultiNet (Process Software),
  TCPware (Process Software) are all documented as options historically.
  Whichever stack the target system runs matters for exact socket-option
  behavior.
- WireGuard's wire protocol is plain UDP, so the transport requirement is
  modest: create a UDP socket, `sendto`/`recvfrom` with peer endpoints,
  ideally non-blocking with some readiness-notification mechanism (a
  `select`/`poll`/`epoll`-equivalent) for a single-threaded event loop.

## What we could not verify (needs the target system)

- [ ] Raw socket support and any privilege requirements
- [ ] Non-blocking I/O support on UDP sockets (`O_NONBLOCK`, `ioctl(FIONBIO)`,
      or the VMS-native equivalent)
- [ ] `select()`/`poll()` availability and behavior, or whether the
      recommended pattern is QIO-with-AST instead
- [ ] Socket option completeness relevant to WireGuard (`SO_REUSEADDR`,
      IPv6 dual-stack behavior, path MTU discovery controls)
- [ ] Which of VSI TCP/IP / MultiNet / TCPware the target system actually
      runs, and whether that affects any of the above

**Primary source to pull directly**: "VSI TCP/IP Services for OpenVMS
Sockets API and System Services Programming" manual.

## The hard blocker: no TUN/TAP equivalent

WireGuard's core OS integration point on Linux is a TUN device: a virtual
network interface that hands the application raw IP packets addressed to it,
and accepts packets back for injection into the routing stack. This is what
lets WireGuard appear as an ordinary network interface with routes pointed
at it.

- No publicly documented OpenVMS equivalent of TUN/TAP was found.
- OpenVMS **does** have prior art for the underlying architecture: VSI's
  **PEDRIVER** implements a virtual LAN adapter used for OpenVMS Cluster
  communication over IP (the "IPCI" — IP as a Cluster Interconnect —
  feature). This demonstrates that a kernel-mode virtual network adapter is
  architecturally possible on OpenVMS, but PEDRIVER itself is VSI-internal
  and not documented for third-party reuse or emulation.
- Public documentation on writing OpenVMS device drivers is thin even for
  Itanium ("no external documentation on writing device drivers for IA64"
  per community/forum reports) and effectively nonexistent for x86-64 in
  public sources as of this research. Driver development likely requires
  direct engagement with VSI (support contract, DDK access, possibly NDA'd
  materials).

See `driver-feasibility.md` for how this is being tracked as a separate,
non-blocking investigation.
