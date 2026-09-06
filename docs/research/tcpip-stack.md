# OpenVMS x86-64 TCP/IP stack

## Confirmed on the target system (2026-09-06)

Source: text-library module listings from the target OpenVMS x86-64 system,
captured in `data/decc_headers.txt` (`SYS$LIBRARY:DECC$RTLDEF.TLB`, 102
modules, revised 21-JUN-2025) and `data/starlet_headers.txt`
(`SYS$LIBRARY:SYS$STARLET_C.TLB`, 346 modules, revised 07-OCT-2024).

**Important caveat**: this establishes which headers *ship*, not that the
functions behind them work as expected. Behaviour still needs the probe kit
(see `probes.md` once written). Header presence is necessary, not sufficient.

### Present — BSD sockets are complete

`SOCKET`, `IN`, `IN6`, `IN6_MACHTYPES`, `INET`, `NETDB`, `TCP`, `UN`
(AF_UNIX), `UIO`, `NAMESER`, `NAMESER_COMPAT`, `RESOLV`.

This is a full Berkeley sockets surface. WireGuard's UDP transport needs
nothing exotic here.

### Present — event loop options

- **`POLL`** — `poll()` ships. This is the significant one: a single-threaded
  `poll()`-based event loop is the portable design used by the POSIX
  reference harness, so the same structure should carry to OpenVMS rather
  than requiring a VMS-specific rewrite.
- `IOCTL`, `FCNTL` — the pieces needed for non-blocking sockets
  (`FIONBIO` / `O_NONBLOCK`).
- No `SELECT` module, but `select()` is conventionally declared in
  `socket.h`/`time.h` on this platform rather than its own header, so its
  absence from the listing is not evidence it's missing.
- No `EPOLL`/`KQUEUE` equivalent, as expected. Not needed.
- `IODEF`, `IOSBDEF`, `IOSADEF` in STARLET — the `$QIO` function codes and
  I/O status block definitions, i.e. the native VMS asynchronous I/O path
  with ASTs remains available as a fallback or optimisation if `poll()`
  disappoints.

### Present — interface enumeration

`IF`, `IFADDRS`, `IF_ARP`, `IF_TYPES`, `IF_TRNSTAT`. Enough to enumerate and
inspect interfaces.

### Present — packet capture (unexpected, and significant)

**`PCAP` and `PCAP-BPF`** both ship in the C RTL header library. libpcap
being present means there is some BPF-style packet capture facility on
OpenVMS x86-64. See `driver-feasibility.md` — this is the most promising
lead found so far for the packet-interception problem, though whether it can
*inject* as well as *capture* is unresolved.

### Also present, worth noting

`SCTP`/`SCTP_UIO`, `STROPTS`, `DLFCN` (dynamic loading), `MMAN` (mmap),
`SEM`/`SEMAPHORE`/`SHM`/`IPC`, `PTHREAD` and friends in STARLET (`PTHREAD`,
`PTHREAD_D4`, `PTHREAD_DEBUG`, `PTHREAD_EXC`, `PTHREAD_EXCEPTION`,
`PTHREAD_TRACE`, `CMA`, `TIS`). `X86REGDEF` confirms the x86-64 target.

### Confirmed absent

- **No `TUN`, no `TAP`, no `IF_TUN`** — no TUN/TAP device. The expected
  blocker is now confirmed rather than assumed.
- **No standalone `BPF` module** — only `PCAP-BPF`, which is libpcap's own
  bundled header defining filter-program structures. This does *not* by
  itself prove a writable `/dev/bpf`-equivalent exists.
- **No `ROUTE` module** (no `net/route.h` equivalent) — so no BSD routing
  sockets. Programmatic route manipulation will have to go through the
  TCP/IP management interface or `TCPIP SET ROUTE` DCL rather than a
  routing socket.

## Still open

- [ ] Which stack is actually running (VSI TCP/IP Services vs MultiNet vs
      TCPware) and its version — `TCPIP SHOW VERSION`
- [ ] `SOCK_RAW` support and the privileges it requires
- [ ] Whether the TCP/IP-specific `$QIO` definitions (`TCPIP$INETDEF` /
      `UCX$INETDEF`) ship, and where — they are *not* in STARLET, so they
      come from a TCP/IP-provided library that still needs locating
- [ ] Socket options relevant to WireGuard: `SO_REUSEADDR`, IPv6 dual-stack
      behaviour, path-MTU/DF controls
- [ ] Whether libpcap here can inject (`pcap_inject`/`pcap_sendpacket`) or
      only capture

## Background

- **VSI TCP/IP Services** is VSI's stack for OpenVMS, offering both the
  Berkeley Sockets API and native OpenVMS system-service network
  programming.
- Multiple stacks can be installed and switched via
  `SYS$MANAGER:IP$SET_STACK` — VSI TCP/IP, MultiNet, TCPware. Which one is
  running affects exact socket-option behaviour.
- WireGuard's wire protocol is plain UDP, so the transport requirement is
  modest: a UDP socket with `sendto`/`recvfrom`, non-blocking, driven by a
  readiness mechanism. Everything needed for that is confirmed present.

## The TUN/TAP problem

WireGuard's OS integration point on Linux is a TUN device: a virtual network
interface that hands the application raw IP packets addressed to it and
accepts packets back for injection into the routing stack, letting WireGuard
appear as an ordinary interface with routes pointed at it. OpenVMS has no
such facility — now confirmed by the header listing, not just inferred from
absent documentation.

OpenVMS does have prior art for the underlying architecture: VSI's
**PEDRIVER** implements a virtual LAN adapter used for OpenVMS Cluster
communication over IP ("IPCI"). A kernel-mode virtual network adapter is
therefore architecturally possible, but PEDRIVER is VSI-internal and not
documented for third-party reuse.

Public documentation on writing OpenVMS device drivers is thin even for
Itanium and effectively absent for x86-64, so driver development likely
requires direct engagement with VSI.

See `driver-feasibility.md`, where this is tracked as a separate,
non-blocking investigation.
