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
  *sockets*. Note this does **not** mean routes can't be manipulated
  programmatically: see the ioctl section below, which corrects an earlier
  conclusion in this document.

## From the Sockets API manual (2026-09-06)

Source: "VSI TCP/IP Services for OpenVMS Sockets API and System Services
Programming" (VSI, 2025), 352pp. **Version caveat**: the manual documents
TCP/IP Services **5.7** on IA-64/Alpha; the target runs **V6.0-30 on
x86-64**. Close enough to be authoritative on API shape, but version-
specific details should be spot-checked against the running system.

### Correction: routes *can* be manipulated programmatically

An earlier revision of this document concluded that the absence of
`net/route.h` meant route changes had to go through DCL or the management
interface. That was wrong. BSD 4.3-style route ioctls are supported through
`$QIO`:

| Operation | Data type | `$QIO` function |
| --- | --- | --- |
| `SIOCADDRT` | `struct ortentry` | `IO$_SETMODE` |
| `SIOCDELRT` | `struct ortentry` | `IO$_SETMODE` |

No routing socket, but a working programmatic route API all the same.

### Interface configuration ioctls

A full complement, including the ones a tunnel would need:

`SIOCSIFADDR`, `SIOCGIFADDR`, `SIOCSIFDSTADDR`/`SIOCGIFDSTADDR`
(**point-to-point** destination address), `SIOCSIFFLAGS`/`SIOCGIFFLAGS`,
`SIOCSIFNETMASK`/`SIOCGIFNETMASK`, `SIOCSIFBRDADDR`/`SIOCGIFBRDADDR`,
`SIOCAIFADDR`/`SIOCDIFADDR`/`SIOCPIFADDR`, `SIOCSIPMTU`/`SIOCRIPMTU`,
`SIOCGIFINDEX`, `SIOCGIFTYPE`, `SIOCGMEDIAMTU`, `SIOCGIFCONF`,
`SIOCADDMULTI`/`SIOCDELMULTI`, `SIOCENABLBACK`/`SIOCDISABLBACK`.

ARP is manipulable too: `SIOCSARP`, `SIOCDARP`, `SIOCGARP` (the last needs
OPER privilege).

That the stack models point-to-point interfaces and exposes MTU control is
encouraging — those are exactly the knobs a TUN-style interface needs. What
remains missing is any way to *create* such an interface.

### Raw sockets are supported

> `SOCK_RAW` — Provides access to internal network interfaces. Available
> only to users with the SYSPRV privilege.

And critically, **`IP_HDRINCL` is supported**:

> If specified for a raw IP socket, you must build the IP header for all
> datagrams sent on the raw socket.

So arbitrary IP packets can be constructed and injected at layer 3 with
SYSPRV. See `driver-feasibility.md` — this is a cleaner injection path than
pcap.

### Socket options available

`SO_REUSEADDR`, `SO_REUSEPORT`, `SO_BROADCAST`, `SO_DONTROUTE`,
`SO_KEEPALIVE`, `SO_LINGER`, `SO_OOBINLINE`, `SO_RCVBUF`, `SO_SNDBUF`,
`SO_RCVTIMEO`, `SO_SNDTIMEO`, `SO_SNDLOWAT`, `SO_ERROR`, `SO_TYPE`,
`SO_USELOOPBACK`, `SO_SHARE`, `SO_FULL_DUPLEX_CLOSE`.

`SO_REUSEADDR` is confirmed, which is all the MVP needs.

**Gap worth noting**: there is no per-socket don't-fragment or path-MTU
control (`IP_MTU_DISCOVER`/`IP_DONTFRAG` are absent). WireGuard normally
sets DF on its outer UDP packets. MTU is settable per *interface* via
`SIOCSIPMTU`, but not per socket. Not an MVP blocker; note it for later.

### The `$QIO` path

The "network pseudodevice" (the BG driver) exposes sockets through `$QIO`
with AST completion: `IO$_ACCESS` (open a connection), `IO$_DEACCESS`
(close), `IO$_READVBLK`/`IO$_WRITEVBLK` (transfer),
`IO$_SETMODE`/`IO$_SENSEMODE` (socket options and the ioctls above).

This is the socket API in `$QIO` form — an alternative I/O model, not a raw
packet interface. Useful as an event-loop fallback if `poll()` disappoints,
since AST-driven completion is the native VMS idiom.

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
