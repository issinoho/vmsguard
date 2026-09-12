# CLAUDE.md

Working notes for this repository. `README.md` explains what vmsguard is
and what it can do; this file is about how to change it without breaking
things.

## Build and test

```sh
make            # everything, and syntax-checks the gateway
make test       # 508 checks across nine binaries
make loopback   # end-to-end over real UDP, needs no privilege
```

`tools/gateway/gateway.c` needs pcap and only runs on OpenVMS. `make
gateway-check` links it against the stub libpcap in
`tools/gateway/pcapstub/` and **runs** it against
`tests/data/sample.conf`, checking what it derived from that file before
the stub stops it. `all` depends on it.

Compiling it was not enough. A config value left pointing into a struct
scrubbed on scope exit parsed perfectly and then failed on the target: a
syntax check cannot see a lifetime bug, and running it can. Anything
past `pcap_open_live` still belongs on the target.

Note also that a `memset` used to scrub a secret from a local is a dead
store the compiler may remove, and GCC at -O2 does. Use `wg_zero`.

Always run `make test` before committing. `make loopback` too if you
touched anything in `src/client/`, `src/platform/` or `src/proto/`.

OpenVMS builds with `@build_vms TEST` (DCL) or `MMS` (`descrip.mms`,
core and tools only). `build_vms.com` is the exercised path.

## Hard constraints

### C99, not C11

VSI C V7.7 on OpenVMS is GEM-based, not Clang. No `_Generic`, no
`_Static_assert`, no anonymous unions or structs, no VLAs, no C11
atomics or `<threads.h>`.

The Linux build uses `-std=c99 -pedantic -Wall -Wextra` precisely so
violations surface here rather than on a machine you cannot reach. Do not
weaken those flags.

### Clean-room licensing

The protocol is written from the public WireGuard whitepaper and the
Noise Protocol Framework specification. **Do not consult, copy from, or
adapt the Linux kernel WireGuard module or any other GPLv2
implementation.** Deriving from it would force this project to GPLv2,
which is exactly what the clean-room approach exists to avoid. Reference
material is the whitepaper, RFCs, and the specifications.

### The platform layer stays platform-neutral

`src/platform/wg_platform.h` is the entire surface an unfamiliar
platform must provide. It contains no `sockaddr`, no file descriptors,
no `timeval`, and it must stay that way — a `$QIO`-based implementation
should remain possible. Put POSIX types in the implementation, never the
interface.

### The protocol core does no I/O

`src/proto/` allocates nothing, performs no I/O, and has no platform
dependencies. That is why it compiled and passed on OpenVMS unchanged.
Keep it that way; anything needing a socket or a clock belongs above it.

## Conventions

- **Wire formats use explicit offsets and `memcpy`, never packed
  structs.** Struct packing is compiler-specific.
- **Byte order is always explicit.** Never rely on the host being
  little-endian, even though both current targets are.
- **Pure logic goes in a testable module.** Packet inspection, framing
  and parsing live in `src/tun/` with tests, rather than inline in an
  I/O loop where they could only be exercised on OpenVMS.
- Comments explain *why*, particularly where something looks odd because
  a platform forced it.

## OpenVMS

You cannot reach either OpenVMS machine. The workflow is: develop and
test on Linux, the user builds and runs on OpenVMS and pastes the output.

There are now two targets: the x86-64 box (V9.2-3, VSI C V7.7-003, TCP/IP
Services V6.0-30) where everything has been measured, and an Itanium
rx2660 (V8.4-2L3, VSI C V7.4-001, TCP/IP Services V6.0-31) added
2026-09-12, where the tree builds and all self-tests pass but nothing
about the *gateway* has been measured. Do not assume a finding
transfers. The Itanium stack is a point release newer, not older, so it
is not evidence about pre-6.0 behaviour, and its pcap is the same
`libpcap version 0.9.4`. What it is evidence about is architecture.
Its LAN interface is `WE1`, not `IE0`, so any command with
`--interface` differs between the two machines.

That makes a round trip expensive, so:

- **Probe before building.** `tools/probes/` exists because a facility
  being declared in a header proves nothing here. SLIP framing was
  written and tested before anyone checked whether a driver existed —
  it did not.
- **Give complete commands, never placeholders.** `<peer key>` in a
  pasted command wastes a round trip. Look the real value up.
- **Check the link output.** Undefined symbols are *warnings* on VMS.
  A broken image builds cleanly and crashes when execution reaches the
  unresolved reference. `build_vms.com` now tests `$SEVERITY` after
  every link and stops, because `ON ERROR` does not catch a warning and
  the build otherwise prints "build complete" over a broken image.
- **A new dependency has three build files, not one.** `Makefile`,
  `build_vms.com` and `descrip.mms`. Only the first is exercised here,
  so the other two fail on the machine you cannot reach — and on VMS
  they fail *quietly*. This happened three times in two days, all in
  `descrip.mms` and all found only when the user ran `MMS`: a rule it
  lacked (`ethip.obj`), an object it did not link (`icmp.obj`), and an
  include directory it did not name (`[.src.tun]`). Nothing here can see
  any of them, because nothing here runs MMS. If you touch what a tool
  links or includes, open all three files in the same edit.
  Note the scope difference too — `descrip.mms` builds the protocol
  core, tools and protocol tests, but *not* the gateway, which needs
  pcap.

Compiler settings that are not optional are documented in the README's
OpenVMS notes, along with the platform differences found so far. Read
that section before writing anything that touches sockets, time, or
packet headers.

## Testing

- **Watch both ends.** The two subtlest bugs in this project — reused
  sender indices, and a zero timeout that never read the socket — were
  each invisible from one side. The client reported success while the
  responder's logs and the peer's counters disagreed.
- **A test that cannot fail is not a test.** When adding one, confirm it
  fails without the fix. The zero-timeout regression test was checked
  that way.
- **In-process tests share a blind spot.** `tests/test_proto.c` runs our
  initiator against our responder, so a misreading of the specification
  would pass. Only `vmsguard-interop` against real WireGuard settles
  wire compatibility.

There is a WireGuard peer set up on the user's laptop for testing;
`tools/interop/setup_wg_peer.sh` manages it. Keys must live under
`/etc/wireguard` — AppArmor confines `wg` to that path and denies by
path rather than uid, so root does not help.

## Settled questions — do not reopen without new information

- **There is no TUN/TAP on OpenVMS.** Confirmed from the header
  inventory, not inferred. **But see the configured-tunnel finding
  below**: `ITn` is not a TUN device, and for handing the stack a packet
  it turns out to do the same job.
- **SLIP is unusable**: the management layer knows the controller, but
  no driver exists. `SET INTERFACE SL0` returns success and creates
  nothing. **Closed on both architectures, 2026-09-12.** Retested on
  Itanium V8.4-2L3 on the theory that a driver dropped by the fresh
  x86-64 port might survive on older iron: same acceptance, same absent
  `SL0` in `SHOW INTERFACE`. Two architectures and two OS versions now,
  so do not reopen this for want of different hardware.
- **PPP is unusable**: the driver exists and creates an interface, but
  requires `/MODEM` and `/DIALUP`, which a `PTD$` pseudo-terminal
  cannot be given (`SYSTEM-E-UNSUPPORTED`).
- **pcap cannot inject.** `pcap_sendpacket` is declared and returns
  "socket is not connected". Capture works. Injection uses a raw socket.
  Confirmed on Itanium too (2026-09-12): same failure, same message, and
  `SOCK_RAW` opens there as well.
- **IPv6 cannot be injected directly.** Confirmed 2026-09-07 with
  `probe_inject6`: a raw IPv6 socket opens, but `IPV6_HDRINCL` is not
  declared and binding to an address we do not own is refused
  (`EADDRNOTAVAIL`). Those are the only two portable mechanisms. **This
  no longer blocks an IPv6 gateway** — see the configured-tunnel finding
  below; the return packet goes in wrapped in IPv4 protocol 41 and the
  stack unwraps it.
- **There is no packet-filter facility** that can drop by rule, which is
  why the gateway shape works and a capture-and-suppress client does
  not. A tunnel-routed client would not need suppression at all; what
  stops that one is capture, not suppression — see below.

`docs/research/slip-tunnel.md` and `docs/research/driver-feasibility.md`
have the full reasoning. If reopening any of these, say what new
information justifies it.

**Reopened (2026-09-07): configured tunnels work.** `iptunnel create`
makes a real virtual interface `ITn`, and the stack **decapsulates a
packet injected into it** — `probe_encap` took `IT0`'s `Ipkts` from 0 to
1. So this machine can be *given* a packet and made to process it as
though it arrived from elsewhere, which is not the same as originating
one and is enough for an IPv6 gateway's inbound half.

Bring the interface up first: `iptunnel create` leaves it `RUNNING` but
not `UP`, and `netstat -i` marks that with a `*`. Missing it makes the
probe read as a flat no.

The inner packet is also **acted upon**: the injected ICMP echo request
was answered and the reply routed out to the address it claimed to come
from, `id 16962` matching the probe's own. No reverse-path check
intervened, though the inner source was an address directly connected on
another interface.

The **IPv6 round trip completes**: `ifconfig "IT0" ipv6 up` needs no
system reconfiguration, and an injected protocol-41 packet carrying an
ICMPv6 echo request to the tunnel's own address moved both `Ipkts` and
`Opkts` — received, decapsulated, answered, and the answer
re-encapsulated on the way out. Every element of an IPv6 gateway's
inbound path is therefore demonstrated, with nothing forged.

The client shape is **narrowed, not solved**. Its inbound half is the
above. Its outbound half needs the encapsulated frame captured, and
capture would have to happen on `IE0`, where the frame carries the
inner packet unencrypted to the router. A tunnel cannot terminate
locally — `127.0.0.1` and the machine's own address are both refused
with `invalid argument`, while a remote one succeeds — so the
encapsulated frame must reach the wire and the leak is unavoidable.

Reported to VSI on 2026-09-12 — `docs/vsi-question-pcap-tunnel.md`,
with two smaller findings alongside it. Until there is an answer, the
client shape is waiting on someone else and should not be picked up as
though it were merely unstarted.

**Corrected 2026-09-12.** This used to say pcap does not list `ITn`,
and that the ask was to make it visible. Both were wrong, and wrong
because the conclusion came from `pcap_findalldevs` alone —
`pcap_open_live("IT0")` had never been called. Given an **IPv4**
address on the interface (every tunnel tested before was IPv6-only),
pcap both lists a tunnel and opens it. What it then hands back is
`IE0`'s traffic, reporting link type EN10MB: the frames carry `EIA0`'s
own MAC while the tunnel's counters sit at zero. So the real ask is
that a handle opened on a non-LAN interface stop silently delivering
the LAN device's packets. See `docs/research/driver-feasibility.md`.

## Known gaps, in priority order

Nothing outstanding is known to block ordinary use. The nearest things
to gaps:

1. **Datagrams are not reassembled**, only passed through. Later
   fragments inherit their first fragment's mapping, and inbound ones
   arriving early are held until it does; nothing puts the pieces back
   together, and nothing needs to.
2. **Inbound latency is bounded by the pcap read timeout.** Measured on
   the target 2026-09-12: ping through the gateway averages 58 ms where
   the LAN floor is 6 ms, and `PCAP_TIMEOUT_MS` is 50. The loop blocks
   in `pcap_next_ex` and only then polls the tunnel socket, so an
   inbound packet waits for the capture timeout to expire before
   anything looks at it. Outbound does not wait, which is why it
   measures 12.1 Mbit/s against inbound's 8.2. Fixing it means waiting
   on both sources at once rather than in turn — and `wg_platform.h`
   has no way to say "wait on these two things", which is the actual
   work.

Done: IPv6 through the gateway (including ICMPv6 Packet Too Big,
which needs `--gateway-ip6` for a source address), several peers, cryptokey routing in
both directions, non-blocking rekeying, detached operation with logging,
peer-initiated handshakes,
rekeying, the replay sliding window,
PersistentKeepalive, the
gateway's source filter, source NAT, hash-indexed NAT lookups, ICMP
fragmentation-needed, NAT of
fragmented datagrams, the cookie mechanism (`mac2`), and reading a
provider's `.conf` directly, roaming, endpoint re-resolution, holding
out-of-order inbound fragments, and detection of the stack's own
contradictory ICMP unreachables.

## Commits

Explain why, not just what — particularly the reasoning behind a
platform workaround, since that is what makes it defensible later rather
than looking arbitrary. Record what was verified and how.
