# CLAUDE.md

Working notes for this repository. `README.md` explains what vmsguard is
and what it can do; this file is about how to change it without breaking
things.

## Build and test

```sh
make            # everything, and syntax-checks the gateway
make test       # 402 checks across eight binaries
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

OpenVMS builds with `@build_vms TEST` (DCL) or `MMS` (`descrip.mms`).

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

You cannot reach the OpenVMS machine. The workflow is: develop and test
on Linux, the user builds and runs on OpenVMS and pastes the output.

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
  they fail *quietly*.

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
  inventory, not inferred.
- **SLIP is unusable**: the management layer knows the controller, but
  no driver exists. `SET INTERFACE SL0` returns success and creates
  nothing.
- **PPP is unusable**: the driver exists and creates an interface, but
  requires `/MODEM` and `/DIALUP`, which a `PTD$` pseudo-terminal
  cannot be given (`SYSTEM-E-UNSUPPORTED`).
- **pcap cannot inject.** `pcap_sendpacket` is declared and returns
  "socket is not connected". Capture works. Injection uses a raw socket.
- **IPv6 cannot be injected at all.** Confirmed 2026-09-07 with
  `probe_inject6`: a raw IPv6 socket opens, but `IPV6_HDRINCL` is not
  declared and binding to an address we do not own is refused
  (`EADDRNOTAVAIL`). Those are the only two portable mechanisms. An IPv6
  gateway needs to put a packet on the LAN sourced from the far end, so
  it is blocked — by the same missing facility as the client shape.
- **There is no packet-filter facility** that can drop by rule, which is
  why the client shape is impossible and the gateway shape is not.

`docs/research/slip-tunnel.md` and `docs/research/driver-feasibility.md`
have the full reasoning. If reopening any of these, say what new
information justifies it.

**Open lead (2026-09-07): configured tunnels — and `IT0` is real.**
`iptunnel create 192.0.2.1` produces a `RUNNING` virtual interface with
a resolved next hop. It is the first documented virtual interface on
this platform that actually exists. What is *not* yet known is whether
the stack decapsulates a packet we inject into it (`probe_encap` asks
exactly that) and whether the encapsulated output can be captured
without putting the inner packet on the wire in the clear. See
`docs/research/driver-feasibility.md`.

## Known gaps, in priority order

Nothing outstanding is known to block ordinary use. The nearest things
to gaps:

1. **The NAT table is scanned linearly**, for every outbound packet, and
   is now 2048 entries. Cheap next to encrypting the same packet, but it
   is the first thing to index if the gateway is ever pushed hard.
2. **Datagrams are not reassembled**, only passed through. Later
   fragments inherit their first fragment's mapping, and inbound ones
   arriving early are held until it does; nothing puts the pieces back
   together, and nothing needs to.

Done: several peers, cryptokey routing in both directions, non-blocking rekeying, detached operation with logging,
peer-initiated handshakes,
rekeying, the replay sliding window,
PersistentKeepalive, the
gateway's source filter, source NAT, ICMP fragmentation-needed, NAT of
fragmented datagrams, the cookie mechanism (`mac2`), and reading a
provider's `.conf` directly, roaming, endpoint re-resolution, holding
out-of-order inbound fragments, and detection of the stack's own
contradictory ICMP unreachables.

## Commits

Explain why, not just what — particularly the reasoning behind a
platform workaround, since that is what makes it defensible later rather
than looking arbitrary. Record what was verified and how.
