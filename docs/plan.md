# Plan

## Context

`vmsguard` targets a port of WireGuard to OpenVMS x86-64. WireGuard needs a
kernel-level virtual network interface (TUN/TAP-equivalent) to intercept and
inject IP packets; OpenVMS has no publicly documented equivalent. Rather than
block on that, this project separates two tracks: a protocol-correctness MVP
that doesn't need a virtual NIC at all, and a parallel feasibility
investigation into OS-level integration.

Decisions:
- **Scope for now**: the kernel pseudo-NIC/driver question is a **feasibility
  investigation**, not a committed build — it does not block the protocol
  work.
- **MVP target**: a **client only** that completes a real WireGuard handshake
  (Noise_IKpsk2) and exchanges wire-compatible encrypted transport packets
  with a genuine WireGuard peer (e.g. a Linux `wg` box). Interop correctness
  first, OS-level transparent tunneling later.
- **License**: permissive (MIT or BSD-2-Clause). The protocol core is written
  clean-room from the public WireGuard whitepaper and the Noise Protocol
  Framework spec — not derived from the GPLv2 Linux kernel module.

## Phase 0 — Repo scaffolding + verify on real hardware

- README, LICENSE, `docs/research/` findings docs (this commit).
- On the user's OpenVMS x86 system, gather ground truth that could not be
  verified from this environment (VSI's doc/wiki hosts are not reachable
  here):
  - `CC/VERSION`, available compiler products (`PRODUCT SHOW PRODUCT`)
  - VSI TCP/IP Services sockets manual: raw socket support, non-blocking
    I/O, `select`/`poll` availability
  - Build tooling available: MMS/MMK, GNV+gmake, CMake port status
  - Whether the user's VSI license/support entitles them to driver
    development docs or a DDK for x86-64

## Phase 1 — Protocol core in portable C (the MVP)

- `src/proto/`: Noise_IKpsk2 handshake state machine, cookie reply
  mechanism, transport keepalive/rekey timers, transport data
  encrypt/decrypt — written from the whitepaper/spec, platform-agnostic C,
  linked against OpenSSL 3 for primitives.
- `src/platform/posix/`: thin reference harness (sockets, event loop) so the
  protocol core can be developed and iterated on quickly on Linux/POSIX
  before touching the OpenVMS box — same core code, different platform shim.
- `tools/interop/`: stand up a real `wg` peer (container or VM) with a known
  keypair, and validate the OpenVMS/POSIX client can complete a handshake
  and exchange correctly-encrypted transport packets with it. This is the
  MVP's actual acceptance test and does not require a TUN device, since we
  control both ends of the payload in the test.
- `src/platform/vms/`: the OpenVMS-specific shim implementing the same
  platform interface as the POSIX one, using VSI TCP/IP Services sockets for
  UDP transport and `$QIO`/AST (or pthreads, pending verification) for the
  event loop.

## Phase 2 — OpenVMS driver/pseudo-NIC feasibility spike (parallel/after)

- Document what would be required to present a virtual network interface to
  OpenVMS's routing table (PEDRIVER-style), including whether VSI needs to
  be engaged directly.
- Evaluate fallback integration shapes that avoid a kernel driver entirely,
  e.g. a userspace SOCKS/HTTP proxy fed by the Phase 1 protocol core, if the
  driver path proves impractical near-term.
- Output is a decision document, not committed driver code, until
  feasibility is confirmed.

## Open items to track (not blocking, but flagged)

- Confirm `wireguard-lwip`'s license before treating it as more than an
  architectural reference.
- Verify pthreads stability on OpenVMS x86-64 directly rather than trusting
  release-note summaries.
- Confirm raw-socket / non-blocking-IO completeness of VSI TCP/IP Services
  sockets API from the primary manual (inaccessible from this environment).

## Verification

- Phase 1 MVP is verified by the interop test harness: a scripted run where
  the OpenVMS (or POSIX reference) client and a real `wg` peer complete a
  handshake and exchange N correctly-encrypted/decrypted test packets,
  confirmed via `wg show` / packet captures on the peer side.
- No kernel-mode code ships until Phase 2's feasibility spike is written up
  and reviewed with the user.
