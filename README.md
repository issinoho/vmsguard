# vmsguard

A port of the WireGuard® protocol to OpenVMS x86-64.

WireGuard depends on a kernel-level virtual network interface (a TUN/TAP
equivalent) that OpenVMS has no publicly documented facility for. This
project treats that as an open feasibility question rather than a blocker:
the near-term goal is a **client** that speaks wire-compatible WireGuard
(Noise_IKpsk2 handshake + transport data encryption) against a real
WireGuard peer, implemented in portable C on top of OpenSSL 3. Transparent
OS-level tunneling (a real virtual NIC integrated with OpenVMS routing) is a
separate, later track — see `docs/research/driver-feasibility.md`.

## Status

Early research phase. No working code yet. See `docs/research/` for what's
been established so far about the target platform, and `docs/plan.md` for
the phased approach.

## Layout (planned)

- `src/proto/` — platform-agnostic WireGuard protocol core (handshake,
  cookie mechanism, transport encryption), written from the public
  WireGuard whitepaper and the Noise Protocol Framework spec.
- `src/platform/posix/` — POSIX/Linux reference harness for fast iteration
  on the protocol core.
- `src/platform/vms/` — OpenVMS x86-64 platform shim (VSI TCP/IP Services
  sockets, VMS-native event loop).
- `tools/interop/` — test harness that validates the protocol core against
  a real `wg` peer.
- `docs/research/` — findings on the OpenVMS x86-64 toolchain, TCP/IP
  stack, crypto libraries, and kernel driver feasibility.

## License

MIT (or BSD-2-Clause) — see `LICENSE`. The protocol implementation is
written clean-room from public specifications, not derived from the
GPLv2-licensed Linux kernel WireGuard module, so this project is not bound
to GPLv2.

WireGuard is a registered trademark of Jason A. Donenfeld. This project is
not affiliated with or endorsed by the WireGuard project.
