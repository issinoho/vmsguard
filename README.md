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

**Running on OpenVMS x86-64.** As of 2026-09-06, on OpenVMS V9.2-3 with
VSI C V7.7-003 and OpenSSL 3.0.21:

- The protocol core passes all 92 self-tests natively.
- The interop client completes a WireGuard handshake over a real
  network to a peer on Linux, exchanges encrypted transport data, and
  gets an ICMP echo reply back through the tunnel.

**Not yet proven: wire compatibility with upstream WireGuard.** Both
ends of that test are vmsguard's own code, so a shared misreading of the
specification would pass it. The next milestone is `vmsguard-interop`
against a real `wg` peer — see `docs/interop.md`.

Also still open is the transparent-tunnel question: how vmsguard would
present itself as a network interface OpenVMS can route to, without
writing a kernel driver. SLIP over a pseudo-terminal looks like the most
promising route; see `docs/research/slip-tunnel.md`.

`docs/building-vms.md` covers building on OpenVMS, including the five
platform differences found so far.

## Layout

- `src/proto/` — platform-agnostic WireGuard protocol core (handshake,
  transport encryption, BLAKE2s, key encoding), written from the public
  WireGuard whitepaper and the Noise Protocol Framework spec.
- `src/platform/` — the platform interface, and its implementation. The
  one implementation in `posix/` serves both Linux and OpenVMS: the C
  RTL supplied everything needed, so no separate VMS socket shim was
  required.
- `src/client/` — handshake and transport driven over a platform socket.
- `tools/interop/` — interop client, test responder, and a loopback
  self-test.
- `tools/keys/` — `vmsguard-key`, the equivalent of `wg genkey` /
  `wg pubkey`, since OpenVMS has no wireguard-tools.
- `tools/probes/` — standalone probes for OpenSSL, sockets and libpcap.
- `docs/research/` — findings on the OpenVMS x86-64 toolchain, TCP/IP
  stack, crypto libraries, and the virtual-interface question.

## License

MIT (or BSD-2-Clause) — see `LICENSE`. The protocol implementation is
written clean-room from public specifications, not derived from the
GPLv2-licensed Linux kernel WireGuard module, so this project is not bound
to GPLv2.

WireGuard is a registered trademark of Jason A. Donenfeld. This project is
not affiliated with or endorsed by the WireGuard project.
