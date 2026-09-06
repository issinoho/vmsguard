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

**vmsguard interoperates with upstream WireGuard, from OpenVMS x86-64.**

On 2026-09-06, running on OpenVMS V9.2-3 (VSI C V7.7-003, OpenSSL
3.0.21), vmsguard completed a Noise_IKpsk2 handshake with the Linux
kernel WireGuard module over a real network, sent encrypted transport
data, and received an ICMP echo reply back through the tunnel.

```
handshake: sending initiation (3 attempts, 5000 ms each)
  handshake complete
  our index      : 0xefdfdd7f
  peer index     : 0x982476b7

sending ICMP echo request through the tunnel
  10.9.0.2 -> 10.9.0.1
  echo reply received — data path works both ways

PASS — handshake completed and data path verified
```

Confirmed from the peer's side: the `wg` interface counted decrypted
inbound packets, and the peer index above is a random value chosen by
the kernel module, not by any part of vmsguard.

The protocol core also passes all 92 self-tests natively on OpenVMS.

### Forwarding for a subnet

vmsguard also works as a **gateway**, forwarding traffic for other hosts
through the tunnel. Confirmed end to end: a LAN host pinging through
OpenVMS to a WireGuard peer and getting replies, 3/3 with no loss.

Capture is done with libpcap and injection with a raw socket and
`IP_HDRINCL`. See `docs/gateway.md`.

There is no transparent path for traffic *originating* on the OpenVMS
box itself, because that would need a TUN device to claim outbound
packets and OpenVMS has nothing that can. SLIP and PPP over a
pseudo-terminal were both investigated and ruled out — see
`docs/research/slip-tunnel.md`.

### Remaining gaps

Rekeying is implemented and verified against real WireGuard. Still
outstanding: no replay sliding window, no cookie support, no roaming.
Each is noted in the code where it matters, and listed in
`docs/interop.md`.

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
