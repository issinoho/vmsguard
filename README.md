# vmsguard

WireGuard® for OpenVMS x86-64.

A clean-room implementation of the WireGuard protocol in portable C,
running on OpenVMS and interoperating with the reference implementation.

---

## Status

Working on OpenVMS V9.2-3 x86-64 (VSI C V7.7-003, VSI TCP/IP Services
V6.0-30, OpenSSL 3.0.21), verified against the Linux kernel WireGuard
module and against a commercial VPN provider over the public internet.

| | |
| --- | --- |
| Protocol core | 113 self-tests pass natively on OpenVMS |
| Handshake and transport | Wire-compatible with upstream WireGuard |
| Rekeying | Verified against real WireGuard |
| Replay window | 64-bit sliding window, RFC-style |
| Cookies (`mac2`) | Full mechanism, incl. XChaCha20-Poly1305 |
| Source NAT | TCP, UDP and ICMP echo, with connection tracking |
| Fragmented datagrams | Translated, both directions |
| Path MTU | ICMP fragmentation-needed, RFC 1191 |
| PersistentKeepalive | Verified: fires on an idle tunnel |
| Roaming | Follows the peer, on authenticated packets only |
| Provider configs | Reads a `wg-quick` `.conf` directly |
| Gateway | Forwards a subnet through the tunnel, end to end |
| Key tooling | `genkey`/`pubkey` agree with `wg(8)` on 100/100 keys |

### Endpoint

vmsguard on OpenVMS completes a Noise_IKpsk2 handshake with the kernel
WireGuard module and exchanges encrypted transport data:

```
handshake: sending initiation (3 attempts, 5000 ms each)
  handshake complete
  our index      : 0xefdfdd7f
  peer index     : 0x982476b7

sending ICMP echo request through the tunnel
  10.9.0.2 -> 10.9.0.1
  echo reply received — data path works both ways
```

The peer index is a random value chosen by the kernel module, and the
peer's own interface counters recorded the decrypted packets — evidence
from the far side, not from our own tool.

It also connects to a **commercial VPN provider** over the public
internet. Pointed at a TorGuard endpoint, it completes a handshake and
gets an ICMP echo answered by their DNS server through the tunnel — a
third independent WireGuard implementation, and the first test over a
real internet path. Their `.conf` file is read directly. See
[`docs/vpn-provider.md`](docs/vpn-provider.md).

### Gateway

vmsguard also forwards traffic for *other* hosts through the tunnel. A
LAN host pinging a WireGuard peer through OpenVMS:

```
out 10.50.0.50 -> 10.9.0.1  proto 1  84 bytes
in  10.9.0.1 -> 10.50.0.50  proto 1  84 bytes
```

```
3 packets transmitted, 3 received, 0% packet loss
```

Capture is libpcap; injection is a raw socket with `IP_HDRINCL`. See
[`docs/gateway.md`](docs/gateway.md).

With source NAT it also works against a **commercial VPN provider**: a
LAN client with one route pointed at the OpenVMS box, and no VPN
software of its own, reaching the internet through TorGuard. ICMP, DNS
and a TLS session all confirmed. See
[`docs/vpn-provider.md`](docs/vpn-provider.md).

### What it deliberately does not do

There is **no transparent tunnel for traffic originating on the OpenVMS
box itself**. That needs a TUN device to claim outbound packets before
the stack sends them, and OpenVMS has nothing that can. SLIP and PPP
over a pseudo-terminal were both investigated in depth and ruled out;
[`docs/research/slip-tunnel.md`](docs/research/slip-tunnel.md) records
why, so nobody repeats the work.

The gateway shape sidesteps the problem entirely: forwarded traffic was
never ours, so there is no plaintext original to suppress.

### Remaining gaps

Nothing known blocks ordinary use of the gateway. The nearest things:

- **The NAT table is a linear scan**, 2048 entries, walked for every
  outbound packet. Cheap next to encrypting that same packet, but it is
  the first thing to index if the gateway is pushed hard.
- **Datagrams are passed through, not reassembled.** Later fragments
  inherit their first fragment's mapping, and inbound ones that arrive
  early are held until it does. Nothing puts the pieces back together,
  and for a forwarder nothing needs to.
- **ICMP unreachables from the local stack** cannot be suppressed —
  there is no packet filter on the platform that drops by rule. The
  gateway detects and reports them instead; the fix is `TCPIP SET
  PROTOCOL IP /NOFORWARD` on the OpenVMS box.

---

## Building

### Linux

```sh
make          # protocol core, tools, tests, and runs the gateway
make test     # 375 checks across eight binaries
make loopback # end-to-end self-test over real UDP: handshake,
              # cookie challenge, roaming and data path
```

Needs OpenSSL headers. Builds with `-std=c99 -pedantic -Wall -Wextra`
deliberately: VSI C is the ceiling, so violations should surface here.

### OpenVMS

```
$ git clone https://github.com/issinoho/vmsguard
$ set default [.vmsguard]
$ @build_vms TEST
```

`build_vms.com` uses only `CC` and `LINK`. There is also a `descrip.mms`
for MMS, checked against the manual but less exercised. Full detail in
[`docs/building-vms.md`](docs/building-vms.md).

---

## Architecture

```
  tools/       vmsguard-key   vmsguard-interop   vmsguard-gateway
                     |               |                  |
  src/client/        |          wg_client  ──────────────┤
                     |               |                  |
  src/proto/    wg_key      wg_noise, wg_crypto, blake2s │
                                     |                  |
  src/platform/            wg_platform (sockets, clock)  │
                                                         |
  src/tun/                        ethip, rawinject, slip, hdlc
```

**`src/proto/`** is the protocol: Noise_IKpsk2, transport encryption,
BLAKE2s, key encoding. No allocation, no I/O, no platform dependencies —
which is why it compiled and passed on OpenVMS unchanged.

**`src/platform/`** is the entire surface an unfamiliar platform has to
provide: a UDP socket, a clock, name resolution. It exposes no POSIX
types — no `sockaddr`, no fd, no `timeval` — so a `$QIO`-based
implementation would have been equally possible. In the event none was
needed.

**`src/tun/`** holds packet plumbing: Ethernet/IPv4 inspection, raw
injection, and SLIP and HDLC framing left over from the virtual-interface
investigation.

### Two decisions that paid off

**BLAKE2s is implemented here rather than taken from OpenSSL.** WireGuard
needs it keyed with a 16-byte output for `mac1`, which OpenSSL exposes
only through `EVP_MAC`/`BLAKE2SMAC`, and there was no evidence the VMS
build included it. 150 lines from RFC 7693 removed the risk entirely —
and it was the one piece of crypto that worked first time on an
unfamiliar compiler.

**Wire formats use explicit offsets and `memcpy`, never packed structs.**
Struct packing is compiler-specific. Byte order is explicit everywhere,
so nothing depends on the host being little-endian.

---

## OpenVMS notes

The expensive part of this port was not the protocol. It was the
platform. Recorded here because rediscovering it is slow.

### Compiler and linker

| Setting | Why |
| --- | --- |
| `/DEFINE=(_SOCKADDR_LEN)` | Selects BSD 4.4 sockets. Without it there is no `sockaddr_in6` or `sockaddr_storage`. |
| `/PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES` | Without it only ANSI names get the `DECC$` prefix the C RTL exports, so `socket`, `close`, `poll`, `getaddrinfo` all fail to link. |
| `/POINTER_SIZE=32` | Must match the OpenSSL image. `SSL3$LIBCRYPTO_SHR32` is 32-bit, `..._SHR` is 64-bit. |
| `/STANDARD=C99` | VSI C V7.7 is GEM-based, not Clang. C99 is the ceiling. |

No socket library is needed on the `LINK` line; `TCPIP$IPC_SHR` is picked
up automatically. OpenSSL needs an options file naming an explicit path —
a bare logical name makes the linker search the current directory.

### Traps

**Undefined symbols are link *warnings*, not errors.** VMS produces a
working image that crashes when execution reaches the unresolved
reference. One `in6addr_any` reference cost a debugging session that
looked like a wild pointer. Always check the link output.

**DCL lowercases unquoted arguments** to a foreign command. Base64 keys
must be quoted — they are case-sensitive and contain `/`, which DCL reads
as a qualifier. Device names too: `IE0` arrives as `ie0` and pcap is
case-sensitive.

**A declaration proves nothing.** Three times a facility was present in
the headers and absent in practice:

- SLIP's controller is listed by `LIST COMMUNICATION_CONTROLLER`, but
  there is no driver. `SET INTERFACE SL0` returns `SS$_NORMAL` and
  creates nothing.
- `pcap_sendpacket` is declared and non-functional — "socket is not
  connected". Capture works; injection does not.
- PPP has a driver and creates a real interface, but demands
  `/MODEM` and `/DIALUP`, which a `PTD$` pseudo-terminal cannot be given.

Probe before building. `tools/probes/` exists for this.

### Platform differences found

Four of these five were latent bugs in code that worked on Linux:

| | |
| --- | --- |
| `gettimeofday` | Absent on OpenVMS. Use `$GETTIM` — 100ns units since 17-NOV-1858. |
| `in6addr_any` | Not exported. A zeroed `sockaddr` already holds the wildcard address. |
| Dual-stack sockets | Linux accepts an `AF_INET` destination on an `AF_INET6` socket; OpenVMS refuses, and is the stricter reading. Open in the peer's family. |
| `IP_HDRINCL` | BSD-derived stacks want `ip_len`/`ip_off` in **host** byte order. Network order fails with `ENOBUFS` — the stack reads `0x0031` as `0x3100`. |
| `<pcap.h>` | Uses `struct timeval` without defining it, and its symbols need `#pragma names as_is` against VSI C's default upcasing. |

### What the C RTL provided

More than expected. `socket`, `bind`, `sendto`, `recvfrom`, `poll`,
`fcntl`, `ioctl`, `getaddrinfo`, `inet_ntop` all resolved. **No
VMS-specific socket implementation was needed** — one platform file
serves Linux and OpenVMS, with a single `#ifdef __VMS` for the clock.

Also confirmed available: `SOCK_RAW` with SYSPRV, `IP_HDRINCL`,
`SIOCADDRT`/`SIOCDELRT` for programmatic routing, and the full interface
ioctls. Absent: TUN/TAP, BSD routing sockets, any packet-filter facility
that can drop by rule.

---

## Testing

```sh
make test       # 155 checks: protocol, SLIP framing, HDLC framing, IP inspection
make loopback   # handshake, keepalive and ICMP round trip over real UDP
```

Against real WireGuard — the test that actually establishes wire
compatibility, since everything else has vmsguard's own code on both
ends:

```sh
sudo sh tools/interop/setup_wg_peer.sh up '<vmsguard-public-key>'
```

See [`docs/interop.md`](docs/interop.md). Two tests earned their keep by
watching *both* ends: a rekey soak that showed the responder logging six
handshakes while the client reported none (sender indices were being
reused), and a gateway run showing `out` without `in` while the peer
reported no drops (a zero timeout that never read the socket). Neither
would have surfaced from one side alone.

---

## Layout

```
src/proto/      protocol core — Noise, transport, BLAKE2s, keys
src/platform/   the platform interface, and its POSIX/VMS implementation
src/client/     handshake and transport over a platform socket
src/tun/        packet plumbing — Ethernet/IPv4, raw injection, SLIP, HDLC
tools/keys/     vmsguard-key: genkey, pubkey, genpsk
tools/interop/  interop client, test responder, loopback and peer setup
tools/gateway/  the subnet gateway
tools/probes/   OpenSSL, sockets, pcap and injection probes
tools/spike/    the pseudo-terminal spike from the TUN investigation
tests/          155 checks
docs/           building, interop, gateway
docs/research/  toolchain, TCP/IP stack, crypto, virtual-interface findings
```

---

## License

MIT — see [`LICENSE`](LICENSE). The protocol is written clean-room from
the public WireGuard whitepaper and the Noise Protocol Framework
specification, not derived from the GPLv2 Linux kernel module, so this
project is not bound to GPLv2.

WireGuard is a registered trademark of Jason A. Donenfeld. This project
is not affiliated with or endorsed by the WireGuard project.
