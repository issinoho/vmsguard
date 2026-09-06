# Phase 2: the gateway shape

## Why this shape and not the other one

WireGuard normally works as a *client*: traffic originating on the host
is routed into a tunnel interface. That requires a TUN device, and
OpenVMS has none — the search for a substitute is documented in
`slip-tunnel.md` and `driver-feasibility.md`, and ended in a dead end.

The obstacle in the client shape is **suppression**. pcap can observe
outbound packets but cannot claim them, so the plaintext original goes
out alongside the encrypted copy. Nothing on OpenVMS was found that can
drop a packet by rule.

The gateway shape sidesteps that entirely. If OpenVMS forwards traffic
for *other* hosts rather than originating it, there is no plaintext
original of ours to suppress — the packet was never ours to begin with.

That inverts the usual difficulty: on most platforms the client is the
easy case and the gateway the elaborate one. Here it is the other way
round.

## How it works

```
  LAN host                OpenVMS (vmsguard)              WireGuard peer
  10.0.0.50                 192.168.0.80                    the internet
      |                          |                               |
      |  1. packet to 10.9.0.5   |                               |
      |------------------------->|                               |
      |     (VMS is its route    | 2. pcap on IE0 captures it    |
      |      to 10.9.0.0/24)     |                               |
      |                          | 3. encrypt, send over UDP     |
      |                          |------------------------------>|
      |                          |                               |
      |                          | 4. reply arrives, decrypt     |
      |                          |<------------------------------|
      |  5. inject to 10.0.0.50  |                               |
      |<-------------------------|  raw socket, IP_HDRINCL       |
```

1. LAN hosts are configured with the OpenVMS box as their route to the
   tunnel subnet.
2. vmsguard captures those packets with libpcap on the LAN interface.
3. It encrypts them and sends them to the WireGuard peer over UDP,
   using the protocol core that already works.
4. Replies are decrypted the same way.
5. Decrypted packets are injected back onto the LAN with a raw socket
   and `IP_HDRINCL`, addressed to the original host. OpenVMS has a
   perfectly good route for that, so this half needs no tricks at all.

## Mechanisms this depends on

All three are documented as present; none has been exercised on the
target. Given how the SLIP investigation went — framing written before
discovering there was no driver — these get verified first.

| Mechanism | Evidence | Verified |
| --- | --- | --- |
| libpcap capture | `PCAP` in the C RTL headers, `TCPIP$LIBPCAP_SHR.EXE` present | no |
| `SOCK_RAW` | Sockets manual: available with SYSPRV | no |
| `IP_HDRINCL` | Sockets manual: build your own IP header | no |
| `SIOCADDRT` | Sockets manual, via `$QIO IO$_SETMODE` | no |

`tools/probes/` tests the first three directly. Run those before any
gateway code is written:

```
$ RUN [.build]PROBE_SOCKETS      ! sockets, poll, SOCK_RAW
$ RUN [.build]PROBE_PCAP         ! capture and injection
```

Both will likely need privilege — `SOCK_RAW` needs SYSPRV per the
manual, and packet capture almost certainly needs something similar.

## Known problems to design around

**ICMP unreachables.** When a packet arrives for a subnet OpenVMS has no
route to, the stack will normally answer with an ICMP destination
unreachable while we are separately tunnelling the packet. The sender
then gets a contradictory signal.

No blackhole-route facility was found on OpenVMS — the only "blackhole"
in the Management manual is a BIND ACL. Options, none yet tested:

- give the tunnel subnet a route pointing somewhere inert, so the stack
  believes it is handled
- accept the noise for a proof of concept and measure whether it
  actually breaks anything

**Layer 2.** pcap captures Ethernet frames, so the capture side has to
strip and validate framing before it sees an IP packet. The injection
side avoids this by using raw sockets at layer 3.

**Asymmetry.** Capture is layer 2 and inject is layer 3, which is
slightly odd but is the right choice on each side: pcap is the only
capture mechanism available, and raw sockets are much the cleaner way to
put a packet back.

**MTU.** No SLIP 1006-byte limit here — the LAN MTU is 1500. Standard
WireGuard MTU arithmetic applies: 1500 − 20 IP − 8 UDP − 32 WireGuard
overhead leaves 1440 for the inner packet.

## Scope

This is a gateway for a *subnet*, not a client for the OpenVMS host
itself. Traffic originating on the OpenVMS box still has no transparent
path into the tunnel — that would need the suppression problem solved.
`vmsguard-interop` remains the way to exercise the tunnel from the box
directly.
