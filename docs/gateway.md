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

Verified on the target before any gateway code was written — the SLIP
investigation, where framing was built before anyone checked for a
driver, is the reason for that order.

| Mechanism | Status |
| --- | --- |
| libpcap capture | **works** — real LAN frames at EN10MB |
| `SOCK_RAW` | **works** — opens on the target |
| pcap injection | **broken** — not used; see below |
| `IP_HDRINCL` | set at open; not yet exercised end to end |

### Capture: confirmed working (2026-09-06)

```
vmsguard pcap probe
  library: libpcap version 0.9.4
  devices:
    IE0
    LO0
  ok    pcap_open_live(IE0)
  note  link type 1 (EN10MB)
  ok    captured frame, 122 bytes on the wire
  ok    captured frame, 138 bytes on the wire
  ok    captured frame, 138 bytes on the wire
```

Real frames off the LAN, at Ethernet link type. The capture half of the
gateway is available.

### pcap injection: confirmed broken

```
  FAIL  pcap_sendpacket: send: socket is not connected
INJECTION UNAVAILABLE — capture-only
```

`pcap_sendpacket` is declared in the header but does not work — VSI's
port appears to be capture-only, with the send path a stub over a socket
that was never set up for transmitting. A reminder that a declaration in
a header proves nothing on this platform, which is also how SLIP was
lost.

**This does not affect the design**, which never used pcap to inject:
capture is layer 2 because pcap is what exists, injection is layer 3
because raw sockets are cleaner. The remaining question is whether
`SOCK_RAW` and `IP_HDRINCL` work, which `probe_sockets` answers.

### SOCK_RAW: confirmed working

```
  --- raw sockets (Phase 2 only, not required for MVP) ---
  note  SOCK_RAW opened successfully
```

Both halves of the design are therefore available: capture through
pcap, injection through a raw socket. What has not been exercised is
`IP_HDRINCL` actually transmitting a packet, which only a live run will
show.

## Running it

```
$ GW := $SYS$DISK:[.build]VMSGUARD_GATEWAY.EXE
$ GW --key "<private>" --peer-key "<peer public>" -
     --endpoint 192.168.0.131:51820 -
     --interface IE0 -
     --tunnel-subnet 10.9.0.0/24 -
     --verbose
```

Needs privilege for both capture and raw sockets. LAN hosts must route
the tunnel subnet via the OpenVMS box, and the WireGuard peer must list
the LAN hosts' addresses in its `allowed-ips`, or it will decrypt the
packets and discard them.

`--verbose` prints a line per packet in each direction, which is the
quickest way to see which half of the path is working.

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
