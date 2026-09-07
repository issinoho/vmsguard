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
| `IP_HDRINCL` | **works** — injected packets reach the wire and are answered |
| pcap injection | **broken** — not used; see below |

Every mechanism the design needs is now confirmed on the target.

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

### Outbound path: confirmed working end to end (2026-09-06)

With the gateway running on OpenVMS and a LAN host routing
`10.99.0.0/24` via it, three pings produced three tunnelled packets:

```
out 192.168.0.131 -> 10.99.0.1  proto 1  84 bytes
out 192.168.0.131 -> 10.99.0.1  proto 1  84 bytes
out 192.168.0.131 -> 10.99.0.1  proto 1  84 bytes
```

pcap captured the frames, `ethip` accepted them as IPv4 for the tunnel
subnet, and the protocol core encrypted and sent them to the peer. The
capture half of the gateway works on real traffic.

The pings did not reply, which is expected: the peer's `allowed-ips`
covers `10.9.0.2/32` and so it discards packets sourced from
`192.168.0.131`.

### SOCK_RAW: confirmed working

```
  --- raw sockets (Phase 2 only, not required for MVP) ---
  note  SOCK_RAW opened successfully
```

Both halves of the design are therefore available: capture through
pcap, injection through a raw socket. What has not been exercised is
`IP_HDRINCL` actually putting a packet on the wire.

### Why the inbound path needs its own probe

Testing injection through the gateway needs the LAN host and the
WireGuard peer to be *different machines*. When they are the same host,
the reply never traverses the tunnel: the kernel sees a destination that
is local and delivers it directly. Any test built that way is circular
and proves nothing about injection.

`tools/probes/probe_inject.c` sidesteps the topology. It injects an ICMP
echo request with addresses of your choosing, straight from a raw
socket, and leaves verification to whatever is watching the network:

```
$ PINJ := $SYS$DISK:[.build]PROBE_INJECT.EXE
$ PINJ --src 192.168.0.80 --dst 192.168.0.131
```

and on the destination:

```sh
sudo tcpdump -ni any icmp and host 192.168.0.80
```

`sendto` succeeding only means the stack accepted the packet. Seeing it
arrive is what proves injection works.

### Injection: confirmed working, and a byte-order trap

The first attempt failed on every packet:

```
  FAIL  sendto: no buffer space available
```

`ENOBUFS` for a 49-byte packet is not a buffer problem. **4.4BSD-derived
stacks expect `ip_len` and `ip_off` in host byte order when
`IP_HDRINCL` is set**, while Linux expects network order. Read the wrong
way round, `0x0031` becomes `0x3100` — the stack tried to allocate 12KB
for a 49-byte packet and gave up.

The probe sends both orders and reports which is accepted:

```
  --- IP total length in network byte order ---
  FAIL  sendto: no buffer space available   (x3)

  --- IP total length in host byte order ---
  ok    injected 49 bytes, seq 1            (x3)
  ==>   host byte order is accepted
```

And on the destination, all three arrived and were answered:

```
In  IP 192.168.0.80 > 192.168.0.131: ICMP echo request, id 30210, seq 1
Out IP 192.168.0.131 > 192.168.0.80: ICMP echo reply,   id 30210, seq 1
```

`id 30210` is `0x7602`, the host-order variant; `0x7601` never appeared
on the wire at all. The replies matter as much as the arrivals — they
mean the receiver parsed the packet and validated both checksums.

Note what that implies about the IP header checksum: the probe computed
it over a *host-order* header, which is wrong for the wire, and the
packet was still accepted. The stack therefore recomputes it. So
`rawinject.c` zeroes the checksum and leaves it to the stack, which both
Linux and the BSD-derived stacks fill in under `IP_HDRINCL`.

## Confirmed working end to end (2026-09-06)

A LAN host reaching a WireGuard peer through OpenVMS, and getting
answers back:

```
iain@docker-nuc:~$ ping -I 10.50.0.50 -c3 10.9.0.1
64 bytes from 10.9.0.1: icmp_seq=1 ttl=64 time=16.7 ms
64 bytes from 10.9.0.1: icmp_seq=2 ttl=64 time=10.9 ms
64 bytes from 10.9.0.1: icmp_seq=3 ttl=64 time=13.2 ms

3 packets transmitted, 3 received, 0% packet loss
```

Every stage of the path ran on OpenVMS x86-64: pcap captured the frames
off `IE0`, `ethip` accepted them as IPv4 for the tunnel subnet, the
protocol core encrypted them, the Linux kernel WireGuard module decrypted
and answered, and the replies came back through the tunnel to be
decrypted and injected onto the LAN with a raw socket.

### The topology that makes this a real test

Three machines, and the arrangement matters:

```
  machine B                OpenVMS                  laptop
  192.168.0.218            192.168.0.80             192.168.0.131
  + 10.50.0.50/32          (gateway)                wg peer, 10.9.0.1
```

- **B** routes `10.9.0.0/24` via OpenVMS and sources from a secondary
  address, `10.50.0.50`.
- **The laptop** lists `10.50.0.50/32` in the peer's `allowed-ips` and
  has a route for it via the tunnel interface, so replies go back
  through the tunnel rather than straight across the LAN.
- **OpenVMS** has a host route for `10.50.0.50` via B, so injected
  replies know where to go.

Two earlier arrangements were rejected for being circular. With the LAN
host and the WireGuard peer on the *same* machine, the reply never
traverses the tunnel — the kernel sees a local destination and delivers
it directly, so injection is never exercised and the test proves
nothing.

Using B's real LAN address also fails, more subtly: the laptop would
answer directly over the LAN, so the request goes via the tunnel and the
reply does not. The secondary address exists precisely to force both
directions through the tunnel, and it has the practical advantage of
leaving SSH to `192.168.0.218` untouched throughout.

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
quickest way to see which half of the path is working:

```
out 10.13.127.177 -> 1.1.1.1  proto 17  76 bytes
in  1.1.1.1 -> 192.168.0.218  proto 17  122 bytes
out 192.168.0.218 -> 224.0.0.22  proto 2  40 bytes  DROPPED: unsupported protocol
```

Refusals are printed in the same shape, with the reason. This matters
more than it looks: the first live run against a provider ended with
`dropped 2 unsupported` and nothing at all in the log to say what those
two had been, because every packet that *did* print was ordinary UDP.
A count you cannot explain is barely better than no count.

The reasons come from `nat_reason()` in `src/tun/nat.c`, so the tests
assert the specific one — that a fragment is refused *as a fragment*
rather than incidentally as a malformed header, which a return of plain
`-1` could never distinguish.

### Roaming

The peer endpoint given at startup is where the first handshake goes,
and after that the tunnel follows the peer. Any packet that
*authenticates* — a handshake response that completed, or transport data
that decrypted and passed the replay check — updates the endpoint to
wherever it came from. A provider that moves a server, or a NAT that
rebinds its port mid-session, no longer ends the session.

The word that matters is *authenticates*. The endpoint is never moved by
a packet that merely claims to be from the peer, and the update sits
after the replay check rather than before it, so a captured packet
replayed from somewhere else cannot drag the tunnel with it. Following
an unauthenticated source address would let anyone able to forge one
redirect the tunnel, which is a considerably worse failure than not
roaming at all.

The summary says so when it happened:

```
peer roamed 1 time; last seen at 64.20.211.140:1443
```

Not covered: an endpoint given as a hostname is resolved once, at
startup. If a provider moves a server *and* stops answering at the old
address before sending anything from the new one, there is nothing
authenticated to learn from and the DNS name would have to be resolved
again. No provider tested has done this.

### Using the provider's config file directly

Every value above except the three that describe the local network is
already in the `.conf` a provider sends, so `--config` reads it rather
than having it transcribed:

```
$ GW := $SYS$DISK:[.build]VMSGUARD_GATEWAY.EXE
$ GW --config DKA0:[WIREGUARD]68.CONF -
     --interface IE0 -
     --client 192.168.0.218/32 -
     --exclude 192.168.0.0/24 -
     --verbose
```

`PrivateKey`, `PublicKey`, `PresharedKey`, `Endpoint`, `Address`,
`AllowedIPs`, `MTU`, `PersistentKeepalive` and `ListenPort` all come
from the file.

`Address` loses its prefix length while `AllowedIPs` keeps its, which
looks inconsistent and is not: the first describes an interface, the
second a subnet, and it is the subnet the tunnel is selected by. `MTU`
is the inner MTU, which is exactly what `--tunnel-mtu` wants.

Any flag given as well overrides the file, wherever it appears on the
command line — a flag the operator typed beats a file they may not have
written.

Three things are not in a config file and must still be given:
`--interface`, and for a full tunnel `--client` and `--exclude`. The
gateway says so when it reads a file, along with anything in it that was
*not* acted on. `DNS` is the one that matters: it is for the machines
behind the gateway to set for themselves, and appearing to have honoured
a line we ignored is how someone ends up debugging the wrong thing.

Nothing is dropped in silence. An unknown section, a second `[Peer]`, a
key that is not base64, a number that is not a number, more `AllowedIPs`
entries than fit — each is refused, with the line number, because a
provider config is a wall of base64 and "bad key" on its own locates
nothing. wg-quick's own directives (`PostUp`, `Table`, `SaveConfig`) are
ignored rather than refused, since a real file contains them.

### Stopping it, and the counters

Both interrupt keys end the run with a summary:

```
ran for 1m 25s
captured 860, tunnelled 856, received 852, injected 852, dropped 4
NAT: 856 translated, 852 restored, 296 of 512 mappings live, dropped ...
     856 new flows over the run, 604 per minute
```

The duration is there because without it the rest cannot be read.
"296 of 512 mappings live" means the timeouts are doing their job if the
run was twenty seconds and that they are not if it was ten minutes, and
an earlier summary gave no way to tell which. The flow rate makes the
same point directly: with a 30-second UDP timeout, a table holding
roughly half a minute's worth of flows is behaving.

They get there by different routes, because the two keys are different
kinds of event:

- **Ctrl-C** raises `SIGINT`. A handler sets a flag, the forwarding loop
  leaves by its own front door, and the capture and tunnel socket are
  closed in order.
- **Ctrl-Y** belongs to DCL, not to the image; no handler here ever sees
  it. It runs the image down as soon as the next DCL command is typed,
  and rundown calls exit handlers — so the summary is registered with
  `atexit` as well, which is the route both keys share.

The one gap is **Ctrl-Y followed by `STOP`**, which skips exit handlers
by design. Use `EXIT` instead, or Ctrl-C, if the counters matter.

Earlier builds printed the summary only when an error broke the loop, so
every ordinary run threw its counters away — and the counters are how a
run is judged.

## Full tunnels need exclusions

`--tunnel-subnet 0.0.0.0/0` matches local destinations exactly as
readily as remote ones. Without exclusions the gateway forwards a
client's LAN traffic — its conversations with other hosts on the
segment, and with the OpenVMS box itself — out to the far end, where it
is useless and where it should not be going.

A real VPN client does not have this problem because its routing table
holds a more specific route for the local subnet. There is no equivalent
here: capture sees the frame regardless of what any routing table thinks.

So `--exclude` is **required** whenever the tunnel subnet is wider than
/8, alongside `--client`:

```
--tunnel-subnet 0.0.0.0/0 --exclude 192.168.0.0/24 --client 192.168.0.218/32
```

Multicast, the limited broadcast address and `0.0.0.0` are always
excluded, since none of them means anything at the far end of a
point-to-point tunnel. Directed broadcasts such as `192.168.0.255` fall
inside the local subnet exclusion.

This was found by running a full tunnel to a commercial provider and
watching the gateway forward the test client's SSH session to the
OpenVMS box out through the VPN. The traffic still worked — capture
takes copies — and the provider discarded it, but it had no business
leaving the network.

## Known problems to design around

**ICMP unreachables.** The OpenVMS stack sees the same forwarded packets
pcap does. Having no route for them, it may answer the sender with
"destination unreachable" while the gateway is quietly tunnelling the
very same packet — and the sender believes the ICMP. A TCP connect fails
outright rather than waiting for the reply that is already on its way,
so the symptom is connections that fail immediately and intermittently
while ping works perfectly.

Nothing in this program can prevent it. There is no packet-filter
facility on the platform that drops by rule, which is the same fact that
makes the gateway shape necessary rather than the client shape (see
`docs/research/driver-feasibility.md`). What the gateway does instead is
notice: it recognises an ICMP error sent from its own address whose
*quoted* original was headed for the tunnel subnet, which is precise
enough not to fire on other people's ICMP crossing the segment. Under
`--verbose` each one prints:

```
STACK: told 192.168.0.218 that 1.1.1.1 is unreachable, proto 6 — we are tunnelling it
```

and the summary ends with a warning naming the count.

**The fix is on the OpenVMS box, not here: IP forwarding should be
off.** A host that is not a router discards a packet not addressed to it
and says nothing, which is exactly what is wanted — the gateway already
has its copy from pcap. A host that *is* forwarding, and has no route,
generates the unreachable instead. Check and clear it with:

```
$ TCPIP SHOW PROTOCOL IP
$ TCPIP SET PROTOCOL IP /NOFORWARD
```

This has not been exercised on the target: no run so far has reported a
non-zero count, which either means forwarding is already off or that the
conditions have not arisen. The detection is what makes the difference
visible either way.

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
