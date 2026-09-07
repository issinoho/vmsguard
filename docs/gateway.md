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

Roaming cannot cover a peer that goes *silent* and reappears elsewhere,
because nothing authenticated ever arrives from the new address to learn
from — which is exactly what a provider retiring a server looks like.
For that, an endpoint given as a name is looked up again once every
handshake attempt has failed, and the handshake retried at wherever it
now points.

Only then, never on each attempt: a DNS lookup in the path of an
ordinary retransmission would add a stall to the common case for the
sake of a rare one. A lookup that fails leaves the endpoint alone, since
an unreachable DNS server is not evidence that the peer has moved, and
discarding a working address on that basis would turn a brief outage
into a permanent one. A name that has moved to another address family is
also declined: the socket was opened in the old family and rebuilding it
is not something to do halfway through a handshake.

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

Confirmed on the target (2026-09-07) against a real TorGuard config. The
public key the gateway derived matched every earlier run made with the
key typed by hand, which is what shows the file was read correctly
rather than merely read.

That run also gives the first sight of the NAT table's headroom: 197
flows in 15.7 seconds, 749 per minute. At that rate sustained, the
30-second UDP timeout holds roughly 375 mappings — about three quarters
of the 512 entries. Nothing was dropped or evicted, but somewhere near
1000 flows per minute is where NAT_ENTRIES would need raising.

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

### Running it detached

Everything above assumes a terminal. For a gateway that has to outlive
your login there are three flags:

```
--log DISK$TOOLS:[CODE.VMSGUARD]VMSGUARD.LOG
--stop-file DISK$TOOLS:[CODE.VMSGUARD]VMSGUARD.STOP
--status 300
```

`--log` is acted on **before** anything else, ahead even of `--config`.
A detached process has no terminal, so output produced before the
redirect goes nowhere — and that used to include the config file's own
diagnostics, meaning a config that failed to parse reported the reason
to nobody and exited with an empty log. It appends rather than
truncates, so a restart adds to the record instead of erasing it.

`--status` writes one line at that interval, in the same shape as the
exit summary so there is only one format to learn:

```
14:22:07  up, 84210 captured / 84102 tunnelled / 83994 injected, 0 dropped, 4 rekeys, 61 mappings
```

It defaults to 300 seconds whenever `--log` is given. A log that says
nothing between starting and stopping cannot distinguish a working
gateway from a wedged one, which for an unattended process is the only
question that matters.

Confirmed on the target (2026-09-07), from a batch job:

```
12:20:06  ---- vmsguard gateway starting ----
...
12:25:07  up, 247 captured / 247 tunnelled / 244 injected, 0 dropped, 2 rekeys, 24 mappings
```

301 seconds, being the 300-second interval plus the one-second tick it
is checked on. Two rekeys in five minutes matches the 120-second
interval, and matches what an interactive run reported over the same
period through an entirely separate path.

The log was read with `TYPE` while the gateway held it, which is the
thing the append-and-close design exists for.

### A long run (2026-09-07)

The same job left to run for **1 h 50 m**:

```
12:20:06  ---- vmsguard gateway starting ----
12:25:07  up, 247 captured / ... 2 rekeys, 24 mappings
13:10:13  up, 3831 captured / ... 24 rekeys, 437 mappings
14:10:18  up, 11325 captured / 11324 tunnelled / 11248 injected,
          1 dropped, 54 rekeys, 27 mappings, 2 FAILED rekeys
```

It was stopped with `vmsguard_stop.com`, and finished properly:

```
stopped on request
ran for 110m 54s
captured 11362, tunnelled 11361, received 11285, injected 11285, dropped 1
rekeys: 55 succeeded, 2 failed
NAT: 11361 translated, 11285 restored, 23 of 2048 mappings live,
     dropped 1 unsupported / 0 unmatched / 0 table-full / 0 orphan fragments
     11238 new flows over the run, 101 per minute
```

**55 rekeys over 6654 seconds is one per 121 seconds**, against a
120-second interval — the timers fire at the right rate over hours, not
merely once in a five-minute sample.

**One packet dropped in 11,362**, and the summary says which kind: a
single `unsupported`, meaning NAT declined to translate it. Almost
certainly an ICMP error message, which it refuses on purpose because the
header quoted inside one would need translating too. Nothing was lost
that should have been carried.

`stopped on request` is the graceful shutdown: the stop file was seen,
the loop left by its ordinary path, and the summary was written. That
was the last part of detached operation never to have run anywhere.

Two rekeys failed, both inside the first 35 minutes, and neither
recurred in the 75 minutes after. A rekey that fails is retried after
`REKEY_TIMEOUT` and the session is good until `REJECT_AFTER_TIME`, so a
peer that misses one handshake costs nothing permanent.

**Each failure also stalled forwarding for five seconds**, because the
handshake was synchronous inside the packet loop — ten seconds of not
forwarding, in a run whose whole point was that it forwarded reliably.
That measurement is what prompted making the rekey a state machine: the
initiation goes out, the answer is picked up by the ordinary receive
path whenever it arrives, and nothing waits.

`worst pass` in the status line is how to tell. It reports the longest
single trip through the forwarding loop, which should stay near the pcap
read timeout of 50 ms and never approach a handshake timeout:

```
14:10:18  up, 11325 captured / ... 54 rekeys, worst pass 51ms
```

### IPv6

IPv6 traverses the gateway, by a route this platform makes possible and
most do not.

**Outbound needs nothing special.** An IPv6 frame from the client is
captured by pcap like any other, matched against the peer's `AllowedIPs`
by longest prefix, and encrypted. The WireGuard layer never cared which
family it was carrying.

**Inbound is the interesting half.** A decrypted IPv6 packet cannot be
put on the LAN directly: the stack will not let a program originate a
packet with a source address it does not own, and OpenVMS has no
`IPV6_HDRINCL` to ask with. So the packet is *given* to the stack
instead — wrapped in an IPv4 header, protocol 41, addressed to this
machine from the far end of a configured tunnel. The stack matches it to
that tunnel, unwraps it, and routes the IPv6 inside natively.

Nothing is forged: the injection is addressed to us, and what leaves
afterwards is the stack's own routing. See
`docs/research/driver-feasibility.md`, where the mechanism was proven
before any of this was written.

Set the tunnel up first, and tell the gateway its two ends:

```
$ iptunnel create 192.0.2.1
$ ifconfig -a                     ! which unit did it get?
$ ifconfig "IT1" ipv6 up

$ GW --config ... --encap-local 192.168.0.80 --encap-remote 192.0.2.1
```

Two things about the interface, both learned the tiresome way:

**A configured tunnel does not survive a restart of TCP/IP Services.**
Anything depending on one has to create it at startup, which is why
`vmsguard_run.com` does.

**`iptunnel` numbers upward and does not reuse freed units.** Create one
without `-I` and you get whatever comes next, which cannot be brought up
by name afterwards without looking. `vmsguard_run.com` names the unit
explicitly for that reason. `SHOW DEVICE` will not find these at all —
they are TCP/IP pseudo-interfaces, not VMS devices, so `ifconfig -a` is
the only place they appear.

The gateway is told the tunnel's *endpoints* rather than its name, so
the unit number does not matter to it.

Confirmed initialising on the target (2026-09-07):

```
  allowed-ips    : 0.0.0.0 mask 0.0.0.0
  ipv6 return    : a configured tunnel, 192.0.2.1 -> 192.168.0.80
  source NAT to  : 10.13.49.21
  handshake with 64.20.211.133:1443
    established, keepalive every 25 s
```

That run carried no IPv6 — the provider's config has no IPv6
`AllowedIPs`, so nothing matched — but it is the first on real hardware
with cryptokey routing, several peers and the IPv6 paths all compiled
in, and the IPv4 tunnel came up unchanged.

Exercising IPv6 properly needs a peer that offers it. A commercial
provider handing out one IPv4 address will not; a second WireGuard
interface on a machine you control, with an IPv6 prefix in its
`AllowedIPs`, will.

The startup header says whether it can deliver:

```
  allowed-ips    : 10.9.0.0 mask 255.255.255.0
                 : fd00:1234::/48
  ipv6 return    : a configured tunnel, 192.0.2.1 -> 192.168.0.80
```

and says so just as plainly when it cannot, rather than leaving it to be
discovered as traffic that goes out and never comes back:

```
  ipv6 return    : NOTHING. --encap-local and --encap-remote were not
                   given, so inbound IPv6 will be dropped.
```

`--client` and `--exclude` take IPv6 prefixes as readily as IPv4, so a
dual-stack client is two entries rather than a different flag.

**No NAT.** There is no NAT66 and a site-to-site link does not want one,
so IPv6 is forwarded with its addresses intact. A provider that assigns
a single IPv6 address rather than a prefix would therefore reject it —
`--tunnel-address` is IPv4 only.

**ICMPv6 Packet Too Big needs `--gateway-ip6`.** An IPv6 router may not
fragment, so a packet larger than the tunnel MTU has to be refused and
the sender told — otherwise a large flow does not slow down, it stops.
The gateway sends the message, but it needs an address to send it from,
and unlike the IPv4 side it cannot work one out: the IPv4 equivalent
learns the gateway's address from its own socket, whereas this machine
may have no IPv6 address at all and the tunnel's own is link-local,
which is the wrong scope for a client that is not on link.

    --gateway-ip6 fd00:1234::1

The error goes back the same way inbound IPv6 does — wrapped in protocol
41 and injected, for the stack to decapsulate and route to the client —
because there is no `IPV6_HDRINCL` here to put it on the LAN directly.

Without the flag the oversized packet is dropped and counted, and
startup says so:

```
  icmpv6 from    : nothing. --gateway-ip6 was not given, so an
                   oversized IPv6 packet is dropped without telling
                   the sender, and large flows will stall
```

### Several peers

A config file may hold more than one `[Peer]`. Each is a separate
tunnel with its own keys, endpoint, session, timers and `AllowedIPs`,
and each gets its own UDP socket — so a peer that is rekeying, roaming
or simply not answering affects nothing but itself.

Which tunnel a packet takes is decided by `AllowedIPs`, by longest
prefix, exactly as a routing table decides a next hop:

```
  allowed-ips    : 10.9.0.0 mask 255.255.255.0  via 192.0.2.1:51820
  allowed-ips    : 10.20.0.0 mask 255.255.0.0  via 192.0.2.2:51820
                 : 172.16.0.0 mask 255.240.0.0
```

A peer holding `10.9.0.0/24` takes that traffic even when another holds
`0.0.0.0/0`. Getting this wrong is not a loud failure — the packet goes
down the other peer's tunnel, encrypted to the wrong key, and is
discarded at the far end without a word — which is why the matching
itself is `ipv4_best_match` in `src/tun/ethip.c` with tests, rather than
a loop written inline.

**Only a config file can express several peers.** Command-line flags
configure one, and override the first peer in a file; there is no way
for a command line to say where one peer ends and the next begins
without inventing a syntax nobody would recognise.

**Source NAT works with one peer only**, and is refused with more:

```
error: source NAT works with one peer only. This config has 2.
```

`--tunnel-address` rewrites every outbound packet to a single address
and restores replies from one table, and that table cannot say which
tunnel a reply arrived through. It is also not what several peers are
for: source NAT exists because a commercial provider accepts only its
own assigned address, and a link between networks you control does not
need it.

All peers must complete their handshake at startup. A gateway that came
up with one tunnel of three would forward a third of the traffic and
drop the rest, which is harder to diagnose than not starting.

### Cryptokey routing

`AllowedIPs` is enforced in both directions, which is the whole idea it
carries in WireGuard: it says both what may be *sent* to a peer and what
that peer may claim to *be*.

The outbound half was always there — a packet is tunnelled only if its
destination falls inside the list. The inbound half was missing.
Decryption proves a packet came from the peer and says nothing about
what address the peer may put in it, so without a check a peer — or
whoever has taken it over — could inject packets bearing any source
address at all onto the LAN behind the gateway.

Now a decrypted packet whose source is outside `AllowedIPs` is dropped
and counted as `outside-allowedips`. The check runs on the packet as
decrypted, before NAT rewrites anything, because what is being validated
is what the peer sent rather than what we made of it.

With a full tunnel the list is `0.0.0.0/0` and this permits everything.
That is correct rather than pointless: such a configuration really does
authorise the peer to send as anyone, and the operator chose it.

All the `AllowedIPs` entries in a config are used, not just the first.
They appear in the startup header:

```
  allowed-ips    : 10.9.0.0 mask 255.255.255.0
                 : 192.168.7.0 mask 255.255.255.0
```

### Drops, by cause

The total on its own says a run lost something without saying what,
which for an unattended run is the only part that matters. Both the
status line and the summary now break it down, listing only the causes
that actually happened:

```
1 dropped (unmatched 1)
```

`unsupported`, `unmatched`, `table-full` and `orphan-fragment` come
straight from the NAT table's own counters rather than being tallied
again, so they cannot drift from what NAT believes. `send-failed`,
`inject-failed`, `malformed` and `too-big-to-translate` are the
gateway's own.

**The peak of 437 live mappings vindicates raising `NAT_ENTRIES`.** That
is 21% of the current 2048 and would have been 85% of the 512 it
replaced, which is where eviction starts recycling live flows. The
change was made on a measured 375-mapping estimate; a real browsing
burst went past it within the hour.

`--stop-file` names a file the gateway checks for once a second. When it
appears, the gateway shuts down through its ordinary path and writes its
summary — then removes the file, so its disappearance is the
acknowledgement and a restart does not stop immediately.

**This is why stopping it is not `STOP/IDENTIFICATION`.** Deleting the
process skips the exit handler, and with it the summary, which for a run
lasting days is the only record of what actually happened.

Three DCL procedures in `tools/gateway/` do this:

| | |
| --- | --- |
| `vmsguard_run.com` | the invocation; all site settings are symbols at the top |
| `vmsguard_start.com` | submits it as a batch job |
| `vmsguard_stop.com` | creates the stop file and waits for the acknowledgement |

```
$ SET DEFAULT DISK$TOOLS:[CODE.VMSGUARD]
$ @[.TOOLS.GATEWAY]VMSGUARD_START
```

`vmsguard_start.com` finds `vmsguard_run.com` beside itself, through
`F$ENVIRONMENT("PROCEDURE")`, rather than assuming it sits in the
repository root two directories up — which is what the first version
did, and `SUBMIT` failed with `RMS-E-FNF`. It also checks `$STATUS`
afterwards: `SET NOON` means a failed `SUBMIT` does not stop the
procedure, so without that check it printed "vmsguard submitted"
directly beneath the error saying it had not been.

Batch rather than `RUN/DETACHED`, because a batch job inherits the
submitting account's privileges — which is what packet capture and the
raw socket need. `RUN/DETACHED` would mean naming every privilege on the
command line and getting the quota list right as well.

Two things to check before relying on it, neither of which the gateway
can detect for itself:

- **The queue's CPU time limit** (`SHOW QUEUE/FULL`). A limit there will
  stop the gateway at some arbitrary hour with nothing in its own log to
  explain it.
- **Nothing restarts it.** A gateway that silently comes back after
  failing is worse than one that stays down, because the log is the only
  thing that will ever tell you it happened.

Watch it with `TYPE/CONTINUOUS`. The gateway flushes after every line it
writes, which is why it opens the log itself rather than relying on the
batch log — that one is buffered and would show nothing for minutes.

It also never holds the log open. On OpenVMS the C RTL opens files for
exclusive access, so the first version of this held the log and
`TYPE/CONTINUOUS` failed with `RMS-E-FLK, file currently locked by
another user` — a log nobody can read while the process is running is
not a log.

Sharing can be asked for, but only outside strict standard mode, and
this is built with `/STANDARD=C99` deliberately. So the gateway appends
and closes for every line instead. At a status line every five minutes
that costs nothing; `--verbose` together with `--log` is an open and
close per packet, which is a debugging combination rather than how this
runs.

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
notice.

Getting that precise took a correction. The first version asked only
whether the quoted destination was in the tunnel subnet, which under
`--tunnel-subnet 0.0.0.0/0` is no question at all — every address is —
and the first live run duly reported the OpenVMS box telling the LAN
router that the OpenVMS box was unreachable, for a closed local UDP
port. A correct answer about itself, and nothing to do with the tunnel.

Four conditions now have to hold together:

- the error comes from the gateway's own address;
- its code is a *routing* failure — net or host unreachable, net or host
  unknown, or time exceeded. Port and protocol unreachable are a host
  answering about itself. **Fragmentation-needed is excluded above all**,
  because the gateway sends those itself and captures its own injected
  packets, so counting them would report the MTU feature working as the
  stack misbehaving;
- the quoted destination survives the same exclusions the forwarding
  path applies, and is not multicast, broadcast or the peer endpoint;
- and the complaint is addressed to a host named by `--client`, since a
  complaint to anyone else is not about traffic we carry.

Under `--verbose` each one prints:

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

Whether the OpenVMS box does this at all is still unknown: the one run
that reported a count was the false positive described above. The
detection is what will make the difference visible if it happens.

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
