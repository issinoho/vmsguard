# Using a commercial VPN provider

Analysis of what stands between vmsguard and consuming a typical
provider configuration — worked through against a TorGuard config, but
the shape is common to Mullvad, IVPN, ProtonVPN and the rest.

The config in question:

```
[Interface]
PrivateKey  = <redacted>
ListenPort  = 59612
MTU         = 1390
DNS         = 10.8.0.1
Address     = 10.13.127.177/24

[Peer]
PublicKey           = <redacted>
AllowedIPs          = 0.0.0.0/0
Endpoint            = 64.20.211.133:1443
PersistentKeepalive = 25
```

## Confirmed: the protocol side works against a provider (2026-09-06)

`vmsguard-interop` on OpenVMS, pointed at the TorGuard endpoint over the
public internet:

```
  peer endpoint  : 64.20.211.133:1443
  local port     : 59612

handshake: sending initiation (3 attempts, 5000 ms each)
  handshake complete
  our index      : 0xf0eda799
  peer index     : 0xec3359c0

sending ICMP echo request through the tunnel
  10.13.127.177 -> 10.8.0.1
  echo reply received — data path works both ways
```

A handshake with a commercial provider, and an ICMP echo answered by
their DNS server through the tunnel. That is a third independent
WireGuard implementation, after the Linux kernel module and
`vmsguard-responder`, and the first over a real internet path rather
than a LAN.

No cookie reply was issued, so cookie support is not needed to reach
this provider — it drops off the critical path.

**Everything remaining is gateway plumbing, not protocol work.**

## The short answer

**As written, this config cannot work on OpenVMS**, and not because of
anything missing from vmsguard. `AllowedIPs = 0.0.0.0/0` describes a
*full-tunnel client*: every packet the host originates goes through the
VPN. That requires a TUN device to claim outbound traffic before the
stack transmits it, and OpenVMS has none — see
[`research/slip-tunnel.md`](research/slip-tunnel.md).

**What is achievable is OpenVMS as a VPN gateway**: LAN clients route
through the OpenVMS box, which tunnels their traffic to the provider.
That is a genuinely useful arrangement and the gateway already does most
of it. The gaps below are what stand in the way.

## Gaps, in order of how much they block

### 1. Source NAT — the big one

A provider assigns one tunnel address, here `10.13.127.177/24`, and
their server's cryptokey routing will only accept packets from us that
are sourced within it. Tunnel a packet sourced `192.168.0.218` and the
far end decrypts it, finds the source outside what our key is permitted,
and discards it silently.

So the gateway must **rewrite the source address** of outbound packets
to the assigned tunnel address, and reverse the translation on the way
back. That means connection tracking: a table keyed on protocol, ports
and addresses, with the original source stored so replies can be
restored.

This is what any consumer VPN router does, and it is the largest single
piece of work here. It also brings the usual complications — ICMP error
payloads carrying an embedded original header that needs translating
too, and table expiry.

Without it, nothing else matters: the provider will drop everything.

### 2. Promiscuous capture with `AllowedIPs = 0.0.0.0/0`

The gateway currently filters captured frames on **destination** only.
That was safe for a test subnet nobody else used. With a full tunnel it
is not: pcap capture is promiscuous, so a `0.0.0.0/0` filter would match
every IPv4 frame on the segment, including traffic between machines that
have nothing to do with vmsguard.

Tunnelling other people's packets to a commercial VPN would be both a
correctness disaster and a privacy one.

The gateway therefore needs a **source filter** — an explicit list of
client addresses it forwards for — before it can be pointed at
`0.0.0.0/0`. This is not optional.

### 3. Routing loop

With a `0.0.0.0/0` destination filter, the gateway would capture its own
encrypted UDP packets heading to `64.20.211.133:1443` and tunnel those
too, recursively.

The endpoint address must be excluded from capture. A source filter
(gap 2) mostly handles this incidentally, since the outer packets are
sourced from the OpenVMS box rather than a client, but it deserves an
explicit exclusion rather than relying on that.

### 4. MTU and fragmentation

The config specifies `MTU = 1390`, which is well below the LAN's 1500.
A 1500-byte packet from a LAN client becomes 1560 bytes once wrapped
(20 IP + 8 UDP + 32 WireGuard), exceeding the path.

vmsguard does not fragment, and does not send ICMP "fragmentation
needed" back to clients, so large packets would fail silently — the
classic symptom being that small requests work and large transfers hang.

The minimum viable answer is to emit ICMP Type 3 Code 4 with the correct
next-hop MTU when an oversized packet arrives with DF set, so client
path-MTU discovery adapts. Fragmenting ourselves is the fuller answer.

Note also that OpenVMS offers **no per-socket DF control** — there is no
`IP_MTU_DISCOVER` or `IP_DONTFRAG` (see
[`research/tcpip-stack.md`](research/tcpip-stack.md)), so the outer
packets' DF behaviour is whatever the stack chooses.

### 5. PersistentKeepalive

`PersistentKeepalive = 25` keeps a NAT mapping alive between us and the
provider. Without it, a stateful firewall or NAT in the path drops the
mapping after a minute or two of silence and inbound packets stop
arriving.

Straightforward to implement: send an empty transport packet when
nothing has been sent for the interval. The keepalive mechanism already
exists — only the timer is missing.

### 6. Replay sliding window

Currently a strict highest-counter check, which drops any packet
arriving out of order. On a loopback or a quiet LAN that never happens.
Across the public internet to a commercial endpoint it certainly will,
and every reordered packet is a retransmission.

This moves from "nice to have" to "actively harmful" the moment a real
WAN path is involved.

### 7. Cookie replies

`mac2` is always zero, so a provider under load that demands a
cookie-derived MAC will refuse our handshakes. vmsguard detects the
cookie reply and reports it rather than retrying blindly, so the failure
is at least legible — but it is a hard failure.

Commercial endpoints are exactly the kind that get loaded.

### 8. Config file parsing

vmsguard takes command-line arguments only. Consuming a `.conf` directly
is convenience rather than capability, but it is what anyone will expect,
and it avoids transcribing keys by hand onto a DCL command line where
quoting matters.

`DNS` and `Address` would be recorded for the operator's use rather than
acted on — vmsguard has no interface to assign an address to, and no
resolver configuration to change.

## What works already

Worth being clear that the protocol side is not the problem:

- The keys, endpoint and listen port are all supported as-is.
- The handshake is wire-compatible with the reference implementation.
- Rekeying works and is verified against real WireGuard.
- Capture, encryption and raw-socket injection are all proven on
  OpenVMS.

A provider endpoint is just another WireGuard peer. `vmsguard-interop`
pointed at `64.20.211.133:1443` with these keys should complete a
handshake today, which would be a worthwhile first test — it isolates
"can we talk to this provider at all" from everything above.

## Suggested order

1. ~~Handshake against the provider.~~ **Done** — see above.
2. ~~Source filtering in the gateway.~~ **Done.** `--client` takes a
   repeatable address or subnet, and is *required* when the tunnel
   subnet is wider than /8. The gateway also refuses to tunnel packets
   addressed to the peer endpoint, so its own outer traffic cannot loop.
3. ~~PersistentKeepalive.~~ **Done.** `--keepalive` on the gateway and
   the interop client. Verified idle: four packets in nine seconds at a
   two-second interval, none with it disabled.
4. ~~Replay window.~~ **Done.** A 64-bit sliding window replaces the
   strict counter check, so reordered packets are accepted and
   duplicates still rejected. 20 checks cover reordering, duplicates,
   window edges, large forward jumps and counters near the 64-bit
   ceiling.
5. **Source NAT with connection tracking.** The substantial one, and now
   the next thing standing in the way.
6. **ICMP fragmentation-needed.** Enough to make large transfers work.
7. **Config parsing.** Last, because it is ergonomics.

Cookie support is off the critical path: this provider did not challenge
us. Worth revisiting only if one does.

### One gap the config found before it was even run

TorGuard writes base64 keys **without** the trailing `=`, 43 characters
rather than 44, and `wg_key_from_base64` rejected them outright. It
would have failed with "not a valid base64 key" and looked like a
transcription error.

`wg(8)` accepts both forms, so the strictness was wrong rather than
defensive. Fixed, and cross-checked against `wg(8)` on 50 keypairs.

A reminder that generated test data is not the same as real-world
input.
