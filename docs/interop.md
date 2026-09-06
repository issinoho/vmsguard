# Interop testing

## Result: wire compatibility confirmed

**OpenVMS x86-64 against the Linux kernel WireGuard module, over a real
network, 2026-09-06.**

```
  handshake complete
  our index      : 0xefdfdd7f
  peer index     : 0x982476b7

sending ICMP echo request through the tunnel
  10.9.0.2 -> 10.9.0.1
  echo reply received — data path works both ways

PASS — handshake completed and data path verified
```

Two pieces of evidence that the far end really was upstream WireGuard
rather than `vmsguard-responder`:

- **The peer index is random.** `vmsguard-responder` always allocates
  indices from `0xC0DE0000`. `0x982476b7` came from the kernel module.
- **The `wg` interface counted decrypted inbound packets** — the kernel
  decrypted vmsguard's traffic and handed it to the Linux IP stack,
  which generated the echo reply.

This closes the MVP: the protocol implementation is wire-compatible with
upstream WireGuard, written clean-room from the whitepaper and the Noise
specification.

### Earlier: OpenVMS to vmsguard-responder

The same client first completed a handshake against `vmsguard-responder`
on Linux, which established that the OpenVMS socket layer worked —
`poll()`, non-blocking I/O, `sendto`/`recvfrom`, `getaddrinfo` — before
a real peer was involved:

```
handshake: sending initiation (3 attempts, 5000 ms each)
  handshake complete
  our index      : 0xefd5c75f
  peer index     : 0xc0de0000

sending keepalive
  sent

sending ICMP echo request through the tunnel
  10.9.0.2 -> 10.9.0.1
  echo reply received — data path works both ways

PASS — handshake completed and data path verified
```

That exercises the OpenVMS socket layer end to end — `poll()`,
non-blocking I/O, `sendto`/`recvfrom`, `getaddrinfo` — against a
known-good peer. It does **not** establish wire compatibility with
upstream WireGuard, because both ends are vmsguard. That remains the
outstanding milestone, described below.

## Two levels of testing

The difference between them matters.

| | What it proves | What it does not |
| --- | --- | --- |
| `make loopback` | Socket layer, client state machine, and protocol work end to end over real UDP | Nothing about upstream WireGuard — both ends are our code |
| Against a real `wg` peer | **Wire compatibility with WireGuard** | — |

The in-process tests in `tests/test_proto.c` and the loopback test share a
blind spot: our initiator and our responder are written from the same
reading of the specification. A misreading would be made identically by
both halves and still pass. Only a genuine WireGuard peer settles it.

## Loopback self-test

```sh
make loopback
```

Starts `vmsguard-responder`, points `vmsguard-interop` at it over
localhost, and runs a handshake, a keepalive, and an ICMP echo through
the tunnel. Useful as a smoke test, and — once the OpenVMS build
exists — as a cross-platform test: run the responder on Linux, point the
OpenVMS client at it, and the VMS socket shim is exercised before any
real WireGuard peer is involved.

## Against a real WireGuard peer

This is the MVP acceptance test.

### 1. Generate keys

On any machine with `wg`:

```sh
wg genkey | tee client.key | wg pubkey > client.pub
wg genkey | tee server.key | wg pubkey > server.pub
```

### 2. Configure the Linux peer

`tools/interop/setup_wg_peer.sh` does this. It needs root, because it
creates a network interface:

```sh
sudo sh tools/interop/setup_wg_peer.sh up '<vmsguard-public-key>'
```

It creates `wg-vmsguard` on UDP 51820 with the given key as its only
peer, prints the peer's public key, and prints the exact OpenVMS command
to run against it. To remove everything afterwards:

```sh
sudo sh tools/interop/setup_wg_peer.sh down
```

**Keys must live under `/etc/wireguard`.** Ubuntu ships an AppArmor
profile for `/usr/bin/wg` whose only file rule is
`file rw @{etc_rw}/wireguard/{,**}`, so `wg` cannot open a key file
anywhere else. AppArmor denies by path rather than uid, so this fails
even as root, and the symptom is a bare `fopen: Permission denied` that
looks nothing like a confinement problem. The script keeps its keys in
`/etc/wireguard/vmsguard/` for that reason.

Doing it by hand is four commands; `10.9.0.0/24` is the tunnel subnet,
the peer takes `.1` and vmsguard `.2`:

```sh
ip link add dev wg0 type wireguard
ip addr add 10.9.0.1/24 dev wg0
wg set wg0 \
    listen-port 51820 \
    private-key ./server.key \
    peer "$(cat client.pub)" \
        allowed-ips 10.9.0.2/32
ip link set wg0 up
```

`allowed-ips` must cover the source address vmsguard will send from, or
the peer will decrypt the packet and then discard it. That is the most
common reason for a successful handshake followed by no echo reply.

Add `preshared-key ./psk` to the `peer` line if testing with a PSK, and
pass the same key to `--psk`.

### 3. Run vmsguard against it

```sh
./build/vmsguard-interop \
    --key      "$(cat client.key)" \
    --peer-key "$(cat server.pub)" \
    --endpoint 192.0.2.10:51820 \
    --ping     10.9.0.2 10.9.0.1
```

Expected:

```
handshake: sending initiation (3 attempts, 5000 ms each)
  handshake complete
  our index      : 0x...
  peer index     : 0x...

sending keepalive
  sent

sending ICMP echo request through the tunnel
  10.9.0.2 -> 10.9.0.1
  echo reply received — data path works both ways

PASS — handshake completed and data path verified
```

### 4. Confirm from the peer's side

```sh
wg show wg0
```

A `latest handshake` timestamp and non-zero `transfer` figures confirm
the peer accepted our handshake and our data — independent evidence, not
just our own tool reporting success.

## Interpreting failures

**`no handshake response received`** — the peer never replied, or replied
with something we rejected. Check that the peer lists our public key
(the tool prints it) under `allowed-ips`, that UDP reaches the endpoint,
and that the preshared key matches on both sides if used. A wrong peer
public key produces exactly this message too, because the peer cannot
decrypt an initiation addressed to a key it does not hold.

**`peer sent a cookie reply (it is under load)`** — the peer wants a
cookie-derived `mac2` before processing handshakes. The MVP does not
implement the cookie mechanism; `mac2` is always zero. This only happens
on a peer under load, so it is unlikely in testing, but it is a real gap
before production use.

**Handshake succeeds, no echo reply** — key agreement and transport
framing are working. Almost always `allowed-ips` on the peer not covering
the `--ping` source address, or the destination simply not answering
pings. Try `--verbose` to see the decrypted packets that did arrive.

## Known gaps

The client is an MVP and does not yet implement:

- **a replay sliding window** — only counters above the highest seen are
  accepted, so legitimately reordered packets are dropped
- **the cookie mechanism** — `mac2` is always zero
- **roaming** — the peer endpoint is fixed at startup

None of these affect a short interop test, and all are noted in the code
where they bite.

## Rekeying

Implemented, following the whitepaper's section 6.5: the session is
replaced once it reaches `REKEY_AFTER_TIME` (120s) or
`REKEY_AFTER_MESSAGES` (2^60), and refused outright past
`REJECT_AFTER_TIME` (180s). Receiving triggers a rekey slightly earlier
than sending does, so the session is replaced before the far side starts
rejecting it.

Two details worth knowing:

- **The previous keypair is retained** after a rekey, so packets already
  in flight under the old key still decrypt instead of being dropped.
  WireGuard proper keeps three keypairs; two is enough for a client that
  always initiates.
- **A failed rekey is not fatal.** While the session is still inside
  `REJECT_AFTER_TIME` the old key keeps working, and the attempt is made
  again later — a briefly unreachable peer costs no traffic. Attempts
  are paced by `REKEY_TIMEOUT` and abandoned after
  `REKEY_ATTEMPT_TIME`.

To exercise it without waiting two minutes, `vmsguard-interop` takes
`--rekey-after` and `--duration`:

```sh
./build/vmsguard-interop --key ... --peer-key ... \
    --endpoint 127.0.0.1:51820 --rekey-after 2000 --duration 12
```

```
  rekeyed (1) at 2 s, new index 0x7775d019
  rekeyed (2) at 5 s, new index 0x7775d01a
  rekeyed (3) at 8 s, new index 0x7775d01b
  rekeyed (4) at 11 s, new index 0x7775d01c

  12 keepalives sent, 0 failed, 4 rekeys
```

It fails if no rekey happens or if any send fails, so it is a genuine
check rather than a demonstration.

### Confirmed on OpenVMS against real WireGuard (2026-09-06)

```
running for 12 seconds, rekeying every 2000 ms
  rekeyed (1) at 2 s, new index 0xf04e076a
  rekeyed (2) at 5 s, new index 0xf04e076c
  rekeyed (3) at 8 s, new index 0xf04e076d
  rekeyed (4) at 11 s, new index 0xf04e076e

  12 keepalives sent, 0 failed, 4 rekeys
```

The far end was the Linux kernel WireGuard module, not
`vmsguard-responder`, so this exercises rekeying against the reference
implementation's own session handling. The peer's interface counted 22
decrypted packets across the run, confirming it accepted traffic under
every successive session rather than only the first.

It also exercises the timer path through `$GETTIM`, which is the one
piece of the platform layer that differs between the OpenVMS and POSIX
builds.
