# Candidate architecture: SLIP over a pseudo-terminal as a TUN substitute

**Status: SLIP confirmed present; the pseudo-terminal question is still
open.** This is the strongest lead for giving vmsguard a real network
interface without writing a kernel driver.

**Confirmed 2026-09-06**: SLIP still exists in VSI TCP/IP Services
V6.0-30 on OpenVMS x86-64. `TCPIP SET INTERFACE SL0` was accepted as a
command and rejected only on the device argument:

```
$ TCPIP SET INTERFACE SL0 /HOST=10.9.0.2 /NETWORK_MASK=255.255.255.0 -
        /SERIAL_DEVICE=TTA0
%TCPIP-E-INTEERROR, error processing interface request
-TCPIP-E-INVQUAL, invalid qualifier value for /SERIAL_DEVICE
-SYSTEM-W-NOSUCHDEV, no such device available
```

`NOSUCHDEV` refers to `TTA0`, which does not exist on that system — the
interface type and the qualifier itself were both accepted. That removes
the first risk: SLIP had not been dropped from the current release.

## The problem it solves

The transparent-tunnel problem has three steps. Capture and injection both
have available mechanisms (pcap, and raw sockets with `IP_HDRINCL`), but
**suppression** — stopping the plaintext original from also being
transmitted — had no mechanism, because pcap sees *copies* of packets rather
than claiming them. There was also nothing for the routing table to point
at, since OpenVMS has no TUN device.

SLIP over a pseudo-terminal addresses both at once.

## The mechanism

OpenVMS TCP/IP Services supports SLIP (Serial Line IP) on **any standard
OpenVMS terminal device**:

```
TCPIP> SET INTERFACE SL0 /HOST=<tunnel-ip> /NETWORK_MASK=<mask> -
_TCPIP>               /SERIAL_DEVICE=<device>
```

`/SERIAL_DEVICE` takes an OpenVMS device name — the manual's example is
`TTA3`. OpenVMS also has a pseudo-terminal driver (`PTD$` services;
`PTDDEF` is confirmed present in `SYS$LIBRARY:SYS$STARLET_C.TLB` on the
target system, see `data/starlet_headers.txt`), which creates `FTAn:`
devices that present as terminals but are driven by a user-mode process.

Wire the two together:

1. vmsguard creates a pseudo-terminal via `PTD$CREATE`, yielding `FTAn:`.
2. SLIP is configured on that device: `SET INTERFACE SL0 /SERIAL_DEVICE=FTAn`.
3. The stack now has a **real point-to-point IP interface** `SL0` with the
   tunnel's IP address.
4. Routes are pointed at it, via `SIOCADDRT` (see `tcpip-stack.md`) or
   `TCPIP SET ROUTE`.
5. Traffic routed to `SL0` is SLIP-framed by the stack and written to the
   pseudo-terminal, where **vmsguard reads it** — encrypts it, sends it over
   the WireGuard UDP socket.
6. Inbound: vmsguard decrypts, SLIP-frames the plaintext IP packet, and
   writes it to the pseudo-terminal. The stack receives it as if it had
   arrived on `SL0`.

This is the classic pre-TUN tunnelling technique from Unix, assembled
entirely from parts OpenVMS already ships.

## Why this is better than the pcap approach

| | pcap capture/suppress/inject | SLIP over pty |
| --- | --- | --- |
| Suppression | **unsolved** | not needed — traffic is *claimed*, not copied |
| Something to route to | nothing exists | a real `SL0` interface |
| Layer | 2 (Ethernet frames) | 3 (IP packets) |
| MAC/ARP handling | required | not required |
| Kernel driver | not needed | not needed |

The decisive difference is step 5: packets routed to `SL0` go to the
pseudo-terminal *instead of* out a physical NIC. There is no plaintext
original left to suppress.

## Framing: implemented and tested

`src/tun/slip.c` implements RFC 1055 framing, independent of OpenVMS so
it can be tested on Linux. 15 checks cover escaping, one-byte-at-a-time
streaming, back-to-back datagrams, oversized frames and buffer limits.

Doing this before the spike was worthwhile: the tests caught a decoder
bug where a delivered packet was left in the buffer, so the next frame's
leading `END` reported it a second time and the following datagram was
appended to the stale bytes. Only the back-to-back test exposed it. Had
that gone undetected, it would have surfaced on OpenVMS as SLIP
"nearly working", which is a far worse place to debug it.

## The assumption that decides this

**Does SLIP accept a pseudo-terminal (`FTAn:`) rather than a real terminal
(`TTAn:`)?**

The manual says "any standard OpenVMS terminal device", and a pseudo-terminal
presents as a terminal device, so it *should* qualify. But this is not
stated explicitly and some SLIP implementations on other platforms require a
real terminal driver. **This is untested and the whole approach depends on
it.** Test it before building anything on this design.

## Other things to verify

- **Is SLIP still present in TCP/IP Services V6.0-30 on x86-64?** The
  management manual documents version 5.7 on IA-64/Alpha. SLIP is an old
  facility and could have been dropped. Check `TCPIP SET INTERFACE SL0` is
  accepted on the target.
- Does `PTD$CREATE` work as expected on x86-64?
- What privileges are needed for both halves?
- Throughput. Every packet crosses the terminal driver with SLIP byte
  stuffing. This may be slow. Acceptable for a proof of concept; unknown for
  production.

## Known constraints

- **MTU is 1006 bytes.** Per the manual: "The TCP/IP Services implementation
  of SLIP accepts 1006-byte datagrams and does not send more than 1006 bytes
  in a datagram." So the tunnel interior MTU is 1006, well below a typical
  1420 WireGuard MTU. Note this is *not* a fragmentation risk on the outer
  path — a 1006-byte inner packet plus WireGuard's 32-byte overhead, 8 bytes
  UDP and 20 bytes IP is 1066, comfortably inside a 1500-byte Ethernet MTU.
  It costs throughput efficiency, not correctness.
- **IPv4 only.** SLIP carries no IPv6. The tunnel interior would be v4-only,
  though the outer WireGuard transport could still run over either.
- **PPP is not an option**: the manual states PPP is available for OpenVMS
  Alpha systems only. SLIP is the candidate.
- SLIP framing is RFC 1055: `END` (0xC0) terminates, `ESC` (0xDB) escapes,
  with `DB DC` and `DB DD` for literal END and ESC bytes. CSLIP header
  compression is available via `/COMPRESS` but only helps TCP headers, and
  would have to be implemented on our side too if enabled — leave it off
  initially.

## Next step

A small spike, independent of the protocol core:

1. Create a pseudo-terminal with `PTD$CREATE`.
2. Attempt `TCPIP SET INTERFACE SL0 /SERIAL_DEVICE=FTAn: /HOST=... /NETWORK_MASK=...`.
3. If accepted, `ping` the tunnel address from the OpenVMS box and see
   whether SLIP-framed ICMP appears on the pseudo-terminal.

If a SLIP-framed echo request shows up, Phase 2 is a userspace project and
no kernel driver is needed. If SLIP rejects the pseudo-terminal, fall back to
the pcap investigation or the proxy model.
