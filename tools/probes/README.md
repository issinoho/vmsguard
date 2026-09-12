# Probe kit

Three standalone programs that answer the remaining Phase 0 questions by
testing the target system directly, rather than inferring from headers.

| Probe | Answers | Matters for |
| --- | --- | --- |
| `probe_openssl.c` | Does OpenSSL 3.0.21 really provide working X25519, ChaCha20-Poly1305, BLAKE2s and HKDF? | Settled — the MVP works |
| `probe_sockets.c` | Non-blocking + `poll()`, and is `SOCK_RAW` usable? | `SOCK_RAW` gates the gateway |
| `probe_pcap.c` | Does libpcap actually capture and inject? | Gates the gateway |

The MVP has since been proven end to end against real WireGuard, so the
first two are historical for the protocol. What still matters is the
`SOCK_RAW` section of `probe_sockets` and all of `probe_pcap`: those are
the two mechanisms the gateway design in `docs/gateway.md` rests on, and
neither has been exercised on OpenVMS.

Run them before writing gateway code. The SLIP investigation is the
cautionary tale — framing was written and tested before anyone checked
whether a driver existed, and none did.

On OpenVMS both are built by `@build_vms`:

```
$ RUN [.build]PROBE_SOCKETS
$ RUN [.build]PROBE_PCAP
```

Expect to need privilege: the Sockets manual says `SOCK_RAW` requires
SYSPRV, and packet capture will likely want something similar.

## Building on Linux first

Worth doing before touching OpenVMS — it catches ordinary mistakes on a
platform with better diagnostics, and `-std=c99 -pedantic` enforces the
dialect the VSI C compiler expects.

Build `probe_openssl` both ways. Its pre-3.0 branch is what an OpenVMS
system with only 1.1.1 compiles, and every call in it still exists in
3.x, so forcing the define here runs that branch for real rather than
merely compiling it. It was 3.0-only until an Itanium build against
1.1.1 stopped on `<openssl/params.h>`.

```sh
cc -std=c99 -pedantic -Wall -Wextra -o probe_openssl probe_openssl.c -lcrypto
cc -std=c99 -pedantic -Wall -Wextra -DVMSGUARD_LEGACY_OPENSSL \
   -o probe_openssl_legacy probe_openssl.c -lcrypto
cc -std=c99 -pedantic -Wall -Wextra -o probe_sockets probe_sockets.c
cc -std=c99 -pedantic -Wall -Wextra -D_DEFAULT_SOURCE \
   -o probe_pcap probe_pcap.c -lpcap
```

`probe_pcap` needs `-D_DEFAULT_SOURCE` on glibc because strict `-std=c99`
hides the BSD `u_char`/`u_int` types that `<pcap.h>` uses. This is a Linux
quirk; it doesn't apply on OpenVMS.

It also includes a time header before `<pcap.h>`, because
`struct pcap_pkthdr` has a `struct timeval` member that `<pcap.h>` does
not define itself. Without that, VSI C reports `%CC-E-INCOMPMEM`.
OpenVMS supplies it from `<time.h>`; glibc from `<sys/time.h>`.

### Verification status

- `probe_openssl` — **built and passing** on Linux (OpenSSL 3.5.5)
- `probe_sockets` — **built and passing** on Linux
- `probe_pcap` — **syntax-checked only.** No libpcap was available on the
  development machine, so it was compiled against a stub header matching
  the exact signatures from the VMS `PCAP` module, including the
  non-`const` `pcap_sendpacket(pcap_t *, u_char *, int)` that OpenVMS
  declares. It has not been run anywhere.

## Building on OpenVMS

First find the right logical names — these vary between OpenSSL packagings
and I'd rather you check than have me guess:

```dcl
$ SHOW LOGICAL SSL3$*
$ DIRECTORY SYS$SHARE:SSL3$*
$ DIRECTORY SYS$SHARE:TCPIP$LIBPCAP*
```

Then, adjusting the include directory and shareable image names to match
what those show:

```dcl
$ CC /STANDARD=C99 /INCLUDE_DIRECTORY=SSL3$INCLUDE PROBE_OPENSSL.C
$ LINK PROBE_OPENSSL, SYS$INPUT: /OPTIONS
SSL3$LIBCRYPTO_SHR/SHAREABLE
$
$ CC /STANDARD=C99 PROBE_SOCKETS.C
$ LINK PROBE_SOCKETS
$
$ CC /STANDARD=C99 PROBE_PCAP.C
$ LINK PROBE_PCAP, SYS$INPUT: /OPTIONS
TCPIP$LIBPCAP_SHR/SHAREABLE
```

Run them with:

```dcl
$ RUN PROBE_OPENSSL
$ RUN PROBE_SOCKETS
$ RUN PROBE_PCAP
```

`probe_pcap` takes an optional interface name; with no argument it uses the
first non-loopback device pcap reports:

```dcl
$ PROBE_PCAP == "$SYS$DISK:[]PROBE_PCAP.EXE"
$ PROBE_PCAP "IE0"
```

## Privileges

`probe_pcap` and the `SOCK_RAW` section of `probe_sockets` will almost
certainly need elevated privileges. If either reports a failure that looks
privilege-related, retry from a suitably privileged account before
concluding the facility is missing — both probes say so in their output
rather than reporting a hard failure.

## What a pass does and does not mean

`probe_pcap` printing `INJECTION AVAILABLE` confirms capture and injection
work. It does **not** mean a transparent tunnel is feasible: pcap sees
copies of packets rather than claiming them, so suppressing the plaintext
original on the outbound path remains unsolved. See
`docs/research/driver-feasibility.md`.

## probe_inject6 — can we forge an IPv6 source?

Asks the one question an IPv6 gateway depends on, before anything is
built on the answer.

Injecting a packet that arrived through the tunnel means writing a
header whose source we do not own. For IPv4 that is `IP_HDRINCL`, and
`probe_inject` proved it works here. IPv6 has no portable equivalent:
Linux has no `IPV6_HDRINCL` at all, the BSDs mostly removed theirs, and
what VSI TCP/IP Services does is unknown. A declaration would settle
nothing either way — `pcap_sendpacket` is declared on this system and
returns "socket is not connected".

```
$ pinj6 := $sys$disk:[.build]probe_inject6.exe
$ pinj6 --src fd00::1 --dst fd00::2
```

`--src` must be an address this machine does **not** own; forging it is
the whole question. Watch the destination:

```
tcpdump -ni any icmp6 and host fd00::1
```

The packet it builds was checked byte for byte against an independent
implementation, checksum included, so a packet that fails to arrive is
the stack's answer rather than a malformed datagram. That distinction is
the entire value of the probe: a send that returns success and delivers
nothing is what cost this project a week over SLIP.
