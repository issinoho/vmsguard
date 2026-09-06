# Probe kit

Three standalone programs that answer the remaining Phase 0 questions by
testing the target system directly, rather than inferring from headers.

| Probe | Answers | Blocks the MVP? |
| --- | --- | --- |
| `probe_openssl.c` | Does OpenSSL 3.0.21 really provide working X25519, ChaCha20-Poly1305, BLAKE2s and HKDF? | **Yes** |
| `probe_sockets.c` | Does the non-blocking + `poll()` event loop design hold? | **Yes** |
| `probe_pcap.c` | Does libpcap actually capture and inject? | No — Phase 2 only |

The first two gate the MVP. The third only informs the Phase 2 transparent
tunnelling question, so a failure there is disappointing rather than
blocking.

## Building on Linux first

Worth doing before touching OpenVMS — it catches ordinary mistakes on a
platform with better diagnostics, and `-std=c99 -pedantic` enforces the
dialect the VSI C compiler expects.

```sh
cc -std=c99 -pedantic -Wall -Wextra -o probe_openssl probe_openssl.c -lcrypto
cc -std=c99 -pedantic -Wall -Wextra -o probe_sockets probe_sockets.c
cc -std=c99 -pedantic -Wall -Wextra -D_DEFAULT_SOURCE \
   -o probe_pcap probe_pcap.c -lpcap
```

`probe_pcap` needs `-D_DEFAULT_SOURCE` on glibc because strict `-std=c99`
hides the BSD `u_char`/`u_int` types that `<pcap.h>` uses. This is a Linux
quirk; it shouldn't apply on OpenVMS.

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
