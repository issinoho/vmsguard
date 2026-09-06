# Building on OpenVMS x86-64

**Neither build file has been run on a real system.** They were written
from the VSI TCP/IP Services Sockets API manual and the toolchain
inventory in `docs/research/`, but everything here is a first attempt.
Expect to adjust it. This document records what is known, what is
guessed, and what to check first.

## Get the source onto the box

`VSI X86VMS GIT V2.44-1C` is installed, so clone directly:

```
$ git clone https://github.com/issinoho/vmsguard
$ set default [.vmsguard]
```

That avoids any question of file transfer mangling line endings.

## Two build paths

| | Confidence | Notes |
| --- | --- | --- |
| `@build_vms` | Higher | Uses only `CC` and `LINK` |
| `$ MMS` | Good | Syntax checked against the MMS manual |

**Start with `@build_vms.com`.** It has fewer moving parts. `descrip.mms`
has since been checked against the VSI DECset *Guide to the Module
Management System*, so it is no longer guesswork, but it has still never
been run.

Four things that manual settled, all of which the first draft had wrong:

- Comments are `!`, not `#`.
- **A hyphen as the last character of any line — a comment included — is
  a continuation character.** Section dividers ending in dashes would
  have silently swallowed the following line.
- The target macro is `$(MMS$TARGET)`; `$@` is a make-ism and does not
  exist in MMS.
- `$(CC)`, `$(LINK)`, `$(MMS$SOURCE)`, `.FIRST` and the `@` (silent) and
  `-` (ignore) action-line prefixes are all real and used as documented.

```
$ @build_vms          ! build everything
$ @build_vms TEST     ! build, then run the protocol self-tests
$ @build_vms CLEAN    ! remove build products
```

## Check these first

Both build files start with configuration that is very likely to need
changing:

```
$ SHOW LOGICAL SSL3$*
$ DIRECTORY SYS$SHARE:SSL3$*
```

`SSL3` is OpenSSL 3.0.21, the LTS branch, and is what the build assumes.
`SSL31` (3.1.4) is also installed if 3.0 turns out to be missing
something. The two names the build needs are the include directory
(`SSL3$INCLUDE`) and the crypto shareable image (`SSL3$LIBCRYPTO_SHR`) —
there may be a `_SHR32` variant, and the correct one depends on pointer
size.

## What the build does, and why

### `/DEFINE=(_SOCKADDR_LEN)`

Required, not optional. Section 1.4.1 of the Sockets API manual: this
selects the BSD Version 4.4 socket structures. The platform layer uses
`sockaddr_in6` and `sockaddr_storage`, which only exist in that form.
Without this define the platform layer will not compile.

### `/STANDARD=C99`

`VSI C x86-64 V7.7-003` is GEM-based, not Clang, so C99 is the ceiling
and the code was written to stay inside it — no `_Generic`, no
`_Static_assert`, no anonymous unions, no VLAs. The POSIX build enforces
this with `-std=c99 -pedantic` so violations surface on Linux first.

If `/STANDARD=C99` rejects something, `/STANDARD=RELAXED` is the fallback.

### No socket library on the LINK line

Section 1.4 of the manual shows `$ LINK MAIN.OBJ` with nothing else for
a sockets program: the run-time library `TCPIP$IPC_SHR` is picked up
automatically. Only OpenSSL needs an options file. `TCPIP$LIB.OLB` in
`TCPIP$LIBRARY` exists if it turns out something is missing.

### The POSIX platform layer is used as-is

`src/platform/posix/wg_platform_posix.c` is compiled directly rather
than writing a VMS-specific shim first. That is a deliberate bet: BSD
sockets, `poll()`, `getaddrinfo()`, `fcntl()` and `ioctl()` were all
confirmed present in the OpenVMS C RTL header inventory, and the file
was written to avoid anything Linux-specific.

Unix-style include paths like `<netinet/in.h>` should resolve: VSI C
looks up the last component of the path in its text libraries, where the
module is named `IN`. The header inventory in
`docs/research/data/decc_headers.txt` lists the flat module names.

If it does not build, a VMS-specific implementation belongs in
`src/platform/vms/`, exposing exactly the functions in
`src/platform/wg_platform.h` — that header is the whole surface, and it
deliberately contains no `sockaddr`, no fd and no `timeval`, so a
`$QIO`-based implementation is equally possible.

## Once it builds

```
$ RUN [.build]TEST_PROTO
```

92 checks, all of which pass on Linux. Any failure here is a genuine
platform difference and worth investigating carefully — most likely
candidates are endianness assumptions (there should be none; all
conversion is explicit) or an OpenSSL algorithm missing from the VMS
build, which `tools/probes/probe_openssl.c` tests directly.

Then, keys:

```
$ VG_KEY := $SYS$DISK:[.build]VMSGUARD_KEY.EXE
$ VG_KEY GENKEY
```

Then the cross-platform test, before involving real WireGuard: run
`vmsguard-responder` on Linux, point the OpenVMS `vmsguard_interop` at
it, and the VMS socket layer is exercised end to end. See
`docs/interop.md`.

## Known unknowns

- The OpenSSL shareable image name and pointer-size variant — the most
  likely thing to need changing.
- Whether `poll()` behaves as expected on VMS sockets —
  `tools/probes/probe_sockets.c` answers this directly and is worth
  running first.
- Whether `getaddrinfo()` is present. If not, the fallback is
  `gethostbyname()`, which is certainly available (`NETDB` is in the
  header inventory). Only `wg_endpoint_resolve` would change.
- Executable names use underscores rather than the hyphens the POSIX
  build uses, since hyphens are awkward to type in DCL.
