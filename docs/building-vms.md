# Building on OpenVMS x86-64

First run on a real OpenVMS x86-64 system on 2026-09-06. The protocol
core and client compiled cleanly on the first attempt; two problems
turned up and both are fixed. The build has not yet been carried all the
way through to a linked executable.

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

**Start with `@build_vms.com`.** It has fewer moving parts.

```
$ @build_vms          ! build everything
$ @build_vms TEST     ! build, then run the protocol self-tests
$ @build_vms CLEAN    ! remove build products
```

`descrip.mms` has since been checked against the VSI DECset *Guide to
the Module Management System*, so it is no longer guesswork, but it has
still never been run. Four things that manual settled, all of which the
first draft had wrong:

- Comments are `!`, not `#`.
- **A hyphen as the last character of any line — a comment included — is
  a continuation character.** Section dividers ending in dashes would
  have silently swallowed the following line.
- The target macro is `$(MMS$TARGET)`; `$@` is a make-ism and does not
  exist in MMS.
- `$(CC)`, `$(LINK)`, `$(MMS$SOURCE)`, `.FIRST` and the `@` (silent) and
  `-` (ignore) action-line prefixes are all real and used as documented.

## What the first real build found

### `SSL3$INCLUDE` works as-is

The protocol core compiled including `<openssl/evp.h>` without
complaint, so the include logical is defined and correct. No change
needed.

### The crypto image needs an explicit path

Naming it bare as `SSL3$LIBCRYPTO_SHR` made the linker look in the
current directory:

```
%ILINK-F-OPENIN, error opening DISK$TOOLS:[CODE.VMSGUARD]SSL3$LIBCRYPTO_SHR.EXE;
-RMS-E-FNF, file not found
```

There is no such logical name; the file lives in
`SYS$COMMON:[SYSLIB]`, reachable as
`SYS$LIBRARY:SSL3$LIBCRYPTO_SHR.EXE`. `build_vms.com` now searches for
it across `SYS$LIBRARY:` and `SYS$SHARE:`, including the `_SHR32`
variants, and fails with a clear message naming what it tried.
`descrip.mms` cannot search, so it is fixed to the confirmed path.

### `gettimeofday` does not exist on OpenVMS

```
%CC-I-IMPLICITFUNC, In this statement, the identifier "gettimeofday"
is implicitly declared as a function.
```

Informational rather than fatal, but an implicitly declared function
would likely have failed at link time. `wg_time_ms` now uses `$GETTIM`
under `#ifdef __VMS`, which returns 100-nanosecond intervals since
17-NOV-1858 — divide by 10000 for milliseconds. It is a core system
service, so availability is not in question.

That is the only VMS-specific branch in the platform layer so far.
Everything else — sockets, `poll()`, `bind`, `recvfrom`, `fcntl` — was
accepted unchanged, which is a good sign for the bet described below.

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
