# Compilers & languages on OpenVMS x86-64

## Confirmed on the target system (2026-09-06)

```
VSI TCP/IP Services for OpenVMS x86_64 Version V6.0-30
on a QEMU Standard PC (Q35 + ICH9, 2009) running OpenVMS V9.2-3
VSI C x86-64 V7.7-003 (GEM 50Z9T) on OpenVMS x86_64 V9.2-3
```

- **OS**: OpenVMS V9.2-3 x86-64, running under QEMU.
- **C compiler**: **VSI C V7.7-3**, GEM-based. This is the classic VSI/DEC C
  lineage, *not* the Clang-based compiler.
- **C++ compiler**: **VSI C++ V10.1-3U1** — this is the LLVM/Clang-based
  one. So C and C++ come from two different compiler lineages on this
  platform.

### Design consequence: target C99

Because the C compiler is the GEM-based VSI C rather than Clang, we should
**target C99 and not assume C11**. Practical rules for `src/`:

- No `_Generic`, no `_Static_assert`, no anonymous unions/structs
- No variable-length arrays
- No C11 atomics or `<threads.h>`
- Fixed-width types via `<inttypes.h>`/`<stdint.h>` (both confirmed present
  in the C RTL header library)
- Compile with an explicit `/STANDARD=` on VMS and `-std=c99 -pedantic` on
  the POSIX reference build, so violations are caught on Linux first

The protocol core was already going to be conservative portable C; this
just fixes the exact dialect.

### Other languages installed

Fortran V8.7-1, COBOL V3.4-3, BASIC V1.11-1, BLISS V1.15-148, Java
(OpenJDK 8 and 17), Python 3.10, Perl 5.34/5.40, PHP, Lua. Plus **X86ASM
A10.1-3** if hand-written assembly is ever wanted (it shouldn't be — OpenSSL
covers the hot paths).

### Build tooling — all questions answered

- **MMS V4.0-5** — VMS-native build tool, present.
- **GNV V3.0-2F** — GNU environment, present (so a POSIX-ish `make` path
  exists too).
- **GIT V2.44-1C** — git runs on the box, so the repo can be cloned directly
  onto OpenVMS rather than shuttling files around.
- **OpenSSH V9.9-2C** — scp/sftp available as a fallback transfer path.

Plan: a plain `Makefile` for the POSIX reference build, and a `descrip.mms`
for the OpenVMS build.

## Not available

- **Go**: no OpenVMS x86-64 port found. This rules out reusing
  `wireguard-go` directly.
- **Rust**: no OpenVMS x86-64 port found. This rules out reusing
  `boringtun` directly.

**Conclusion**: a from-scratch WireGuard implementation on OpenVMS x86-64
has to be written in **C** (or C++). This is the deciding factor behind the
plan's Phase 1 approach (clean-room C protocol core against OpenSSL 3).

## Threading

- POSIX Threads Library (`PTHREAD$RTL`) exists on x86-64. Linking with
  `/THREADS_ENABLE` lets an application receive upcalls from VMS and/or map
  user threads to multiple kernel threads.
- Release notes for VSI OpenVMS x86-64 V9.2 mention known issues including
  "unexpected access violations" in pthreads — severity/scope unclear from
  public summaries alone.
- **Action item**: verify pthreads stability directly on the target system
  before committing to a pthreads-based event loop. VMS-native `$QIO`/AST
  asynchronous I/O is the fallback/likely-more-idiomatic model and is
  well-proven on VMS generally.
- **Confirmed present 2026-09-06**: `SYS$LIBRARY:SYS$STARLET_C.TLB` on the
  target system contains `PTHREAD`, `PTHREAD_D4`, `PTHREAD_DEBUG`,
  `PTHREAD_EXC`, `PTHREAD_EXCEPTION`, `PTHREAD_TRACE`, plus `CMA` and `TIS`
  (see `data/starlet_headers.txt`). Headers shipping is not evidence of
  stability, so the action item above stands.
- **Design consequence**: `poll()` is confirmed present in the C RTL (see
  `tcpip-stack.md`), so the intended design is a single-threaded
  `poll()`-driven event loop with no pthreads dependency at all. That
  sidesteps the pthreads stability question entirely for the MVP.

## To verify on the target system

- [ ] `CC/VERSION` and `CXX/VERSION` output
- [ ] `PRODUCT SHOW PRODUCT` for full list of installed compilers/languages
- [ ] Whether GNV (GNU utilities for OpenVMS) is installed, and what POSIX
      build tooling it brings (gmake, autoconf, etc.)
- [ ] MMS/MMK availability (VMS-native build tools) as an alternative to
      GNU make
- [ ] Whether a CMake port exists/works reliably on OpenVMS x86-64
