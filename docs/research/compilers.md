# Compilers & languages on OpenVMS x86-64

Findings from public sources (2025-2026); not yet confirmed on the target
system.

## Available

- **C** and **C++**: VSI's compiler for x86-64 is LLVM/Clang-based with
  OpenVMS-specific extensions (e.g. VSI C++ A10.1-3, tracking a fairly
  recent Clang). VSI's stated approach for the x86 port was to build
  clang/LLVM on Linux, then produce x86-native OpenVMS object libraries and
  the compiler itself from that.
- **Fortran**: available.
- COBOL and BASIC: were reported "in progress" on some cross-tool paths;
  status on native x86-64 needs re-checking against current VSI release
  notes.

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
