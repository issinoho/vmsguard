# CLAUDE.md — vmsotel

Working notes for Claude Code. `README.md` says what is here and how to
run it; `docs/design.md` is the design. This file is about how to
change it without wasting a round trip to a machine you cannot reach.

vmsotel is an OpenTelemetry host-metrics agent for OpenVMS: it reads
the system services and posts OTLP/HTTP JSON to a collector on Linux.
It is **at the probe stage**. No agent code exists yet.

## Where it lives

For now, `drafts/vmsotel/` inside the vmsguard repository, on a branch,
only so the probes reach the VMS machines by `git`. It shares no code
with vmsguard. vmsguard's root `CLAUDE.md` also loads; its OpenVMS
lessons apply here, but its **clean-room rule does not** — see
Licensing. When this moves to its own repository
(`git subtree split --prefix=drafts/vmsotel`), this file becomes its
root `CLAUDE.md`.

Do not touch anything outside `drafts/vmsotel/`, and run vmsguard's
`make test` before committing anyway: it is cheap and proves nothing
was disturbed.

## Build and test

```sh
cd drafts/vmsotel
make check     # build all probes; run them against stub/; run the
               # OTLP probes against tools/fake_collector.py
```

`PYTHON=<venv>/bin/python make check` with `opentelemetry-proto`
installed in that venv makes the fake collector parse every payload
against the official OTLP schema. Without it, only the JSON syntax is
checked, and it says so. Use the schema check for anything that changes
a payload.

The four system-service probes compile without `-pedantic`, because
pedantic C rejects `$` in identifiers and VMS names cannot avoid it.
Everything else keeps `-std=c99 -pedantic -Wall -Wextra -Werror`. Do
not weaken that further.

`make items` regenerates `probes/items_*.h` and the stub headers from
`probes/gen_items.py`. Edit the generator, not the output.

## The machines

You cannot reach any of them. The workflow: develop and test on Linux,
the user runs on OpenVMS and pastes the output back.

| | x86-64 | Itanium rx2660 |
| --- | --- | --- |
| OS | V9.2-3 | V8.4-2L3 |
| C | VSI C V7.7-003 | VSI C V7.4-001 |
| TCP/IP | V6.0-30 | V6.0-31 |
| LAN interface | `IE0`, 192.168.0.80 | `WE1` |

The laptop running the test collector is **192.168.0.218**. The probes
default to it: port 4318 for plain HTTP, 4319 for TLS.

Do not assume a finding on one machine holds on the other. The point
of having two is that they differ in architecture, OS version and
compiler.

## Hard constraints

- **C99, not C11.** VSI C is GEM-based. No `_Generic`,
  `_Static_assert`, anonymous structs or unions, VLAs, C11 atomics or
  `<threads.h>`.
- **No C++.** That is why this is not a port of opentelemetry-cpp.
- **Item lists assume 32-bit pointers.** `probe_ile3` is
  item_list_3 only when `sizeof(void *) == 4`. The system-service code
  builds without `/POINTER_SIZE`. Code linking the OpenSSL `..._SHR32`
  images uses `/POINTER_SIZE=32`. Mixing the two crashes inside OpenSSL
  at a sign-extended address.
- **Encoder and model do no I/O** and have no VMS dependency, so they
  are tested on Linux. VMS-specific code lives in the sources only.
- **The platform interface stays platform-neutral**: no `sockaddr`, no
  file descriptors, no `timeval` in the header, so a `$QIO`
  implementation remains possible.
- **Wire formats are written explicitly.** No packed structs, and
  byte order is always stated.

## Lessons inherited from vmsguard — each cost a round trip

- **Probe before building.** A facility being declared in a header
  proves nothing on VMS. Each *(probe)* in `docs/design.md` must be
  answered on both machines before code depends on it.
- **Give complete commands, never placeholders.** `<collector ip>` in
  a pasted command wastes a round trip. Look the value up.
- **Undefined symbols are link *warnings* on VMS.** The image builds
  and crashes when it reaches the missing routine. Every LINK in a
  `.com` file checks `$SEVERITY` and deletes the image on a warning.
  `ON ERROR` does not catch warnings.
- **A new source file or dependency touches three build files**:
  `Makefile`, the DCL procedure, and (once it exists) `descrip.mms`.
  Only the first runs here, and the other two fail quietly on a
  machine you cannot see. Open all three in the same edit.
- **The OpenSSL header version is chosen by the logical name
  `OPENSSL`,** not by `/INCLUDE_DIRECTORY`. The kits ship headers flat
  in `[INCLUDE]`. Define it `/JOB` to match the image being linked, and
  deassign it on every exit path. `build_probes.com` shows how.
- **Case on the DCL command line.** Unquoted arguments to a C foreign
  command arrive lowercased; git has been seen preserving case.
  Quote anything case-sensitive. Type git subcommands in lowercase.
- **`gettimeofday` is absent.** Use `time()` for UTC seconds, once
  `probe_syi` has shown it is UTC, or `$GETTIM` for intervals.
- **Commands for the user to paste must not depend on the default
  directory.** `build_probes.com` sets default to its own directory and
  restores it on exit.

Unproven on VMS so far, and checked by the probes: `printf("%llu")`
(nothing in vmsguard has printed a `long long` there), and `atoll`
(avoided, `strtol` is used).

## Testing

- **Watch both ends.** A 200 from the collector proves only that the
  JSON parsed. The collector's debug output, and MONITOR or SHOW on VMS,
  are the other end.
- **A test that cannot fail is not a test.** Confirm a new check fails
  without the fix. The CPU-unit check in `probe_rmi` was confirmed
  that way, against a stub reporting one CPU's ticks.
- **The stub only tests logic.** `stub/vmsstub.c` invents its values
  and item codes. Its job is to exercise the probes' branches — refused
  items, longword-only buffers, NOPRIV and SUSPENDED processes,
  unmounted disks — not to say what VMS returns.

## Licensing

OpenTelemetry's specification and `.proto` files are Apache-2.0, so
they can be read and followed directly. vmsguard's clean-room rule
exists because of WireGuard's GPLv2 kernel module and does not apply
here.

vmsotel itself is **MIT** (`LICENSE`), as vmsguard is. Following the
OTLP specification and `.proto` files to write our own code is fine.
Copying Apache-2.0 code verbatim is not, unless its licence notice
travels with it — so write the code, don't paste it.

## Recording what the probes show

Probe results go in `docs/findings.md`, one row per question per
machine, with the pasted evidence quoted. Update `docs/design.md`
wherever a finding changes it, and remove the *(probe)* marker. Never
mark a question answered from one machine's output.

## Commits

Explain why, not just what — especially the reasoning behind a VMS
workaround, since that is what makes it defensible later. Record what
was verified and how, and say plainly what has not run on VMS.
