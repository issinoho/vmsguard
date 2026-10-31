# Prompts for Claude Code

Paste-ready prompts for each stage of vmsotel. Each one stands alone:
it says which files to read, so a new session needs nothing else. Use
them in order. Stage 1 can be repeated as often as the probes need.

All of them assume the session has the vmsguard repository on branch
`ccr-97df299c-rjyniw`, or the vmsotel repository once it exists.
`drafts/vmsotel/CLAUDE.md` loads automatically when Claude works in
that directory. The prompts name it anyway, because a session started
at the repository root may not have read it.

---

## 0. Starting any session

Prefix any request with this when the session is new:

```text
Read drafts/vmsotel/CLAUDE.md, drafts/vmsotel/docs/design.md and
drafts/vmsotel/docs/findings.md before doing anything. vmsotel is an
OpenTelemetry host-metrics agent for OpenVMS, in C99, at the stage
those files describe. I run everything on the VMS machines and paste
the output back; you cannot reach them. Work only inside
drafts/vmsotel/, on branch ccr-97df299c-rjyniw.
```

---

## 1. Read the probe results

After running `@[.drafts.vmsotel]build_probes/OUTPUT=probes.log RUN`
on a machine. Paste one machine per message, or both, labelled.

```text
[Stage 0 prompt]

Here is probes.log from the <x86-64 | Itanium> machine, run
<unprivileged | with privileges: ...>. The collector on the laptop
printed <paste its output, or "nothing">.

<paste probes.log>

1. Fill in docs/findings.md for this machine. Quote the line that
   settles each question. Leave a row empty where the output does not
   settle it, and say why.
2. For each item that came back "not declared" or "no", say whether
   the name is probably wrong (and what to check in the HEADERS
   output) or the item is really unavailable.
3. Fix any probe or build_probes.com bug the output reveals. Run
   `make check` and confirm that a test that should catch the bug
   fails without the fix.
4. Update docs/design.md wherever a finding changes it, and remove
   the (probe) marker from anything now answered on both machines.
5. Commit and push. Then give me the exact DCL to run next, if
   anything is needed — complete commands, no placeholders.

Do not start agent code in this stage.
```

If many items were "not declared", run
`@[.drafts.vmsotel]build_probes/OUTPUT=headers.log HEADERS` and paste
`headers.log` with this:

```text
[Stage 0 prompt]

Here is headers.log from the <machine>: the #define lines for SYI$_,
RMI$_, JPI$_ and DVI$_ from SYS$STARLET_C.TLB. Correct the item names
in probes/gen_items.py against it, regenerate with `make items`, run
`make check`, and note in docs/findings.md which names were wrong and
on which machine. Commit and push, and tell me to rerun the probes.
```

If the build failed, paste the compiler or linker messages instead and
ask for a fix. Say which machine. A fix for one machine must not break
the other, and the reply should say how that was checked.

---

## 2. Move to its own repository

Once every findings row has both machines filled in. First create an
empty GitHub repository named `vmsotel`.

```text
[Stage 0 prompt]

I have created an empty repository issinoho/vmsotel. Move
drafts/vmsotel there with its history, using
`git subtree split --prefix=drafts/vmsotel`, and push it as main.

In the new repository:
- drafts/vmsotel/CLAUDE.md becomes the root CLAUDE.md. Rewrite its
  "Where it lives" section, and copy into it the vmsguard OpenVMS
  lessons it currently refers to, because vmsguard's CLAUDE.md will no
  longer load. Keep the lessons, not the vmsguard history.
- Fix every path that assumed drafts/vmsotel/, including
  build_probes.com usage lines, README and docs/prompts.md.
- Add a LICENSE: <MIT | Apache-2.0>.
- Run `make check` there.

Then, in vmsguard, open a pull request on branch ccr-97df299c-rjyniw
that removes drafts/vmsotel and points to the new repository. Do not
merge it.
```

---

## 3. Phase 1, step by step

Phase 1 is the system metrics in the design's table, sent over plain
HTTP and TLS, by an agent running detached. Do it as four steps, each
a session or more. Each step ends with something to run, here or on
VMS.

### 3a. Encoder and model (Linux only)

```text
[Stage 0 prompt]

Start phase 1 of docs/design.md: the model and the OTLP JSON encoder.
Both are pure C99 with no I/O and no VMS dependency.

- src/model/: a snapshot struct holding everything in the design's
  metrics table, in plain C types. Include the 32-to-64-bit counter
  widening described under "Counters", with the restart rule.
- src/otlp/: encode a snapshot plus resource attributes into an
  ExportMetricsServiceRequest in OTLP JSON, into a caller-supplied
  buffer. No allocation, explicit length checks, and a clear error
  when the buffer is too small.
- tests/: unit tests for both. Include a counter wrapping at 2^32,
  an exact-fit and a one-byte-short buffer, JSON escaping of names,
  and golden payloads. Validate the golden payloads against the
  official schema with tools/fake_collector.py's validator.
- Pin the semantic-conventions version you follow in a comment, and
  in docs/design.md.

Add everything to the Makefile and `make check`. Leave the VMS build
files for 3c, but list in your reply what they will need. Confirm a
test fails when you break the code it covers. Commit and push.
```

### 3b. Transport and a fake source (Linux end to end)

```text
[Stage 0 prompt]

Phase 1, step b: the transport, and the agent running end to end on
Linux.

- src/platform/: a platform-neutral interface (connect, send,
  receive, close, UTC time, interval time, sleep), and a POSIX
  implementation. No sockaddr, fd or timeval in the header.
- src/transport/: HTTP/1.1 POST of an encoded payload, optional TLS
  through OpenSSL supporting both 3.x and 1.1.1 the way vmsguard's
  wg_crypto.c does, response handling as the design describes (200
  with partialSuccess, retry on 429/503 with Retry-After, loud failure
  on other 4xx), and the bounded drop-oldest queue.
- src/sources/fake/: a source that fills the snapshot with scripted
  values, including a counter wrap.
- src/agent/: the collect, encode, send loop, with a small key = value
  config file and the agent's own health metrics.
- tests/: transport tests against tools/fake_collector.py, extended
  as needed, including the 429/503 retry and a collector that is down.

Show it working against the fake collector. Commit and push, and tell
me how to run it against the real collector on the laptop.
```

### 3c. VMS sources and build files

```text
[Stage 0 prompt]

Phase 1, step c: the real VMS sources, using only items and behaviour
that docs/findings.md confirms on both machines. If something the
design needs is not confirmed, stop and tell me rather than guess.

- src/sources/vms/: fill the snapshot from $GETSYI, $GETRMI, $GETJPI
  (counts only, no per-process metrics yet) and $GETDVI, skipping
  shadow-set members and unmounted disks.
- Add a self-test that prints each value beside the MONITOR or SHOW
  command that shows the same number.
- Build files: build_vms.com and descrip.mms, alongside the Makefile,
  in the same edit, for everything from 3a and 3b as well. Check every
  LINK's severity in the .com file.
- Keep the stub in stub/ up to date so the VMS source builds and runs
  on Linux.

Then give me the exact DCL to build, run the self-test, and run the
agent once against the laptop collector at 192.168.0.218, on each
machine. Commit and push.
```

### 3d. Running it for real

```text
[Stage 0 prompt]

Phase 1, step d: run the agent as a service.

- A DCL procedure to start it detached (RUN/DETACHED, output to a log
  file), and the line to add to SYSTARTUP_VMS.COM.
- The startup clock check from docs/design.md "Time": refuse to run,
  saying why, if time() and $GETTIM minus the differential disagree.
- Clean shutdown on STOP/ID: lose nothing that is already queued
  without logging it.
- A short operator page in docs/: install, configure, start, stop,
  what the log means.

Give me the exact commands to install and start it on each machine,
and what to compare between MONITOR SYSTEM and the collector output
to confirm the numbers agree. Commit and push.
```

---

## 4. Asking for a review

Before moving to the next phase:

```text
[Stage 0 prompt]

Review vmsotel against its CLAUDE.md: C99 only, no I/O in the model
or encoder, a platform-neutral interface, all three build files in
step, every LINK checked, and no claim in docs/ that findings.md does
not support. List what does not comply, most serious first, then fix
what I agree to.
```
