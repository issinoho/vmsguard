# vmsotel — design draft

An agent that reports OpenVMS host metrics to an OpenTelemetry
Collector. Working name; this lives in vmsguard's tree only until it has
its own repository.

Status: **draft, nothing built.** Every claim below about what VMS
returns is a question for `probes/` until the probes have been run on
both machines. They are marked *(probe)*.

## Goal

A VMS system shows up in Grafana, Prometheus, Datadog or Splunk the
same way a Linux host running the collector's `hostmetrics` receiver
does: CPU by mode, memory, paging, processes, disks, uptime. The same
dashboards should mostly just work.

### Not in the first version

- Tracing or an instrumentation library for applications (later, see
  Phases)
- Logs (OPCOM, audit) — phase 3
- Pulling metrics from other cluster members. Each node runs its own
  agent and reports itself.
- Receiving anything. The agent only pushes.
- Prometheus scrape endpoint. Pushing OTLP needs no listener on VMS and
  no firewall change, and the collector can expose Prometheus itself.

## Shape

```
 +------------------------ VMS node --------------------------+
 |                                                            |
 |  sources/        $GETRMI  $GETSYI  $GETJPI  $GETDVI         |
 |   (VMS only)        \        |        |        /           |
 |                      v       v        v       v            |
 |  model/          snapshot: plain structs, no VMS types     |
 |   (pure)                    |                              |
 |                             v                              |
 |  otlp/           JSON encoder -> ExportMetricsServiceRequest|
 |   (pure)                    |                              |
 |                             v                              |
 |  transport/      HTTP/1.1 POST over TCP, optional TLS       |
 |   (platform)                |                              |
 +-----------------------------|------------------------------+
                               v
                OpenTelemetry Collector (Linux), port 4318
                               |
               Prometheus / Grafana / Splunk / ...
```

It follows vmsguard's rules, for vmsguard's reasons:

- **The encoder and the model do no I/O** and have no VMS dependency, so
  they are tested exhaustively on Linux. That covers most of the code.
- **Sources are the only VMS-specific code**, behind an interface that
  fills a snapshot struct. On Linux, a fake source fills it with
  scripted values, so the whole agent runs end to end against a real
  collector without a VMS machine.
- **The transport goes through a small platform interface**: connect,
  send, receive, close, time, sleep. No `sockaddr` in the interface, so
  a `$QIO` version stays possible.
- **C99, VSI C**, the same compiler settings as vmsguard
  (`/STANDARD=C99 /PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES`, and
  `_SOCKADDR_LEN`).
- **Three build files** from the start: `Makefile`, `build_vms.com`,
  `descrip.mms`.

### Why not opentelemetry-cpp

It needs C++14 (very likely out of reach for Itanium's compiler), and its OTLP
exporters pull in gRPC, protobuf, abseil and libcurl. The OTLP JSON
encoding over HTTP needs none of that: the payload is text, and the
collector does all the fan-out. The JSON form is a stable part of the
OTLP specification, not a debugging aid.

### Licensing

OpenTelemetry's specification and `.proto` files are Apache-2.0, so
unlike vmsguard there is no clean-room constraint: the message
definitions can be read and followed directly. The agent itself would be
MIT like vmsguard, which combines with Apache-2.0 without difficulty.
*Decision for the owner.*

## The wire format

OTLP/HTTP, `POST /v1/metrics`, `Content-Type: application/json`, body
an `ExportMetricsServiceRequest` in the protobuf JSON mapping. The rules
that bite:

- field names are lowerCamelCase (`timeUnixNano`, `dataPoints`)
- enums are integers (`"aggregationTemporality": 2`)
- 64-bit integers, which covers every timestamp and every `asInt`, are
  **decimal strings**
- unknown fields are an error to a strict parser

The encoder writes into a caller-supplied buffer with explicit length
checks, no allocation, in the style of vmsguard's wire code. Its tests
compare against fixtures that have been parsed by protobuf's own JSON
parser against the official schema (`tools/fake_collector.py` does
this with the `opentelemetry-proto` package). That check is a
development-time tool; nothing on VMS needs Python.

Responses: 200 is success, but the body may carry `partialSuccess` with
`rejectedDataPoints`, which is logged. 429 and 503 are retried with
backoff, honouring `Retry-After`. Any other 4xx is a bug in the encoder
and is logged loudly, not retried.

No compression in version 1. A full host export is a few kilobytes
every 30 to 60 seconds; gzip can come later if zlib proves to be
available on both machines.

## Time

OTLP timestamps are Unix nanoseconds, UTC. VMS system time is **local**
time. If the C RTL's `time()` follows the timezone differential, it is
UTC and usable directly; if a system's timezone is misconfigured, every
point lands hours out and is silently mis-graphed, which is worse than
an error. *(probe: `probe_syi` checks `time()` against
`$GETTIM − SYS$TIMEZONE_DIFFERENTIAL`; `probe_otlp` measures skew
against the collector's `Date` header.)*

The agent will compare the two at startup and refuse to run if they
disagree by more than a few seconds, saying why.

## Counters

Every VMS counter of interest is cumulative since boot (or process
start), so the metrics are OTLP **cumulative sums**. The agent stores no
history and computes no rates; the backend does that. `startTimeUnixNano`
is the boot time from `SYI$_BOOTTIME` for system counters, and
`JPI$_LOGINTIM` for per-process ones.

**Longword counters wrap.** A 32-bit count of 10 ms ticks wraps after
497 days, and if the system-wide CPU totals sum over all CPUs, a
four-CPU system wraps after about 124 days of uptime. VMS systems run that long
routinely. The agent widens each 32-bit counter to 64 bits by adding
2^32 whenever a reading is lower than the last. A restart of the agent
loses the widening, so after a restart it reports a new start time
instead of a value that has gone backwards. *(probe: `probe_rmi`
reports each item's size.)*

## Metrics, version 1

Names follow the OpenTelemetry semantic conventions for `system.*`
where one fits, so that existing host dashboards work. The conventions
have been renaming attributes (`state` became `cpu.mode`, and so on), so
the exact set is pinned to one semantic-conventions release at
implementation time.

| Metric | Type | Unit | Source | Notes |
| --- | --- | --- | --- | --- |
| `system.cpu.time` | sum | s | `RMI$_CPU*` | attribute `cpu.mode`; see mapping below. *(probe: unit and whether summed over CPUs)* |
| `system.cpu.logical.count` | gauge | {cpu} | `SYI$_ACTIVECPU_CNT` | |
| `system.memory.usage` | gauge | By | `RMI$_FRLIST`, `RMI$_MODLIST`, `SYI$_MEMSIZE` | `system.memory.state` = free, used, `modified` (VMS-specific: the modified page list) |
| `system.memory.limit` | gauge | By | `SYI$_MEMSIZE` × `SYI$_PAGE_SIZE` | |
| `system.paging.faults` | sum | {fault} | `RMI$_FAULTS`, `RMI$_PREADS` | hard faults = page reads; soft = the rest |
| `system.paging.operations` | sum | {operation} | `RMI$_PREADIO`, `RMI$_PWRITIO` | |
| `system.paging.usage` | gauge | By | `SYI$_PAGEFILE_PAGE`, `SYI$_PAGEFILE_FREE` | *(probe: items exist on both versions)* |
| `system.process.count` | gauge | {process} | `RMI$_COM`, `LEF`, `HIB`, … | attribute `process.state` = the VMS scheduling state, lower-cased |
| `system.uptime` | gauge | s | `SYI$_BOOTTIME` | |
| `system.filesystem.usage` | gauge | By | `DVI$_FREEBLOCKS`, `DVI$_MAXBLOCK` | per mounted disk; 512-byte blocks; `system.device`, `system.filesystem.mountpoint` = volume label |
| `system.disk.operations` | sum | {operation} | `DVI$_OPCNT` | per disk; no read/write split exists, so no `disk.io.direction` |
| `openvms.io.direct` | sum | {operation} | `RMI$_DIRIO` | no semconv equivalent |
| `openvms.io.buffered` | sum | {operation} | `RMI$_BUFIO` | |

Per-process metrics (`process.cpu.time`, `process.memory.usage`) come
in phase 2, filtered by name. A wildcard scan of every process every
interval, with a series per PID, is the cardinality mistake that gets
an agent switched off.

### CPU modes

| VMS mode | `cpu.mode` |
| --- | --- |
| user | `user` |
| kernel | `kernel` |
| executive | `executive` |
| supervisor | `supervisor` |
| interrupt stack | `interrupt` |
| MP synchronisation | `mpsynch` |
| compatibility | `compat` (always zero after VAX; dropped if so) |
| idle | `idle` |

`user`, `kernel`, `interrupt` and `idle` are standard values. The others
are VMS's own and are kept rather than folded into `system`, because the
split between kernel and executive time is what a VMS administrator
actually reads in MONITOR.

### Resource attributes

| Attribute | Source |
| --- | --- |
| `service.name` | `vmsotel` |
| `host.name` | `SYI$_NODENAME` |
| `host.arch` | `SYI$_ARCH_NAME` → `amd64` / `ia64` |
| `host.type` | `SYI$_HW_NAME` |
| `os.type` | `openvms` (not in the semconv enum; custom values are allowed) |
| `os.version` | `SYI$_VERSION`, trimmed |
| `openvms.cluster.member` | `SYI$_CLUSTER_MEMBER` |
| `openvms.scsnode` | `SYI$_SCSNODE` |

### Disks and shadow sets

Shadow-set members are skipped and the virtual unit (`DSAn:`) is
reported, or a mirrored volume counts twice. Unmounted disks are
skipped. *(probe: `probe_dvi` prints the shadow items per disk.)*

`DVI$_FREEBLOCKS` and `DVI$_MAXBLOCK` are longwords: correct up to 2
TiB per volume. Larger volumes, if the system has any, need a 64-bit
item. *(probe: `DVI$_VOLSIZE`)*

## Running it

- A detached process, started from `SYSTARTUP_VMS.COM` the same way
  vmsguard's gateway is (`RUN/DETACHED`, output to a log file).
- Configuration in a small `key = value` file: collector URL, interval
  (default 60 s), TLS CA file, extra resource attributes, process
  filter.
- **Privilege**: none, if the probes show that `$GETRMI` needs none.
  Per-process metrics need WORLD to see other users' processes; that is
  phase 2 and opt-in. *(probe: `probe_rmi` run unprivileged;
  `probe_jpi` count against `SHOW SYSTEM`)*
- Collection takes a snapshot, encodes it, sends it. If the collector is
  unreachable, a bounded queue keeps the last N exports (default 10) and
  drops the oldest. A VMS production box must never fill its disk or
  its memory because a monitoring server is down.
- The agent's own health goes in its own metrics: export failures,
  queue length, collection time.

## TLS

Through the installed OpenSSL, choosing 3.x or 1.1.1 the way vmsguard
does, with the same care over the `OPENSSL` logical and pointer size.
Certificates are verified by default against a configured CA file; no
"skip verification" option in the agent itself. *(probe: `probe_otlp_tls`)*

## Testing

| Layer | Where | How |
| --- | --- | --- |
| encoder | Linux | unit tests; output checked against the official schema |
| model, counter widening | Linux | unit tests, including a wrap at 2^32 |
| agent end to end | Linux | fake source → real collector |
| sources | VMS | self-test that prints each value beside its MONITOR / SHOW equivalent |
| whole thing | VMS | `MONITOR SYSTEM` beside the Grafana panel |

The rule from vmsguard holds: watch both ends. A 200 from the
collector proves only that the JSON parsed. The collector's debug output
and the numbers in MONITOR are the other end.

## Phases

0. **Probes** — `probes/`, this draft. Answer the *(probe)* questions on
   both machines.
1. **System metrics** — the table above, plain HTTP and TLS, running
   detached.
2. **Per-process metrics** — filtered by process name or username;
   needs WORLD.
3. **Logs** — OPCOM messages and the audit journal as OTLP logs
   (`/v1/logs`). Needs its own probes: OPCOM via a mailbox, audit via
   the audit server's listener mailbox.
4. **Application instrumentation** — a small C library VMS applications
   link to emit their own metrics and spans through the same transport.

## Open questions

| Question | Answered by |
| --- | --- |
| Which `RMI$_` items exist on V9.2-3 and V8.4-2L3, and their sizes | `probe_rmi`, `HEADERS` |
| Are the CPU mode counters 10 ms ticks summed over all CPUs | `probe_rmi` |
| Does `$GETRMI` need privilege | `probe_rmi` run unprivileged |
| Is `time()` UTC | `probe_syi`, `probe_otlp` |
| `JPI$_PPGCNT`: pages or pagelets | `probe_jpi` beside `SHOW SYSTEM` |
| How many processes an unprivileged scan sees | `probe_jpi` |
| Does `$DEVICE_SCAN` by class find every disk; shadow items | `probe_dvi` beside `SHOW DEVICE D` |
| Does `printf` support `%llu` | every probe's first line |
| TCP and an HTTP exchange to the collector | `probe_otlp` |
| libssl image names; TLS handshake | `probe_otlp_tls`, `build_probes.com` |
| Is zlib available (gzip) | later |
| License | owner |
