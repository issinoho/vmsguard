# Probe findings

One row per question per machine. Quote the line of output that settles
it. A question is answered only when both machines have a row.

Machines: **x86** = V9.2-3, VSI C V7.7-003. **I64** = rx2660,
V8.4-2L3, VSI C V7.4-001.

| # | Question | x86 | I64 | Evidence / notes |
| --- | --- | --- | --- | --- |
| 1 | All six probes build; no LINK warnings | | | `build_probes` summary line |
| 2 | `printf("%llu")` works | | | first line of each probe |
| 3 | Item-list layout is 12 bytes | | | `item list entry:` line |
| 4 | `SYI$_` items: which are declared, which accepted | | | `probe_syi` table |
| 5 | `time()` is UTC | | | `probe_syi` Clock; `probe_otlp` skew |
| 6 | `SYS$TIMEZONE_DIFFERENTIAL` defined and correct | | | `probe_syi` Clock |
| 7 | `RMI$_` items: declared, accepted, byte size | | | `probe_rmi` table |
| 8 | CPU mode counters are 10 ms ticks summed over CPUs | | | `probe_rmi` CPU section |
| 9 | `$GETRMI` works unprivileged | | | privileges line + `probe_rmi` |
| 10 | Which `RMI$_` items are counters and which gauges | | | delta column |
| 11 | `JPI$_PPGCNT`/`GPGCNT` are pages or pagelets | | | `probe_jpi` top table vs `SHOW SYSTEM` Ph.Mem |
| 12 | Processes visible unprivileged vs `SHOW SYSTEM` | | | `probe_jpi` scan counts |
| 13 | Full `$GETJPI` scan cost | | | `scan took` |
| 14 | `$DEVICE_SCAN` finds every disk in `SHOW DEVICE D` | | | `probe_dvi` vs `SHOW DEVICE D` |
| 15 | `DVI$_FREEBLOCKS` matches `SHOW DEVICE D` | | | |
| 16 | Shadow-set items available | | | |
| 17 | `DVI$_OPCNT` is cumulative | | | `probe_dvi` 5 s delta |
| 18 | TCP and HTTP exchange to the collector; HTTP 200 | | | `probe_otlp` |
| 19 | Collector shows the data points | | | collector debug output, laptop side |
| 20 | libssl image name and family found | | | `build_probes` OpenSSL line |
| 21 | TLS handshake; version and cipher | | | `probe_otlp_tls` |
| 22 | Certificate verifies with `--cafile` | | | optional, needs `collector.crt` on VMS |

## Surprises

Anything the probes showed that no question anticipated goes here, with
what it changes in the design.
