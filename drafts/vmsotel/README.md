# vmsotel (draft)

An OpenTelemetry host-metrics agent for OpenVMS, at the probe stage.
It sits in vmsguard's tree only so the probes can travel to the VMS
machines by `git pull`; it shares no code with vmsguard and will move
to its own repository (`git subtree split --prefix=drafts/vmsotel`
keeps its history).

MIT licensed (`LICENSE`).

- `CLAUDE.md` — working notes for Claude Code sessions
- `docs/design.md` — the design, and the questions the probes answer
- `docs/findings.md` — what the probes showed, per machine
- `docs/prompts.md` — paste-ready prompts for each stage
- `probes/` — six probes: four system-service probes, and the OTLP
  export without and with TLS
- `collector/` — collector configuration for the laptop
- `tools/fake_collector.py` — a schema-checking stand-in collector for
  Linux testing
- `stub/` — Linux stand-ins for the VMS system services, so the probes
  run here first

## On Linux

```sh
cd drafts/vmsotel
make check
```

That builds every probe, runs the four system-service probes against
the stub, and runs `probe_otlp` and `probe_otlp_tls` against the fake
collector — including the cases that must fail (an HTTP 503, an hour
of clock skew, plain HTTP to a TLS port). With the
`opentelemetry-proto` Python package installed
(`PYTHON=/path/to/venv/bin/python make check`) the fake collector
parses every payload against the official schema; without it, only the
JSON syntax is checked, and it says so.

## On the laptop: the collector

The OTLP probes post to `192.168.0.218`, ports 4318 (plain) and 4319
(TLS).

```sh
cd drafts/vmsotel/collector
./make-cert.sh
docker run --rm -p 4318:4318 -p 4319:4319 \
  -v "$PWD/collector.yaml:/etc/otelcol/config.yaml:ro" \
  -v "$PWD/collector.crt:/etc/otelcol/collector.crt:ro" \
  -v "$PWD/collector.key:/etc/otelcol/collector.key:ro" \
  otel/opentelemetry-collector:0.111.0
```

If the laptop runs a firewall, ports 4318 and 4319 must be open to the
LAN (`sudo ufw allow 4318:4319/tcp` with ufw). Leave the collector's
output in view: each probe's data points appear there, and that is the
other end to watch.

Without Docker, `tools/fake_collector.py --port 4318` will do for the
plain-HTTP probe.

## On OpenVMS

Same commands on both machines, from the top of the vmsguard checkout.
The probes are on the branch `ccr-97df299c-rjyniw`, not on `main`:

```dcl
$ git fetch origin ccr-97df299c-rjyniw
$ git checkout ccr-97df299c-rjyniw
$ @[.drafts.vmsotel]build_probes/OUTPUT=probes.log RUN
$ type probes.log
```

That builds the six probes, runs them, and runs `SHOW SYSTEM` and
`SHOW DEVICE D` beside the probes that need comparing with them. Run it
**without** elevated privileges first; whether the probes need any is
one of the questions.

If many items come back "not declared", this lists what the system
headers actually contain:

```dcl
$ @[.drafts.vmsotel]build_probes/OUTPUT=headers.log HEADERS
```

## Verified

- All six probes build with `-std=c99 -Wall -Wextra -Werror` on Linux
  (`probe_otlp` with `-pedantic` too). The four system-service probes
  drop `-pedantic` only because it rejects `$` in identifiers, which VMS
  names cannot avoid.
- The system-service probes run against `stub/vmsstub.c`, including the
  refused-item, longword-retry, NOPRIV/SUSPENDED and unmounted-disk
  paths. The CPU-unit check was confirmed to fail when the stub reports
  one CPU's ticks against two active CPUs.
- `probe_otlp` and `probe_otlp_tls` pass all seven fake-collector
  cases, with every payload parsed by protobuf against
  `opentelemetry-proto` 1.27.0.

Not verified: anything on VMS. The item codes, header names and service
signatures are from documentation and memory; that is what the probes
are for. Nor has the collector configuration been run, because no
collector binary could be run here.
