#!/usr/bin/env python3
"""A stand-in OTLP/HTTP collector for testing probe_otlp on Linux.

It accepts POST /v1/metrics with Content-Type application/json, and
checks the body the way a real collector would: parsed into the
official ExportMetricsServiceRequest message with protobuf's JSON
parser, which rejects unknown fields, wrong types and badly encoded
64-bit integers. That needs the opentelemetry-proto package; without
it only the JSON syntax and the outline are checked, and it says so.

    fake_collector.py --port 4318            serve until interrupted
    fake_collector.py --selftest PLAIN TLS   run both probe images
                                             against it, including the
                                             cases that must fail

This is development tooling only. The real test is a real collector:
see collector/collector.yaml.
"""

import argparse
import email.utils
import http.server
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time

try:
    from google.protobuf import json_format
    from opentelemetry.proto.collector.metrics.v1 import metrics_service_pb2
    HAVE_PROTO = True
except ImportError:
    HAVE_PROTO = False


def validate(body):
    """Return (ok, message, number of data points)."""
    try:
        doc = json.loads(body)
    except ValueError as e:
        return False, f"not JSON: {e}", 0
    if HAVE_PROTO:
        msg = metrics_service_pb2.ExportMetricsServiceRequest()
        try:
            json_format.Parse(body, msg)
        except json_format.ParseError as e:
            return False, f"schema: {e}", 0
        points = 0
        for rm in msg.resource_metrics:
            for sm in rm.scope_metrics:
                for m in sm.metrics:
                    kind = m.WhichOneof("data")
                    if kind is None:
                        return False, f"metric {m.name} has no data", 0
                    dps = getattr(m, kind).data_points
                    for dp in dps:
                        if dp.time_unix_nano == 0:
                            return False, f"{m.name}: zero timeUnixNano", 0
                    points += len(dps)
        return True, "valid ExportMetricsServiceRequest", points
    if "resourceMetrics" not in doc:
        return False, "no resourceMetrics", 0
    return True, "JSON syntax only (opentelemetry-proto not installed)", -1


class State:
    """What the handler should do, and what it saw."""
    status = 200
    date_offset = 0          # seconds added to the Date header
    last = None              # (ok, message, points) of the last request


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("collector: " + (fmt % args) + "\n")

    def date_time_string(self, timestamp=None):
        return email.utils.formatdate(time.time() + State.date_offset,
                                      usegmt=True)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        ctype = self.headers.get("Content-Type", "")
        if self.path != "/v1/metrics":
            result = (False, f"wrong path {self.path}", 0)
        elif ctype != "application/json":
            result = (False, f"wrong Content-Type {ctype!r}", 0)
        else:
            result = validate(body)
        State.last = result
        sys.stderr.write(f"collector: {result[1]}, {result[2]} points\n")

        status = State.status if result[0] else 400
        reply = b"{}" if status == 200 else json.dumps(
            {"code": 3, "message": result[1]}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(reply)


def start(tls_dir=None):
    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    if tls_dir:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(tls_dir, "collector.crt"),
                            os.path.join(tls_dir, "collector.key"))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def make_cert(d):
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "1", "-subj", "/CN=fake-collector",
         "-addext", "subjectAltName=IP:127.0.0.1",
         "-keyout", os.path.join(d, "collector.key"),
         "-out", os.path.join(d, "collector.crt")],
        check=True, capture_output=True)


def run_probe(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=30)
    return p.returncode, p.stdout


def selftest(plain, tls):
    failures = 0

    def expect(name, args, want_ok, must_contain=()):
        nonlocal failures
        State.last = None
        rc, out = run_probe(args)
        good = (rc == 0) == want_ok and all(s in out for s in must_contain)
        if want_ok and State.last is not None and not State.last[0]:
            good = False
        print(f"{'ok  ' if good else 'FAIL'}  {name}")
        if not good:
            failures += 1
            print(out)

    if not HAVE_PROTO:
        print("note  opentelemetry-proto not installed: payload checked "
              "for JSON syntax only")

    srv, port = start()
    base = ["--host", "127.0.0.1", "--port", str(port)]

    State.status, State.date_offset = 200, 0
    expect("plain export accepted", [plain] + base, True,
           ["HTTP 200", "clock agrees"])

    State.status = 503
    expect("plain export: a 503 is reported as failure", [plain] + base,
           False, ["HTTP status 503"])

    State.status, State.date_offset = 200, 3600
    expect("plain export: an hour of skew is reported as failure",
           [plain] + base, False, ["clock skew: ours minus collector's = -36"])
    State.date_offset = 0

    expect("plain image refuses --tls", [plain, "--tls"] + base, False)
    srv.shutdown()

    with tempfile.TemporaryDirectory() as d:
        make_cert(d)
        srv, port = start(d)
        base = ["--host", "127.0.0.1", "--port", str(port), "--tls"]
        expect("TLS export accepted, unverified without --cafile",
               [tls] + base, True, ["TLS handshake", "not verified"])
        expect("TLS export verified with --cafile",
               [tls] + base + ["--cafile", os.path.join(d, "collector.crt")],
               True, ["certificate verified"])
        expect("plain HTTP to a TLS port fails",
               [plain, "--host", "127.0.0.1", "--port", str(port)], False)
        srv.shutdown()

    print(f"\n{'PASS' if failures == 0 else 'FAILURES'}: {failures}")
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=4318)
    ap.add_argument("--selftest", nargs=2, metavar=("PLAIN", "TLS"))
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest(*a.selftest))
    srv = http.server.HTTPServer(("0.0.0.0", a.port), Handler)
    print(f"fake collector on :{a.port}, schema check "
          f"{'on' if HAVE_PROTO else 'OFF'}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
