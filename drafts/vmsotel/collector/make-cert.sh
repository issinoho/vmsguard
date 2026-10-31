#!/bin/sh
# Self-signed certificate for the collector's TLS receiver, valid for
# the laptop's address as the probes reach it. probe_otlp_tls reports
# it as unverified unless given --cafile collector.crt, which is
# expected; the handshake is the thing under test.
set -e
cd "$(dirname "$0")"
openssl req -x509 -newkey rsa:2048 -nodes -days 90 \
    -subj "/CN=vmsotel-test-collector" \
    -addext "subjectAltName=IP:192.168.0.218" \
    -keyout collector.key -out collector.crt
chmod 644 collector.key   # the collector container runs as non-root
echo "wrote collector.crt and collector.key"
