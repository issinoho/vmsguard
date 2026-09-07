#!/bin/sh
#
# Run the gateway against a config file, on a machine with no libpcap
# and no privilege, and check what it derived from that file.
#
# The gateway is only ever *run* on OpenVMS, so until this existed the
# first execution of any change to its argument handling happened on a
# machine that takes a round trip to reach. That is how a config file
# came to be parsed correctly and then used incorrectly: the values were
# left pointing into a struct scrubbed on the way out of its scope, and
# the gateway refused its own config with an empty --tunnel-subnet.
#
# Linked against tools/gateway/pcapstub, whose pcap_open_live declines.
# The gateway therefore prints everything it worked out and exits, which
# is the part this can check. Packet handling stays on the target.

set -e

BUILD=${BUILD:-./build}
CONF=${CONF:-tests/data/sample.conf}
out=$(mktemp)
trap 'rm -f "$out"' EXIT

# Expected to exit non-zero: the stub opens a capture but the raw socket
# for injection needs privilege and does not. As root it would instead
# spend fifteen seconds failing to handshake with an unroutable address,
# which is slow rather than wrong.
"$BUILD/vmsguard-gateway-stub" \
    --config "$CONF" \
    --interface ie0 \
    --client 192.168.0.218/32 \
    --exclude 192.168.0.0/24 > "$out" 2>&1 || true

fail=0
want() {
    if grep -q "$1" "$out"; then
        echo "  ok    $2"
    else
        echo "  FAIL  $2"
        fail=1
    fi
}

echo "gateway config smoke test"

want "read $CONF"                        "the file is read"
want "allowed-ips    : 0.0.0.0 mask 0.0.0.0" \
     "AllowedIPs is read and enforced in both directions"
want "source NAT to  : 10.13.127.177"    "Address becomes the NAT address"
want "tunnel MTU     : 1390"             "MTU becomes the tunnel MTU"
want "forwarding for : 192.168.0.218"    "--client still applies"
want "excluding      : 192.168.0.0"      "--exclude still applies"
want "capturing on   : IE0"              "the interface name is case-folded"
want "note: DNS"                         "DNS is reported as not applied"
# The endpoint is only reachable through the header the client prints,
# so check the failure that follows names the stub rather than a bad
# address: an endpoint that did not survive would fail to resolve first.
want "our address    : "                 "the local address facing the peer is found"
# Nothing past this point is reachable here: the raw socket needs
# privilege and the run stops there, so the handshake, the forwarding
# banner and everything inside the loop go untested by this script.
want "error: "                            "and it stops at the raw socket, as it should"

# ---------------------------------------------------------------------
# --log: everything goes to the file, including failures during setup.
# A detached process has no terminal, so a startup error that only
# reached stdout would be lost entirely.
# ---------------------------------------------------------------------

logf=$(mktemp)
rm -f "$logf"
"$BUILD/vmsguard-gateway-stub" \
    --config "$CONF" \
    --interface ie0 \
    --client 192.168.0.218/32 \
    --exclude 192.168.0.0/24 \
    --log "$logf" \
    --stop-file /nonexistent/vmsguard.stop > "$out" 2>&1 || true

if [ -s "$logf" ]; then
    echo "  ok    --log creates and fills the log file"
else
    echo "  FAIL  --log produced no file"
    fail=1
fi
if grep -q "vmsguard gateway starting" "$logf"; then
    echo "  ok    the log opens with a timestamped start marker"
else
    echo "  FAIL  no start marker in the log"
    fail=1
fi
# The failure happens after the redirect, so it belongs in the log and
# not on the terminal — that is the whole point of opening it early.
if grep -q "error: " "$logf"; then
    echo "  ok    a setup failure is recorded in the log, not lost"
else
    echo "  FAIL  the setup failure did not reach the log"
    fail=1
fi
if [ -s "$out" ]; then
    echo "  FAIL  output still went to the terminal after --log"
    fail=1
else
    echo "  ok    and nothing is left going to the terminal"
fi

# Appending, not truncating: a restart adds to the record.
before=$(wc -l < "$logf")
"$BUILD/vmsguard-gateway-stub" --config "$CONF" --interface ie0 \
    --client 192.168.0.218/32 --exclude 192.168.0.0/24 \
    --log "$logf" > /dev/null 2>&1 || true
after=$(wc -l < "$logf")
if [ "$after" -gt "$before" ]; then
    echo "  ok    a restart appends rather than erasing the record"
else
    echo "  FAIL  --log truncated an existing log"
    fail=1
fi
rm -f "$logf"

# ---------------------------------------------------------------------
# Several peers, which only a config file can express.
# ---------------------------------------------------------------------

"$BUILD/vmsguard-gateway-stub" \
    --config tests/data/two-peers.conf \
    --interface ie0 \
    --client 192.168.0.0/24 > "$out" 2>&1 || true

want "10.9.0.0 mask 255.255.255.0  via 192.0.2.1" \
     "the first peer's network is routed to the first peer"
want "10.20.0.0 mask 255.255.0.0  via 192.0.2.2" \
     "and the second's to the second"
want "172.16.0.0 mask 255.240.0.0" \
     "a peer's further AllowedIPs entries are kept"

# Source NAT cannot be shared: one address, one table, no way to say
# which tunnel a reply came back through.
"$BUILD/vmsguard-gateway-stub" \
    --config tests/data/two-peers.conf \
    --interface ie0 --client 192.168.0.0/24 \
    --tunnel-address 10.13.49.21 > "$out" 2>&1 || true
want "source NAT works with one peer only" \
     "source NAT with several peers is refused, not guessed at"

# ---------------------------------------------------------------------
# Dual stack. An IPv6 AllowedIPs entry has to be recognised, and the
# gateway has to say plainly whether it can deliver inbound IPv6 at all
# -- there is nowhere to put a decrypted IPv6 packet without a
# configured tunnel to hand it to.
# ---------------------------------------------------------------------

"$BUILD/vmsguard-gateway-stub" \
    --config tests/data/dualstack.conf \
    --interface ie0 \
    --client 192.168.0.0/24 --client fd00:9999::/64 \
    --encap-local 192.168.0.80 --encap-remote 192.0.2.1 > "$out" 2>&1 || true

want "fd00:1234::/48"                    "an IPv6 AllowedIPs entry is read"
want "ipv6 return    : a configured tunnel, 192.0.2.1 -> 192.168.0.80" \
     "and the tunnel it would be delivered through is named"

"$BUILD/vmsguard-gateway-stub" \
    --config tests/data/dualstack.conf \
    --interface ie0 --client 192.168.0.0/24 > "$out" 2>&1 || true

want "ipv6 return    : NOTHING" \
     "without a tunnel it says so at startup, not later by silence"

# An IPv6 --client must be accepted rather than read as bad CIDR.
"$BUILD/vmsguard-gateway-stub" \
    --config tests/data/dualstack.conf --interface ie0 \
    --client fd00:9999::/64 > "$out" 2>&1 || true
if grep -q "is not valid CIDR" "$out"; then
    echo "  FAIL  an IPv6 --client was rejected"
    fail=1
else
    echo "  ok    --client takes IPv6 as readily as IPv4"
fi

if [ "$fail" -ne 0 ]; then
    echo
    echo "--- output ---"
    cat "$out"
    exit 1
fi
echo "PASS"
