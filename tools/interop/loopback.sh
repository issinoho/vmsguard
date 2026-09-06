#!/bin/sh
#
# Loopback self-test: our initiator against our responder over real UDP.
#
# Exercises the socket layer, client state machine, handshake, keepalive
# and ICMP data path. Does NOT prove wire compatibility with upstream
# WireGuard — both ends are our own code. See docs/interop.md.
#
# Uses only vmsguard's own tools, so it runs on OpenVMS too. Override
# the keys with CLIENT_KEY / SERVER_KEY (base64 private keys) if you
# want a reproducible run.

set -e

BUILD=${BUILD:-./build}
PORT=${PORT:-51820}

if [ -n "$CLIENT_KEY" ] && [ -n "$SERVER_KEY" ]; then
    ck=$CLIENT_KEY
    sk=$SERVER_KEY
else
    ck=$("$BUILD/vmsguard-key" genkey)
    sk=$("$BUILD/vmsguard-key" genkey)
fi

# Derive public keys with our own tool.
cp=$(printf '%s\n' "$ck" | "$BUILD/vmsguard-key" pubkey)
sp=$(printf '%s\n' "$sk" | "$BUILD/vmsguard-key" pubkey)

log=$(mktemp)
cleanup() {
    [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
    rm -f "$log"
}
trap cleanup EXIT

"$BUILD/vmsguard-responder" \
    --key "$sk" --peer-key "$cp" \
    --listen-port "$PORT" --packets 2 > "$log" 2>&1 &
rpid=$!

# Give the responder a moment to bind before the client sends.
sleep 1

if ! "$BUILD/vmsguard-interop" \
        --key "$ck" --peer-key "$sp" \
        --endpoint "127.0.0.1:$PORT" \
        --ping 10.9.0.2 10.9.0.1 \
        --timeout 3000; then
    echo
    echo "--- responder output ---"
    cat "$log"
    exit 1
fi

wait "$rpid" 2>/dev/null || true
rpid=

echo
echo "--- responder output ---"
cat "$log"
