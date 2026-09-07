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
# Not 51820: that is WireGuard's conventional port and a real
# interface on the same machine would collide with it.
PORT=${PORT:-51899}

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
out=$(mktemp)
cleanup() {
    [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
    rm -f "$log" "$out"
}
trap cleanup EXIT

# --cookie 1: the responder answers the first initiation with a cookie
# challenge, as a peer under load does, and then requires the mac2 it
# asked for. This is the only place the cookie path runs over a real
# socket — the unit tests drive the pieces, but only here does the
# client have to notice a challenge mid-handshake and retry.
"$BUILD/vmsguard-responder" \
    --key "$sk" --peer-key "$cp" \
    --listen-port "$PORT" --packets 2 --cookie 1 --roam-after 0 \
    --reinitiate-after 0 > "$log" 2>&1 &
rpid=$!

# Give the responder a moment to bind before the client sends.
sleep 1

# Captured rather than piped: a pipeline reports the *last* command's
# status, so `| tee` hid a failing client behind a succeeding tee, and
# the wait below then blocked forever on a responder still counting
# packets that were never going to arrive.
if ! "$BUILD/vmsguard-interop" \
        --key "$ck" --peer-key "$sp" \
        --endpoint "127.0.0.1:$PORT" \
        --ping 10.9.0.2 10.9.0.1 \
        --timeout 3000 > "$out" 2>&1; then
    cat "$out"
    echo
    echo "--- responder output ---"
    cat "$log"
    exit 1
fi
cat "$out"

wait "$rpid" 2>/dev/null || true
rpid=

echo
echo "--- responder output ---"
cat "$log"

# The client reporting success is not enough on its own: it would also
# report success if the responder had never challenged it. Both halves
# have to appear.
if ! grep -q "sent a cookie challenge" "$log"; then
    echo
    echo "FAILED: the responder never sent a cookie challenge"
    exit 1
fi
if ! grep -q "mac2 verified after the cookie challenge" "$log"; then
    echo
    echo "FAILED: the cookie challenge was not answered with a valid mac2"
    exit 1
fi
echo
echo "cookie challenge issued and answered with a valid mac2"

# --roam-after 0 moves the responder to a fresh port before it answers
# the keepalive, and closes the old socket. The ping that follows is
# therefore delivered only if the client learned the new address from
# that keepalive echo; had it kept aiming at the old port the packet
# would have gone to a port nobody is listening on, and there would be
# no echo reply above.
if ! grep -q "roamed: now answering from port" "$log"; then
    echo
    echo "FAILED: the responder never roamed"
    exit 1
fi
if ! grep -q "peer roamed 1 time" "$out"; then
    echo
    echo "FAILED: the client did not report following the peer"
    exit 1
fi
echo "peer roamed mid-session and the client followed it"

# --reinitiate-after 0 makes the responder start a handshake of its own
# after the keepalive, the way a peer with queued data on an ageing
# session does. The client has to answer it; a client that ignores the
# message — as this one used to — leaves the session to expire.
if ! grep -q "initiating a handshake of our own" "$log"; then
    echo
    echo "FAILED: the responder never started its own handshake"
    exit 1
fi
if ! grep -q "the client answered our handshake" "$log"; then
    echo
    echo "FAILED: the client did not answer a peer-initiated handshake"
    exit 1
fi
# The responder sends its initiation twice, byte for byte. The second
# carries the same TAI64N timestamp and is therefore a replay: the
# client must answer the first and refuse the second, which is what
# stops a captured initiation being replayed at it later.
if ! grep -q "the replayed initiation was refused" "$log"; then
    echo
    echo "FAILED: the client answered a replayed handshake initiation"
    exit 1
fi
echo "peer-initiated handshake answered, its replay refused"

# ---------------------------------------------------------------------
# Scenario 2: the handshake response goes missing.
#
# The responder initiates, then throws away the client's answer. The
# client is now holding a keypair the responder never derived. If it
# sends under that keypair the traffic is undecryptable and the ping is
# lost; keeping to the previous keypair until the peer has been seen to
# use the new one is what makes this survivable. Nothing in scenario 1
# exercises that, because there the response arrives.
# ---------------------------------------------------------------------

PORT2=$((PORT + 1))
log2=$(mktemp)
out2=$(mktemp)
cleanup2() { [ -n "$rpid2" ] && kill "$rpid2" 2>/dev/null; rm -f "$log2" "$out2"; }
trap 'cleanup; cleanup2' EXIT

"$BUILD/vmsguard-responder" \
    --key "$sk" --peer-key "$cp" \
    --listen-port "$PORT2" --packets 2 \
    --reinitiate-after 0 --drop-response 1 > "$log2" 2>&1 &
rpid2=$!
sleep 1

if ! "$BUILD/vmsguard-interop" \
        --key "$ck" --peer-key "$sp" \
        --endpoint "127.0.0.1:$PORT2" \
        --ping 10.9.0.2 10.9.0.1 \
        --timeout 3000 > "$out2" 2>&1; then
    cat "$out2"
    echo
    echo "--- responder output ---"
    cat "$log2"
    echo
    echo "FAILED: a lost handshake response broke the data path"
    exit 1
fi

wait "$rpid2" 2>/dev/null || true
rpid2=

if ! grep -q "dropping the client's handshake response" "$log2"; then
    echo
    echo "FAILED: the responder never dropped a response"
    exit 1
fi
if grep -q "transport data failed to decrypt" "$log2"; then
    echo
    echo "--- responder output ---"
    cat "$log2"
    echo
    echo "FAILED: the client sent on a keypair the peer never derived"
    exit 1
fi
echo "a lost handshake response did not break the data path"
