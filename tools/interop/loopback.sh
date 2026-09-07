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

# ---------------------------------------------------------------------
# Scenario 3: a peer that will not rekey must not stop the client.
#
# The responder answers the first handshake and ignores every later
# initiation. The client should go on sending its keepalive every
# second regardless: a rekey is started and left outstanding, not
# waited for.
#
# This is the regression test for a real measurement. Rekeying used to
# block the caller for up to REKEY_TIMEOUT, and a two-hour run on the
# target recorded two rekeys failing -- ten seconds during which the
# gateway forwarded nothing. Under that behaviour eight seconds here
# would yield three or four keepalives rather than eight.
#
# --reject-after is given explicitly because it otherwise follows
# --rekey-after, and a session that expires after 2.25s ends the test
# before the interesting part.
# ---------------------------------------------------------------------

PORT3=$((PORT + 2))
log3=$(mktemp)
out3=$(mktemp)
cleanup3() { [ -n "$rpid3" ] && kill "$rpid3" 2>/dev/null; rm -f "$log3" "$out3"; }
trap 'cleanup; cleanup2; cleanup3' EXIT

"$BUILD/vmsguard-responder" \
    --key "$sk" --peer-key "$cp" \
    --listen-port "$PORT3" --ignore-rekey > "$log3" 2>&1 &
rpid3=$!
sleep 1

# The exit status is expected to be non-zero: --duration asserts that a
# rekey completed, and here by construction none can. What matters is
# the keepalive count, and a crash would leave no such line at all.
"$BUILD/vmsguard-interop" \
    --key "$ck" --peer-key "$sp" \
    --endpoint "127.0.0.1:$PORT3" \
    --rekey-after 1500 --reject-after 60000 --duration 8 > "$out3" 2>&1 || true

kill "$rpid3" 2>/dev/null || true
rpid3=

if ! grep -q "ignoring a rekey initiation" "$log3"; then
    echo
    echo "FAILED: the responder never ignored a rekey"
    exit 1
fi

sent=$(sed -n 's/.*  \([0-9]*\) keepalives sent, \([0-9]*\) failed.*/\1 \2/p' "$out3")
ka=$(echo "$sent" | cut -d' ' -f1)
bad=$(echo "$sent" | cut -d' ' -f2)
if [ -z "$ka" ]; then
    cat "$out3"
    echo
    echo "FAILED: the client produced no keepalive count"
    exit 1
fi
if [ "$ka" -lt 7 ] || [ "$bad" -ne 0 ]; then
    cat "$out3"
    echo
    echo "FAILED: only $ka keepalives in 8s ($bad failed);"
    echo "        an unanswered rekey is stalling the caller"
    exit 1
fi
echo "an unanswered rekey did not stall the client ($ka keepalives in 8s)"

# ---------------------------------------------------------------------
# Scenario 4: cryptokey routing.
#
# The responder echoes the ping back with its source rewritten to
# 8.8.8.8. Decryption still succeeds -- it really is the peer, using the
# right keys -- so nothing about the crypto rejects it. What must reject
# it is AllowedIPs: a peer may only source addresses it was permitted
# to. Without that check a peer, or whoever has taken it over, can put a
# packet bearing any source address at all onto the far end's network.
# ---------------------------------------------------------------------

PORT4=$((PORT + 3))
log4=$(mktemp)
out4=$(mktemp)
cleanup4() { [ -n "$rpid4" ] && kill "$rpid4" 2>/dev/null; rm -f "$log4" "$out4"; }
trap 'cleanup; cleanup2; cleanup3; cleanup4' EXIT

"$BUILD/vmsguard-responder" \
    --key "$sk" --peer-key "$cp" \
    --listen-port "$PORT4" --packets 2 \
    --spoof-source 8.8.8.8 > "$log4" 2>&1 &
rpid4=$!
sleep 1

# Non-zero by design: the echo reply is refused, so none arrives.
"$BUILD/vmsguard-interop" \
    --key "$ck" --peer-key "$sp" \
    --endpoint "127.0.0.1:$PORT4" \
    --ping 10.9.0.2 10.9.0.1 \
    --allowed-ips 10.9.0.0/24 \
    --timeout 2000 > "$out4" 2>&1 || true

kill "$rpid4" 2>/dev/null || true
rpid4=

if ! grep -q "echoing it back sourced from elsewhere" "$log4"; then
    echo
    echo "FAILED: the responder never spoofed a source"
    exit 1
fi
if ! grep -q "refused a packet sourced 8.8.8.8" "$out4"; then
    cat "$out4"
    echo
    echo "FAILED: a packet sourced outside AllowedIPs was accepted"
    exit 1
fi
echo "a peer claiming an address outside AllowedIPs was refused"
