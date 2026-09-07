#!/bin/sh
#
# Set up a real WireGuard peer on Linux for vmsguard to handshake with.
#
# This is the far end of the MVP acceptance test: unlike
# vmsguard-responder, the peer here is upstream WireGuard, so a
# successful handshake proves wire compatibility rather than merely that
# vmsguard agrees with itself.
#
# Needs root, because it creates a network interface.
#
#   sudo sh tools/interop/setup_wg_peer.sh up <vmsguard-public-key>
#   sudo sh tools/interop/setup_wg_peer.sh down
#   sh tools/interop/setup_wg_peer.sh status
#
# Everything it creates is confined to the interface named below and the
# key files in STATE_DIR, and "down" removes both.
#
# STATE_DIR must live under /etc/wireguard. Ubuntu ships an AppArmor
# profile for /usr/bin/wg (/etc/apparmor.d/wg) whose only file rule is:
#
#     file rw @{etc_rw}/wireguard/{,**},
#
# so wg cannot open a key file anywhere else — including /tmp, and
# including when run as root, since AppArmor denies by path rather than
# by uid. Putting keys elsewhere fails with a bare "fopen: Permission
# denied" that looks nothing like a confinement error.

set -e

# Keys must not be world-readable; wg warns about it otherwise.
umask 077

IFACE=${IFACE:-wg-vmsguard}
PORT=${PORT:-51820}
PEER_ADDR=${PEER_ADDR:-10.9.0.1}
VMSGUARD_ADDR=${VMSGUARD_ADDR:-10.9.0.2}
# The IPv6 pair. A ULA prefix rather than anything globally routed: this
# is a point-to-point test link and nothing outside it needs to reach
# these addresses.
PEER_ADDR6=${PEER_ADDR6:-fd00:1234::1}
VMSGUARD_ADDR6=${VMSGUARD_ADDR6:-fd00:1234::2}
# Extra networks to add to the peer's allowed-ips, comma-separated.
# Needed for a gateway test, where vmsguard forwards for LAN hosts and
# so sends from their addresses rather than its own -- allowed-ips that
# does not cover them means the peer decrypts and then discards, which
# looks exactly like a working handshake with no reply.
EXTRA_ALLOWED=${EXTRA_ALLOWED:-}
STATE_DIR=${STATE_DIR:-/etc/wireguard/vmsguard}

usage() {
    cat >&2 <<EOF
usage: $0 up <vmsguard-public-key>
       $0 down
       $0 status

  up      create $IFACE listening on UDP $PORT, with the given key as
          its only peer, allowed-ips $VMSGUARD_ADDR/32 and
          $VMSGUARD_ADDR6/128
  down    delete the interface and the generated keys
  status  show the interface and handshake state

Environment overrides: IFACE, PORT, PEER_ADDR, VMSGUARD_ADDR,
PEER_ADDR6, VMSGUARD_ADDR6, EXTRA_ALLOWED, STATE_DIR
EOF
    exit 2
}

need_root() {
    if [ "$(id -u)" != "0" ]; then
        echo "error: must run as root (creates a network interface)" >&2
        exit 1
    fi
}

case "${1:-}" in
up)
    [ -n "${2:-}" ] || usage
    need_root
    CLIENT_PUB=$2

    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"

    case "$STATE_DIR" in
    /etc/wireguard/*) ;;
    *)  echo "warning: STATE_DIR is outside /etc/wireguard; the AppArmor" >&2
        echo "         profile for wg will deny access to keys there." >&2 ;;
    esac

    if [ ! -f "$STATE_DIR/server.key" ]; then
        wg genkey > "$STATE_DIR/server.key"
        chmod 600 "$STATE_DIR/server.key"
    fi
    wg pubkey < "$STATE_DIR/server.key" > "$STATE_DIR/server.pub"

    # Start from a clean slate so re-running is safe.
    ip link del dev "$IFACE" 2>/dev/null || true

    ip link add dev "$IFACE" type wireguard
    ip addr add "$PEER_ADDR/24" dev "$IFACE"
    # nodad: with no other node on the link duplicate-address detection
    # has nothing to find, and skipping it avoids a window where the
    # address is still tentative and a ping to it is answered by
    # nothing at all.
    ip -6 addr add "$PEER_ADDR6/64" dev "$IFACE" nodad

    # allowed-ips must cover the address vmsguard sends from, or the
    # peer decrypts our packets and then drops them — which looks like a
    # successful handshake with no echo reply.
    ALLOWED="$VMSGUARD_ADDR/32,$VMSGUARD_ADDR6/128"
    [ -n "$EXTRA_ALLOWED" ] && ALLOWED="$ALLOWED,$EXTRA_ALLOWED"

    wg set "$IFACE" \
        listen-port "$PORT" \
        private-key "$STATE_DIR/server.key" \
        peer "$CLIENT_PUB" \
            allowed-ips "$ALLOWED"

    ip link set "$IFACE" up

    echo "interface $IFACE is up"
    echo
    echo "  peer public key : $(cat "$STATE_DIR/server.pub")"
    echo "  listening on    : UDP $PORT"
    echo "  tunnel address  : $PEER_ADDR (vmsguard should use $VMSGUARD_ADDR)"
    echo "  tunnel address 6: $PEER_ADDR6 (vmsguard should use $VMSGUARD_ADDR6)"
    echo "  allowed-ips     : $ALLOWED for $CLIENT_PUB"
    echo
    # Fill in the host address rather than leaving a placeholder to be
    # pasted literally. The private key is the one paired with the
    # public key passed in, and only the caller has it.
    HOST_IP=$(ip -4 -o addr show scope global 2>/dev/null \
              | grep -v " $IFACE " \
              | awk 'NR==1 {split($4,a,"/"); print a[1]}')
    [ -n "$HOST_IP" ] || HOST_IP="<this-host-ip>"

    echo "Run this on OpenVMS, quoting the keys so DCL does not upcase"
    echo "them or read / as a qualifier. Substitute the private key that"
    echo "pairs with the public key you passed to this script:"
    echo
    echo '$ VG_INTEROP -'
    echo '    --key "<the-private-key-for-the-public-key-above>" -'
    echo "    --peer-key \"$(cat "$STATE_DIR/server.pub")\" -"
    echo "    --endpoint $HOST_IP:$PORT -"
    echo "    --ping $VMSGUARD_ADDR $PEER_ADDR"
    echo
    echo "and the same with --ping6 to carry an IPv6 packet instead,"
    echo "which is the only way to exercise the inner-IPv6 path against"
    echo "upstream WireGuard rather than against our own responder:"
    echo
    echo '$ VG_INTEROP -'
    echo '    --key "<the-private-key-for-the-public-key-above>" -'
    echo "    --peer-key \"$(cat "$STATE_DIR/server.pub")\" -"
    echo "    --endpoint $HOST_IP:$PORT -"
    echo "    --ping6 $VMSGUARD_ADDR6 $PEER_ADDR6"
    if [ "$HOST_IP" = "<this-host-ip>" ]; then
        echo
        echo "  (could not determine this host's address automatically)"
    else
        echo
        echo "  $HOST_IP is this host; use another of its addresses if"
        echo "  the OpenVMS system reaches it by a different route."
    fi
    echo
    echo "Then check the peer's own view with:"
    echo "  sh $0 status"
    ;;

down)
    need_root
    ip link del dev "$IFACE" 2>/dev/null && echo "removed $IFACE" \
        || echo "$IFACE was not present"

    # Remove only the files this script created, then the directory if
    # it is empty. A recursive delete would be a poor idea pointed at
    # /etc/wireguard if STATE_DIR were ever overridden.
    rm -f "$STATE_DIR/server.key" "$STATE_DIR/server.pub"
    rmdir "$STATE_DIR" 2>/dev/null && echo "removed $STATE_DIR" \
        || echo "left $STATE_DIR in place (not empty)"
    ;;

status)
    if ! ip link show "$IFACE" >/dev/null 2>&1; then
        echo "$IFACE does not exist"
        exit 1
    fi
    ip -brief addr show "$IFACE" || true
    echo
    # wg show needs root to reveal keys, but reports transfer counters
    # and handshake time to anyone who can see the interface.
    wg show "$IFACE" 2>/dev/null || sudo wg show "$IFACE"
    echo
    echo "A 'latest handshake' time and non-zero transfer figures are"
    echo "independent confirmation: upstream WireGuard accepted our"
    echo "handshake and decrypted our data."
    ;;

*)
    usage
    ;;
esac
