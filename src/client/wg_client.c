/*
 * WireGuard client — vmsguard
 */

#include <stdio.h>
#include <string.h>

#include "wg_client.h"
#include "wg_proto.h"

static void set_error(struct wg_client *c, const char *msg)
{
    snprintf(c->error, sizeof c->error, "%s", msg);
}

int wg_client_init(struct wg_client *c,
                   const uint8_t private_key[WG_KEY_LEN],
                   const uint8_t peer_public_key[WG_KEY_LEN],
                   const uint8_t *psk,
                   const struct wg_endpoint *endpoint,
                   uint16_t listen_port)
{
    memset(c, 0, sizeof *c);

    if (wg_local_init(&c->local, private_key) != 0) {
        set_error(c, "invalid private key");
        return -1;
    }
    wg_peer_init(&c->peer, peer_public_key, psk);
    wg_mac1_key(c->self_mac1_key, c->local.static_public);

    c->endpoint = *endpoint;
    c->rekey_after_ms = WG_REKEY_AFTER_TIME_MS;
    c->reject_after_ms = WG_REJECT_AFTER_TIME_MS;

    /* Open in the peer's address family. A dual-stack IPv6 socket
       would need IPv4-mapped destinations, which OpenVMS rejects. */
    if (wg_socket_open(&c->sock, listen_port, endpoint->family) != 0) {
        set_error(c, "could not open UDP socket");
        return -1;
    }

    /* Any nonzero index works; the peer only echoes it back. Deriving
       it from the clock avoids collisions across restarts. */
    c->local_index = (uint32_t) (wg_time_ms() & 0xFFFFFFFFUL);
    if (c->local_index == 0)
        c->local_index = 1;

    c->state = WG_STATE_IDLE;
    return 0;
}

void wg_client_close(struct wg_client *c)
{
    if (c->sock != NULL) {
        wg_socket_close(c->sock);
        c->sock = NULL;
    }
    wg_handshake_clear(&c->hs);
    wg_keypair_clear(&c->kp);
    wg_keypair_clear(&c->prev_kp);
    c->have_prev = 0;
    c->state = WG_STATE_IDLE;
}

/* ---- session age ----------------------------------------------------- */

uint64_t wg_client_session_age_ms(const struct wg_client *c)
{
    uint64_t now;

    if (c->state != WG_STATE_ESTABLISHED)
        return 0;
    now = wg_time_ms();
    return now > c->established_ms ? now - c->established_ms : 0;
}

int wg_client_needs_rekey(const struct wg_client *c)
{
    if (c->state != WG_STATE_ESTABLISHED)
        return 1;
    if (wg_client_session_age_ms(c) >= c->rekey_after_ms)
        return 1;
    if (c->kp.send_counter >= WG_REKEY_AFTER_MESSAGES)
        return 1;
    return 0;
}

int wg_client_session_expired(const struct wg_client *c)
{
    if (c->state != WG_STATE_ESTABLISHED)
        return 1;
    return wg_client_session_age_ms(c) >= c->reject_after_ms ? 1 : 0;
}

/* ---- handshake ------------------------------------------------------- */

/*
 * One handshake, producing a keypair without disturbing the current
 * session. Both the initial handshake and a rekey go through here; the
 * caller decides what to do with the result, which is what allows a
 * failed rekey to leave the existing session intact.
 */
static int do_handshake(struct wg_client *c, struct wg_keypair *out,
                        int attempts, int timeout_ms)
{
    uint8_t init_msg[WG_INIT_LEN];
    uint8_t buf[WG_MAX_PACKET];
    struct wg_handshake hs;
    struct wg_endpoint from;
    size_t len;
    int attempt;

    for (attempt = 0; attempt < attempts; attempt++) {
        uint64_t deadline;

        /*
         * Every handshake gets a fresh sender index, not just every
         * retry. The peer demultiplexes sessions on it, and reusing one
         * across a rekey would leave the old and new keypairs
         * indistinguishable — which also defeats keypair_for, and with
         * it the whole point of retaining the previous keypair.
         */
        c->local_index++;
        if (c->local_index == 0)
            c->local_index = 1;

        if (wg_handshake_create_initiation(init_msg, &hs, &c->local,
                                           &c->peer, c->local_index) != 0) {
            set_error(c, "failed to build handshake initiation");
            return -1;
        }

        if (wg_socket_send(c->sock, &c->endpoint, init_msg,
                           WG_INIT_LEN) != 0) {
            set_error(c, "failed to send handshake initiation");
            return -1;
        }

        deadline = wg_time_ms() + (uint64_t) timeout_ms;

        for (;;) {
            uint64_t now = wg_time_ms();
            int remaining;
            int rc;

            if (now >= deadline)
                break;
            remaining = (int) (deadline - now);

            rc = wg_socket_recv(c->sock, &from, buf, sizeof buf, &len,
                                remaining);
            if (rc == WG_SOCK_TIMEOUT)
                break;
            if (rc != WG_SOCK_OK) {
                set_error(c, "socket error while awaiting response");
                return -1;
            }

            if (len < 4)
                continue;

            if (buf[0] == WG_MSG_COOKIE_REPLY) {
                /* The peer is under load and wants a cookie-derived
                   mac2 before it will process our handshake. Answering
                   requires the cookie mechanism, which is not
                   implemented — report it rather than retrying
                   forever. */
                set_error(c, "peer sent a cookie reply (it is under load); "
                             "mac2/cookie support is not implemented");
                wg_handshake_clear(&hs);
                return -1;
            }

            /*
             * Transport data may well arrive mid-rekey, encrypted under
             * the session still in use. Ignore it here rather than
             * treating it as a failure; the caller's next receive will
             * pick it up if it is still queued.
             */
            if (buf[0] != WG_MSG_HANDSHAKE_RESP || len != WG_RESP_LEN)
                continue;

            /* mac1 on a response is keyed with *our* static public
               key, so this both authenticates the message shape and
               filters out traffic meant for someone else. */
            if (!wg_mac1_verify(buf, len, WG_RESP_OFF_MAC1,
                                c->self_mac1_key))
                continue;

            if (wg_handshake_consume_response(buf, &hs, &c->local,
                                              &c->peer, out) != 0)
                continue;   /* not for us, or corrupt: keep waiting */

            return 0;
        }

    }

    wg_handshake_clear(&hs);
    set_error(c, "no handshake response received");
    return -1;
}

/* Install a freshly negotiated keypair, retiring the current one. */
static void install_keypair(struct wg_client *c, const struct wg_keypair *kp)
{
    if (c->state == WG_STATE_ESTABLISHED) {
        c->prev_kp = c->kp;
        c->prev_established_ms = c->established_ms;
        c->have_prev = 1;
    }
    c->kp = *kp;
    c->kp.recv_counter_max = 0;
    c->established_ms = wg_time_ms();
    c->state = WG_STATE_ESTABLISHED;
    c->rekey_started_ms = 0;
}

int wg_client_handshake(struct wg_client *c, int attempts, int timeout_ms)
{
    struct wg_keypair kp;

    memset(&kp, 0, sizeof kp);
    if (do_handshake(c, &kp, attempts, timeout_ms) != 0)
        return -1;

    install_keypair(c, &kp);
    wg_keypair_clear(&kp);
    return 0;
}

/*
 * Replace the session if it is old enough to need it.
 *
 * Deliberately does not fail the caller's send when a rekey does not
 * succeed: while the current session is still inside reject_after_ms it
 * remains perfectly usable, so a peer that is briefly unreachable costs
 * nothing. Attempts are paced by WG_REKEY_TIMEOUT_MS so a dead peer is
 * not hammered, and abandoned after WG_REKEY_ATTEMPT_TIME_MS.
 */
static void maybe_rekey(struct wg_client *c)
{
    struct wg_keypair kp;
    uint64_t now;

    if (c->state != WG_STATE_ESTABLISHED || !wg_client_needs_rekey(c))
        return;

    now = wg_time_ms();

    if (c->rekey_started_ms == 0)
        c->rekey_started_ms = now;
    else if (now - c->rekey_started_ms > WG_REKEY_ATTEMPT_TIME_MS)
        return;   /* given up; the session will expire on its own */

    if (c->last_rekey_attempt_ms != 0 &&
        now - c->last_rekey_attempt_ms < WG_REKEY_TIMEOUT_MS)
        return;
    c->last_rekey_attempt_ms = now;

    memset(&kp, 0, sizeof kp);
    if (do_handshake(c, &kp, 1, (int) WG_REKEY_TIMEOUT_MS) == 0) {
        install_keypair(c, &kp);
        c->last_rekey_attempt_ms = 0;
    }
    wg_keypair_clear(&kp);
}

/* ---- data ------------------------------------------------------------ */

int wg_client_send(struct wg_client *c, const uint8_t *pt, size_t ptlen)
{
    uint8_t msg[WG_MAX_PACKET];
    size_t msglen;

    if (c->state != WG_STATE_ESTABLISHED) {
        set_error(c, "not established");
        return -1;
    }

    maybe_rekey(c);

    /* Past reject_after_ms the keys must not be used at all, even if
       rekeying has not managed to replace them. */
    if (wg_client_session_expired(c)) {
        set_error(c, "session expired and could not be rekeyed");
        return -1;
    }

    if (ptlen + WG_DATA_HDR_LEN + WG_TAG_LEN + 16 > sizeof msg) {
        set_error(c, "packet too large");
        return -1;
    }

    if (wg_transport_encrypt(msg, &msglen, &c->kp, pt, ptlen) != 0) {
        set_error(c, "encryption failed");
        return -1;
    }
    if (wg_socket_send(c->sock, &c->endpoint, msg, msglen) != 0) {
        set_error(c, "send failed");
        return -1;
    }
    return 0;
}

/*
 * Pick the keypair a received packet belongs to, by the index the far
 * side echoed back. Returns NULL if it matches neither, which is how
 * stale packets from a session two generations old are discarded.
 */
static struct wg_keypair *keypair_for(struct wg_client *c, uint32_t index)
{
    if (c->state == WG_STATE_ESTABLISHED && c->kp.local_index == index)
        return &c->kp;

    if (c->have_prev && c->prev_kp.local_index == index) {
        uint64_t now = wg_time_ms();
        /* The previous keypair stays usable only as long as it would
           have been valid in its own right. */
        if (now - c->prev_established_ms < c->reject_after_ms)
            return &c->prev_kp;
    }
    return NULL;
}

int wg_client_recv(struct wg_client *c, uint8_t *out, size_t cap,
                   size_t *outlen, int timeout_ms)
{
    uint8_t buf[WG_MAX_PACKET];
    struct wg_endpoint from;
    uint64_t deadline;
    size_t len;

    if (c->state != WG_STATE_ESTABLISHED) {
        set_error(c, "not established");
        return WG_SOCK_ERROR;
    }

    deadline = wg_time_ms() + (uint64_t) timeout_ms;

    for (;;) {
        struct wg_keypair *kp;
        uint64_t now = wg_time_ms();
        uint64_t counter;
        size_t plainlen;
        int remaining;
        int rc;

        /*
         * Compute the remaining budget and always attempt a receive,
         * rather than returning early once the deadline has passed.
         *
         * A zero timeout means "poll once without blocking", which is
         * how the gateway drains this socket between pcap reads.
         * Checking the deadline first made that case return
         * immediately without ever touching the socket, so the gateway
         * never read a single packet from the tunnel. The loop still
         * terminates: a zero budget makes wg_socket_recv poll and
         * report a timeout when nothing is waiting.
         */
        remaining = (now >= deadline) ? 0 : (int) (deadline - now);

        rc = wg_socket_recv(c->sock, &from, buf, sizeof buf, &len,
                            remaining);
        if (rc == WG_SOCK_TIMEOUT)
            return WG_SOCK_TIMEOUT;
        if (rc != WG_SOCK_OK)
            return WG_SOCK_ERROR;

        if (len < WG_DATA_HDR_LEN + WG_TAG_LEN)
            continue;
        if (buf[0] != WG_MSG_TRANSPORT_DATA)
            continue;
        if (len - WG_DATA_HDR_LEN - WG_TAG_LEN > cap)
            continue;   /* would not fit; drop rather than truncate */

        kp = keypair_for(c, wg_get32(buf + WG_DATA_OFF_RECEIVER));
        if (kp == NULL)
            continue;

        if (wg_transport_decrypt(out, &plainlen, &counter, kp,
                                 buf, len) != 0)
            continue;

        /*
         * Replay guard, per keypair. WireGuard proper keeps a sliding
         * window so that packets reordered by the network are still
         * accepted; this only rejects counters at or below the highest
         * seen, which is stricter than the spec and will drop
         * legitimately reordered packets.
         */
        if (counter != 0 && counter <= kp->recv_counter_max)
            continue;
        kp->recv_counter_max = counter;

        /*
         * Receiving is also a rekey trigger, and at a slightly earlier
         * age than sending: the initiator should replace the session
         * before the far side begins rejecting it.
         */
        if (kp == &c->kp &&
            wg_client_session_age_ms(c) >= WG_REKEY_AFTER_TIME_RECV_MS)
            maybe_rekey(c);

        *outlen = plainlen;
        return WG_SOCK_OK;
    }
}
