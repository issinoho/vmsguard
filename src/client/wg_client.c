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
    wg_cookie_init(&c->cookie, peer_public_key);
    c->roaming_enabled = 1;   /* as WireGuard does; see wg_client.h */
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

void wg_client_set_endpoint_name(struct wg_client *c, const char *host,
                                 uint16_t port)
{
    snprintf(c->endpoint_host, sizeof c->endpoint_host, "%s", host);
    c->endpoint_port = port;
    c->have_host = 1;
}

/*
 * Look the endpoint name up again. Returns 1 if it now resolves
 * somewhere else, 0 if it does not or there is nothing to look up.
 *
 * A failed lookup leaves the endpoint alone deliberately: a DNS server
 * that is briefly unreachable is not evidence that the peer has moved,
 * and discarding a working address on that basis would turn a momentary
 * outage into a permanent one.
 */
static int reresolve_endpoint(struct wg_client *c)
{
    struct wg_endpoint fresh;

    if (!c->have_host)
        return 0;
    if (wg_endpoint_resolve(&fresh, c->endpoint_host,
                            c->endpoint_port) != 0)
        return 0;
    if (wg_endpoint_equal(&fresh, &c->endpoint))
        return 0;

    /*
     * A peer that has moved to another address family would need a
     * socket in that family, which means tearing down and rebuilding
     * this one. Refused rather than half-done.
     */
    if (fresh.family != c->endpoint.family)
        return 0;

    c->endpoint = fresh;
    c->reresolves++;
    return 1;
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
/*
 * Follow the peer to a new address.
 *
 * Called only from paths where the packet has already authenticated,
 * which is the whole security argument: the endpoint moves because
 * something arrived that only the peer could have produced, never
 * because something arrived claiming to be from it.
 */
static void maybe_roam(struct wg_client *c, const struct wg_endpoint *from)
{
    if (!c->roaming_enabled)
        return;
    if (wg_endpoint_equal(&c->endpoint, from))
        return;

    c->endpoint = *from;
    c->roams++;
}

/*
 * One sequence of handshake attempts against the endpoint as it stands.
 *
 * Returns 0 on success, 1 if nothing answered (which is worth trying
 * again elsewhere), and -1 for a failure that retrying cannot help,
 * with c->error already set.
 */
static int handshake_round(struct wg_client *c, struct wg_keypair *out,
                           int attempts, int timeout_ms)
{
    uint8_t init_msg[WG_INIT_LEN];
    uint8_t buf[WG_MAX_PACKET];
    struct wg_handshake hs;
    struct wg_endpoint from;
    size_t len;
    int attempt;
    int cookie_retries = 0;

    /*
     * A cookie challenge is an extra round trip the peer imposes, not
     * an attempt of ours that failed, so it does not consume one — a
     * rekey runs with attempts == 1 and would otherwise always lose to
     * a loaded peer. Bounded so a peer that only ever sends cookies
     * cannot hold us here.
     */
#define COOKIE_RETRIES_MAX 2

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

        /*
         * mac2 if we hold a cookie, and a note of the mac1 either way:
         * a cookie reply to this message is authenticated with it, so
         * it has to be recorded before the message goes out.
         */
        (void) wg_cookie_apply(&c->cookie, init_msg, WG_INIT_OFF_MAC2,
                               wg_time_ms());
        wg_cookie_sent(&c->cookie, init_msg, WG_INIT_OFF_MAC1);

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
                /*
                 * The peer is under load and will not do the expensive
                 * half of a handshake until we prove we can receive at
                 * the address we claim. Take the cookie and start the
                 * next attempt straight away rather than waiting out
                 * the timeout: this attempt is already refused, and the
                 * retry will carry the mac2 it wanted.
                 */
                if (wg_cookie_consume(&c->cookie, buf, len,
                                      c->local_index, wg_time_ms()) == 0) {
                    c->cookies_received++;
                    wg_handshake_clear(&hs);
                    if (cookie_retries < COOKIE_RETRIES_MAX) {
                        cookie_retries++;
                        attempt--;      /* this one did not count */
                    }
                    break;
                }
                /* Malformed, misaddressed, or forged: ignore it and
                   keep waiting for a real response. */
                continue;
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

            /* It decrypted under keys only the peer holds, so this is
               the peer, wherever it answered from. */
            maybe_roam(c, &from);
            return 0;
        }

    }

    wg_handshake_clear(&hs);
    return 1;

#undef COOKIE_RETRIES_MAX
}

static int do_handshake(struct wg_client *c, struct wg_keypair *out,
                        int attempts, int timeout_ms)
{
    int rc = handshake_round(c, out, attempts, timeout_ms);

    if (rc <= 0)
        return rc;          /* success, or a failure retrying cannot fix */

    /*
     * Nothing answered. If the endpoint came from a name, the peer may
     * not be there any more — a provider retiring a server moves its
     * DNS, and roaming cannot help with that because nothing
     * authenticated ever arrives from the new address to learn from.
     *
     * Looked up only now, never on each attempt: a lookup in the path
     * of an ordinary retransmission would add a stall to the common
     * case for the sake of a rare one.
     */
    if (reresolve_endpoint(c)) {
        char epbuf[80];

        rc = handshake_round(c, out, attempts, timeout_ms);
        if (rc <= 0)
            return rc;

        wg_endpoint_format(epbuf, sizeof epbuf, &c->endpoint);
        snprintf(c->error, sizeof c->error,
                 "no handshake response, nor at %.70s where the name now"
                 " points", epbuf);
        return -1;
    }

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
    wg_replay_init(&c->kp.replay);
    c->established_ms = wg_time_ms();
    if (c->last_send_ms == 0)
        c->last_send_ms = c->established_ms;
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
        c->rekeys++;
    } else {
        c->rekeys_failed++;
    }
    wg_keypair_clear(&kp);
}

/* ---- data ------------------------------------------------------------ */

/*
 * Answer a handshake initiation from the peer.
 *
 * Returns 1 if the message was one and was dealt with (well or badly),
 * 0 if it was not an initiation at all, so the caller can carry on
 * looking at it.
 */
static int handle_initiation(struct wg_client *c, const uint8_t *buf,
                             size_t len, const struct wg_endpoint *from)
{
    struct wg_handshake hs;
    struct wg_keypair kp;
    uint8_t timestamp[WG_TIMESTAMP_LEN];
    uint8_t resp[WG_RESP_LEN];
    uint32_t index;

    if (len != WG_INIT_LEN || buf[0] != WG_MSG_HANDSHAKE_INIT)
        return 0;

    /*
     * mac1 first: it is keyed with our own static public key, so it is
     * the cheap check that this was addressed to us at all, before any
     * Diffie-Hellman is done. That ordering is the point of mac1.
     */
    if (!wg_mac1_verify(buf, len, WG_INIT_OFF_MAC1, c->self_mac1_key))
        return 1;

    if (wg_handshake_consume_initiation(buf, &hs, &c->local, timestamp) != 0)
        return 1;

    /* It decrypted, so we now know who sent it. It must be our peer. */
    if (!wg_equal(hs.remote_static, c->peer.static_public, WG_KEY_LEN)) {
        wg_handshake_clear(&hs);
        return 1;
    }

    /*
     * Strictly greater than the last accepted, which is what makes a
     * captured initiation useless to replay. TAI64N is big-endian
     * seconds then nanoseconds, so it compares as a byte string.
     */
    if (c->have_last_init &&
        memcmp(timestamp, c->last_init_timestamp, WG_TIMESTAMP_LEN) <= 0) {
        wg_handshake_clear(&hs);
        return 1;
    }

    index = c->local_index + 1;
    if (index == 0)
        index = 1;

    if (wg_handshake_create_response(resp, &hs, &c->local, &c->peer,
                                     index, &kp) != 0) {
        wg_handshake_clear(&hs);
        return 1;
    }

    /* mac2 if the peer has previously challenged us and the cookie is
       still good; zero otherwise, which is the normal case. */
    (void) wg_cookie_apply(&c->cookie, resp, WG_RESP_OFF_MAC2,
                           wg_time_ms());

    if (wg_socket_send(c->sock, from, resp, WG_RESP_LEN) != 0) {
        wg_zero(&kp, sizeof kp);
        return 1;
    }

    c->local_index = index;
    memcpy(c->last_init_timestamp, timestamp, WG_TIMESTAMP_LEN);
    c->have_last_init = 1;

    /*
     * The initiation authenticated, so its source is the peer — the
     * same rule the rest of the roaming code follows.
     */
    maybe_roam(c, from);

    install_keypair(c, &kp);
    c->kp_unconfirmed = 1;
    c->peer_handshakes++;
    wg_zero(&kp, sizeof kp);
    return 1;
}

/*
 * The keypair to encrypt with.
 *
 * Normally the current one. The exception is a keypair we built as
 * responder and the peer has not yet sent on: if our handshake response
 * was lost, the peer never derived it and would discard anything we
 * sent under it, so the previous keypair — which the peer demonstrably
 * has — is the better bet until the new one is confirmed.
 */
static struct wg_keypair *sending_keypair(struct wg_client *c)
{
    if (c->kp_unconfirmed && c->have_prev &&
        wg_time_ms() - c->prev_established_ms < c->reject_after_ms)
        return &c->prev_kp;
    return &c->kp;
}

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

    if (wg_transport_encrypt(msg, &msglen, sending_keypair(c), pt,
                             ptlen) != 0) {
        set_error(c, "encryption failed");
        return -1;
    }
    if (wg_socket_send(c->sock, &c->endpoint, msg, msglen) != 0) {
        set_error(c, "send failed");
        return -1;
    }

    c->last_send_ms = wg_time_ms();
    return 0;
}

int wg_client_tick(struct wg_client *c)
{
    uint64_t now;

    if (c->state != WG_STATE_ESTABLISHED)
        return 0;

    /* Rekeying is time-driven too, and an idle tunnel would otherwise
       never notice its session ageing out. */
    maybe_rekey(c);

    if (c->keepalive_interval_ms == 0)
        return 0;

    now = wg_time_ms();
    if (c->last_send_ms != 0 &&
        now - c->last_send_ms < c->keepalive_interval_ms)
        return 0;

    /* An empty transport packet: enough to refresh a NAT mapping, and
       what WireGuard itself sends. */
    return wg_client_send(c, NULL, 0);
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

        /*
         * The peer may start a handshake of its own — it does when it
         * has data queued on an ageing session. Answering it here is
         * what keeps such a session alive; ignoring it, as this used
         * to, left the session to die at REJECT_AFTER_TIME with
         * nothing in the log to explain why.
         */
        if (handle_initiation(c, buf, len, &from))
            continue;

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

        /* Sliding-window replay check, per keypair. */
        if (!wg_replay_check(&kp->replay, counter))
            continue;

        /*
         * Authenticated and not a replay, so the source is the peer.
         * Deliberately after the replay check: a captured packet
         * replayed from elsewhere must not be able to move the
         * endpoint, and it is exactly the packets an attacker can
         * resend that would otherwise do it.
         */
        maybe_roam(c, &from);

        /*
         * Data on the current keypair confirms it. If we built that
         * keypair as responder, this is the peer demonstrating it
         * derived the same one, so it is now safe to send on.
         */
        if (kp == &c->kp)
            c->kp_unconfirmed = 0;

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
