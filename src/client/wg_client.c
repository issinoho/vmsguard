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
    c->state = WG_STATE_IDLE;
}

int wg_client_handshake(struct wg_client *c, int attempts, int timeout_ms)
{
    uint8_t init_msg[WG_INIT_LEN];
    uint8_t buf[WG_MAX_PACKET];
    struct wg_endpoint from;
    size_t len;
    int attempt;

    for (attempt = 0; attempt < attempts; attempt++) {
        uint64_t deadline;

        if (wg_handshake_create_initiation(init_msg, &c->hs, &c->local,
                                           &c->peer, c->local_index) != 0) {
            set_error(c, "failed to build handshake initiation");
            return -1;
        }

        if (wg_socket_send(c->sock, &c->endpoint, init_msg,
                           WG_INIT_LEN) != 0) {
            set_error(c, "failed to send handshake initiation");
            return -1;
        }
        c->state = WG_STATE_HANDSHAKE_SENT;

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
                   requires the cookie mechanism, which the MVP does not
                   implement — report it rather than silently retrying
                   forever. */
                set_error(c, "peer sent a cookie reply (it is under load); "
                             "mac2/cookie support is not implemented");
                return -1;
            }

            if (buf[0] != WG_MSG_HANDSHAKE_RESP || len != WG_RESP_LEN)
                continue;

            /* mac1 on a response is keyed with *our* static public
               key, so this both authenticates the message shape and
               filters out traffic meant for someone else. */
            if (!wg_mac1_verify(buf, len, WG_RESP_OFF_MAC1,
                                c->self_mac1_key))
                continue;

            if (wg_handshake_consume_response(buf, &c->hs, &c->local,
                                              &c->peer, &c->kp) != 0)
                continue;   /* not for us, or corrupt: keep waiting */

            c->state = WG_STATE_ESTABLISHED;
            c->recv_counter_max = 0;
            return 0;
        }

        /* Retry with a fresh ephemeral key and a fresh index, as a
           repeated initiation with the same index could be treated as a
           replay. */
        c->local_index++;
        if (c->local_index == 0)
            c->local_index = 1;
    }

    set_error(c, "no handshake response received");
    return -1;
}

int wg_client_send(struct wg_client *c, const uint8_t *pt, size_t ptlen)
{
    uint8_t msg[WG_MAX_PACKET];
    size_t msglen;

    if (c->state != WG_STATE_ESTABLISHED) {
        set_error(c, "not established");
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
        uint64_t now = wg_time_ms();
        uint64_t counter;
        size_t plainlen;
        int remaining;
        int rc;

        if (now >= deadline)
            return WG_SOCK_TIMEOUT;
        remaining = (int) (deadline - now);

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

        if (wg_transport_decrypt(out, &plainlen, &counter, &c->kp,
                                 buf, len) != 0)
            continue;

        /*
         * Replay guard. WireGuard proper keeps a sliding window so that
         * packets reordered by the network are still accepted; this
         * only rejects counters at or below the highest seen, which is
         * stricter than the spec and will drop legitimately reordered
         * packets. Adequate for interop testing, not for production.
         */
        if (counter != 0 && counter <= c->recv_counter_max)
            continue;
        c->recv_counter_max = counter;

        *outlen = plainlen;
        return WG_SOCK_OK;
    }
}
