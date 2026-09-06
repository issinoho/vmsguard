/*
 * WireGuard client — vmsguard
 *
 * Ties the protocol core to a platform socket: performs the handshake
 * against a peer and then carries transport data. Deliberately a
 * *client* only — it initiates handshakes and does not respond to them,
 * which is the MVP's agreed scope.
 *
 * What this does not yet do, and would need before production use:
 *   - rekeying (WireGuard rekeys after 2 minutes or 2^60 messages)
 *   - a replay sliding window (only a highest-counter check is done)
 *   - cookie replies under load (mac2 is always zero; a cookie reply is
 *     detected and reported rather than answered)
 *   - roaming (the peer endpoint is fixed at configuration time)
 * These are noted in the code where they bite.
 */

#ifndef VMSGUARD_WG_CLIENT_H
#define VMSGUARD_WG_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "wg_noise.h"
#include "wg_platform.h"

/* Largest datagram we will accept or produce. */
#define WG_MAX_PACKET 2048

enum wg_client_state {
    WG_STATE_IDLE = 0,
    WG_STATE_HANDSHAKE_SENT,
    WG_STATE_ESTABLISHED
};

struct wg_client {
    struct wg_local      local;
    struct wg_peer       peer;
    struct wg_endpoint   endpoint;
    struct wg_socket    *sock;

    struct wg_handshake  hs;
    struct wg_keypair    kp;

    uint32_t             local_index;
    uint64_t             recv_counter_max;   /* crude replay guard */
    int                  state;

    /* Our own mac1 key, for validating messages sent back to us. */
    uint8_t              self_mac1_key[WG_KEY_LEN];

    char                 error[160];
};

/*
 * Configure a client. private_key and peer_public_key are raw 32-byte
 * keys; psk may be NULL. The socket is created here, bound to
 * listen_port (0 for any). Returns 0 on success, -1 on failure with
 * client->error set.
 */
int wg_client_init(struct wg_client *c,
                   const uint8_t private_key[WG_KEY_LEN],
                   const uint8_t peer_public_key[WG_KEY_LEN],
                   const uint8_t *psk,
                   const struct wg_endpoint *endpoint,
                   uint16_t listen_port);

void wg_client_close(struct wg_client *c);

/*
 * Perform a handshake, retrying the initiation up to `attempts` times
 * with `timeout_ms` to wait for each response. Returns 0 once transport
 * keys are established, -1 on failure with client->error set.
 */
int wg_client_handshake(struct wg_client *c, int attempts, int timeout_ms);

/*
 * Send a plaintext IP packet through the tunnel. A NULL/zero payload
 * sends a keepalive. Returns 0 on success.
 */
int wg_client_send(struct wg_client *c, const uint8_t *pt, size_t ptlen);

/*
 * Wait for a transport data packet and decrypt it. Returns WG_SOCK_OK
 * with the plaintext, WG_SOCK_TIMEOUT if nothing valid arrived within
 * timeout_ms, or WG_SOCK_ERROR.
 *
 * Packets that are not valid transport data for this session are
 * skipped rather than returned, so a noisy port does not break the
 * caller — but they do consume the timeout budget.
 */
int wg_client_recv(struct wg_client *c, uint8_t *out, size_t cap,
                   size_t *outlen, int timeout_ms);

#endif /* VMSGUARD_WG_CLIENT_H */
