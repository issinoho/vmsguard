/*
 * WireGuard client — vmsguard
 *
 * Ties the protocol core to a platform socket: performs the handshake
 * against a peer and then carries transport data. Deliberately a
 * *client* only — it initiates handshakes and does not respond to them,
 * which is the MVP's agreed scope.
 *
 * What this does not yet do, and would need before production use:
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

    /*
     * Current and previous keypairs. The previous one is retained after
     * a rekey so packets already in flight, encrypted under the old
     * key, still decrypt rather than being dropped. WireGuard proper
     * keeps three (previous, current, next); two is enough for a client
     * that always initiates.
     */
    struct wg_keypair    kp;
    struct wg_keypair    prev_kp;
    int                  have_prev;
    uint64_t             established_ms;
    uint64_t             prev_established_ms;
    uint64_t             last_rekey_attempt_ms;
    uint64_t             rekey_started_ms;

    /*
     * Rekeys, counted so a run can be judged. A session is replaced
     * every two minutes and the replacement is invisible when it works,
     * which means a run that never reports one is indistinguishable
     * from a run too short to have needed one.
     */
    unsigned long        rekeys;
    unsigned long        rekeys_failed;

    /*
     * A rekey in flight.
     *
     * Rekeying used to be done by sending an initiation and then
     * waiting up to REKEY_TIMEOUT for the answer, inside the caller's
     * send path. That blocks whatever is driving the client: a gateway
     * stops forwarding for five seconds every time a peer misses a
     * handshake, which a two-hour run measured happening twice.
     *
     * So the initiation is sent and the state kept here, and the answer
     * is picked up by the ordinary receive path whenever it arrives.
     * Nothing waits.
     */
    struct wg_handshake  pending_hs;
    int                  pending_rekey;
    uint64_t             pending_sent_ms;

    /*
     * Overridable so tests need not wait two minutes. Both default to
     * the whitepaper's figures in wg_client_init.
     */
    uint64_t             rekey_after_ms;
    uint64_t             reject_after_ms;

    /*
     * PersistentKeepalive. Zero disables it, which is the default and
     * matches WireGuard. A provider config's "PersistentKeepalive = 25"
     * becomes 25000 here.
     */
    uint64_t             keepalive_interval_ms;
    uint64_t             last_send_ms;

    uint32_t             local_index;
    int                  state;

    /* Our own mac1 key, for validating messages sent back to us. */
    uint8_t              self_mac1_key[WG_KEY_LEN];

    /*
     * The cookie a loaded peer last challenged us with, and the mac1 a
     * reply would be authenticated against. Kept across handshakes: a
     * cookie stays usable for two minutes, so a peer under sustained
     * load is answered on the first attempt rather than costing a
     * wasted round trip every time.
     */
    struct wg_cookie     cookie;
    unsigned long        cookies_received;

    /*
     * Roaming. A peer that moves — a new address, or a NAT rebinding
     * its port — keeps working because the endpoint follows the source
     * of packets from it.
     *
     * Only ever updated from a packet that has *authenticated*: a
     * handshake response that completed, or transport data that
     * decrypted. Following an unauthenticated source address would let
     * anyone who can forge a source address redirect the tunnel, which
     * is a far worse failure than not roaming at all.
     */
    unsigned long        roams;
    int                  roaming_enabled;

    /*
     * Handshakes the *peer* started.
     *
     * WireGuard is symmetric: either end may initiate, and a peer with
     * data queued on an ageing session will. Ignoring those left the
     * session to die at REJECT_AFTER_TIME with nothing to explain it.
     *
     * last_init_timestamp is the greatest TAI64N seen in an initiation
     * from this peer. An initiation carrying anything at or below it is
     * a replay and is refused — the timestamp is what stops a captured
     * initiation being replayed later, and it is the responder's job to
     * enforce that.
     *
     * kp_unconfirmed marks a keypair we built as *responder*. The
     * initiator confirms it by sending on it; until then we keep
     * sending on the previous one, because a lost handshake response
     * means the initiator never derived this keypair and would discard
     * anything we sent under it.
     */
    uint8_t              last_init_timestamp[WG_TIMESTAMP_LEN];
    int                  have_last_init;
    int                  kp_unconfirmed;
    unsigned long        peer_handshakes;

    /*
     * The endpoint as a name, when it was given as one.
     *
     * Roaming covers a peer that moves and keeps talking, because
     * something authenticated arrives from the new address. It cannot
     * cover one that goes silent and reappears elsewhere — there is
     * nothing to learn from — and that is exactly what happens when a
     * provider retires a server and points its DNS somewhere else.
     *
     * So when every handshake attempt has failed and the endpoint was
     * a name, it is looked up again. Only then: a resolution on every
     * attempt would put a DNS lookup in the path of an ordinary
     * retransmission, and a name that resolves to the same address is
     * a wasted round trip repeated forever.
     */
    char                 endpoint_host[128];
    uint16_t             endpoint_port;
    int                  have_host;
    unsigned long        reresolves;

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

/*
 * Record the name the endpoint was given as, so it can be looked up
 * again if the peer stops answering. Optional: without it the endpoint
 * is whatever wg_client_init was handed, for the life of the client.
 *
 * A literal address may be passed and costs nothing — re-resolving it
 * simply yields the same answer — so callers need not distinguish.
 */
void wg_client_set_endpoint_name(struct wg_client *c, const char *host,
                                 uint16_t port);

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
 *
 * Rekeys first if the session is old enough to need it. A failed rekey
 * is not fatal while the current session is still within
 * reject_after_ms: the old key keeps working and the attempt is made
 * again later, so a momentarily unreachable peer does not cost traffic.
 */
int wg_client_send(struct wg_client *c, const uint8_t *pt, size_t ptlen);

/*
 * Whether the session needs replacing, and whether it is past use.
 * Exposed mainly so callers can report state; wg_client_send applies
 * both itself.
 */
int wg_client_needs_rekey(const struct wg_client *c);
int wg_client_session_expired(const struct wg_client *c);

/*
 * Age of the current session in milliseconds, or 0 if none.
 */
uint64_t wg_client_session_age_ms(const struct wg_client *c);

/*
 * Periodic work: sends a keepalive if keepalive_interval_ms has elapsed
 * since anything was last sent, and rekeys if the session is due.
 *
 * Call it regularly from an event loop. Cheap when there is nothing to
 * do. Returns 0 on success, -1 if a keepalive was due and could not be
 * sent, with client->error set.
 *
 * Without this a NAT or stateful firewall between us and the peer drops
 * its mapping after a minute or two of silence, and inbound packets
 * stop arriving — which is what PersistentKeepalive exists to prevent.
 */
int wg_client_tick(struct wg_client *c);

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
