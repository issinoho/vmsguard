/*
 * WireGuard Noise_IKpsk2 handshake — vmsguard
 *
 * Written from the WireGuard whitepaper (section 5.4) and the Noise
 * Protocol Framework specification, not derived from the GPLv2 Linux
 * kernel implementation, so this project stays permissively licensed.
 *
 * Both roles are implemented. The MVP only needs the initiator, but the
 * responder is what lets the handshake be tested end to end in-process,
 * without standing up a peer — and it is only a little extra code.
 *
 * No allocation, no I/O, no platform dependencies: this layer is pure
 * state transformation over byte buffers, which is what makes it
 * portable to OpenVMS unchanged.
 */

#ifndef VMSGUARD_WG_NOISE_H
#define VMSGUARD_WG_NOISE_H

#include <stddef.h>
#include <stdint.h>

#include "wg_crypto.h"
#include "wg_proto.h"

/* Our own identity. */
struct wg_local {
    uint8_t static_private[WG_KEY_LEN];
    uint8_t static_public[WG_KEY_LEN];
};

/* A remote peer. */
struct wg_peer {
    uint8_t static_public[WG_KEY_LEN];
    uint8_t preshared_key[WG_KEY_LEN];  /* all zeroes when unused */
    uint8_t mac1_key[WG_KEY_LEN];       /* HASH(LABEL_MAC1 || static_public) */
};

/* In-flight handshake state. Discarded once a keypair is derived. */
struct wg_handshake {
    uint8_t  chaining_key[WG_HASH_LEN];
    uint8_t  hash[WG_HASH_LEN];
    uint8_t  ephemeral_private[WG_KEY_LEN];
    uint8_t  ephemeral_public[WG_KEY_LEN];
    uint8_t  remote_ephemeral[WG_KEY_LEN];
    uint8_t  remote_static[WG_KEY_LEN];  /* learned by the responder */
    uint32_t local_index;
    uint32_t remote_index;
};

/*
 * Timer and counter limits from the WireGuard whitepaper, section 6.5.
 * Times are milliseconds here; the paper gives seconds.
 */
#define WG_REKEY_AFTER_TIME_MS    120000UL  /* rekey once a session is this old */
#define WG_REJECT_AFTER_TIME_MS   180000UL  /* a session older than this is dead */
#define WG_REKEY_TIMEOUT_MS         5000UL  /* pace between handshake attempts */
#define WG_KEEPALIVE_TIMEOUT_MS    10000UL
#define WG_REKEY_ATTEMPT_TIME_MS   90000UL  /* give up rekeying after this */

/*
 * The receiver rekeys slightly earlier than the sender would, so that a
 * session is replaced before the far side starts rejecting it. The
 * paper's figure is REKEY_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT.
 */
#define WG_REKEY_AFTER_TIME_RECV_MS \
    (WG_REKEY_AFTER_TIME_MS - WG_KEEPALIVE_TIMEOUT_MS - WG_REKEY_TIMEOUT_MS)

/* 2^60 messages. Reaching this before the time limit takes some doing,
   but the counter must not be allowed to wrap. */
#define WG_REKEY_AFTER_MESSAGES   (1ULL << 60)

/*
 * Replay protection.
 *
 * A strict "counter must exceed the highest seen" rule rejects any
 * packet the network reorders, and networks reorder. WireGuard specifies
 * a sliding window instead: a packet is accepted if it is newer than
 * everything seen, or within the window and not already seen.
 *
 * 64 bits is narrower than the kernel implementation's 2048 but far
 * simpler, and covers ordinary reordering comfortably. The bitmap holds
 * one bit per counter below max, bit 0 being max itself.
 */
#define WG_REPLAY_WINDOW 64

struct wg_replay {
    uint64_t max;
    uint64_t bitmap;
};

void wg_replay_init(struct wg_replay *r);

/*
 * Test a counter and record it. Returns 1 to accept, 0 to reject as a
 * duplicate or as too old to judge.
 *
 * Counter 0 is valid: a fresh window accepts it exactly once.
 */
int wg_replay_check(struct wg_replay *r, uint64_t counter);

/* Derived transport keys. */
struct wg_keypair {
    uint8_t  send_key[WG_KEY_LEN];
    uint8_t  recv_key[WG_KEY_LEN];
    uint64_t send_counter;
    struct wg_replay replay;
    uint32_t local_index;
    uint32_t remote_index;
};

/* ---- setup ---------------------------------------------------------- */

/* Fill in static_public from static_private. Returns 0 on success. */
int wg_local_init(struct wg_local *local,
                  const uint8_t static_private[WG_KEY_LEN]);

/* psk may be NULL, meaning no preshared key. */
void wg_peer_init(struct wg_peer *peer,
                  const uint8_t static_public[WG_KEY_LEN],
                  const uint8_t *psk);

/* ---- initiator ------------------------------------------------------ */

/*
 * Build a handshake initiation into msg (WG_INIT_LEN bytes) and leave the
 * in-flight state in hs. local_index is our sender index, chosen by the
 * caller. Returns 0 on success, -1 on failure.
 */
int wg_handshake_create_initiation(uint8_t msg[WG_INIT_LEN],
                                   struct wg_handshake *hs,
                                   const struct wg_local *local,
                                   const struct wg_peer *peer,
                                   uint32_t local_index);

/*
 * Consume a handshake response, completing the handshake and producing
 * transport keys. Returns 0 on success, -1 on failure (including a failed
 * authentication tag). hs is scrubbed on success.
 */
int wg_handshake_consume_response(const uint8_t msg[WG_RESP_LEN],
                                  struct wg_handshake *hs,
                                  const struct wg_local *local,
                                  const struct wg_peer *peer,
                                  struct wg_keypair *kp);

/* ---- responder ------------------------------------------------------ */

/*
 * Consume a handshake initiation. The initiator's static public key is
 * recovered into hs->remote_static; the caller is responsible for
 * deciding whether it belongs to a known peer. The TAI64N timestamp is
 * written to timestamp (WG_TIMESTAMP_LEN bytes) for replay checking by
 * the caller. Returns 0 on success, -1 on failure.
 */
int wg_handshake_consume_initiation(const uint8_t msg[WG_INIT_LEN],
                                    struct wg_handshake *hs,
                                    const struct wg_local *local,
                                    uint8_t timestamp[WG_TIMESTAMP_LEN]);

/*
 * Build a handshake response into msg (WG_RESP_LEN bytes) and derive
 * transport keys. Returns 0 on success, -1 on failure. hs is scrubbed on
 * success.
 */
int wg_handshake_create_response(uint8_t msg[WG_RESP_LEN],
                                 struct wg_handshake *hs,
                                 const struct wg_local *local,
                                 const struct wg_peer *peer,
                                 uint32_t local_index,
                                 struct wg_keypair *kp);

/* ---- mac1 ----------------------------------------------------------- */

/*
 * Verify the mac1 field of a received handshake message against our own
 * static public key. Returns 1 if valid, 0 if not.
 *
 * mac1_key must be HASH(LABEL_MAC1 || our static public key) — note this
 * is the *receiver's* key, so it differs from the peer->mac1_key used
 * when sending.
 */
int wg_mac1_verify(const uint8_t *msg, size_t msglen, size_t mac1_offset,
                   const uint8_t mac1_key[WG_KEY_LEN]);

/* ---- cookies -------------------------------------------------------- */

/*
 * Under load a responder stops doing the expensive part of a handshake
 * and instead replies with a cookie: a MAC over the initiator's address
 * under a secret it rotates. The initiator must echo that cookie back
 * as mac2 on its next attempt, which proves it can receive at the
 * address it claims, and costs an attacker forging source addresses
 * everything while costing a real peer one round trip.
 *
 * We are the initiator, so we never mint cookies in normal operation —
 * we decrypt one, remember it, and attach mac2 until it goes stale.
 * wg_cookie_reply_create exists for the responder role and for testing
 * the exchange end to end.
 *
 * mac2 covers the whole message including mac1, so it can only be
 * applied once the message is otherwise finished. That is why it is a
 * separate step rather than a parameter to the create functions: the
 * ordering is forced by the protocol, not by taste.
 *
 * A cookie older than this is not used. The responder rotates its
 * secret every two minutes, so an older one would be rejected anyway.
 */
#define WG_COOKIE_VALIDITY_MS 120000UL

struct wg_cookie {
    uint8_t  cookie_key[WG_KEY_LEN];  /* HASH(LABEL_COOKIE || peer pubkey) */
    uint8_t  cookie[WG_MAC_LEN];      /* the last one received             */
    uint8_t  last_mac1[WG_MAC_LEN];   /* of the message we last sent       */
    uint64_t received_ms;
    int      have;                    /* a cookie has been received        */
    int      have_mac1;               /* we have something to authenticate
                                         a cookie reply against            */
};

/* peer_static_public is the *responder's* key: the cookie is encrypted
   to it, so only someone holding its private key could have sent it. */
void wg_cookie_init(struct wg_cookie *ck,
                    const uint8_t peer_static_public[WG_KEY_LEN]);

/*
 * Remember the mac1 of a message just built, which is the additional
 * data a cookie reply to it will be authenticated with. Call after
 * creating a handshake message and before sending it.
 */
void wg_cookie_sent(struct wg_cookie *ck, const uint8_t *msg,
                    size_t mac1_offset);

/*
 * Write mac2 into a finished handshake message if a usable cookie is
 * held. Returns 1 if one was written, 0 if the field was left zero —
 * which is correct and normal when no cookie has been received or the
 * last one has gone stale.
 */
int wg_cookie_apply(const struct wg_cookie *ck, uint8_t *msg,
                    size_t mac2_offset, uint64_t now_ms);

/*
 * Consume a cookie reply. our_index is the sender index we used in the
 * message being answered; a reply naming anything else is not ours.
 * Returns 0 on success, -1 if it is malformed, misaddressed, or fails
 * to decrypt — which is what an off-path forgery looks like.
 */
int wg_cookie_consume(struct wg_cookie *ck, const uint8_t *msg, size_t msglen,
                      uint32_t our_index, uint64_t now_ms);

/*
 * Build a cookie reply, the responder's half. `secret` is the responder's
 * rotating secret, `endpoint` the initiator's address and port in
 * whatever encoding the caller uses consistently, and msg_mac1 the mac1
 * of the message being answered.
 *
 * Returns 0 on success, -1 on failure.
 */
int wg_cookie_reply_create(uint8_t msg[WG_COOKIE_LEN],
                           const uint8_t cookie_key[WG_KEY_LEN],
                           const uint8_t secret[WG_KEY_LEN],
                           const uint8_t *endpoint, size_t endpoint_len,
                           const uint8_t msg_mac1[WG_MAC_LEN],
                           uint32_t receiver_index);

/* Compute HASH(LABEL_COOKIE || static_public) into out. */
void wg_cookie_key(uint8_t out[WG_KEY_LEN],
                   const uint8_t static_public[WG_KEY_LEN]);

/* Compute HASH(LABEL_MAC1 || static_public) into out. */
void wg_mac1_key(uint8_t out[WG_KEY_LEN],
                 const uint8_t static_public[WG_KEY_LEN]);

/* ---- transport data ------------------------------------------------- */

/*
 * Encrypt a plaintext packet into a transport data message. out must have
 * room for WG_DATA_HDR_LEN + ptlen + WG_TAG_LEN bytes; the total is
 * written to outlen. The keypair's send_counter is incremented.
 *
 * WireGuard pads plaintext to a multiple of 16 bytes before encryption;
 * that padding is applied here, so out must allow for it.
 *
 * Returns 0 on success, -1 on failure.
 */
int wg_transport_encrypt(uint8_t *out, size_t *outlen,
                         struct wg_keypair *kp,
                         const uint8_t *pt, size_t ptlen);

/*
 * Decrypt a transport data message. out must have room for
 * msglen - WG_DATA_HDR_LEN - WG_TAG_LEN bytes. The recovered counter is
 * written to counter for replay checking by the caller.
 *
 * Note the plaintext length includes any padding the sender applied;
 * stripping it is the caller's job, using the inner packet's own length
 * field. A zero-length result is a keepalive.
 *
 * Returns 0 on success, -1 on failure.
 */
int wg_transport_decrypt(uint8_t *out, size_t *outlen, uint64_t *counter,
                         const struct wg_keypair *kp,
                         const uint8_t *msg, size_t msglen);

/* ---- misc ----------------------------------------------------------- */

/* Current time as a TAI64N timestamp, guaranteed strictly increasing
   within this process. */
void wg_timestamp(uint8_t out[WG_TIMESTAMP_LEN]);

void wg_handshake_clear(struct wg_handshake *hs);
void wg_keypair_clear(struct wg_keypair *kp);

#endif /* VMSGUARD_WG_NOISE_H */
