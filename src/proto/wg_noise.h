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

/* Derived transport keys. */
struct wg_keypair {
    uint8_t  send_key[WG_KEY_LEN];
    uint8_t  recv_key[WG_KEY_LEN];
    uint64_t send_counter;
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
