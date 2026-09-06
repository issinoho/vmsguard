/*
 * WireGuard Noise_IKpsk2 handshake — vmsguard
 *
 * Follows the WireGuard whitepaper section 5.4 closely enough that the
 * two can be read side by side. Where the paper writes
 *
 *     temp = HMAC(ck, x); ck = HMAC(temp, 0x1); key = HMAC(temp, ck || 0x2)
 *
 * this code calls wg_kdf(&ck, &key, NULL, ck, x, len), which is the same
 * construction.
 */

#include <string.h>
#include <time.h>

#include "wg_noise.h"

/* ---- setup ---------------------------------------------------------- */

int wg_local_init(struct wg_local *local,
                  const uint8_t static_private[WG_KEY_LEN])
{
    memcpy(local->static_private, static_private, WG_KEY_LEN);
    return wg_dh_pubkey(local->static_public, local->static_private);
}

void wg_mac1_key(uint8_t out[WG_KEY_LEN],
                 const uint8_t static_public[WG_KEY_LEN])
{
    wg_hash2(out, (const uint8_t *) WG_LABEL_MAC1, strlen(WG_LABEL_MAC1),
             static_public, WG_KEY_LEN);
}

void wg_peer_init(struct wg_peer *peer,
                  const uint8_t static_public[WG_KEY_LEN],
                  const uint8_t *psk)
{
    memset(peer, 0, sizeof *peer);
    memcpy(peer->static_public, static_public, WG_KEY_LEN);
    if (psk != NULL)
        memcpy(peer->preshared_key, psk, WG_KEY_LEN);
    wg_mac1_key(peer->mac1_key, static_public);
}

/* ---- shared handshake pieces ---------------------------------------- */

/*
 * Both roles start from the same initial chaining key and hash. The hash
 * is bound to the *responder's* static public key, so the initiator uses
 * the peer's and the responder uses its own.
 */
static void handshake_begin(struct wg_handshake *hs,
                            const uint8_t responder_static[WG_KEY_LEN])
{
    uint8_t tmp[WG_HASH_LEN];

    memset(hs, 0, sizeof *hs);

    wg_hash(hs->chaining_key, (const uint8_t *) WG_CONSTRUCTION,
            strlen(WG_CONSTRUCTION));
    wg_hash2(tmp, hs->chaining_key, WG_HASH_LEN,
             (const uint8_t *) WG_IDENTIFIER, strlen(WG_IDENTIFIER));
    wg_hash2(hs->hash, tmp, WG_HASH_LEN, responder_static, WG_KEY_LEN);

    wg_zero(tmp, sizeof tmp);
}

/* hash = HASH(hash || data) */
static void mix_hash(struct wg_handshake *hs, const uint8_t *data, size_t len)
{
    uint8_t tmp[WG_HASH_LEN];

    wg_hash2(tmp, hs->hash, WG_HASH_LEN, data, len);
    memcpy(hs->hash, tmp, WG_HASH_LEN);
    wg_zero(tmp, sizeof tmp);
}

/* chaining_key = KDF1(chaining_key, data) */
static void mix_key(struct wg_handshake *hs, const uint8_t *data, size_t len)
{
    uint8_t ck[WG_HASH_LEN];

    wg_kdf(ck, NULL, NULL, hs->chaining_key, data, len);
    memcpy(hs->chaining_key, ck, WG_HASH_LEN);
    wg_zero(ck, sizeof ck);
}

/* chaining_key, key = KDF2(chaining_key, data) */
static void mix_key_and_derive(struct wg_handshake *hs, uint8_t key[WG_KEY_LEN],
                               const uint8_t *data, size_t len)
{
    uint8_t ck[WG_HASH_LEN];

    wg_kdf(ck, key, NULL, hs->chaining_key, data, len);
    memcpy(hs->chaining_key, ck, WG_HASH_LEN);
    wg_zero(ck, sizeof ck);
}

/*
 * The psk mixing step, common to both roles:
 *     ck, tau, key = KDF3(ck, psk)
 *     hash = HASH(hash || tau)
 */
static void mix_psk(struct wg_handshake *hs, uint8_t key[WG_KEY_LEN],
                    const uint8_t psk[WG_KEY_LEN])
{
    uint8_t ck[WG_HASH_LEN], tau[WG_HASH_LEN];

    wg_kdf(ck, tau, key, hs->chaining_key, psk, WG_KEY_LEN);
    memcpy(hs->chaining_key, ck, WG_HASH_LEN);
    mix_hash(hs, tau, WG_HASH_LEN);

    wg_zero(ck, sizeof ck);
    wg_zero(tau, sizeof tau);
}

/*
 * Final transport key derivation. The initiator sends with the first
 * output and receives with the second; the responder is the mirror.
 */
static void derive_keys(struct wg_keypair *kp, const struct wg_handshake *hs,
                        int is_initiator)
{
    uint8_t t1[WG_HASH_LEN], t2[WG_HASH_LEN];

    wg_kdf(t1, t2, NULL, hs->chaining_key, NULL, 0);

    if (is_initiator) {
        memcpy(kp->send_key, t1, WG_KEY_LEN);
        memcpy(kp->recv_key, t2, WG_KEY_LEN);
    } else {
        memcpy(kp->send_key, t2, WG_KEY_LEN);
        memcpy(kp->recv_key, t1, WG_KEY_LEN);
    }
    kp->send_counter = 0;
    kp->local_index = hs->local_index;
    kp->remote_index = hs->remote_index;

    wg_zero(t1, sizeof t1);
    wg_zero(t2, sizeof t2);
}

/* mac1 over everything preceding the mac1 field; mac2 left zero (we
   never send a cookie-derived mac2 until challenged). */
static void append_macs(uint8_t *msg, size_t mac1_offset,
                        const uint8_t mac1_key[WG_KEY_LEN])
{
    wg_mac(msg + mac1_offset, mac1_key, msg, mac1_offset);
    memset(msg + mac1_offset + WG_MAC_LEN, 0, WG_MAC_LEN);
}

int wg_mac1_verify(const uint8_t *msg, size_t msglen, size_t mac1_offset,
                   const uint8_t mac1_key[WG_KEY_LEN])
{
    uint8_t expected[WG_MAC_LEN];
    int ok;

    if (msglen < mac1_offset + WG_MAC_LEN)
        return 0;

    wg_mac(expected, mac1_key, msg, mac1_offset);
    ok = wg_equal(expected, msg + mac1_offset, WG_MAC_LEN);
    wg_zero(expected, sizeof expected);
    return ok;
}

/* ---- initiator ------------------------------------------------------ */

int wg_handshake_create_initiation(uint8_t msg[WG_INIT_LEN],
                                   struct wg_handshake *hs,
                                   const struct wg_local *local,
                                   const struct wg_peer *peer,
                                   uint32_t local_index)
{
    uint8_t key[WG_KEY_LEN];
    uint8_t dh[WG_KEY_LEN];
    uint8_t timestamp[WG_TIMESTAMP_LEN];
    int rc = -1;

    handshake_begin(hs, peer->static_public);
    hs->local_index = local_index;

    if (wg_dh_generate(hs->ephemeral_private, hs->ephemeral_public) != 0)
        goto out;

    memset(msg, 0, WG_INIT_LEN);
    msg[WG_INIT_OFF_TYPE] = WG_MSG_HANDSHAKE_INIT;
    wg_put32(msg + WG_INIT_OFF_SENDER, local_index);
    memcpy(msg + WG_INIT_OFF_EPHEMERAL, hs->ephemeral_public, WG_KEY_LEN);

    mix_hash(hs, hs->ephemeral_public, WG_KEY_LEN);
    mix_key(hs, hs->ephemeral_public, WG_KEY_LEN);

    /* es: ephemeral-static */
    if (wg_dh(dh, hs->ephemeral_private, peer->static_public) != 0)
        goto out;
    mix_key_and_derive(hs, key, dh, WG_KEY_LEN);

    if (wg_aead_encrypt(msg + WG_INIT_OFF_STATIC, key, 0,
                        local->static_public, WG_KEY_LEN,
                        hs->hash, WG_HASH_LEN) != 0)
        goto out;
    mix_hash(hs, msg + WG_INIT_OFF_STATIC, WG_KEY_LEN + WG_TAG_LEN);

    /* ss: static-static */
    if (wg_dh(dh, local->static_private, peer->static_public) != 0)
        goto out;
    mix_key_and_derive(hs, key, dh, WG_KEY_LEN);

    wg_timestamp(timestamp);
    if (wg_aead_encrypt(msg + WG_INIT_OFF_TIMESTAMP, key, 0,
                        timestamp, WG_TIMESTAMP_LEN,
                        hs->hash, WG_HASH_LEN) != 0)
        goto out;
    mix_hash(hs, msg + WG_INIT_OFF_TIMESTAMP,
             WG_TIMESTAMP_LEN + WG_TAG_LEN);

    append_macs(msg, WG_INIT_OFF_MAC1, peer->mac1_key);
    rc = 0;

out:
    wg_zero(key, sizeof key);
    wg_zero(dh, sizeof dh);
    wg_zero(timestamp, sizeof timestamp);
    return rc;
}

int wg_handshake_consume_response(const uint8_t msg[WG_RESP_LEN],
                                  struct wg_handshake *hs,
                                  const struct wg_local *local,
                                  const struct wg_peer *peer,
                                  struct wg_keypair *kp)
{
    uint8_t key[WG_KEY_LEN];
    uint8_t dh[WG_KEY_LEN];
    uint8_t nothing[1];       /* decrypts to zero bytes */
    int rc = -1;

    if (msg[WG_RESP_OFF_TYPE] != WG_MSG_HANDSHAKE_RESP)
        return -1;
    if (wg_get32(msg + WG_RESP_OFF_RECEIVER) != hs->local_index)
        return -1;

    hs->remote_index = wg_get32(msg + WG_RESP_OFF_SENDER);
    memcpy(hs->remote_ephemeral, msg + WG_RESP_OFF_EPHEMERAL, WG_KEY_LEN);

    mix_hash(hs, hs->remote_ephemeral, WG_KEY_LEN);
    mix_key(hs, hs->remote_ephemeral, WG_KEY_LEN);

    /* ee: our ephemeral with their ephemeral */
    if (wg_dh(dh, hs->ephemeral_private, hs->remote_ephemeral) != 0)
        goto out;
    mix_key(hs, dh, WG_KEY_LEN);

    /* se: our static with their ephemeral */
    if (wg_dh(dh, local->static_private, hs->remote_ephemeral) != 0)
        goto out;
    mix_key(hs, dh, WG_KEY_LEN);

    mix_psk(hs, key, peer->preshared_key);

    /* The empty payload authenticates the whole transcript. */
    if (wg_aead_decrypt(nothing, key, 0, msg + WG_RESP_OFF_EMPTY,
                        WG_TAG_LEN, hs->hash, WG_HASH_LEN) != 0)
        goto out;
    mix_hash(hs, msg + WG_RESP_OFF_EMPTY, WG_TAG_LEN);

    derive_keys(kp, hs, 1);
    wg_handshake_clear(hs);
    rc = 0;

out:
    wg_zero(key, sizeof key);
    wg_zero(dh, sizeof dh);
    return rc;
}

/* ---- responder ------------------------------------------------------ */

int wg_handshake_consume_initiation(const uint8_t msg[WG_INIT_LEN],
                                    struct wg_handshake *hs,
                                    const struct wg_local *local,
                                    uint8_t timestamp[WG_TIMESTAMP_LEN])
{
    uint8_t key[WG_KEY_LEN];
    uint8_t dh[WG_KEY_LEN];
    int rc = -1;

    if (msg[WG_INIT_OFF_TYPE] != WG_MSG_HANDSHAKE_INIT)
        return -1;

    handshake_begin(hs, local->static_public);
    hs->remote_index = wg_get32(msg + WG_INIT_OFF_SENDER);
    memcpy(hs->remote_ephemeral, msg + WG_INIT_OFF_EPHEMERAL, WG_KEY_LEN);

    mix_hash(hs, hs->remote_ephemeral, WG_KEY_LEN);
    mix_key(hs, hs->remote_ephemeral, WG_KEY_LEN);

    /* es, from the responder's side */
    if (wg_dh(dh, local->static_private, hs->remote_ephemeral) != 0)
        goto out;
    mix_key_and_derive(hs, key, dh, WG_KEY_LEN);

    if (wg_aead_decrypt(hs->remote_static, key, 0,
                        msg + WG_INIT_OFF_STATIC, WG_KEY_LEN + WG_TAG_LEN,
                        hs->hash, WG_HASH_LEN) != 0)
        goto out;
    mix_hash(hs, msg + WG_INIT_OFF_STATIC, WG_KEY_LEN + WG_TAG_LEN);

    /* ss */
    if (wg_dh(dh, local->static_private, hs->remote_static) != 0)
        goto out;
    mix_key_and_derive(hs, key, dh, WG_KEY_LEN);

    if (wg_aead_decrypt(timestamp, key, 0,
                        msg + WG_INIT_OFF_TIMESTAMP,
                        WG_TIMESTAMP_LEN + WG_TAG_LEN,
                        hs->hash, WG_HASH_LEN) != 0)
        goto out;
    mix_hash(hs, msg + WG_INIT_OFF_TIMESTAMP,
             WG_TIMESTAMP_LEN + WG_TAG_LEN);

    rc = 0;

out:
    wg_zero(key, sizeof key);
    wg_zero(dh, sizeof dh);
    return rc;
}

int wg_handshake_create_response(uint8_t msg[WG_RESP_LEN],
                                 struct wg_handshake *hs,
                                 const struct wg_local *local,
                                 const struct wg_peer *peer,
                                 uint32_t local_index,
                                 struct wg_keypair *kp)
{
    uint8_t key[WG_KEY_LEN];
    uint8_t dh[WG_KEY_LEN];
    int rc = -1;

    (void) local;   /* the responder's static key is already folded in */

    hs->local_index = local_index;

    if (wg_dh_generate(hs->ephemeral_private, hs->ephemeral_public) != 0)
        goto out;

    memset(msg, 0, WG_RESP_LEN);
    msg[WG_RESP_OFF_TYPE] = WG_MSG_HANDSHAKE_RESP;
    wg_put32(msg + WG_RESP_OFF_SENDER, local_index);
    wg_put32(msg + WG_RESP_OFF_RECEIVER, hs->remote_index);
    memcpy(msg + WG_RESP_OFF_EPHEMERAL, hs->ephemeral_public, WG_KEY_LEN);

    mix_hash(hs, hs->ephemeral_public, WG_KEY_LEN);
    mix_key(hs, hs->ephemeral_public, WG_KEY_LEN);

    /* ee */
    if (wg_dh(dh, hs->ephemeral_private, hs->remote_ephemeral) != 0)
        goto out;
    mix_key(hs, dh, WG_KEY_LEN);

    /* se: our ephemeral with their static */
    if (wg_dh(dh, hs->ephemeral_private, hs->remote_static) != 0)
        goto out;
    mix_key(hs, dh, WG_KEY_LEN);

    mix_psk(hs, key, peer->preshared_key);

    if (wg_aead_encrypt(msg + WG_RESP_OFF_EMPTY, key, 0, NULL, 0,
                        hs->hash, WG_HASH_LEN) != 0)
        goto out;
    mix_hash(hs, msg + WG_RESP_OFF_EMPTY, WG_TAG_LEN);

    append_macs(msg, WG_RESP_OFF_MAC1, peer->mac1_key);

    derive_keys(kp, hs, 0);
    wg_handshake_clear(hs);
    rc = 0;

out:
    wg_zero(key, sizeof key);
    wg_zero(dh, sizeof dh);
    return rc;
}

/* ---- transport data ------------------------------------------------- */

int wg_transport_encrypt(uint8_t *out, size_t *outlen,
                         struct wg_keypair *kp,
                         const uint8_t *pt, size_t ptlen)
{
    uint8_t padded[2048];
    size_t padded_len;

    /* WireGuard pads plaintext up to a multiple of 16 bytes so that
       packet lengths leak less. A zero-length payload is a keepalive and
       is sent unpadded. */
    if (ptlen == 0) {
        padded_len = 0;
    } else {
        padded_len = (ptlen + 15) & ~(size_t) 15;
        if (padded_len > sizeof padded)
            return -1;
        memcpy(padded, pt, ptlen);
        memset(padded + ptlen, 0, padded_len - ptlen);
    }

    out[WG_DATA_OFF_TYPE] = WG_MSG_TRANSPORT_DATA;
    out[1] = out[2] = out[3] = 0;
    wg_put32(out + WG_DATA_OFF_RECEIVER, kp->remote_index);
    wg_put64(out + WG_DATA_OFF_COUNTER, kp->send_counter);

    if (wg_aead_encrypt(out + WG_DATA_HDR_LEN, kp->send_key,
                        kp->send_counter,
                        padded_len > 0 ? padded : NULL, padded_len,
                        NULL, 0) != 0) {
        wg_zero(padded, sizeof padded);
        return -1;
    }

    kp->send_counter++;
    *outlen = WG_DATA_HDR_LEN + padded_len + WG_TAG_LEN;

    wg_zero(padded, sizeof padded);
    return 0;
}

int wg_transport_decrypt(uint8_t *out, size_t *outlen, uint64_t *counter,
                         const struct wg_keypair *kp,
                         const uint8_t *msg, size_t msglen)
{
    size_t ctlen;

    if (msglen < WG_DATA_HDR_LEN + WG_TAG_LEN)
        return -1;
    if (msg[WG_DATA_OFF_TYPE] != WG_MSG_TRANSPORT_DATA)
        return -1;
    if (wg_get32(msg + WG_DATA_OFF_RECEIVER) != kp->local_index)
        return -1;

    *counter = wg_get64(msg + WG_DATA_OFF_COUNTER);
    ctlen = msglen - WG_DATA_HDR_LEN;

    if (wg_aead_decrypt(out, kp->recv_key, *counter,
                        msg + WG_DATA_HDR_LEN, ctlen, NULL, 0) != 0)
        return -1;

    *outlen = ctlen - WG_TAG_LEN;
    return 0;
}

/* ---- misc ----------------------------------------------------------- */

void wg_timestamp(uint8_t out[WG_TIMESTAMP_LEN])
{
    /*
     * TAI64N: 8 bytes of seconds since the TAI epoch, big-endian, then 4
     * bytes of nanoseconds, big-endian. The 0x400000000000000a base is
     * 2^62 plus the 10-second TAI-UTC offset, matching what WireGuard
     * uses.
     *
     * clock_gettime is avoided for portability — VSI C's availability is
     * unconfirmed. time() gives whole seconds only, so a counter keeps
     * timestamps strictly increasing within a second, which is what the
     * replay check on the far side needs.
     */
    static uint64_t last_sec;
    static uint32_t nsec;

    uint64_t sec = (uint64_t) time(NULL);
    int i;

    if (sec == last_sec) {
        nsec += 1000;
    } else {
        last_sec = sec;
        nsec = 0;
    }

    sec += 0x400000000000000AULL;

    for (i = 0; i < 8; i++)
        out[i] = (uint8_t) ((sec >> (8 * (7 - i))) & 0xFF);
    for (i = 0; i < 4; i++)
        out[8 + i] = (uint8_t) ((nsec >> (8 * (3 - i))) & 0xFF);
}

void wg_handshake_clear(struct wg_handshake *hs)
{
    wg_zero(hs, sizeof *hs);
}

void wg_keypair_clear(struct wg_keypair *kp)
{
    wg_zero(kp, sizeof *kp);
}
