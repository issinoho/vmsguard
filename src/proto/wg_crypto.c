/*
 * Cryptographic primitives for WireGuard — vmsguard
 */

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "blake2s.h"
#include "wg_crypto.h"

/* ---- hashing -------------------------------------------------------- */

void wg_hash(uint8_t out[WG_HASH_LEN], const uint8_t *in, size_t inlen)
{
    blake2s(out, WG_HASH_LEN, NULL, 0, in, inlen);
}

void wg_hash2(uint8_t out[WG_HASH_LEN],
              const uint8_t *a, size_t alen,
              const uint8_t *b, size_t blen)
{
    struct blake2s_state s;

    blake2s_init(&s, WG_HASH_LEN, NULL, 0);
    blake2s_update(&s, a, alen);
    blake2s_update(&s, b, blen);
    blake2s_final(&s, out);
}

void wg_mac(uint8_t out[WG_MAC_LEN], const uint8_t key[WG_KEY_LEN],
            const uint8_t *in, size_t inlen)
{
    blake2s(out, WG_MAC_LEN, key, WG_KEY_LEN, in, inlen);
}

void wg_hmac(uint8_t out[WG_HASH_LEN], const uint8_t key[WG_KEY_LEN],
             const uint8_t *in, size_t inlen)
{
    /* Standard HMAC over BLAKE2s-256, block size 64. Our keys are always
       32 bytes, comfortably under the block size, so the key never needs
       hashing down first. */
    struct blake2s_state s;
    uint8_t pad[BLAKE2S_BLOCK_LEN];
    uint8_t inner[WG_HASH_LEN];
    size_t i;

    memset(pad, 0, sizeof pad);
    memcpy(pad, key, WG_KEY_LEN);
    for (i = 0; i < sizeof pad; i++)
        pad[i] ^= 0x36;

    blake2s_init(&s, WG_HASH_LEN, NULL, 0);
    blake2s_update(&s, pad, sizeof pad);
    blake2s_update(&s, in, inlen);
    blake2s_final(&s, inner);

    memset(pad, 0, sizeof pad);
    memcpy(pad, key, WG_KEY_LEN);
    for (i = 0; i < sizeof pad; i++)
        pad[i] ^= 0x5C;

    blake2s_init(&s, WG_HASH_LEN, NULL, 0);
    blake2s_update(&s, pad, sizeof pad);
    blake2s_update(&s, inner, sizeof inner);
    blake2s_final(&s, out);

    wg_zero(pad, sizeof pad);
    wg_zero(inner, sizeof inner);
}

void wg_kdf(uint8_t *out1, uint8_t *out2, uint8_t *out3,
            const uint8_t key[WG_KEY_LEN], const uint8_t *in, size_t inlen)
{
    uint8_t temp[WG_HASH_LEN];
    uint8_t buf[WG_HASH_LEN + 1];
    uint8_t prev[WG_HASH_LEN];

    wg_hmac(temp, key, in, inlen);

    buf[0] = 0x01;
    wg_hmac(prev, temp, buf, 1);
    if (out1 != NULL)
        memcpy(out1, prev, WG_HASH_LEN);
    if (out2 == NULL && out3 == NULL)
        goto done;

    memcpy(buf, prev, WG_HASH_LEN);
    buf[WG_HASH_LEN] = 0x02;
    wg_hmac(prev, temp, buf, sizeof buf);
    if (out2 != NULL)
        memcpy(out2, prev, WG_HASH_LEN);
    if (out3 == NULL)
        goto done;

    memcpy(buf, prev, WG_HASH_LEN);
    buf[WG_HASH_LEN] = 0x03;
    wg_hmac(prev, temp, buf, sizeof buf);
    memcpy(out3, prev, WG_HASH_LEN);

done:
    wg_zero(temp, sizeof temp);
    wg_zero(buf, sizeof buf);
    wg_zero(prev, sizeof prev);
}

/* ---- X25519 --------------------------------------------------------- */

int wg_dh_generate(uint8_t sk[WG_KEY_LEN], uint8_t pk[WG_KEY_LEN])
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    size_t len;
    int rc = -1;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);
    if (ctx == NULL)
        goto out;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_generate(ctx, &key) <= 0)
        goto out;

    len = WG_KEY_LEN;
    if (EVP_PKEY_get_raw_private_key(key, sk, &len) <= 0 || len != WG_KEY_LEN)
        goto out;
    len = WG_KEY_LEN;
    if (EVP_PKEY_get_raw_public_key(key, pk, &len) <= 0 || len != WG_KEY_LEN)
        goto out;

    rc = 0;
out:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

int wg_dh_pubkey(uint8_t pk[WG_KEY_LEN], const uint8_t sk[WG_KEY_LEN])
{
    EVP_PKEY *key;
    size_t len = WG_KEY_LEN;
    int rc = -1;

    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, WG_KEY_LEN);
    if (key == NULL)
        return -1;
    if (EVP_PKEY_get_raw_public_key(key, pk, &len) > 0 && len == WG_KEY_LEN)
        rc = 0;

    EVP_PKEY_free(key);
    return rc;
}

int wg_dh(uint8_t out[WG_KEY_LEN], const uint8_t sk[WG_KEY_LEN],
          const uint8_t pk[WG_KEY_LEN])
{
    EVP_PKEY *priv = NULL, *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t len = WG_KEY_LEN;
    int rc = -1;

    priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, WG_KEY_LEN);
    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pk, WG_KEY_LEN);
    if (priv == NULL || peer == NULL)
        goto out;

    ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (ctx == NULL)
        goto out;

    /* OpenSSL rejects an all-zero shared secret, which is exactly the
       small-order-key case WireGuard also treats as a failure. */
    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer) <= 0 ||
        EVP_PKEY_derive(ctx, out, &len) <= 0 || len != WG_KEY_LEN)
        goto out;

    rc = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(priv);
    return rc;
}

/* ---- ChaCha20-Poly1305 ---------------------------------------------- */

static void wg_nonce(uint8_t nonce[12], uint64_t counter)
{
    /* 4 zero bytes, then the counter little-endian. */
    int i;

    memset(nonce, 0, 4);
    for (i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t) ((counter >> (8 * i)) & 0xFF);
}

int wg_aead_encrypt(uint8_t *out, const uint8_t key[WG_KEY_LEN],
                    uint64_t counter, const uint8_t *pt, size_t ptlen,
                    const uint8_t *ad, size_t adlen)
{
    EVP_CIPHER *ciph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t nonce[12];
    int len = 0;
    int rc = -1;

    wg_nonce(nonce, counter);

    ciph = EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL);
    if (ciph == NULL)
        goto out;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto out;

    if (EVP_EncryptInit_ex(ctx, ciph, NULL, key, nonce) <= 0)
        goto out;
    if (adlen > 0 &&
        EVP_EncryptUpdate(ctx, NULL, &len, ad, (int) adlen) <= 0)
        goto out;
    if (ptlen > 0 &&
        EVP_EncryptUpdate(ctx, out, &len, pt, (int) ptlen) <= 0)
        goto out;
    if (EVP_EncryptFinal_ex(ctx, out + ptlen, &len) <= 0)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, WG_TAG_LEN,
                            out + ptlen) <= 0)
        goto out;

    rc = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(ciph);
    wg_zero(nonce, sizeof nonce);
    return rc;
}

int wg_aead_decrypt(uint8_t *out, const uint8_t key[WG_KEY_LEN],
                    uint64_t counter, const uint8_t *ct, size_t ctlen,
                    const uint8_t *ad, size_t adlen)
{
    EVP_CIPHER *ciph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t nonce[12];
    uint8_t tag[WG_TAG_LEN];
    size_t ptlen;
    int len = 0;
    int rc = -1;

    if (ctlen < WG_TAG_LEN)
        return -1;
    ptlen = ctlen - WG_TAG_LEN;

    wg_nonce(nonce, counter);
    memcpy(tag, ct + ptlen, WG_TAG_LEN);

    ciph = EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL);
    if (ciph == NULL)
        goto out;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto out;

    if (EVP_DecryptInit_ex(ctx, ciph, NULL, key, nonce) <= 0)
        goto out;
    if (adlen > 0 &&
        EVP_DecryptUpdate(ctx, NULL, &len, ad, (int) adlen) <= 0)
        goto out;
    if (ptlen > 0 &&
        EVP_DecryptUpdate(ctx, out, &len, ct, (int) ptlen) <= 0)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, WG_TAG_LEN, tag) <= 0)
        goto out;
    if (EVP_DecryptFinal_ex(ctx, out + ptlen, &len) <= 0)
        goto out;   /* tag mismatch */

    rc = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(ciph);
    wg_zero(nonce, sizeof nonce);
    wg_zero(tag, sizeof tag);
    return rc;
}

/* ---- misc ----------------------------------------------------------- */

int wg_random(uint8_t *out, size_t len)
{
    return RAND_bytes(out, (int) len) == 1 ? 0 : -1;
}

int wg_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    return CRYPTO_memcmp(a, b, len) == 0 ? 1 : 0;
}

void wg_zero(void *p, size_t len)
{
    OPENSSL_cleanse(p, len);
}
