/*
 * Cryptographic primitives for WireGuard — vmsguard
 */

#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "blake2s.h"
#include "wg_crypto.h"

/*
 * OpenSSL 3.0 replaced the way an algorithm is named. EVP_CIPHER_fetch,
 * EVP_PKEY_CTX_new_from_name and EVP_PKEY_generate are all 3.0 and
 * later; before that the same primitives were reached through
 * EVP_chacha20_poly1305, EVP_PKEY_CTX_new_id and EVP_PKEY_keygen.
 *
 * This matters for OpenVMS on Itanium, where the shipped OpenSSL is
 * older than the SSL3$ images the x86-64 build links against. Both sets
 * of entry points exist in 3.x -- the older ones are current API, not
 * deprecated -- so the legacy path can be forced on here with
 * -DVMSGUARD_LEGACY_OPENSSL and put through the whole test suite,
 * rather than being written blind and first exercised on hardware that
 * is expensive to reach.
 *
 * The fetched cipher is reference-counted and must be freed; the
 * returned-by-value one must not be. wg_cipher_release hides that
 * difference so the call sites do not have to know which they have.
 */
#if defined(VMSGUARD_LEGACY_OPENSSL) || OPENSSL_VERSION_NUMBER < 0x30000000L
#define WG_LEGACY_OPENSSL 1
#endif

#ifdef WG_LEGACY_OPENSSL
typedef const EVP_CIPHER wg_cipher_t;
#else
typedef EVP_CIPHER wg_cipher_t;
#endif

static wg_cipher_t *wg_cipher_chachapoly(void)
{
#ifdef WG_LEGACY_OPENSSL
    return EVP_chacha20_poly1305();
#else
    return EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL);
#endif
}

static void wg_cipher_release(wg_cipher_t *ciph)
{
#ifdef WG_LEGACY_OPENSSL
    (void) ciph;
#else
    EVP_CIPHER_free(ciph);
#endif
}

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

void wg_mac_n(uint8_t out[WG_MAC_LEN], const uint8_t *key, size_t keylen,
              const uint8_t *in, size_t inlen)
{
    blake2s(out, WG_MAC_LEN, key, keylen, in, inlen);
}

void wg_mac(uint8_t out[WG_MAC_LEN], const uint8_t key[WG_KEY_LEN],
            const uint8_t *in, size_t inlen)
{
    wg_mac_n(out, key, WG_KEY_LEN, in, inlen);
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

#ifdef WG_LEGACY_OPENSSL
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
#else
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);
#endif
    if (ctx == NULL)
        goto out;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto out;
#ifdef WG_LEGACY_OPENSSL
    if (EVP_PKEY_keygen(ctx, &key) <= 0)
        goto out;
#else
    if (EVP_PKEY_generate(ctx, &key) <= 0)
        goto out;
#endif

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

/* ---- HChaCha20, for the extended nonce ------------------------------ */

/*
 * XChaCha20-Poly1305 is ChaCha20-Poly1305 with a 24-byte nonce: the
 * first 16 bytes and the key are run through HChaCha20 to derive a
 * subkey, and the remaining 8 become the last 8 bytes of an ordinary
 * 12-byte nonce.
 *
 * OpenSSL has no XChaCha20 — it offers ChaCha20 and ChaCha20-Poly1305
 * and nothing extended — so the derivation is done here and the subkey
 * handed to the cipher OpenSSL does have.
 *
 * HChaCha20 cannot be built from a ChaCha20 keystream, which is why
 * this is written out rather than borrowed: the stream cipher adds the
 * original state back before emitting a block, and HChaCha20 is defined
 * as the state *without* that final addition. Same rounds, different
 * ending.
 *
 * WireGuard uses this only for the cookie reply, whose nonce is random
 * and therefore too large for a counter-based one to be safe.
 */
static uint32_t rd32le(const uint8_t *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) |
           ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static void wr32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) (v & 0xFF);
    p[1] = (uint8_t) ((v >> 8) & 0xFF);
    p[2] = (uint8_t) ((v >> 16) & 0xFF);
    p[3] = (uint8_t) ((v >> 24) & 0xFF);
}

static uint32_t rotl32(uint32_t v, int n)
{
    /* The mask keeps this defined when n is 0, and lets the compiler
       recognise it as a rotate regardless. */
    return (v << n) | (v >> ((32 - n) & 31));
}

#define QR(a, b, c, d)                                  \
    do {                                                \
        a += b; d ^= a; d = rotl32(d, 16);              \
        c += d; b ^= c; b = rotl32(b, 12);              \
        a += b; d ^= a; d = rotl32(d, 8);               \
        c += d; b ^= c; b = rotl32(b, 7);               \
    } while (0)

static void hchacha20(uint8_t out[32], const uint8_t key[WG_KEY_LEN],
                      const uint8_t nonce16[16])
{
    /* "expand 32-byte k", the ChaCha20 constant. */
    uint32_t x[16];
    int i;

    x[0] = 0x61707865UL;
    x[1] = 0x3320646EUL;
    x[2] = 0x79622D32UL;
    x[3] = 0x6B206574UL;
    for (i = 0; i < 8; i++)
        x[4 + i] = rd32le(key + i * 4);
    for (i = 0; i < 4; i++)
        x[12 + i] = rd32le(nonce16 + i * 4);

    for (i = 0; i < 10; i++) {          /* 10 double rounds = 20 rounds */
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }

    /* The first and last rows only, and no addition of the input state
       — that is the whole difference from a keystream block. */
    for (i = 0; i < 4; i++)
        wr32le(out + i * 4, x[i]);
    for (i = 0; i < 4; i++)
        wr32le(out + 16 + i * 4, x[12 + i]);

    wg_zero(x, sizeof x);
}

#undef QR

/*
 * Shared body for the extended-nonce AEAD. `enc` selects direction so
 * the subkey derivation and nonce splitting are written once.
 */
static int xaead(uint8_t *out, const uint8_t key[WG_KEY_LEN],
                 const uint8_t nonce[WG_XNONCE_LEN],
                 const uint8_t *in, size_t inlen,
                 const uint8_t *ad, size_t adlen, int enc)
{
    wg_cipher_t *ciph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t subkey[32];
    uint8_t n12[12];
    uint8_t tag[WG_TAG_LEN];
    size_t bodylen;
    int len = 0;
    int rc = -1;

    if (!enc && inlen < WG_TAG_LEN)
        return -1;
    bodylen = enc ? inlen : inlen - WG_TAG_LEN;

    hchacha20(subkey, key, nonce);
    memset(n12, 0, 4);                  /* the IETF construction's zeros */
    memcpy(n12 + 4, nonce + 16, 8);

    ciph = wg_cipher_chachapoly();
    if (ciph == NULL)
        goto out;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto out;

    if (enc) {
        if (EVP_EncryptInit_ex(ctx, ciph, NULL, subkey, n12) <= 0)
            goto out;
        if (adlen > 0 &&
            EVP_EncryptUpdate(ctx, NULL, &len, ad, (int) adlen) <= 0)
            goto out;
        if (bodylen > 0 &&
            EVP_EncryptUpdate(ctx, out, &len, in, (int) bodylen) <= 0)
            goto out;
        if (EVP_EncryptFinal_ex(ctx, out + bodylen, &len) <= 0)
            goto out;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, WG_TAG_LEN,
                                out + bodylen) <= 0)
            goto out;
    } else {
        memcpy(tag, in + bodylen, WG_TAG_LEN);
        if (EVP_DecryptInit_ex(ctx, ciph, NULL, subkey, n12) <= 0)
            goto out;
        if (adlen > 0 &&
            EVP_DecryptUpdate(ctx, NULL, &len, ad, (int) adlen) <= 0)
            goto out;
        if (bodylen > 0 &&
            EVP_DecryptUpdate(ctx, out, &len, in, (int) bodylen) <= 0)
            goto out;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, WG_TAG_LEN,
                                tag) <= 0)
            goto out;
        if (EVP_DecryptFinal_ex(ctx, out + bodylen, &len) <= 0)
            goto out;
    }

    rc = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    wg_cipher_release(ciph);
    wg_zero(subkey, sizeof subkey);
    wg_zero(n12, sizeof n12);
    return rc;
}

int wg_xaead_encrypt(uint8_t *out, const uint8_t key[WG_KEY_LEN],
                     const uint8_t nonce[WG_XNONCE_LEN],
                     const uint8_t *pt, size_t ptlen,
                     const uint8_t *ad, size_t adlen)
{
    return xaead(out, key, nonce, pt, ptlen, ad, adlen, 1);
}

int wg_xaead_decrypt(uint8_t *out, const uint8_t key[WG_KEY_LEN],
                     const uint8_t nonce[WG_XNONCE_LEN],
                     const uint8_t *ct, size_t ctlen,
                     const uint8_t *ad, size_t adlen)
{
    return xaead(out, key, nonce, ct, ctlen, ad, adlen, 0);
}

/* ---- ChaCha20-Poly1305 ---------------------------------------------- */

int wg_aead_encrypt(uint8_t *out, const uint8_t key[WG_KEY_LEN],
                    uint64_t counter, const uint8_t *pt, size_t ptlen,
                    const uint8_t *ad, size_t adlen)
{
    wg_cipher_t *ciph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t nonce[12];
    int len = 0;
    int rc = -1;

    wg_nonce(nonce, counter);

    ciph = wg_cipher_chachapoly();
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
    wg_cipher_release(ciph);
    wg_zero(nonce, sizeof nonce);
    return rc;
}

int wg_aead_decrypt(uint8_t *out, const uint8_t key[WG_KEY_LEN],
                    uint64_t counter, const uint8_t *ct, size_t ctlen,
                    const uint8_t *ad, size_t adlen)
{
    wg_cipher_t *ciph = NULL;
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

    ciph = wg_cipher_chachapoly();
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
    wg_cipher_release(ciph);
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
