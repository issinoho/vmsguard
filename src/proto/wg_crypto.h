/*
 * Cryptographic primitives for WireGuard — vmsguard
 *
 * The split here is deliberate:
 *   - BLAKE2s (and HMAC/KDF built on it) is ours, see blake2s.h for why.
 *   - X25519 and ChaCha20-Poly1305 come from OpenSSL, where constant-time
 *     implementation and side-channel resistance matter and are not worth
 *     reimplementing.
 *
 * Naming follows the WireGuard whitepaper so the handshake code can be
 * read against it directly.
 */

#ifndef VMSGUARD_WG_CRYPTO_H
#define VMSGUARD_WG_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define WG_KEY_LEN   32   /* X25519 keys, chaining keys, symmetric keys */
#define WG_HASH_LEN  32   /* BLAKE2s-256 */
#define WG_MAC_LEN   16   /* keyed BLAKE2s-128, for mac1/mac2 */
#define WG_TAG_LEN   16   /* Poly1305 authentication tag */

/* ---- hashing -------------------------------------------------------- */

/* HASH(input) — unkeyed BLAKE2s-256. */
void wg_hash(uint8_t out[WG_HASH_LEN], const uint8_t *in, size_t inlen);

/* HASH(a || b), the form the handshake actually uses throughout. */
void wg_hash2(uint8_t out[WG_HASH_LEN],
              const uint8_t *a, size_t alen,
              const uint8_t *b, size_t blen);

/* MAC(key, input) — keyed BLAKE2s with 16-byte output. */
/*
 * Keyed BLAKE2s-128 with an explicit key length.
 *
 * mac1's key is a 32-byte hash, but mac2's is the 16-byte cookie, and
 * BLAKE2s takes any key up to 32 bytes. The length is a parameter
 * rather than an assumption because assuming it read past the end of a
 * cookie and produced a mac2 no peer would have accepted.
 */
void wg_mac_n(uint8_t out[WG_MAC_LEN], const uint8_t *key, size_t keylen,
              const uint8_t *in, size_t inlen);

void wg_mac(uint8_t out[WG_MAC_LEN], const uint8_t key[WG_KEY_LEN],
            const uint8_t *in, size_t inlen);

/* HMAC(key, input) — HMAC-BLAKE2s-256. */
void wg_hmac(uint8_t out[WG_HASH_LEN], const uint8_t key[WG_KEY_LEN],
             const uint8_t *in, size_t inlen);

/*
 * The WireGuard KDF:
 *     temp = HMAC(key, input)
 *     out1 = HMAC(temp, 0x1)
 *     out2 = HMAC(temp, out1 || 0x2)
 *     out3 = HMAC(temp, out2 || 0x3)
 * Pass NULL for outputs that aren't wanted; they are still computed in
 * order because each feeds the next.
 */
void wg_kdf(uint8_t *out1, uint8_t *out2, uint8_t *out3,
            const uint8_t key[WG_KEY_LEN], const uint8_t *in, size_t inlen);

/* ---- X25519 --------------------------------------------------------- */

/* Generate a keypair. Returns 0 on success, -1 on failure. */
int wg_dh_generate(uint8_t sk[WG_KEY_LEN], uint8_t pk[WG_KEY_LEN]);

/* Derive the public key from a private key. Returns 0 on success. */
int wg_dh_pubkey(uint8_t pk[WG_KEY_LEN], const uint8_t sk[WG_KEY_LEN]);

/*
 * DH(sk, pk). Returns 0 on success, -1 on failure — including the
 * all-zero shared secret produced by a small-order peer key, which
 * OpenSSL rejects and which WireGuard also treats as an error.
 */
int wg_dh(uint8_t out[WG_KEY_LEN], const uint8_t sk[WG_KEY_LEN],
          const uint8_t pk[WG_KEY_LEN]);

/* ---- ChaCha20-Poly1305 ---------------------------------------------- */

/*
 * The nonce is WireGuard's: 4 zero bytes followed by the 64-bit counter
 * little-endian. Handshake messages always use counter 0.
 *
 * Encrypt writes ptlen + WG_TAG_LEN bytes to out.
 * Decrypt writes ctlen - WG_TAG_LEN bytes to out and returns -1 if the
 * tag does not verify. out and in may not overlap.
 *
 * Both return 0 on success, -1 on failure.
 */
int wg_aead_encrypt(uint8_t *out, const uint8_t key[WG_KEY_LEN],
                    uint64_t counter, const uint8_t *pt, size_t ptlen,
                    const uint8_t *ad, size_t adlen);

int wg_aead_decrypt(uint8_t *out, const uint8_t key[WG_KEY_LEN],
                    uint64_t counter, const uint8_t *ct, size_t ctlen,
                    const uint8_t *ad, size_t adlen);

/* ---- XChaCha20-Poly1305 --------------------------------------------- */

/*
 * The extended-nonce variant, used by WireGuard only for the cookie
 * reply — whose nonce is random rather than a counter, and so needs the
 * larger space to be safe.
 *
 * OpenSSL does not provide it, so the HChaCha20 subkey derivation is
 * done in wg_crypto.c and the result handed to ChaCha20-Poly1305.
 *
 * Encrypt writes ptlen + WG_TAG_LEN bytes; decrypt writes
 * ctlen - WG_TAG_LEN and returns -1 if the tag does not verify.
 */
#define WG_XNONCE_LEN 24

int wg_xaead_encrypt(uint8_t *out, const uint8_t key[WG_KEY_LEN],
                     const uint8_t nonce[WG_XNONCE_LEN],
                     const uint8_t *pt, size_t ptlen,
                     const uint8_t *ad, size_t adlen);

int wg_xaead_decrypt(uint8_t *out, const uint8_t key[WG_KEY_LEN],
                     const uint8_t nonce[WG_XNONCE_LEN],
                     const uint8_t *ct, size_t ctlen,
                     const uint8_t *ad, size_t adlen);

/* ---- misc ----------------------------------------------------------- */

/* Cryptographically secure random bytes. Returns 0 on success. */
int wg_random(uint8_t *out, size_t len);

/* Constant-time comparison. Returns 1 if equal, 0 otherwise. */
int wg_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* Best-effort scrub of sensitive memory. */
void wg_zero(void *p, size_t len);

#endif /* VMSGUARD_WG_CRYPTO_H */
