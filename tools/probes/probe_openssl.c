/*
 * vmsguard probe: OpenSSL primitives
 *
 * Confirms the installed OpenSSL provides every primitive WireGuard needs
 * and that each one actually works — not merely that it can be fetched.
 * Vendor builds sometimes ship headers for algorithms the library was
 * configured without.
 *
 * Exercises:
 *   - X25519 keygen and shared-secret agreement (both directions agree)
 *   - ChaCha20-Poly1305 seal/open with AAD, including tamper detection
 *   - BLAKE2s-256 hashing
 *   - HKDF over BLAKE2s-256
 *
 * C99. Build instructions in README.md.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>

/*
 * Two OpenSSL generations, as in src/proto/wg_crypto.c and for the same
 * reason: an OpenVMS system may have 1.1.1 and nothing newer. This probe
 * was 3.0-only and stopped a 1.1.1 build dead on <openssl/params.h>,
 * before the test suite it is built alongside had a chance to run --
 * which is the wrong way round, since the probe is the less important of
 * the two.
 *
 * The 3.0 fetch-by-name calls have pre-3.0 equivalents that are current
 * API rather than deprecated, and all of them still exist in 3.x. So the
 * legacy branch can be forced on with -DVMSGUARD_LEGACY_OPENSSL and
 * actually run on a machine with 3.x installed, which is how it was
 * checked before going anywhere near the target.
 */
#if defined(VMSGUARD_LEGACY_OPENSSL) || OPENSSL_VERSION_NUMBER < 0x30000000L
#define WG_LEGACY_OPENSSL 1
#endif

#ifdef WG_LEGACY_OPENSSL
typedef const EVP_CIPHER wg_cipher_t;
typedef const EVP_MD wg_md_t;
#define wg_md_size(md)      EVP_MD_size(md)
#define wg_cipher_release(c)
#define wg_md_release(m)
#else
#include <openssl/params.h>
typedef EVP_CIPHER wg_cipher_t;
typedef EVP_MD wg_md_t;
#define wg_md_size(md)      EVP_MD_get_size(md)
#define wg_cipher_release(c) EVP_CIPHER_free(c)
#define wg_md_release(m)     EVP_MD_free(m)
#endif

static int failures = 0;

static void ok(const char *what)
{
    printf("  ok    %s\n", what);
}

static void fail(const char *what)
{
    printf("  FAIL  %s\n", what);
    failures++;
}

/* ------------------------------------------------------------------ */

static void test_x25519(void)
{
    EVP_PKEY_CTX *kctx = NULL, *dctx = NULL;
    EVP_PKEY *a = NULL, *b = NULL;
    unsigned char sa[32], sb[32];
    size_t la = sizeof sa, lb = sizeof sb;

#ifdef WG_LEGACY_OPENSSL
    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
#else
    kctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);
#endif
    if (kctx == NULL) {
        fail("X25519 not available");
        return;
    }
#ifdef WG_LEGACY_OPENSSL
    if (EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_keygen(kctx, &a) <= 0 ||
        EVP_PKEY_keygen(kctx, &b) <= 0) {
#else
    if (EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_generate(kctx, &a) <= 0 ||
        EVP_PKEY_generate(kctx, &b) <= 0) {
#endif
        fail("X25519 keygen");
        goto done;
    }
    ok("X25519 keygen");

    /* a's view of the shared secret */
    dctx = EVP_PKEY_CTX_new(a, NULL);
    if (dctx == NULL || EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, b) <= 0 ||
        EVP_PKEY_derive(dctx, sa, &la) <= 0) {
        fail("X25519 derive (a)");
        goto done;
    }
    EVP_PKEY_CTX_free(dctx);

    /* b's view; must match */
    dctx = EVP_PKEY_CTX_new(b, NULL);
    if (dctx == NULL || EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, a) <= 0 ||
        EVP_PKEY_derive(dctx, sb, &lb) <= 0) {
        fail("X25519 derive (b)");
        goto done;
    }

    if (la == 32 && lb == 32 && memcmp(sa, sb, 32) == 0)
        ok("X25519 shared secrets agree");
    else
        fail("X25519 shared secrets DISAGREE");

done:
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
}

/* ------------------------------------------------------------------ */

static void test_chachapoly(void)
{
    static const unsigned char key[32] = { 0 };
    static const unsigned char nonce[12] = { 0 };
    static const unsigned char aad[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    static const unsigned char pt[] = "wireguard on openvms";
    const int ptlen = (int) (sizeof pt - 1);  /* exclude the NUL */

    wg_cipher_t *ciph = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char ct[sizeof pt], tag[16], out[sizeof pt];
    int len = 0;

#ifdef WG_LEGACY_OPENSSL
    ciph = EVP_chacha20_poly1305();
#else
    ciph = EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL);
#endif
    if (ciph == NULL) {
        fail("ChaCha20-Poly1305 not available");
        return;
    }
    ok("ChaCha20-Poly1305 available");

    /* seal */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL || EVP_EncryptInit_ex(ctx, ciph, NULL, key, nonce) <= 0 ||
        EVP_EncryptUpdate(ctx, NULL, &len, aad, (int) sizeof aad) <= 0 ||
        EVP_EncryptUpdate(ctx, ct, &len, pt, ptlen) <= 0 ||
        EVP_EncryptFinal_ex(ctx, ct + len, &len) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) <= 0) {
        fail("ChaCha20-Poly1305 seal");
        goto done;
    }
    ok("ChaCha20-Poly1305 seal");
    EVP_CIPHER_CTX_free(ctx);

    /* open */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL || EVP_DecryptInit_ex(ctx, ciph, NULL, key, nonce) <= 0 ||
        EVP_DecryptUpdate(ctx, NULL, &len, aad, (int) sizeof aad) <= 0 ||
        EVP_DecryptUpdate(ctx, out, &len, ct, ptlen) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) <= 0) {
        fail("ChaCha20-Poly1305 open setup");
        goto done;
    }
    if (EVP_DecryptFinal_ex(ctx, out + len, &len) <= 0) {
        fail("ChaCha20-Poly1305 tag verify");
        goto done;
    }
    if (memcmp(out, pt, (size_t) ptlen) == 0)
        ok("ChaCha20-Poly1305 roundtrip");
    else
        fail("ChaCha20-Poly1305 plaintext mismatch");
    EVP_CIPHER_CTX_free(ctx);

    /* tampered ciphertext must be rejected */
    ct[0] ^= 0x01;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx != NULL && EVP_DecryptInit_ex(ctx, ciph, NULL, key, nonce) > 0 &&
        EVP_DecryptUpdate(ctx, NULL, &len, aad, (int) sizeof aad) > 0 &&
        EVP_DecryptUpdate(ctx, out, &len, ct, ptlen) > 0 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) > 0 &&
        EVP_DecryptFinal_ex(ctx, out + len, &len) <= 0)
        ok("ChaCha20-Poly1305 rejects tampering");
    else
        fail("ChaCha20-Poly1305 ACCEPTED tampered ciphertext");

done:
    EVP_CIPHER_CTX_free(ctx);
    wg_cipher_release(ciph);
}

/* ------------------------------------------------------------------ */

static void test_blake2s(void)
{
#ifdef WG_LEGACY_OPENSSL
    wg_md_t *md = EVP_blake2s256();
#else
    wg_md_t *md = EVP_MD_fetch(NULL, "BLAKE2S-256", NULL);
#endif
    EVP_MD_CTX *ctx = NULL;
    unsigned char out[32];
    unsigned int outlen = 0;

    if (md == NULL) {
        fail("BLAKE2S-256 not available");
        return;
    }
    if (wg_md_size(md) != 32) {
        fail("BLAKE2S-256 unexpected digest size");
        wg_md_release(md);
        return;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL || EVP_DigestInit_ex(ctx, md, NULL) <= 0 ||
        EVP_DigestUpdate(ctx, "abc", 3) <= 0 ||
        EVP_DigestFinal_ex(ctx, out, &outlen) <= 0 || outlen != 32)
        fail("BLAKE2S-256 digest");
    else
        ok("BLAKE2S-256 digest");

    EVP_MD_CTX_free(ctx);
    wg_md_release(md);
}

/* ------------------------------------------------------------------ */

#ifdef WG_LEGACY_OPENSSL

/*
 * Before 3.0 a KDF is reached through EVP_PKEY_derive with
 * EVP_PKEY_HKDF, whose default mode is extract-and-expand -- the same
 * operation the 3.0 branch below performs. The digest is set as an
 * EVP_MD rather than named as a string, which is the only reason BLAKE2s
 * needs mentioning twice in this file.
 */
static void test_hkdf_blake2s(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    unsigned char out[32];
    size_t outlen = sizeof out;
    unsigned char ikm[32], salt[32];

    if (ctx == NULL) {
        fail("HKDF not available");
        return;
    }
    memset(ikm, 0x0b, sizeof ikm);
    memset(salt, 0x00, sizeof salt);

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_blake2s256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int) sizeof salt) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, (int) sizeof ikm) <= 0 ||
        EVP_PKEY_derive(ctx, out, &outlen) <= 0 || outlen != sizeof out)
        fail("HKDF over BLAKE2S-256");
    else
        ok("HKDF over BLAKE2S-256");

    EVP_PKEY_CTX_free(ctx);
}

#else

static void test_hkdf_blake2s(void)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[4];
    unsigned char out[32];
    char digest[] = "BLAKE2S-256";
    unsigned char ikm[32], salt[32];

    if (kdf == NULL) {
        fail("HKDF not available");
        return;
    }
    memset(ikm, 0x0b, sizeof ikm);
    memset(salt, 0x00, sizeof salt);

    ctx = EVP_KDF_CTX_new(kdf);
    if (ctx == NULL) {
        fail("HKDF ctx");
        EVP_KDF_free(kdf);
        return;
    }

    params[0] = OSSL_PARAM_construct_utf8_string("digest", digest, 0);
    params[1] = OSSL_PARAM_construct_octet_string("key", ikm, sizeof ikm);
    params[2] = OSSL_PARAM_construct_octet_string("salt", salt, sizeof salt);
    params[3] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, out, sizeof out, params) <= 0)
        fail("HKDF over BLAKE2S-256");
    else
        ok("HKDF over BLAKE2S-256");

    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
}

#endif /* WG_LEGACY_OPENSSL */

/* ------------------------------------------------------------------ */

int main(void)
{
    printf("vmsguard OpenSSL probe\n");
    printf("  library: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("\n");

    test_x25519();
    test_chachapoly();
    test_blake2s();
    test_hkdf_blake2s();

    printf("\n%s (%d failure%s)\n", failures == 0 ? "PASS" : "FAIL",
           failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
