/*
 * vmsguard protocol core tests
 *
 * Covers:
 *   - BLAKE2s against RFC 7693 and cross-checked vectors
 *   - HMAC-BLAKE2s and the WireGuard KDF
 *   - X25519 agreement and ChaCha20-Poly1305 roundtrip/tamper rejection
 *   - a full in-process Noise_IKpsk2 handshake, both roles, with and
 *     without a preshared key
 *   - transport data encrypt/decrypt, padding, keepalives, and rejection
 *     of tampered or misdirected packets
 *
 * The handshake test running both roles in-process proves the state
 * machine is self-consistent. It does not prove wire compatibility with
 * upstream WireGuard — only interop against a real peer does that, which
 * is the next milestone.
 */

#include <stdio.h>
#include <string.h>

#include "blake2s.h"
#include "wg_crypto.h"
#include "wg_key.h"
#include "wg_noise.h"
#include "wg_proto.h"

static int failures;
static int checks;

static void check(int cond, const char *what)
{
    checks++;
    if (cond) {
        printf("  ok    %s\n", what);
    } else {
        printf("  FAIL  %s\n", what);
        failures++;
    }
}

static int hexeq(const uint8_t *got, const char *want, size_t len)
{
    char buf[160];
    size_t i;

    if (len * 2 >= sizeof buf)
        return 0;
    for (i = 0; i < len; i++)
        sprintf(buf + i * 2, "%02x", got[i]);
    return strcmp(buf, want) == 0;
}

/* ---- BLAKE2s -------------------------------------------------------- */

static void test_blake2s(void)
{
    uint8_t out[32], key[32], big[256];
    size_t i;

    printf("\nBLAKE2s\n");

    for (i = 0; i < 32; i++)
        key[i] = (uint8_t) i;
    for (i = 0; i < sizeof big; i++)
        big[i] = (uint8_t) i;

    /* RFC 7693 Appendix B */
    blake2s(out, 32, NULL, 0, (const uint8_t *) "abc", 3);
    check(hexeq(out, "508c5e8c327c14e2e1a72ba34eeb452f"
                     "37458b209ed63a294d999b4c86675982", 32),
          "RFC 7693 BLAKE2s-256(\"abc\")");

    blake2s(out, 32, NULL, 0, (const uint8_t *) "", 0);
    check(hexeq(out, "69217a3079908094e11121d042354a7c"
                     "1f55b6482ca1a51e1b250dfd1ed0eef9", 32),
          "BLAKE2s-256(empty)");

    /* Keyed, the shape mac1 needs. */
    blake2s(out, 32, key, 32, (const uint8_t *) "", 0);
    check(hexeq(out, "48a8997da407876b3d79c0d92325ad3b"
                     "89cbb754d86ab71aee047ad345fd2c49", 32),
          "keyed BLAKE2s-256(empty)");

    blake2s(out, 16, key, 32, (const uint8_t *) "abc", 3);
    check(hexeq(out, "61ba5f165c194692e09d12520cc4c74a", 16),
          "keyed BLAKE2s-128(\"abc\") [mac1 shape]");

    /* Block boundaries: exactly one block, exactly two. */
    blake2s(out, 32, NULL, 0, big, 64);
    check(hexeq(out, "56f34e8b96557e90c1f24b52d0c89d51"
                     "086acf1b00f634cf1dde9233b8eaaa3e", 32),
          "BLAKE2s-256 of exactly one block");

    blake2s(out, 32, NULL, 0, big, 128);
    check(hexeq(out, "1fa877de67259d19863a2a34bcc6962a"
                     "2b25fcbf5cbecd7ede8f1fa36688a796", 32),
          "BLAKE2s-256 of exactly two blocks");

    blake2s(out, 32, key, 32, big, 200);
    check(hexeq(out, "13c88480a5d00d6c8c7ad2110d76a82d"
                     "9b70f4fa6696d4e5dd42a066dcaf9920", 32),
          "keyed BLAKE2s-256 of 200 bytes");

    /* Streaming in awkward chunks must match the one-shot result. */
    {
        struct blake2s_state s;
        uint8_t streamed[32];

        blake2s_init(&s, 32, key, 32);
        blake2s_update(&s, big, 1);
        blake2s_update(&s, big + 1, 62);
        blake2s_update(&s, big + 63, 1);
        blake2s_update(&s, big + 64, 136);
        blake2s_final(&s, streamed);
        check(memcmp(streamed, out, 32) == 0,
              "streaming matches one-shot across block boundaries");
    }
}

/* ---- KDF ------------------------------------------------------------ */

static void test_kdf(void)
{
    uint8_t key[32], o1[32], o2[32], o3[32];
    uint8_t a1[32], a2[32];
    size_t i;

    printf("\nHMAC / KDF\n");

    for (i = 0; i < 32; i++)
        key[i] = (uint8_t) (i * 3);

    wg_kdf(o1, o2, o3, key, (const uint8_t *) "input", 5);
    check(memcmp(o1, o2, 32) != 0 && memcmp(o2, o3, 32) != 0,
          "KDF outputs are distinct");

    /* Requesting fewer outputs must not change the ones returned. */
    wg_kdf(a1, a2, NULL, key, (const uint8_t *) "input", 5);
    check(memcmp(a1, o1, 32) == 0 && memcmp(a2, o2, 32) == 0,
          "KDF is consistent regardless of how many outputs are wanted");

    wg_kdf(a1, NULL, NULL, key, (const uint8_t *) "input", 5);
    check(memcmp(a1, o1, 32) == 0, "KDF1 matches first output of KDF3");

    /* Empty input is used for the final transport key derivation. */
    wg_kdf(a1, a2, NULL, key, NULL, 0);
    check(memcmp(a1, a2, 32) != 0, "KDF over empty input works");
}

/* ---- primitives ----------------------------------------------------- */

static void test_primitives(void)
{
    uint8_t sk1[32], pk1[32], sk2[32], pk2[32], s1[32], s2[32];
    uint8_t derived[32];
    uint8_t ct[64], pt[32], out[64];
    size_t i;

    printf("\nX25519 / ChaCha20-Poly1305\n");

    check(wg_dh_generate(sk1, pk1) == 0 && wg_dh_generate(sk2, pk2) == 0,
          "keypair generation");

    check(wg_dh_pubkey(derived, sk1) == 0 && memcmp(derived, pk1, 32) == 0,
          "public key derives from private key");

    check(wg_dh(s1, sk1, pk2) == 0 && wg_dh(s2, sk2, pk1) == 0 &&
          memcmp(s1, s2, 32) == 0,
          "X25519 shared secrets agree");

    for (i = 0; i < sizeof pt; i++)
        pt[i] = (uint8_t) i;

    check(wg_aead_encrypt(ct, s1, 7, pt, sizeof pt, s2, 32) == 0,
          "AEAD encrypt");
    check(wg_aead_decrypt(out, s1, 7, ct, sizeof pt + WG_TAG_LEN,
                          s2, 32) == 0 &&
          memcmp(out, pt, sizeof pt) == 0,
          "AEAD decrypt roundtrip");

    check(wg_aead_decrypt(out, s1, 8, ct, sizeof pt + WG_TAG_LEN,
                          s2, 32) != 0,
          "AEAD rejects wrong counter");

    ct[0] ^= 0x01;
    check(wg_aead_decrypt(out, s1, 7, ct, sizeof pt + WG_TAG_LEN,
                          s2, 32) != 0,
          "AEAD rejects tampered ciphertext");
    ct[0] ^= 0x01;

    /* pt is genuinely different data — s1 and s2 are the same shared
       secret, so they would not make a distinguishing test here. */
    check(wg_aead_decrypt(out, s1, 7, ct, sizeof pt + WG_TAG_LEN,
                          pt, 32) != 0,
          "AEAD rejects wrong associated data");
}

/* ---- handshake ------------------------------------------------------ */

static void run_handshake(const uint8_t *psk, const char *label)
{
    struct wg_local initiator, responder;
    struct wg_peer i_peer, r_peer;
    struct wg_handshake i_hs, r_hs;
    struct wg_keypair i_kp, r_kp;
    uint8_t i_sk[32], r_sk[32];
    uint8_t init_msg[WG_INIT_LEN], resp_msg[WG_RESP_LEN];
    uint8_t timestamp[WG_TIMESTAMP_LEN];
    uint8_t mac1_key[32];
    char buf[128];

    printf("\nhandshake (%s)\n", label);

    if (wg_random(i_sk, 32) != 0 || wg_random(r_sk, 32) != 0) {
        check(0, "random key material");
        return;
    }
    if (wg_local_init(&initiator, i_sk) != 0 ||
        wg_local_init(&responder, r_sk) != 0) {
        check(0, "identity setup");
        return;
    }

    /* Each side knows the other's static public key. */
    wg_peer_init(&i_peer, responder.static_public, psk);
    wg_peer_init(&r_peer, initiator.static_public, psk);

    /* --- initiation --- */
    check(wg_handshake_create_initiation(init_msg, &i_hs, &initiator,
                                         &i_peer, 0x11223344) == 0,
          "initiator builds initiation");
    check(init_msg[0] == WG_MSG_HANDSHAKE_INIT &&
          init_msg[1] == 0 && init_msg[2] == 0 && init_msg[3] == 0,
          "initiation type byte and reserved bytes");
    check(wg_get32(init_msg + WG_INIT_OFF_SENDER) == 0x11223344,
          "initiation carries sender index little-endian");

    /* The responder validates mac1 with its own static public key. */
    wg_mac1_key(mac1_key, responder.static_public);
    check(wg_mac1_verify(init_msg, WG_INIT_LEN, WG_INIT_OFF_MAC1,
                         mac1_key) == 1,
          "initiation mac1 verifies");

    check(wg_handshake_consume_initiation(init_msg, &r_hs, &responder,
                                          timestamp) == 0,
          "responder consumes initiation");
    check(memcmp(r_hs.remote_static, initiator.static_public, 32) == 0,
          "responder recovers the initiator's static public key");

    /* --- response --- */
    check(wg_handshake_create_response(resp_msg, &r_hs, &responder,
                                       &r_peer, 0x55667788, &r_kp) == 0,
          "responder builds response");

    wg_mac1_key(mac1_key, initiator.static_public);
    check(wg_mac1_verify(resp_msg, WG_RESP_LEN, WG_RESP_OFF_MAC1,
                         mac1_key) == 1,
          "response mac1 verifies");

    check(wg_handshake_consume_response(resp_msg, &i_hs, &initiator,
                                        &i_peer, &i_kp) == 0,
          "initiator consumes response");

    /* --- the keys must line up --- */
    check(memcmp(i_kp.send_key, r_kp.recv_key, 32) == 0,
          "initiator send key == responder receive key");
    check(memcmp(i_kp.recv_key, r_kp.send_key, 32) == 0,
          "initiator receive key == responder send key");
    check(memcmp(i_kp.send_key, i_kp.recv_key, 32) != 0,
          "send and receive keys differ");
    check(i_kp.remote_index == 0x55667788 && r_kp.remote_index == 0x11223344,
          "indices exchanged correctly");

    /* --- transport data both ways --- */
    {
        uint8_t packet[64], msg[256], plain[256];
        size_t msglen, plainlen;
        uint64_t counter;
        size_t i;

        for (i = 0; i < sizeof packet; i++)
            packet[i] = (uint8_t) (0xA0 + (i & 0x0F));

        check(wg_transport_encrypt(msg, &msglen, &i_kp,
                                   packet, sizeof packet) == 0,
              "initiator encrypts a data packet");
        check(msg[0] == WG_MSG_TRANSPORT_DATA,
              "transport data type byte");
        check(wg_get32(msg + WG_DATA_OFF_RECEIVER) == r_kp.local_index,
              "transport data addressed to the responder's index");

        check(wg_transport_decrypt(plain, &plainlen, &counter, &r_kp,
                                   msg, msglen) == 0 &&
              plainlen == sizeof packet &&
              memcmp(plain, packet, sizeof packet) == 0,
              "responder decrypts it");
        check(counter == 0, "first packet has counter 0");
        check(i_kp.send_counter == 1, "send counter advanced");

        /* Reply in the other direction. */
        check(wg_transport_encrypt(msg, &msglen, &r_kp,
                                   packet, 20) == 0,
              "responder encrypts a reply");
        check(wg_transport_decrypt(plain, &plainlen, &counter, &i_kp,
                                   msg, msglen) == 0,
              "initiator decrypts the reply");
        check(plainlen == 32,
              "20-byte payload padded to a 16-byte boundary");
        check(memcmp(plain, packet, 20) == 0,
              "padded payload still starts with the original bytes");

        /* Keepalive: empty payload. */
        check(wg_transport_encrypt(msg, &msglen, &i_kp, NULL, 0) == 0 &&
              msglen == WG_DATA_HDR_LEN + WG_TAG_LEN,
              "keepalive is header plus tag only");
        check(wg_transport_decrypt(plain, &plainlen, &counter, &r_kp,
                                   msg, msglen) == 0 && plainlen == 0,
              "keepalive decrypts to nothing");

        /* Tampering must be caught. */
        check(wg_transport_encrypt(msg, &msglen, &i_kp,
                                   packet, sizeof packet) == 0,
              "encrypt for tamper test");
        msg[WG_DATA_HDR_LEN + 2] ^= 0x40;
        check(wg_transport_decrypt(plain, &plainlen, &counter, &r_kp,
                                   msg, msglen) != 0,
              "tampered transport data is rejected");
        msg[WG_DATA_HDR_LEN + 2] ^= 0x40;

        /* Wrong receiver index must be caught. */
        wg_put32(msg + WG_DATA_OFF_RECEIVER, 0xDEADBEEF);
        check(wg_transport_decrypt(plain, &plainlen, &counter, &r_kp,
                                   msg, msglen) != 0,
              "transport data for another index is rejected");
    }

    /* --- a corrupted response must not yield keys --- */
    {
        struct wg_handshake bad_hs;
        struct wg_keypair bad_kp;
        uint8_t bad_msg[WG_RESP_LEN];

        if (wg_handshake_create_initiation(init_msg, &bad_hs, &initiator,
                                           &i_peer, 0x99AABBCC) == 0 &&
            wg_handshake_consume_initiation(init_msg, &r_hs, &responder,
                                            timestamp) == 0 &&
            wg_handshake_create_response(bad_msg, &r_hs, &responder,
                                         &r_peer, 0x0F0F0F0F, &r_kp) == 0) {
            bad_msg[WG_RESP_OFF_EPHEMERAL] ^= 0x01;
            sprintf(buf, "corrupted response is rejected");
            check(wg_handshake_consume_response(bad_msg, &bad_hs, &initiator,
                                                &i_peer, &bad_kp) != 0, buf);
        } else {
            check(0, "setup for corrupted-response test");
        }
    }
}

static void test_handshake(void)
{
    uint8_t psk[32];
    size_t i;

    run_handshake(NULL, "no preshared key");

    for (i = 0; i < sizeof psk; i++)
        psk[i] = (uint8_t) (0x5A ^ i);
    run_handshake(psk, "with preshared key");
}

/* ---- psk actually matters ------------------------------------------- */

static void test_psk_mismatch(void)
{
    struct wg_local initiator, responder;
    struct wg_peer i_peer, r_peer;
    struct wg_handshake i_hs, r_hs;
    struct wg_keypair i_kp, r_kp;
    uint8_t i_sk[32], r_sk[32], psk_a[32], psk_b[32];
    uint8_t init_msg[WG_INIT_LEN], resp_msg[WG_RESP_LEN];
    uint8_t timestamp[WG_TIMESTAMP_LEN];
    size_t i;

    printf("\npreshared key enforcement\n");

    for (i = 0; i < 32; i++) {
        psk_a[i] = (uint8_t) i;
        psk_b[i] = (uint8_t) (i + 1);
    }

    if (wg_random(i_sk, 32) != 0 || wg_random(r_sk, 32) != 0 ||
        wg_local_init(&initiator, i_sk) != 0 ||
        wg_local_init(&responder, r_sk) != 0) {
        check(0, "setup");
        return;
    }

    /* The two sides disagree about the preshared key. */
    wg_peer_init(&i_peer, responder.static_public, psk_a);
    wg_peer_init(&r_peer, initiator.static_public, psk_b);

    if (wg_handshake_create_initiation(init_msg, &i_hs, &initiator,
                                       &i_peer, 1) != 0 ||
        wg_handshake_consume_initiation(init_msg, &r_hs, &responder,
                                        timestamp) != 0 ||
        wg_handshake_create_response(resp_msg, &r_hs, &responder,
                                     &r_peer, 2, &r_kp) != 0) {
        check(0, "setup through response");
        return;
    }

    check(wg_handshake_consume_response(resp_msg, &i_hs, &initiator,
                                        &i_peer, &i_kp) != 0,
          "mismatched preshared keys fail the handshake");
}

/* ---- key encoding --------------------------------------------------- */

static void test_keys(void)
{
    uint8_t key[32], back[32];
    char b64[WG_KEY_B64_LEN];
    size_t i;
    int all_ok = 1;

    printf("\nkey encoding\n");

    memset(key, 0, sizeof key);
    wg_key_to_base64(b64, key);
    check(strcmp(b64, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") == 0,
          "all-zero key encodes to the expected base64");

    memset(key, 0xFF, sizeof key);
    wg_key_to_base64(b64, key);
    check(strlen(b64) == 44 && b64[43] == '=',
          "encoded key is 44 characters ending in '='");
    check(wg_key_from_base64(back, b64) == 0 &&
          memcmp(back, key, 32) == 0,
          "all-ones key round-trips");

    for (i = 0; i < 500; i++) {
        if (wg_random(key, 32) != 0) {
            all_ok = 0;
            break;
        }
        wg_key_to_base64(b64, key);
        if (wg_key_from_base64(back, b64) != 0 ||
            memcmp(back, key, 32) != 0) {
            all_ok = 0;
            break;
        }
    }
    check(all_ok, "500 random keys round-trip through base64");

    /* Malformed input must be rejected outright, never partially
       decoded — a silently truncated key would be a security problem. */
    check(wg_key_from_base64(back, "") != 0, "rejects empty string");
    check(wg_key_from_base64(back, NULL) != 0, "rejects NULL");
    check(wg_key_from_base64(back,
              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") != 0,
          "rejects a key that is too short");
    check(wg_key_from_base64(back,
              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") != 0,
          "rejects a key that is too long");
    check(wg_key_from_base64(back,
              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") != 0,
          "rejects a key with no padding");
    check(wg_key_from_base64(back,
              "!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") != 0,
          "rejects invalid base64 characters");
    /* 'B' in the final position sets bits that a 32-byte key cannot
       use, so this is not a canonical encoding. */
    check(wg_key_from_base64(back,
              "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=") != 0,
          "rejects non-canonical trailing bits");
}

/* ---- timestamp ------------------------------------------------------ */

static void test_timestamp(void)
{
    uint8_t a[WG_TIMESTAMP_LEN], b[WG_TIMESTAMP_LEN];

    printf("\nTAI64N timestamp\n");

    wg_timestamp(a);
    wg_timestamp(b);

    check(memcmp(a, b, WG_TIMESTAMP_LEN) < 0,
          "timestamps strictly increase within the same second");
    check(a[0] == 0x40,
          "TAI64N label byte is 0x40");
}

/* ---- main ----------------------------------------------------------- */

int main(void)
{
    printf("vmsguard protocol core tests\n");

    test_blake2s();
    test_kdf();
    test_primitives();
    test_handshake();
    test_psk_mismatch();
    test_keys();
    test_timestamp();

    printf("\n%s — %d checks, %d failure%s\n",
           failures == 0 ? "PASS" : "FAIL",
           checks, failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
