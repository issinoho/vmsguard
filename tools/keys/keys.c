/*
 * vmsguard-key — key generation and derivation
 *
 * The equivalent of `wg genkey` / `wg pubkey` / `wg genpsk`. Needed
 * because OpenVMS has no wireguard-tools: without this there would be
 * no way to produce or inspect keys on the target platform.
 *
 * Subcommands mirror wg(8) so muscle memory carries over:
 *
 *     vmsguard-key genkey            generate a private key
 *     vmsguard-key pubkey            private key on stdin -> public key
 *     vmsguard-key genpsk            generate a preshared key
 *     vmsguard-key check             validate a key on stdin
 */

#include <stdio.h>
#include <string.h>

#include "wg_crypto.h"
#include "wg_key.h"

static int read_key_stdin(uint8_t key[WG_KEY_LEN])
{
    char line[256];

    if (fgets(line, sizeof line, stdin) == NULL) {
        fprintf(stderr, "error: no key on stdin\n");
        return -1;
    }
    line[strcspn(line, "\r\n")] = '\0';

    if (wg_key_from_base64(key, line) != 0) {
        fprintf(stderr, "error: not a valid base64 WireGuard key\n");
        return -1;
    }
    return 0;
}

static int cmd_genkey(void)
{
    uint8_t sk[WG_KEY_LEN], pk[WG_KEY_LEN];
    char b64[WG_KEY_B64_LEN];

    /* Generating a full keypair and discarding the public half means
       the private key is one OpenSSL has already clamped and accepted,
       rather than 32 raw random bytes we would have to clamp here. */
    if (wg_dh_generate(sk, pk) != 0) {
        fprintf(stderr, "error: key generation failed\n");
        return 1;
    }
    wg_key_to_base64(b64, sk);
    printf("%s\n", b64);

    wg_zero(sk, sizeof sk);
    return 0;
}

static int cmd_genpsk(void)
{
    uint8_t psk[WG_KEY_LEN];
    char b64[WG_KEY_B64_LEN];

    if (wg_random(psk, sizeof psk) != 0) {
        fprintf(stderr, "error: could not get random bytes\n");
        return 1;
    }
    wg_key_to_base64(b64, psk);
    printf("%s\n", b64);

    wg_zero(psk, sizeof psk);
    return 0;
}

static int cmd_pubkey(void)
{
    uint8_t sk[WG_KEY_LEN], pk[WG_KEY_LEN];
    char b64[WG_KEY_B64_LEN];

    if (read_key_stdin(sk) != 0)
        return 1;
    if (wg_dh_pubkey(pk, sk) != 0) {
        fprintf(stderr, "error: could not derive public key\n");
        return 1;
    }
    wg_key_to_base64(b64, pk);
    printf("%s\n", b64);

    wg_zero(sk, sizeof sk);
    return 0;
}

static int cmd_check(void)
{
    uint8_t key[WG_KEY_LEN];

    if (read_key_stdin(key) != 0)
        return 1;
    printf("valid\n");
    wg_zero(key, sizeof key);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        goto usage;

    if (strcmp(argv[1], "genkey") == 0)
        return cmd_genkey();
    if (strcmp(argv[1], "pubkey") == 0)
        return cmd_pubkey();
    if (strcmp(argv[1], "genpsk") == 0)
        return cmd_genpsk();
    if (strcmp(argv[1], "check") == 0)
        return cmd_check();

usage:
    fprintf(stderr,
        "usage: %s { genkey | pubkey | genpsk | check }\n"
        "\n"
        "  genkey   write a new private key to stdout\n"
        "  pubkey   read a private key on stdin, write its public key\n"
        "  genpsk   write a new preshared key to stdout\n"
        "  check    validate a key read on stdin\n",
        argc > 0 ? argv[0] : "vmsguard-key");
    return 2;
}
