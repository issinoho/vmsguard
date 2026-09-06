/*
 * vmsguard test responder
 *
 * Answers handshakes and echoes transport data back. Two uses:
 *
 *   1. A loopback self-test of the socket layer and client state machine
 *      over real UDP, which the in-process protocol tests do not cover.
 *
 *   2. Cross-platform testing once the OpenVMS build exists: run this on
 *      Linux, point the OpenVMS interop client at it, and the VMS socket
 *      shim is exercised before a real WireGuard peer is involved.
 *
 * This is NOT evidence of wire compatibility with upstream WireGuard —
 * both ends here are our own code, so a shared misreading of the spec
 * would pass. Only `vmsguard-interop` against a genuine peer settles
 * that.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wg_key.h"
#include "wg_noise.h"
#include "wg_platform.h"
#include "wg_proto.h"

#define BUFLEN 2048

static uint16_t inet_checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i + 1 < len; i += 2)
        sum += ((uint32_t) data[i] << 8) | (uint32_t) data[i + 1];
    if (i < len)
        sum += (uint32_t) data[i] << 8;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t) (~sum & 0xFFFF);
}

/*
 * Turn an ICMP echo request into an echo reply in place: swap the
 * addresses, change the type, and recompute both checksums. Without
 * this the responder would echo the request back verbatim and the
 * client would never see a reply, leaving the ICMP path untested until
 * a real peer is available.
 *
 * Returns 1 if the packet was converted, 0 if it was not an echo
 * request and should be echoed unchanged.
 */
static int make_echo_reply(uint8_t *pkt, size_t len)
{
    uint8_t tmp[4];
    size_t ihl, icmplen;
    uint16_t ck;

    if (len < 20 || (pkt[0] >> 4) != 4)
        return 0;
    ihl = (size_t) (pkt[0] & 0x0F) * 4;
    if (ihl < 20 || len < ihl + 8 || pkt[9] != 1)
        return 0;
    if (pkt[ihl] != 8)              /* not an echo request */
        return 0;

    /* Swap source and destination. */
    memcpy(tmp, pkt + 12, 4);
    memcpy(pkt + 12, pkt + 16, 4);
    memcpy(pkt + 16, tmp, 4);

    pkt[10] = pkt[11] = 0;
    ck = inet_checksum(pkt, ihl);
    pkt[10] = (uint8_t) (ck >> 8);
    pkt[11] = (uint8_t) (ck & 0xFF);

    pkt[ihl] = 0;                   /* echo reply */
    pkt[ihl + 2] = pkt[ihl + 3] = 0;

    /* The ICMP checksum covers the ICMP message only. Trailing bytes
       beyond the IP total length are WireGuard padding and must not be
       included. */
    icmplen = ((size_t) pkt[2] << 8 | pkt[3]);
    if (icmplen > len || icmplen < ihl)
        icmplen = len;
    icmplen -= ihl;

    ck = inet_checksum(pkt + ihl, icmplen);
    pkt[ihl + 2] = (uint8_t) (ck >> 8);
    pkt[ihl + 3] = (uint8_t) (ck & 0xFF);

    return 1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
"usage: %s --key <base64> --peer-key <base64> --listen-port <n>\n"
"          [--psk <base64>] [--packets <n>]\n"
"\n"
"  --packets  exit after echoing this many data packets (default: run\n"
"             until interrupted); a keepalive counts as a packet\n"
"  --ipv6     listen on IPv6 instead of IPv4\n", argv0);
}

int main(int argc, char **argv)
{
    struct wg_local local;
    struct wg_peer peer;
    struct wg_handshake hs;
    struct wg_keypair kp;
    struct wg_socket *sock = NULL;
    struct wg_endpoint from, client_ep;
    uint8_t privkey[WG_KEY_LEN], peerkey[WG_KEY_LEN], psk[WG_KEY_LEN];
    uint8_t *pskp = NULL;
    uint8_t buf[BUFLEN], plain[BUFLEN], out[BUFLEN];
    uint8_t self_mac1[WG_KEY_LEN];
    uint8_t timestamp[WG_TIMESTAMP_LEN];
    char b64[WG_KEY_B64_LEN], epbuf[80];
    size_t len, plainlen, outlen;
    uint64_t counter;
    uint32_t index;
    int have_key = 0, have_peer = 0;
    int established = 0;
    int packets = -1, echoed = 0;
    uint8_t family = WG_AF_INET;
    uint16_t port = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            if (wg_key_from_base64(privkey, argv[++i]) != 0) {
                fprintf(stderr, "bad --key\n");
                return 2;
            }
            have_key = 1;
        } else if (strcmp(argv[i], "--peer-key") == 0 && i + 1 < argc) {
            if (wg_key_from_base64(peerkey, argv[++i]) != 0) {
                fprintf(stderr, "bad --peer-key\n");
                return 2;
            }
            have_peer = 1;
        } else if (strcmp(argv[i], "--psk") == 0 && i + 1 < argc) {
            if (wg_key_from_base64(psk, argv[++i]) != 0) {
                fprintf(stderr, "bad --psk\n");
                return 2;
            }
            pskp = psk;
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            port = (uint16_t) atoi(argv[++i]);
        } else if (strcmp(argv[i], "--packets") == 0 && i + 1 < argc) {
            packets = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--ipv6") == 0) {
            family = WG_AF_INET6;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!have_key || !have_peer || port == 0) {
        usage(argv[0]);
        return 2;
    }

    if (wg_local_init(&local, privkey) != 0) {
        fprintf(stderr, "bad private key\n");
        return 1;
    }
    wg_peer_init(&peer, peerkey, pskp);
    wg_mac1_key(self_mac1, local.static_public);

    if (wg_socket_open(&sock, port, family) != 0) {
        fprintf(stderr, "cannot bind UDP port %u\n", (unsigned) port);
        return 1;
    }

    wg_key_to_base64(b64, local.static_public);
    printf("responder listening on port %u\n", (unsigned) port);
    printf("  our public key : %s\n", b64);
    fflush(stdout);

    memset(&client_ep, 0, sizeof client_ep);
    index = 0xC0DE0000UL;

    for (;;) {
        int rc = wg_socket_recv(sock, &from, buf, sizeof buf, &len, 1000);

        if (rc == WG_SOCK_TIMEOUT) {
            if (packets >= 0 && echoed >= packets)
                break;
            continue;
        }
        if (rc != WG_SOCK_OK) {
            fprintf(stderr, "socket error\n");
            break;
        }
        if (len < 4)
            continue;

        if (buf[0] == WG_MSG_HANDSHAKE_INIT && len == WG_INIT_LEN) {
            uint8_t resp[WG_RESP_LEN];

            if (!wg_mac1_verify(buf, len, WG_INIT_OFF_MAC1, self_mac1)) {
                printf("  initiation with bad mac1, ignored\n");
                continue;
            }
            if (wg_handshake_consume_initiation(buf, &hs, &local,
                                                timestamp) != 0) {
                printf("  initiation failed to decrypt, ignored\n");
                continue;
            }
            if (memcmp(hs.remote_static, peer.static_public,
                       WG_KEY_LEN) != 0) {
                printf("  initiation from an unknown peer, ignored\n");
                continue;
            }

            if (wg_handshake_create_response(resp, &hs, &local, &peer,
                                             index++, &kp) != 0) {
                printf("  failed to build response\n");
                continue;
            }
            if (wg_socket_send(sock, &from, resp, WG_RESP_LEN) != 0) {
                printf("  failed to send response\n");
                continue;
            }

            client_ep = from;
            established = 1;
            wg_endpoint_format(epbuf, sizeof epbuf, &from);
            printf("  handshake completed with %s\n", epbuf);
            fflush(stdout);
            continue;
        }

        if (buf[0] == WG_MSG_TRANSPORT_DATA && established) {
            if (wg_transport_decrypt(plain, &plainlen, &counter, &kp,
                                     buf, len) != 0) {
                printf("  transport data failed to decrypt\n");
                continue;
            }
            printf("  data: counter %lu, %lu bytes\n",
                   (unsigned long) counter, (unsigned long) plainlen);
            fflush(stdout);

            /* Send it back, so the client can verify both directions.
               An ICMP echo request becomes a proper reply; anything
               else, including a keepalive, goes back unchanged. */
            if (make_echo_reply(plain, plainlen))
                printf("  (converted echo request to echo reply)\n");

            if (wg_transport_encrypt(out, &outlen, &kp, plain,
                                     plainlen) == 0)
                (void) wg_socket_send(sock, &client_ep, out, outlen);

            echoed++;
            if (packets >= 0 && echoed >= packets)
                break;
        }
    }

    printf("responder exiting after %d packet%s\n",
           echoed, echoed == 1 ? "" : "s");
    wg_socket_close(sock);
    return 0;
}
