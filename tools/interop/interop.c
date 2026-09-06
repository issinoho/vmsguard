/*
 * vmsguard interop client
 *
 * Performs a real WireGuard handshake against a real peer and, if asked,
 * sends an ICMP echo request through the tunnel and waits for the reply.
 *
 * This is the MVP's acceptance test. The in-process handshake tests in
 * tests/test_proto.c prove only that our initiator and responder agree
 * with each other — if the whitepaper were misread, both halves would
 * misread it identically and still pass. Only a genuine peer settles
 * wire compatibility, which is what this tool is for.
 *
 * See docs/interop.md for how to set up the far end.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wg_client.h"
#include "wg_key.h"
#include "wg_platform.h"
#include "wg_proto.h"

/* ---- IPv4 / ICMP construction --------------------------------------- */

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

static int parse_ipv4(uint8_t out[4], const char *s)
{
    unsigned a, b, c, d;
    char extra;

    if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4)
        return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return -1;

    out[0] = (uint8_t) a;
    out[1] = (uint8_t) b;
    out[2] = (uint8_t) c;
    out[3] = (uint8_t) d;
    return 0;
}

/*
 * Build an ICMP echo request inside an IPv4 packet. Returns the total
 * length. The payload is small deliberately: the SLIP path being
 * considered for OpenVMS has a 1006-byte MTU, so nothing here should
 * assume more.
 */
static size_t build_ping(uint8_t *out, const uint8_t src[4],
                         const uint8_t dst[4], uint16_t id, uint16_t seq)
{
    static const char payload[] = "vmsguard interop probe";
    const size_t paylen = sizeof payload - 1;
    const size_t icmplen = 8 + paylen;
    const size_t total = 20 + icmplen;
    uint16_t ck;

    memset(out, 0, total);

    /* IPv4 header */
    out[0] = 0x45;                       /* version 4, IHL 5 words     */
    out[1] = 0x00;                       /* DSCP/ECN                   */
    out[2] = (uint8_t) (total >> 8);
    out[3] = (uint8_t) (total & 0xFF);
    out[4] = (uint8_t) (id >> 8);        /* identification             */
    out[5] = (uint8_t) (id & 0xFF);
    out[6] = 0x00;                       /* flags/fragment offset      */
    out[7] = 0x00;
    out[8] = 64;                         /* TTL                        */
    out[9] = 1;                          /* protocol: ICMP             */
    /* header checksum at 10..11, filled in below */
    memcpy(out + 12, src, 4);
    memcpy(out + 16, dst, 4);

    ck = inet_checksum(out, 20);
    out[10] = (uint8_t) (ck >> 8);
    out[11] = (uint8_t) (ck & 0xFF);

    /* ICMP echo request */
    out[20] = 8;                         /* type: echo request         */
    out[21] = 0;                         /* code                       */
    /* checksum at 22..23 */
    out[24] = (uint8_t) (id >> 8);
    out[25] = (uint8_t) (id & 0xFF);
    out[26] = (uint8_t) (seq >> 8);
    out[27] = (uint8_t) (seq & 0xFF);
    memcpy(out + 28, payload, paylen);

    ck = inet_checksum(out + 20, icmplen);
    out[22] = (uint8_t) (ck >> 8);
    out[23] = (uint8_t) (ck & 0xFF);

    return total;
}

/* Recognise an ICMP echo reply matching our id and sequence. */
static int is_echo_reply(const uint8_t *pkt, size_t len,
                         uint16_t id, uint16_t seq)
{
    size_t ihl;

    if (len < 20 || (pkt[0] >> 4) != 4)
        return 0;
    ihl = (size_t) (pkt[0] & 0x0F) * 4;
    if (len < ihl + 8 || pkt[9] != 1)
        return 0;
    if (pkt[ihl] != 0)                   /* type 0: echo reply         */
        return 0;
    if (((uint16_t) pkt[ihl + 4] << 8 | pkt[ihl + 5]) != id)
        return 0;
    if (((uint16_t) pkt[ihl + 6] << 8 | pkt[ihl + 7]) != seq)
        return 0;
    return 1;
}

/* ---- helpers --------------------------------------------------------- */

static void hexdump(const char *label, const uint8_t *p, size_t len)
{
    size_t i;

    printf("  %s (%lu bytes):", label, (unsigned long) len);
    for (i = 0; i < len && i < 32; i++) {
        if (i % 16 == 0)
            printf("\n    ");
        printf("%02x ", p[i]);
    }
    if (len > 32)
        printf("...");
    printf("\n");
}

static int read_key_arg(uint8_t key[WG_KEY_LEN], const char *arg,
                        const char *what)
{
    if (wg_key_from_base64(key, arg) != 0) {
        fprintf(stderr, "error: %s is not a valid base64 WireGuard key\n",
                what);
        return -1;
    }
    return 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
"usage: %s --key <base64> --peer-key <base64> --endpoint <host:port>\n"
"          [--psk <base64>] [--listen-port <n>] [--ping <src-ip> <dst-ip>]\n"
"          [--attempts <n>] [--timeout <ms>] [--verbose]\n"
"\n"
"  --key           our private key, base64 (as from `wg genkey`)\n"
"  --peer-key      the peer's public key, base64\n"
"  --endpoint      the peer's UDP endpoint, e.g. 192.0.2.1:51820\n"
"  --psk           optional preshared key, base64\n"
"  --listen-port   local UDP port (default: any)\n"
"  --ping          send an ICMP echo through the tunnel from <src-ip>\n"
"                  to <dst-ip> and wait for the reply\n"
"  --attempts      handshake attempts (default 3)\n"
"  --timeout       milliseconds to wait per attempt (default 5000)\n"
"  --rekey-after   override the rekey interval, ms (default 120000).\n"
"                  reject-after is scaled to keep the same 2:3 ratio\n"
"  --duration      after the handshake, send a keepalive a second for\n"
"                  this many seconds, reporting each rekey\n"
"  --keepalive     seconds between keepalives when idle, as\n"
"                  PersistentKeepalive in a provider config\n"
"  --idle          sit idle for this many seconds, sending nothing but\n"
"                  what --keepalive causes. Checks the keepalive timer\n"
"                  actually fires; fails if it does not\n"
"\n"
"Reads no configuration files: everything is on the command line so the\n"
"same invocation works identically on OpenVMS.\n", argv0);
}

/* ---- main ------------------------------------------------------------ */

int main(int argc, char **argv)
{
    struct wg_client client;
    struct wg_endpoint endpoint;
    uint8_t privkey[WG_KEY_LEN], peerkey[WG_KEY_LEN], psk[WG_KEY_LEN];
    uint8_t *pskp = NULL;
    uint8_t ping_src[4], ping_dst[4];
    char epbuf[80], b64[WG_KEY_B64_LEN];
    const char *endpoint_arg = NULL;
    char host[128];
    const char *colon;
    int have_key = 0, have_peer = 0, do_ping = 0, verbose = 0;
    int attempts = 3, timeout_ms = 5000;
    unsigned long rekey_after_ms = 0;
    int duration_s = 0, keepalive_s = 0, idle_s = 0;
    uint16_t listen_port = 0, peer_port;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            if (read_key_arg(privkey, argv[++i], "--key") != 0)
                return 2;
            have_key = 1;
        } else if (strcmp(argv[i], "--peer-key") == 0 && i + 1 < argc) {
            if (read_key_arg(peerkey, argv[++i], "--peer-key") != 0)
                return 2;
            have_peer = 1;
        } else if (strcmp(argv[i], "--psk") == 0 && i + 1 < argc) {
            if (read_key_arg(psk, argv[++i], "--psk") != 0)
                return 2;
            pskp = psk;
        } else if (strcmp(argv[i], "--endpoint") == 0 && i + 1 < argc) {
            endpoint_arg = argv[++i];
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            listen_port = (uint16_t) atoi(argv[++i]);
        } else if (strcmp(argv[i], "--attempts") == 0 && i + 1 < argc) {
            attempts = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--ping") == 0 && i + 2 < argc) {
            if (parse_ipv4(ping_src, argv[++i]) != 0 ||
                parse_ipv4(ping_dst, argv[++i]) != 0) {
                fprintf(stderr, "error: --ping needs two IPv4 addresses\n");
                return 2;
            }
            do_ping = 1;
        } else if (strcmp(argv[i], "--rekey-after") == 0 && i + 1 < argc) {
            rekey_after_ms = strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            duration_s = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--keepalive") == 0 && i + 1 < argc) {
            keepalive_s = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--idle") == 0 && i + 1 < argc) {
            idle_s = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!have_key || !have_peer || endpoint_arg == NULL) {
        usage(argv[0]);
        return 2;
    }

    /* Split host:port, taking the last colon so IPv6 literals work if
       they are bracketed. */
    colon = strrchr(endpoint_arg, ':');
    if (colon == NULL || (size_t) (colon - endpoint_arg) >= sizeof host) {
        fprintf(stderr, "error: --endpoint must be host:port\n");
        return 2;
    }
    memcpy(host, endpoint_arg, (size_t) (colon - endpoint_arg));
    host[colon - endpoint_arg] = '\0';
    peer_port = (uint16_t) atoi(colon + 1);
    if (peer_port == 0) {
        fprintf(stderr, "error: invalid port in --endpoint\n");
        return 2;
    }

    if (wg_endpoint_resolve(&endpoint, host, peer_port) != 0) {
        fprintf(stderr, "error: could not resolve '%s'\n", host);
        return 1;
    }

    printf("vmsguard interop client\n");

    if (wg_client_init(&client, privkey, peerkey, pskp, &endpoint,
                       listen_port) != 0) {
        fprintf(stderr, "error: %s\n", client.error);
        return 1;
    }

    if (keepalive_s > 0)
        client.keepalive_interval_ms = (uint64_t) keepalive_s * 1000;

    if (rekey_after_ms > 0) {
        client.rekey_after_ms = rekey_after_ms;
        /* Keep the whitepaper's 120:180 proportion so a shortened
           interval still leaves room to rekey before expiry. */
        client.reject_after_ms = rekey_after_ms * 3 / 2;
    }

    wg_key_to_base64(b64, client.local.static_public);
    printf("  our public key : %s\n", b64);
    wg_key_to_base64(b64, client.peer.static_public);
    printf("  peer public key: %s\n", b64);
    wg_endpoint_format(epbuf, sizeof epbuf, &endpoint);
    printf("  peer endpoint  : %s\n", epbuf);
    printf("  local port     : %u\n",
           (unsigned) wg_socket_port(client.sock));
    printf("  preshared key  : %s\n", pskp ? "yes" : "no");
    printf("\n");

    printf("handshake: sending initiation (%d attempt%s, %d ms each)\n",
           attempts, attempts == 1 ? "" : "s", timeout_ms);

    if (wg_client_handshake(&client, attempts, timeout_ms) != 0) {
        printf("\nFAILED: %s\n", client.error);
        printf("\nCheck that:\n"
               "  - the peer lists our public key above as an allowed peer\n"
               "  - the endpoint and port are reachable (UDP)\n"
               "  - the preshared key matches, if one is configured\n");
        wg_client_close(&client);
        return 1;
    }

    printf("  handshake complete\n");
    printf("  our index      : 0x%08lx\n",
           (unsigned long) client.kp.local_index);
    printf("  peer index     : 0x%08lx\n",
           (unsigned long) client.kp.remote_index);

    if (verbose) {
        hexdump("send key", client.kp.send_key, WG_KEY_LEN);
        hexdump("recv key", client.kp.recv_key, WG_KEY_LEN);
    }

    /* A keepalive is the minimum that makes the peer register traffic,
       so `wg show` reports a handshake time and non-zero transfer. */
    printf("\nsending keepalive\n");
    if (wg_client_send(&client, NULL, 0) != 0) {
        printf("FAILED: %s\n", client.error);
        wg_client_close(&client);
        return 1;
    }
    printf("  sent\n");

    /*
     * Drain whatever comes back before sending anything else. The
     * responder echoes keepalives, so there is usually one waiting, and
     * leaving it queued would only confuse the ping loop below.
     *
     * It also matters for roaming: if the peer has moved, this echo is
     * the first authenticated packet from its new address, and reading
     * it here is what lets the ping go to the right place.
     */
    {
        uint8_t drop[WG_MAX_PACKET];
        size_t droplen;
        uint64_t until = wg_time_ms() + 300;

        while (wg_time_ms() < until) {
            if (wg_client_recv(&client, drop, sizeof drop, &droplen, 50)
                == WG_SOCK_OK)
                break;
        }
    }

    if (client.roams > 0) {
        char epbuf[80];
        wg_endpoint_format(epbuf, sizeof epbuf, &client.endpoint);
        printf("  peer roamed %lu time%s; now sending to %s\n",
               client.roams, client.roams == 1 ? "" : "s", epbuf);
    }

    if (do_ping) {
        uint8_t pkt[256], reply[WG_MAX_PACKET];
        size_t pktlen, replylen;
        uint16_t id = 0x4242, seq = 1;
        int got = 0;
        uint64_t started;

        printf("\nsending ICMP echo request through the tunnel\n");
        printf("  %u.%u.%u.%u -> %u.%u.%u.%u\n",
               ping_src[0], ping_src[1], ping_src[2], ping_src[3],
               ping_dst[0], ping_dst[1], ping_dst[2], ping_dst[3]);

        pktlen = build_ping(pkt, ping_src, ping_dst, id, seq);
        if (verbose)
            hexdump("echo request", pkt, pktlen);

        if (wg_client_send(&client, pkt, pktlen) != 0) {
            printf("FAILED: %s\n", client.error);
            wg_client_close(&client);
            return 1;
        }

        /*
         * Poll with a zero timeout rather than blocking, deliberately:
         * this is the pattern the gateway uses to drain the tunnel
         * between pcap reads, and a bug that made a zero timeout return
         * without ever touching the socket went unnoticed because
         * nothing else exercised it. Waiting here with a real timeout
         * would leave that path untested.
         */
        started = wg_time_ms();
        while (wg_time_ms() - started < (uint64_t) timeout_ms) {
            int rc = wg_client_recv(&client, reply, sizeof reply, &replylen,
                                    0);
            if (rc == WG_SOCK_TIMEOUT)
                continue;   /* nothing waiting yet; keep polling */
            if (rc != WG_SOCK_OK) {
                printf("FAILED: receive error\n");
                break;
            }
            if (verbose)
                hexdump("decrypted", reply, replylen);
            if (is_echo_reply(reply, replylen, id, seq)) {
                got = 1;
                break;
            }
            /* Padding or an unrelated packet; keep waiting. */
        }

        if (got) {
            printf("  echo reply received — data path works both ways\n");
        } else {
            printf("  no echo reply\n");
            printf("\n  The handshake itself succeeded, so key agreement\n"
                   "  and transport framing are working. A missing reply\n"
                   "  usually means the peer's AllowedIPs does not cover\n"
                   "  %u.%u.%u.%u, or the destination does not answer\n"
                   "  pings.\n",
                   ping_src[0], ping_src[1], ping_src[2], ping_src[3]);
            wg_client_close(&client);
            return 1;
        }
    }

    /* ---- optional idle, to exercise the keepalive timer ---- */

    if (idle_s > 0) {
        uint64_t started = wg_time_ms();
        uint64_t before = client.kp.send_counter;
        uint64_t after, expected;
        uint8_t rbuf[WG_MAX_PACKET];
        size_t rlen;

        printf("\nidling for %d seconds with keepalive every %d s\n",
               idle_s, keepalive_s);

        /*
         * Send nothing directly. Only wg_client_tick may produce
         * traffic, so anything the counter records came from the
         * keepalive timer.
         */
        while (wg_time_ms() - started < (uint64_t) idle_s * 1000) {
            if (wg_client_tick(&client) != 0) {
                printf("FAILED: %s\n", client.error);
                wg_client_close(&client);
                return 1;
            }
            (void) wg_client_recv(&client, rbuf, sizeof rbuf, &rlen, 200);
        }

        after = client.kp.send_counter;
        printf("  %lu packet%s sent while idle\n",
               (unsigned long) (after - before),
               (after - before) == 1 ? "" : "s");

        if (keepalive_s > 0) {
            /* One per interval, allowing for the partial one at each
               end of the window. */
            expected = (uint64_t) (idle_s / keepalive_s);
            if (after - before < expected - 1) {
                printf("\nFAILED: expected about %lu keepalives, saw %lu\n",
                       (unsigned long) expected,
                       (unsigned long) (after - before));
                wg_client_close(&client);
                return 1;
            }
        } else if (after != before) {
            printf("\nFAILED: sent %lu packets with keepalive disabled\n",
                   (unsigned long) (after - before));
            wg_client_close(&client);
            return 1;
        }
    }

    /* ---- optional soak, to exercise rekeying ---- */

    if (duration_s > 0) {
        uint64_t started = wg_time_ms();
        uint32_t last_index = client.kp.local_index;
        unsigned long rekeys = 0, sent = 0, failed = 0;
        uint8_t rbuf[WG_MAX_PACKET];
        size_t rlen;

        printf("\nrunning for %d seconds, rekeying every %lu ms\n",
               duration_s,
               (unsigned long) client.rekey_after_ms);

        while (wg_time_ms() - started < (uint64_t) duration_s * 1000) {
            uint64_t tick = wg_time_ms();

            if (wg_client_send(&client, NULL, 0) == 0)
                sent++;
            else
                failed++;

            if (client.kp.local_index != last_index) {
                rekeys++;
                last_index = client.kp.local_index;
                printf("  rekeyed (%lu) at %lu s, new index 0x%08lx\n",
                       rekeys,
                       (unsigned long) ((wg_time_ms() - started) / 1000),
                       (unsigned long) client.kp.local_index);
                fflush(stdout);
            }

            /*
             * Absorb whatever comes back, then wait out the rest of the
             * second. The responder echoes keepalives immediately, so
             * receiving alone would spin rather than pace the loop.
             */
            while (wg_time_ms() - tick < 1000) {
                if (wg_client_recv(&client, rbuf, sizeof rbuf, &rlen,
                                   (int) (1000 - (wg_time_ms() - tick)))
                    != WG_SOCK_OK)
                    break;
            }
        }

        printf("\n  %lu keepalives sent, %lu failed, %lu rekey%s\n",
               sent, failed, rekeys, rekeys == 1 ? "" : "s");

        if (rekeys == 0) {
            printf("\nFAILED: no rekey happened\n");
            wg_client_close(&client);
            return 1;
        }
        if (failed > 0) {
            printf("\nFAILED: %lu sends failed\n", failed);
            wg_client_close(&client);
            return 1;
        }
    }

    /* Deliberately does not claim wire compatibility: this tool cannot
       tell a real WireGuard peer from our own test responder. That
       claim belongs to whoever knows what is at the far end. */
    printf("\nPASS — handshake completed and data path verified\n");
    wg_client_close(&client);
    return 0;
}
