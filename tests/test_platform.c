/*
 * Platform layer tests — vmsguard
 *
 * Most of src/platform is sockets and cannot be tested without one, but
 * the endpoint handling in it is pure, and two features now lean on it
 * hard: roaming adopts a new endpoint when it differs from the current
 * one, and endpoint re-resolution declines to adopt one when it does
 * not. Both are decisions made by wg_endpoint_equal, so a wrong answer
 * there either pins the tunnel to a dead address or moves it for no
 * reason.
 */

#include <stdio.h>
#include <string.h>

#include "wg_platform.h"

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

static struct wg_endpoint v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                             uint16_t port)
{
    struct wg_endpoint e;

    memset(&e, 0, sizeof e);
    e.family = WG_AF_INET;
    e.addr[0] = a; e.addr[1] = b; e.addr[2] = c; e.addr[3] = d;
    e.port = port;
    return e;
}

static void test_equality(void)
{
    struct wg_endpoint a, b;

    printf("\nendpoint equality\n");

    a = v4(64, 20, 211, 133, 1443);
    b = v4(64, 20, 211, 133, 1443);
    check(wg_endpoint_equal(&a, &b), "the same address and port match");

    b = v4(64, 20, 211, 140, 1443);
    check(!wg_endpoint_equal(&a, &b), "a different address does not");

    b = v4(64, 20, 211, 133, 51820);
    check(!wg_endpoint_equal(&a, &b),
          "nor does the same address on another port — a NAT rebinding"
          " changes only that");

    /*
     * The bytes past the fourth are meaningless for IPv4 and must not
     * be compared. They are zeroed by the conversion today, so a
     * whole-struct memcmp would pass; it would start failing the moment
     * anything left them dirty, and the failure would look like a peer
     * roaming at random.
     */
    a = v4(10, 0, 0, 1, 51820);
    b = v4(10, 0, 0, 1, 51820);
    b.addr[7] = 0xFF;
    check(wg_endpoint_equal(&a, &b),
          "bytes an IPv4 endpoint does not use are ignored");

    /* Same bytes, different family: not the same endpoint. */
    a = v4(10, 0, 0, 1, 51820);
    b = a;
    b.family = WG_AF_INET6;
    check(!wg_endpoint_equal(&a, &b), "family is part of identity");

    {
        struct wg_endpoint c6, d6;

        memset(&c6, 0, sizeof c6);
        c6.family = WG_AF_INET6;
        c6.port = 1443;
        memset(c6.addr, 0xAB, 16);
        d6 = c6;
        check(wg_endpoint_equal(&c6, &d6), "two identical IPv6 endpoints");

        /* A difference in the last byte is past where IPv4 would look,
           so this is what catches comparing only four bytes. */
        d6.addr[15] ^= 0x01;
        check(!wg_endpoint_equal(&c6, &d6),
              "and IPv6 is compared over all sixteen bytes");
    }
}

static void test_format(void)
{
    struct wg_endpoint e;
    char buf[80];

    printf("\nendpoint formatting\n");

    e = v4(192, 168, 0, 80, 51820);
    wg_endpoint_format(buf, sizeof buf, &e);
    check(strcmp(buf, "192.168.0.80:51820") == 0, "IPv4 with its port");

    memset(&e, 0, sizeof e);
    wg_endpoint_format(buf, sizeof buf, &e);
    check(strcmp(buf, "<unset>") == 0,
          "an endpoint with no family says so rather than printing 0.0.0.0");

    memset(&e, 0, sizeof e);
    e.family = WG_AF_INET6;
    e.addr[15] = 1;
    e.port = 1443;
    wg_endpoint_format(buf, sizeof buf, &e);
    check(strcmp(buf, "[::1]:1443") == 0,
          "IPv6 is bracketed, so the port is not read as part of it");
}

static void test_resolve(void)
{
    struct wg_endpoint e;

    printf("\nresolution\n");

    /* A literal, so this needs no working DNS to pass. */
    check(wg_endpoint_resolve(&e, "192.0.2.1", 1443) == 0 &&
          e.family == WG_AF_INET && e.port == 1443 &&
          e.addr[0] == 192 && e.addr[3] == 1,
          "a dotted literal resolves to itself, port and all");

    check(wg_endpoint_resolve(&e, "::1", 51820) == 0 &&
          e.family == WG_AF_INET6 && e.port == 51820,
          "and an IPv6 literal to the right family");

    /*
     * Re-resolution treats a failed lookup as "no information" and
     * keeps the endpoint it has, so failure must be reported rather
     * than leaving a half-filled struct behind.
     */
    check(wg_endpoint_resolve(&e, "no.such.host.invalid", 1443) != 0,
          "a name that cannot resolve fails rather than half-succeeding");
}

int main(void)
{
    printf("vmsguard platform tests\n");

    test_equality();
    test_format();
    test_resolve();

    printf("\n%s — %d checks, %d failure%s\n",
           failures == 0 ? "PASS" : "FAIL",
           checks, failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
