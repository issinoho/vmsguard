/*
 * vmsotel probe: one OTLP/HTTP JSON export to a real collector
 *
 * The agent's whole transport is this: open TCP, optionally TLS, POST
 * a JSON ExportMetricsServiceRequest to /v1/metrics, read the reply.
 * This probe does exactly that once, so that the round trip is proven
 * against an OpenTelemetry Collector before any agent code exists.
 *
 * Answers:
 *   1. TCP connect and an HTTP/1.1 exchange from VMS to the collector.
 *   2. Whether the collector accepts the JSON encoding as written
 *      (HTTP 200, no rejected points in partialSuccess).
 *   3. With --tls (probe_otlp_tls only): a TLS handshake through the
 *      installed OpenSSL, the version and cipher negotiated, and
 *      whether the certificate verified.
 *   4. Clock skew. The collector's Date header is the laptop's UTC;
 *      the difference from our time() is measured, not assumed.
 *
 * Usage:
 *   probe_otlp [--host H] [--port N] [--path P] [--tls] [--cafile F]
 * Defaults are the test collector on the development laptop.
 */

#if !defined(__VMS) && !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200112L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#ifdef WITH_TLS
#  include <openssl/ssl.h>
#  include <openssl/err.h>
#  include <openssl/x509.h>
#endif

#define DEFAULT_HOST "192.168.0.218"
#define DEFAULT_PORT "4318"
#define DEFAULT_PATH "/v1/metrics"

static int failures = 0;

static void ok(const char *what)   { printf("  ok    %s\n", what); }
static void fail(const char *what) { printf("  FAIL  %s\n", what); failures++; }

/* ------------------------------------------------------------------ */
/* Payload                                                             */

static void json_string(char *out, size_t cap, const char *s)
{
    size_t n = 0;

    while (*s != '\0' && n + 7 < cap) {
        unsigned char c = (unsigned char) *s++;

        if (c == '"' || c == '\\') {
            out[n++] = '\\';
            out[n++] = (char) c;
        } else if (c < 0x20) {
            n += (size_t) sprintf(out + n, "\\u%04x", c);
        } else {
            out[n++] = (char) c;
        }
    }
    out[n] = '\0';
}

/*
 * The OTLP JSON encoding is the protobuf JSON mapping with three
 * rules that matter here (OTLP specification, "JSON Protobuf
 * Encoding"): field names are lowerCamelCase, enums are integers, and
 * 64-bit integers -- every timestamp, and asInt -- are decimal strings.
 * aggregationTemporality 2 is CUMULATIVE, which is what every VMS
 * counter naturally is.
 */
static int build_payload(char *out, size_t cap, long long unix_now,
                         const char *transport)
{
    char host[256], host_json[1600];
    int n;

    if (gethostname(host, sizeof host) != 0)
        strcpy(host, "unknown");
    host[sizeof host - 1] = '\0';
    json_string(host_json, sizeof host_json, host);

    n = snprintf(out, cap,
        "{\"resourceMetrics\":[{"
          "\"resource\":{\"attributes\":["
            "{\"key\":\"service.name\",\"value\":{\"stringValue\":\"vmsotel-probe\"}},"
            "{\"key\":\"host.name\",\"value\":{\"stringValue\":\"%s\"}},"
            "{\"key\":\"os.type\",\"value\":{\"stringValue\":\"openvms\"}}"
          "]},"
          "\"scopeMetrics\":[{"
            "\"scope\":{\"name\":\"vmsotel.probe\",\"version\":\"0.1\"},"
            "\"metrics\":["
              "{\"name\":\"vmsotel.probe.heartbeat\",\"unit\":\"1\","
               "\"gauge\":{\"dataPoints\":[{"
                 "\"timeUnixNano\":\"%lld000000000\",\"asInt\":\"1\"}]}},"
              "{\"name\":\"vmsotel.probe.exports\",\"unit\":\"{request}\","
               "\"sum\":{\"aggregationTemporality\":2,\"isMonotonic\":true,"
                "\"dataPoints\":[{"
                  "\"attributes\":[{\"key\":\"vmsotel.transport\","
                                   "\"value\":{\"stringValue\":\"%s\"}}],"
                  "\"startTimeUnixNano\":\"%lld000000000\","
                  "\"timeUnixNano\":\"%lld000000000\",\"asInt\":\"1\"}]}}"
            "]"
          "}]"
        "}]}",
        host_json, unix_now, transport, unix_now - 1, unix_now);
    return (n > 0 && (size_t) n < cap) ? n : -1;
}

/* ------------------------------------------------------------------ */
/* Connection: plain TCP, or TLS over it                               */

typedef struct {
    int fd;
#ifdef WITH_TLS
    SSL_CTX *ctx;
    SSL *ssl;
#endif
} conn;

static int conn_tcp(conn *c, const char *host, const char *port)
{
    struct addrinfo hints, *res = NULL, *ai;
    int rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        printf("  getaddrinfo(%s, %s): %s\n", host, port, gai_strerror(rc));
        fail("resolve collector address");
        return 0;
    }
    c->fd = -1;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        c->fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (c->fd < 0)
            continue;
        if (connect(c->fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        printf("  connect: %s\n", strerror(errno));
        close(c->fd);
        c->fd = -1;
    }
    freeaddrinfo(res);
    if (c->fd < 0) {
        fail("TCP connect to collector");
        return 0;
    }
    ok("TCP connect");
    return 1;
}

#ifdef WITH_TLS
static void print_ssl_errors(void)
{
    unsigned long e;
    char buf[256];

    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof buf);
        printf("  openssl: %s\n", buf);
    }
}

static int conn_tls(conn *c, const char *host, const char *cafile)
{
    unsigned char addr[16];
    long vr;

    printf("  OpenSSL %s\n", OpenSSL_version(OPENSSL_VERSION));
    c->ctx = SSL_CTX_new(TLS_client_method());
    if (c->ctx == NULL) {
        print_ssl_errors();
        fail("SSL_CTX_new");
        return 0;
    }
    /*
     * Verify, but do not insist: a self-signed test collector should
     * still complete the exchange, and the verify result is printed
     * either way. The agent will insist.
     */
    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_NONE, NULL);
    if (cafile != NULL) {
        if (SSL_CTX_load_verify_locations(c->ctx, cafile, NULL) != 1) {
            print_ssl_errors();
            fail("load --cafile");
        }
    } else {
        SSL_CTX_set_default_verify_paths(c->ctx);
    }

    c->ssl = SSL_new(c->ctx);
    if (c->ssl == NULL || SSL_set_fd(c->ssl, c->fd) != 1) {
        print_ssl_errors();
        fail("SSL_new / SSL_set_fd");
        return 0;
    }
    /*
     * Name checking differs for an address: SNI never carries one, and
     * the certificate must match it as an IP SAN rather than a DNS name.
     */
    if (inet_pton(AF_INET, host, addr) == 1 || inet_pton(AF_INET6, host, addr) == 1) {
        X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(c->ssl), host);
    } else {
        SSL_set_tlsext_host_name(c->ssl, host);
        SSL_set1_host(c->ssl, host);
    }

    if (SSL_connect(c->ssl) != 1) {
        print_ssl_errors();
        fail("TLS handshake");
        return 0;
    }
    printf("  negotiated %s, %s\n", SSL_get_version(c->ssl),
           SSL_CIPHER_get_name(SSL_get_current_cipher(c->ssl)));
    ok("TLS handshake");

    vr = SSL_get_verify_result(c->ssl);
    if (vr == X509_V_OK)
        ok("certificate verified, name matches");
    else
        printf("  note  certificate not verified: %s%s\n",
               X509_verify_cert_error_string(vr),
               cafile ? "" : " (pass --cafile collector.crt to verify)");
    return 1;
}
#endif

static int conn_write(conn *c, const char *p, size_t n)
{
    while (n > 0) {
        long w;

#ifdef WITH_TLS
        if (c->ssl != NULL)
            w = SSL_write(c->ssl, p, (int) n);
        else
#endif
            w = (long) send(c->fd, p, n, 0);
        if (w <= 0)
            return 0;
        p += w;
        n -= (size_t) w;
    }
    return 1;
}

/* Read until the peer closes; the request asked for Connection: close. */
static size_t conn_read_all(conn *c, char *buf, size_t cap)
{
    size_t n = 0;

    while (n + 1 < cap) {
        long r;

#ifdef WITH_TLS
        if (c->ssl != NULL)
            r = SSL_read(c->ssl, buf + n, (int) (cap - 1 - n));
        else
#endif
            r = (long) recv(c->fd, buf + n, cap - 1 - n, 0);
        if (r <= 0)
            break;
        n += (size_t) r;
    }
    buf[n] = '\0';
    return n;
}

static void conn_close(conn *c)
{
#ifdef WITH_TLS
    if (c->ssl != NULL) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    if (c->ctx != NULL)
        SSL_CTX_free(c->ctx);
#endif
    if (c->fd >= 0)
        close(c->fd);
}

/* ------------------------------------------------------------------ */
/* Response                                                            */

/* Days since 1970-01-01 of a proleptic Gregorian date. C99 has no
   timegm, and mktime would apply the local zone we are trying to
   measure. */
static long long days_from_civil(int y, int m, int d)
{
    int era, yoe, doy, doe;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (long long) era * 146097 + doe - 719468;
}

/* "Date: Sat, 31 Oct 2026 12:34:56 GMT" (RFC 9110 IMF-fixdate). */
static int parse_http_date(const char *s, long long *out)
{
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    char mon[4];
    const char *p;
    int d, y, hh, mm, ss;

    if (sscanf(s, "%*3s, %d %3s %d %d:%d:%d", &d, mon, &y, &hh, &mm, &ss) != 6)
        return 0;
    p = strstr(months, mon);
    if (p == NULL || (p - months) % 3 != 0)
        return 0;
    *out = days_from_civil(y, (int) ((p - months) / 3) + 1, d) * 86400LL +
           hh * 3600LL + mm * 60LL + ss;
    return 1;
}

static const char *find_header(const char *head, const char *name)
{
    size_t n = strlen(name);
    const char *p = head;

    while ((p = strstr(p, "\r\n")) != NULL) {
        size_t i;

        p += 2;
        for (i = 0; i < n; i++)
            if (tolower((unsigned char) p[i]) != tolower((unsigned char) name[i]))
                break;
        if (i == n && p[n] == ':') {
            p += n + 1;
            while (*p == ' ')
                p++;
            return p;
        }
    }
    return NULL;
}

static void check_response(char *resp, size_t n, long long sent_at)
{
    char *body = strstr(resp, "\r\n\r\n");
    int code = 0;
    const char *date;

    if (n == 0) {
        fail("no response from collector");
        return;
    }
    if (body != NULL) {
        *body = '\0';
        body += 4;
    }
    printf("\n--- response headers ---\n%s\n--- body ---\n%s\n------------\n",
           resp, body ? body : "(none)");

    if (sscanf(resp, "HTTP/%*d.%*d %d", &code) != 1) {
        fail("response is not HTTP");
        return;
    }
    if (code == 200)
        ok("HTTP 200 from collector");
    else {
        printf("  HTTP status %d\n", code);
        fail("collector did not accept the export");
    }
    /* A 200 can still carry rejected points. */
    if (body != NULL && strstr(body, "rejectedDataPoints") != NULL)
        fail("collector rejected data points (see partialSuccess)");

    date = find_header(resp, "Date");
    if (date != NULL) {
        long long server;

        if (parse_http_date(date, &server)) {
            long long skew = sent_at - server;

            printf("  clock skew: ours minus collector's = %lld s\n", skew);
            if (skew >= -2 && skew <= 2)
                ok("clock agrees with collector within 2 s");
            else
                fail("clock disagrees with collector; timestamps will be off");
        }
    } else {
        printf("  no Date header; skew not measured\n");
    }
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    const char *host = DEFAULT_HOST, *port = DEFAULT_PORT, *path = DEFAULT_PATH;
    const char *cafile = NULL;
    int tls = 0, i;
    static char payload[8192], request[10240], resp[65536];
    int plen, rlen;
    long long now;
    conn c;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)        host = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)   port = argv[++i];
        else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc)   path = argv[++i];
        else if (strcmp(argv[i], "--cafile") == 0 && i + 1 < argc) cafile = argv[++i];
        else if (strcmp(argv[i], "--tls") == 0)                    tls = 1;
        else {
            printf("usage: %s [--host H] [--port N] [--path P] [--tls] [--cafile F]\n",
                   argv[0]);
            return EXIT_FAILURE;
        }
    }
#ifndef WITH_TLS
    if (tls) {
        printf("this image was built without TLS; run probe_otlp_tls\n");
        return EXIT_FAILURE;
    }
#endif

    printf("vmsotel probe_otlp%s -> %s://%s:%s%s\n", tls ? " (TLS)" : "",
           tls ? "https" : "http", host, port, path);

    now = (long long) time(NULL);
    plen = build_payload(payload, sizeof payload, now, tls ? "https" : "http");
    if (plen < 0) {
        fail("payload too large");
        return EXIT_FAILURE;
    }
    rlen = snprintf(request, sizeof request,
                    "POST %s HTTP/1.1\r\n"
                    "Host: %s:%s\r\n"
                    "User-Agent: vmsotel-probe/0.1\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: %d\r\n"
                    "Connection: close\r\n"
                    "\r\n%s", path, host, port, plen, payload);
    if (rlen < 0 || (size_t) rlen >= sizeof request) {
        fail("request too large");
        return EXIT_FAILURE;
    }

    memset(&c, 0, sizeof c);
    c.fd = -1;
    if (!conn_tcp(&c, host, port))
        goto done;
#ifdef WITH_TLS
    if (tls && !conn_tls(&c, host, cafile))
        goto done;
#else
    (void) cafile;
#endif
    if (!conn_write(&c, request, (size_t) rlen)) {
        fail("send request");
        goto done;
    }
    ok("request sent");
    check_response(resp, conn_read_all(&c, resp, sizeof resp), now);

done:
    conn_close(&c);
    printf("\n%s: %d failure%s\n", failures ? "FAILURES" : "PASS",
           failures, failures == 1 ? "" : "s");
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
