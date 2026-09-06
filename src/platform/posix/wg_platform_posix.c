/*
 * POSIX platform implementation — vmsguard
 *
 * Deliberately conservative: plain BSD sockets, poll(), getaddrinfo(),
 * and time(). Every one of these was confirmed present in the OpenVMS
 * C RTL header inventory (see docs/research/tcpip-stack.md), so this
 * file should port to VSI TCP/IP Services with little more than
 * different includes — which is why it avoids anything Linux-specific
 * such as epoll, recvmmsg or clock_gettime's fancier clocks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>

#ifdef __VMS
/* OpenVMS has no gettimeofday: VSI C V7.7 declares it implicitly and it
   may not resolve at link time. $GETTIM is the native equivalent and is
   guaranteed present. See wg_time_ms below. */
#  include <starlet.h>
#else
#  include <sys/time.h>
#endif

#include "wg_platform.h"

struct wg_socket {
    int      fd;
    uint16_t port;
};

/* ---- endpoint conversion -------------------------------------------- */

static int endpoint_to_sockaddr(const struct wg_endpoint *ep,
                                struct sockaddr_storage *ss, socklen_t *len)
{
    memset(ss, 0, sizeof *ss);

    if (ep->family == WG_AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) ss;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(ep->port);
        memcpy(&sin->sin_addr, ep->addr, 4);
        *len = (socklen_t) sizeof *sin;
        return 0;
    }
    if (ep->family == WG_AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) ss;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(ep->port);
        memcpy(&sin6->sin6_addr, ep->addr, 16);
        *len = (socklen_t) sizeof *sin6;
        return 0;
    }
    return -1;
}

static int sockaddr_to_endpoint(struct wg_endpoint *ep,
                                const struct sockaddr *sa)
{
    memset(ep, 0, sizeof *ep);

    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *) sa;
        ep->family = WG_AF_INET;
        ep->port = ntohs(sin->sin_port);
        memcpy(ep->addr, &sin->sin_addr, 4);
        return 0;
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) sa;
        ep->family = WG_AF_INET6;
        ep->port = ntohs(sin6->sin6_port);
        memcpy(ep->addr, &sin6->sin6_addr, 16);
        return 0;
    }
    return -1;
}

/* ---- socket --------------------------------------------------------- */

int wg_socket_open(struct wg_socket **out, uint16_t listen_port,
                   uint8_t family)
{
    struct wg_socket *s;
    struct sockaddr_storage ss;
    socklen_t slen;
    socklen_t alen;
    int on = 1;
    int flags;
    int af;

    if (family == WG_AF_INET) {
        af = AF_INET;
    } else if (family == WG_AF_INET6) {
        af = AF_INET6;
    } else {
        return -1;
    }

    s = (struct wg_socket *) calloc(1, sizeof *s);
    if (s == NULL)
        return -1;

    s->fd = socket(af, SOCK_DGRAM, 0);
    if (s->fd < 0) {
        free(s);
        return -1;
    }

    (void) setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR,
                      (void *) &on, sizeof on);

    /* Bind to the wildcard address of the chosen family. A zeroed
       sockaddr already holds INADDR_ANY / the unspecified IPv6 address,
       so no address constant is needed — which also avoids referencing
       in6addr_any, a symbol OpenVMS does not export. */
    memset(&ss, 0, sizeof ss);
    if (af == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(listen_port);
        slen = (socklen_t) sizeof *sin;
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &ss;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(listen_port);
        slen = (socklen_t) sizeof *sin6;
    }

    if (bind(s->fd, (struct sockaddr *) &ss, slen) < 0) {
        close(s->fd);
        free(s);
        return -1;
    }

    /* Non-blocking, so poll() alone governs when we wait. */
    flags = fcntl(s->fd, F_GETFL, 0);
    if (flags >= 0)
        (void) fcntl(s->fd, F_SETFL, flags | O_NONBLOCK);

    /* Record the port actually assigned, which matters when 0 was
       passed and the system chose one. */
    memset(&ss, 0, sizeof ss);
    alen = (socklen_t) sizeof ss;
    if (getsockname(s->fd, (struct sockaddr *) &ss, &alen) == 0) {
        struct wg_endpoint ep;
        if (sockaddr_to_endpoint(&ep, (struct sockaddr *) &ss) == 0)
            s->port = ep.port;
    }

    *out = s;
    return 0;
}

void wg_socket_close(struct wg_socket *sock)
{
    if (sock == NULL)
        return;
    if (sock->fd >= 0)
        close(sock->fd);
    free(sock);
}

uint16_t wg_socket_port(const struct wg_socket *sock)
{
    return sock->port;
}

int wg_socket_send(struct wg_socket *sock, const struct wg_endpoint *ep,
                   const uint8_t *buf, size_t len)
{
    struct sockaddr_storage ss;
    socklen_t slen = 0;
    ssize_t n;

    if (endpoint_to_sockaddr(ep, &ss, &slen) != 0)
        return -1;

    /* If we ended up on an IPv4 socket but were handed an IPv6
       endpoint (or the reverse), sendto will fail and report it. */
    n = sendto(sock->fd, buf, len, 0, (struct sockaddr *) &ss, slen);
    if (n < 0 || (size_t) n != len)
        return -1;
    return 0;
}

int wg_socket_recv(struct wg_socket *sock, struct wg_endpoint *from,
                   uint8_t *buf, size_t cap, size_t *len, int timeout_ms)
{
    struct pollfd pfd;
    struct sockaddr_storage ss;
    socklen_t slen;
    ssize_t n;
    int rc;

    memset(&pfd, 0, sizeof pfd);
    pfd.fd = sock->fd;
    pfd.events = POLLIN;

    rc = poll(&pfd, 1, timeout_ms);
    if (rc == 0)
        return WG_SOCK_TIMEOUT;
    if (rc < 0)
        return (errno == EINTR) ? WG_SOCK_TIMEOUT : WG_SOCK_ERROR;

    slen = (socklen_t) sizeof ss;
    n = recvfrom(sock->fd, buf, cap, 0, (struct sockaddr *) &ss, &slen);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return WG_SOCK_TIMEOUT;
        return WG_SOCK_ERROR;
    }

    if (sockaddr_to_endpoint(from, (struct sockaddr *) &ss) != 0)
        return WG_SOCK_ERROR;

    /* An IPv4-mapped IPv6 address is really IPv4; normalise it so the
       caller sees a consistent family. */
    if (from->family == WG_AF_INET6) {
        static const uint8_t v4mapped[12] = {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF
        };
        if (memcmp(from->addr, v4mapped, 12) == 0) {
            uint8_t v4[4];
            memcpy(v4, from->addr + 12, 4);
            memset(from->addr, 0, sizeof from->addr);
            memcpy(from->addr, v4, 4);
            from->family = WG_AF_INET;
        }
    }

    *len = (size_t) n;
    return WG_SOCK_OK;
}

/* ---- resolution and formatting -------------------------------------- */

int wg_endpoint_resolve(struct wg_endpoint *ep, const char *host,
                        uint16_t port)
{
    struct addrinfo hints, *res = NULL;
    int rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0 || res == NULL)
        return -1;

    rc = sockaddr_to_endpoint(ep, res->ai_addr);
    freeaddrinfo(res);
    if (rc != 0)
        return -1;

    ep->port = port;
    return 0;
}

int wg_local_address_for(const struct wg_endpoint *peer,
                         struct wg_endpoint *out)
{
    struct sockaddr_storage ss;
    socklen_t slen = 0, alen;
    int fd;
    int rc = -1;

    if (endpoint_to_sockaddr(peer, &ss, &slen) != 0)
        return -1;

    fd = socket(peer->family == WG_AF_INET6 ? AF_INET6 : AF_INET,
                SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    /*
     * connect() on a datagram socket sends nothing; it just asks the
     * routing table which local address would be used. getsockname then
     * reports it. Binding to the wildcard and asking directly would
     * only ever return 0.0.0.0.
     */
    if (connect(fd, (struct sockaddr *) &ss, slen) == 0) {
        alen = (socklen_t) sizeof ss;
        if (getsockname(fd, (struct sockaddr *) &ss, &alen) == 0)
            rc = sockaddr_to_endpoint(out, (struct sockaddr *) &ss);
    }

    close(fd);
    return rc;
}

void wg_endpoint_format(char *out, size_t cap, const struct wg_endpoint *ep)
{
    char host[64];

    if (ep->family == WG_AF_INET) {
        snprintf(host, sizeof host, "%u.%u.%u.%u",
                 ep->addr[0], ep->addr[1], ep->addr[2], ep->addr[3]);
        snprintf(out, cap, "%s:%u", host, (unsigned) ep->port);
    } else if (ep->family == WG_AF_INET6) {
        if (inet_ntop(AF_INET6, ep->addr, host, sizeof host) == NULL)
            snprintf(host, sizeof host, "?");
        snprintf(out, cap, "[%s]:%u", host, (unsigned) ep->port);
    } else {
        snprintf(out, cap, "<unset>");
    }
}

/* ---- time ----------------------------------------------------------- */

uint64_t wg_time_ms(void)
{
    /*
     * Wall-clock time in milliseconds. Only differences over short
     * intervals are used, so the clock stepping does not matter.
     */
#ifdef __VMS
    /*
     * $GETTIM returns a quadword counting 100-nanosecond intervals
     * since 17-NOV-1858, so dividing by 10000 gives milliseconds.
     *
     * This replaces gettimeofday, which VSI C only declares implicitly
     * (%CC-I-IMPLICITFUNC) and which may not resolve at link time.
     * $GETTIM is a core system service and is always available.
     *
     * The cast through void * avoids a prototype mismatch: starlet.h
     * declares the argument as a struct _generic_64 *.
     */
    unsigned long long now = 0;

    if (!(sys$gettim((void *) &now) & 1))    /* odd status is success */
        return (uint64_t) time(NULL) * 1000;

    return (uint64_t) (now / 10000ULL);
#else
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0)
        return (uint64_t) time(NULL) * 1000;

    return (uint64_t) tv.tv_sec * 1000 + (uint64_t) (tv.tv_usec / 1000);
#endif
}
