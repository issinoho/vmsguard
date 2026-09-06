/*
 * Platform abstraction — vmsguard
 *
 * Everything the protocol core cannot do for itself: a UDP socket, a
 * clock, and name resolution. This is the *entire* surface that has to
 * be reimplemented for OpenVMS, so it is deliberately narrow and free of
 * any POSIX types — no sockaddr, no fd, no struct timeval. The POSIX
 * implementation lives in platform/posix, and a VMS implementation will
 * sit beside it exposing exactly these functions.
 *
 * Keeping sockaddr out of this header is the point: VSI TCP/IP Services
 * offers both a BSD sockets API and a native $QIO interface, and the
 * choice between them should not leak into the portable code.
 */

#ifndef VMSGUARD_WG_PLATFORM_H
#define VMSGUARD_WG_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#define WG_AF_INET   4
#define WG_AF_INET6  6

/* Return codes for the receive call. */
#define WG_SOCK_OK       0
#define WG_SOCK_TIMEOUT  1
#define WG_SOCK_ERROR   (-1)

/*
 * A UDP endpoint, platform-neutral. addr holds 4 bytes for IPv4 or 16
 * for IPv6, in network order; port is in host order.
 */
struct wg_endpoint {
    uint8_t  family;
    uint8_t  addr[16];
    uint16_t port;
};

struct wg_socket;   /* opaque, defined by the platform implementation */

/*
 * Open a UDP socket bound to the wildcard address of `family`
 * (WG_AF_INET or WG_AF_INET6). listen_port may be 0 to let the system
 * choose, which is what a client wants.
 *
 * The family is explicit rather than opening a dual-stack IPv6 socket
 * and relying on IPv4-mapped addresses. Linux accepts an AF_INET
 * destination on such a socket; OpenVMS rejects it, and OpenVMS is the
 * stricter and more standard reading. Callers know which family their
 * peer uses, so asking for it directly avoids depending on either
 * behaviour.
 *
 * Returns 0 on success, -1 on failure.
 */
int wg_socket_open(struct wg_socket **sock, uint16_t listen_port,
                   uint8_t family);

void wg_socket_close(struct wg_socket *sock);

/* Returns 0 on success, -1 on failure. */
int wg_socket_send(struct wg_socket *sock, const struct wg_endpoint *ep,
                   const uint8_t *buf, size_t len);

/*
 * Wait up to timeout_ms for a datagram. Returns WG_SOCK_OK with the
 * packet and its source endpoint, WG_SOCK_TIMEOUT if nothing arrived,
 * or WG_SOCK_ERROR. A timeout_ms of 0 polls without blocking.
 */
int wg_socket_recv(struct wg_socket *sock, struct wg_endpoint *from,
                   uint8_t *buf, size_t cap, size_t *len, int timeout_ms);

/* The port the socket is actually bound to, useful when 0 was passed. */
uint16_t wg_socket_port(const struct wg_socket *sock);

/*
 * Resolve host (a name or literal address) and port into an endpoint.
 * Returns 0 on success, -1 on failure.
 */
int wg_endpoint_resolve(struct wg_endpoint *ep, const char *host,
                        uint16_t port);

/* Format an endpoint as text, e.g. "10.0.0.1:51820". */
void wg_endpoint_format(char *out, size_t cap, const struct wg_endpoint *ep);

/*
 * Milliseconds from an unspecified origin, monotonic where the platform
 * offers it. Only differences are meaningful.
 */
uint64_t wg_time_ms(void);

#endif /* VMSGUARD_WG_PLATFORM_H */
