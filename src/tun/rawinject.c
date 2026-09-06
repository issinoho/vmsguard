/*
 * Raw-socket IPv4 injection — vmsguard
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "ethip.h"
#include "rawinject.h"

/*
 * How the IP total length and fragment offset must be presented to
 * sendto when IP_HDRINCL is set.
 *
 * 4.4BSD-derived stacks want ip_len and ip_off in *host* byte order and
 * convert them on the way out; Linux wants them in network order, as
 * they appear on the wire.
 *
 * Confirmed on OpenVMS by tools/probes/probe_inject.c, which sends both
 * and reports which the stack accepts. Network order there fails every
 * time with ENOBUFS — not a buffer problem at all, but the stack
 * reading 0x0031 as 0x3100 and trying to allocate 12KB for a 49-byte
 * packet.
 */
#ifdef __VMS
#  define RAWINJECT_HOST_ORDER_LEN 1
#else
#  define RAWINJECT_HOST_ORDER_LEN 0
#endif

/* Large enough for any packet the tunnel can carry. */
#define RAWINJECT_MAX 2048

struct raw_injector {
    int     fd;
    uint8_t scratch[RAWINJECT_MAX];
    char    error[160];
};

static void set_error(struct raw_injector *inj, const char *what)
{
    snprintf(inj->error, sizeof inj->error, "%s: %s", what,
             strerror(errno));
}

int raw_injector_open(struct raw_injector **out)
{
    struct raw_injector *inj;
    int on = 1;

    inj = (struct raw_injector *) calloc(1, sizeof *inj);
    if (inj == NULL)
        return -1;

    /*
     * IPPROTO_RAW plus IP_HDRINCL means the buffer handed to sendto is
     * the entire IP packet, header and all, rather than a payload the
     * stack would build a header for. That is what lets a decrypted
     * packet go back out with its original addressing intact.
     */
    inj->fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (inj->fd < 0) {
        set_error(inj, "socket(SOCK_RAW)");
        snprintf(inj->error + strlen(inj->error),
                 sizeof inj->error - strlen(inj->error),
                 " (SYSPRV is required on OpenVMS)");
        /* Keep the object so the caller can read the message. */
        *out = inj;
        return -1;
    }

    if (setsockopt(inj->fd, IPPROTO_IP, IP_HDRINCL,
                   (void *) &on, sizeof on) < 0) {
        set_error(inj, "setsockopt(IP_HDRINCL)");
        close(inj->fd);
        inj->fd = -1;
        *out = inj;
        return -1;
    }

    *out = inj;
    return 0;
}

void raw_injector_close(struct raw_injector *inj)
{
    if (inj == NULL)
        return;
    if (inj->fd >= 0)
        close(inj->fd);
    free(inj);
}

int raw_injector_send(struct raw_injector *inj,
                      const uint8_t *packet, size_t len)
{
    struct sockaddr_in dst;
    uint32_t addr;
    ssize_t n;

    if (inj->fd < 0) {
        snprintf(inj->error, sizeof inj->error, "injector is not open");
        return -1;
    }
    if (len < IPV4_MIN_HDR) {
        snprintf(inj->error, sizeof inj->error, "packet too short");
        return -1;
    }
    if (len > sizeof inj->scratch) {
        snprintf(inj->error, sizeof inj->error, "packet too large");
        return -1;
    }

    /* sendto still wants a destination even with IP_HDRINCL; it must
       agree with the header or the stack may route it oddly. Taking it
       from the packet keeps the two consistent by construction. */
    addr = ipv4_dst(packet);

    /*
     * Work on a copy: the caller's packet arrived off the wire with
     * network byte order throughout, and must not be modified.
     */
    memcpy(inj->scratch, packet, len);

    if (RAWINJECT_HOST_ORDER_LEN) {
        uint16_t v;

        /* Read the field as network order, store it as host order.
           Going through a uint16_t rather than swapping bytes keeps
           this correct on a big-endian host, where the two orders
           coincide and nothing should change. */
        v = (uint16_t) (((uint16_t) inj->scratch[2] << 8) | inj->scratch[3]);
        memcpy(inj->scratch + 2, &v, sizeof v);

        v = (uint16_t) (((uint16_t) inj->scratch[6] << 8) | inj->scratch[7]);
        memcpy(inj->scratch + 6, &v, sizeof v);
    }

    /*
     * Leave the header checksum to the stack. It has to recompute it
     * anyway once it has put the length back into network order, and
     * both Linux and the BSD-derived stacks fill this in themselves
     * under IP_HDRINCL.
     */
    inj->scratch[10] = 0;
    inj->scratch[11] = 0;

    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = 0;
    dst.sin_addr.s_addr = htonl(addr);

    n = sendto(inj->fd, inj->scratch, len, 0,
               (struct sockaddr *) &dst, sizeof dst);
    if (n < 0) {
        set_error(inj, "sendto");
        return -1;
    }
    if ((size_t) n != len) {
        snprintf(inj->error, sizeof inj->error,
                 "short write: %ld of %lu bytes",
                 (long) n, (unsigned long) len);
        return -1;
    }
    return 0;
}

const char *raw_injector_error(const struct raw_injector *inj)
{
    if (inj == NULL)
        return "no injector";
    return inj->error[0] != '\0' ? inj->error : "no error";
}
