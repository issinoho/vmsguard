/*
 * vmsguard probe: sockets and event loop
 *
 * The MVP's design assumes a single-threaded poll() loop over a
 * non-blocking UDP socket. This confirms that assumption holds on the
 * target platform, and separately reports whether SOCK_RAW is usable
 * (relevant only to the Phase 2 tunnelling question, not the MVP).
 *
 * C99. Build instructions in README.md.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#ifdef __VMS
#  include <ioctl.h>
#else
#  include <sys/ioctl.h>
#endif

static int failures = 0;

static void ok(const char *what)
{
    printf("  ok    %s\n", what);
}

static void fail(const char *what)
{
    printf("  FAIL  %s (errno %d: %s)\n", what, errno, strerror(errno));
    failures++;
}

static void note(const char *what)
{
    printf("  note  %s\n", what);
}

int main(void)
{
    int s = -1;
    int flags;
    int on = 1;
    struct sockaddr_in addr;
    socklen_t alen;
    struct pollfd pfd;
    char buf[64];
    ssize_t n;
    int rc;

    printf("vmsguard sockets probe\n\n");

    /* --- UDP socket, bound to an ephemeral port on loopback --- */

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        fail("socket(AF_INET, SOCK_DGRAM)");
        return 1;
    }
    ok("socket(AF_INET, SOCK_DGRAM)");

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof on) < 0)
        fail("setsockopt(SO_REUSEADDR)");
    else
        ok("setsockopt(SO_REUSEADDR)");

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(s, (struct sockaddr *) &addr, sizeof addr) < 0) {
        fail("bind(127.0.0.1:0)");
        close(s);
        return 1;
    }
    ok("bind(127.0.0.1:0)");

    alen = sizeof addr;
    if (getsockname(s, (struct sockaddr *) &addr, &alen) < 0) {
        fail("getsockname");
        close(s);
        return 1;
    }
    printf("  note  bound to port %d\n", (int) ntohs(addr.sin_port));

    /* --- non-blocking: try fcntl first, then ioctl(FIONBIO) --- */

    flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0 && fcntl(s, F_SETFL, flags | O_NONBLOCK) >= 0) {
        ok("non-blocking via fcntl(O_NONBLOCK)");
    } else {
        note("fcntl(O_NONBLOCK) unavailable, trying ioctl(FIONBIO)");
        if (ioctl(s, FIONBIO, &on) < 0)
            fail("non-blocking via ioctl(FIONBIO)");
        else
            ok("non-blocking via ioctl(FIONBIO)");
    }

    /* A non-blocking read with nothing queued must return EWOULDBLOCK
       rather than hanging. If this blocks, the socket is not actually
       non-blocking and the whole event-loop design needs rethinking. */
    n = recvfrom(s, buf, sizeof buf, 0, NULL, NULL);
    if (n < 0 && (errno == EWOULDBLOCK || errno == EAGAIN))
        ok("non-blocking recvfrom returns EWOULDBLOCK");
    else
        fail("non-blocking recvfrom did not return EWOULDBLOCK");

    /* --- poll() on an idle socket should time out cleanly --- */

    memset(&pfd, 0, sizeof pfd);
    pfd.fd = s;
    pfd.events = POLLIN;
    rc = poll(&pfd, 1, 100);
    if (rc == 0)
        ok("poll() times out on idle socket");
    else if (rc < 0)
        fail("poll() on idle socket");
    else
        note("poll() reported readiness on an idle socket (unexpected)");

    /* --- send to self, then poll should report readable --- */

    if (sendto(s, "ping", 4, 0, (struct sockaddr *) &addr, sizeof addr) != 4) {
        fail("sendto self");
    } else {
        ok("sendto self");

        memset(&pfd, 0, sizeof pfd);
        pfd.fd = s;
        pfd.events = POLLIN;
        rc = poll(&pfd, 1, 1000);
        if (rc == 1 && (pfd.revents & POLLIN)) {
            ok("poll() reports POLLIN after send");
            n = recvfrom(s, buf, sizeof buf, 0, NULL, NULL);
            if (n == 4 && memcmp(buf, "ping", 4) == 0)
                ok("recvfrom returns the datagram");
            else
                fail("recvfrom did not return the datagram");
        } else if (rc == 0) {
            fail("poll() timed out despite a queued datagram");
        } else {
            fail("poll() after send");
        }
    }

    close(s);

    /* --- SOCK_RAW: informational only, not needed for the MVP --- */

    printf("\n  --- raw sockets (Phase 2 only, not required for MVP) ---\n");
    s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (s < 0) {
        printf("  note  SOCK_RAW unavailable (errno %d: %s)\n",
               errno, strerror(errno));
        printf("  note  likely a privilege issue; retry with elevated\n");
        printf("        privileges before concluding it is unsupported\n");
    } else {
        printf("  note  SOCK_RAW opened successfully\n");
        close(s);
    }

    printf("\n%s (%d failure%s)\n", failures == 0 ? "PASS" : "FAIL",
           failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
