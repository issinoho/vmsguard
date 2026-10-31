/*
 * vmsotel probe: $GETRMI performance counters
 *
 * $GETRMI is the source MONITOR itself reads, and the one place CPU
 * time by mode, paging and process-state counts are available
 * system-wide. Whether VSI carried every item to x86-64, and what units
 * they come back in, is not something a header can tell us.
 *
 * Answers:
 *   1. Which RMI$_ items are declared, and which the service accepts.
 *   2. Whether each is a cumulative counter or a gauge: two samples
 *      are taken five seconds apart and the delta printed.
 *   3. The unit of the CPU-mode counters. The sum of all modes over an
 *      interval must equal wall time multiplied by the number of active
 *      CPUs. If the counters are 10 ms ticks, five seconds on one CPU
 *      is 500; the probe works out the ratio and checks it against
 *      SYI$_ACTIVECPU_CNT. That is the test that can fail.
 *
 * Privilege: unknown, which is part of the question. Run it once
 * unprivileged first.
 */

#include "vmsprobe.h"

#include <rmidef.h>
#include <syidef.h>
#include <unistd.h>

#include "items_rmi.h"

#define INTERVAL_SECONDS 5

typedef struct {
    int accepted;
    unsigned short retlen;
    unsigned long long value;
    unsigned int status;
} rmi_result;

static rmi_result first[RMI_ITEMS_COUNT], second[RMI_ITEMS_COUNT];

/*
 * One item per call. The buffer is offered as a quadword first; if the
 * service insists on exactly a longword, it is asked again with 4.
 */
static void query_one(const probe_item *it, rmi_result *r)
{
    static const unsigned short sizes[2] = { 8, 4 };
    int attempt;

    memset(r, 0, sizeof *r);
    for (attempt = 0; attempt < 2; attempt++) {
        unsigned char buf[8];
        unsigned short retlen = 0;
        unsigned short iosb[4] = { 0, 0, 0, 0 };
        probe_ile3 ile[2];
        unsigned int st;

        memset(buf, 0, sizeof buf);
        memset(ile, 0, sizeof ile);
        ile[0].len = sizes[attempt];
        ile[0].code = (unsigned short) it->code;
        ile[0].buf = buf;
        ile[0].retlen = &retlen;

        /* $GETRMI has no W form: queue it, then wait on the IOSB. */
        st = sys$getrmi(EFN$C_ENF, 0, 0, (void *) ile, (void *) iosb, 0, 0);
        if (st & 1)
            st = sys$synch(EFN$C_ENF, (void *) iosb);
        if ((st & 1) && !(iosb[0] & 1))
            st = iosb[0];
        r->status = st;
        if (st & 1) {
            r->accepted = 1;
            r->retlen = retlen ? retlen : sizes[attempt];
            r->value = probe_le(buf, sizes[attempt]);
            return;
        }
        if (st != SS$_BADPARAM)
            return;
    }
}

static void sample(rmi_result *out)
{
    size_t i;

    for (i = 0; i < RMI_ITEMS_COUNT; i++)
        if (rmi_items[i].code != PROBE_UNDECLARED)
            query_one(&rmi_items[i], &out[i]);
}

static unsigned int active_cpus(void)
{
    unsigned int n = 0;
    unsigned short retlen = 0;
    unsigned short iosb[4] = { 0, 0, 0, 0 };
    probe_ile3 ile[2];

#ifdef SYI$_ACTIVECPU_CNT
    memset(ile, 0, sizeof ile);
    ile[0].len = 4;
    ile[0].code = SYI$_ACTIVECPU_CNT;
    ile[0].buf = &n;
    ile[0].retlen = &retlen;
    if (!(sys$getsyiw(EFN$C_ENF, 0, 0, (void *) ile, (void *) iosb, 0, 0) & 1) ||
        !(iosb[0] & 1))
        n = 0;
#endif
    return n;
}

static unsigned long long now_100ns(void)
{
    unsigned long long t = 0;

    sys$gettim((void *) &t);
    return t;
}

int main(void)
{
    size_t i;
    unsigned long long t0, t1, cpu_sum = 0;
    unsigned int ncpu, cpu_items = 0;
    double seconds;

    probe_banner("probe_rmi");
    if (!probe_check_ile())
        return probe_summary();

    ncpu = active_cpus();
    printf("active CPUs (SYI$_ACTIVECPU_CNT): %u\n", ncpu);
    printf("sampling twice, %d s apart\n", INTERVAL_SECONDS);

    t0 = now_100ns();
    sample(first);
    sleep(INTERVAL_SECONDS);
    t1 = now_100ns();
    sample(second);
    seconds = (double) (t1 - t0) / 1e7;

    printf("\n  %-5s %-16s %20s %20s %12s  bytes\n",
           "", "item", "first", "second", "delta");
    for (i = 0; i < RMI_ITEMS_COUNT; i++) {
        const probe_item *it = &rmi_items[i];
        const rmi_result *a = &first[i], *b = &second[i];

        if (it->code == PROBE_UNDECLARED) {
            printf("  --    %-16s not declared in <rmidef.h>\n", it->name);
            continue;
        }
        if (!a->accepted || !b->accepted) {
            printf("  no    %-16s %s\n", it->name,
                   probe_msg(a->accepted ? b->status : a->status));
            continue;
        }
        printf("  ok    %-16s %20llu %20llu %12lld  %u\n", it->name,
               a->value, b->value,
               (long long) (b->value - a->value), (unsigned) a->retlen);

        if (strncmp(it->name, "RMI$_CPU", 8) == 0) {
            cpu_sum += b->value - a->value;
            cpu_items++;
        }
    }

    printf("\nCPU mode counters\n");
    printf("  %u mode items accepted, sum of deltas %llu over %.2f s\n",
           cpu_items, cpu_sum, seconds);
    if (cpu_items == 0) {
        probe_fail("no CPU mode counters available");
    } else {
        double per_cpu_per_sec = (double) cpu_sum / seconds /
                                 (ncpu ? (double) ncpu : 1.0);

        printf("  = %.1f units per second per active CPU\n", per_cpu_per_sec);
        if (per_cpu_per_sec > 90.0 && per_cpu_per_sec < 110.0)
            probe_ok("CPU mode counters are 10 ms ticks, summed over CPUs");
        else if (ncpu > 1 && per_cpu_per_sec * ncpu > 90.0 &&
                 per_cpu_per_sec * ncpu < 110.0)
            probe_fail("CPU counters cover ONE CPU, not all of them");
        else
            probe_fail("CPU mode counters are not 10 ms ticks of all CPUs; "
                       "unit unknown -- paste this whole output");
    }
    return probe_summary();
}
