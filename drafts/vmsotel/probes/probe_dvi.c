/*
 * vmsotel probe: disks through $DEVICE_SCAN and $GETDVIW
 *
 * Answers:
 *   1. Whether $DEVICE_SCAN filtered by DVS$_DEVCLASS = DC$_DISK finds
 *      the same disks as SHOW DEVICE D.
 *   2. Which DVI$_ items are accepted, per disk -- unmounted disks and
 *      shadow-set members are expected to refuse some.
 *   3. Whether DVI$_OPCNT is cumulative, from two samples five seconds
 *      apart. It becomes system.disk.operations.
 *   4. Free space in 512-byte blocks: compare with SHOW DEVICE D.
 *
 * Shadow-set members are reported so the agent can avoid counting a
 * mirrored volume twice.
 */

#include "vmsprobe.h"

#include <dcdef.h>
#include <dvidef.h>
#include <dvsdef.h>
#include <unistd.h>

#include "items_dvi.h"

#define MAX_DISKS 256

typedef struct {
    char name[65];
    unsigned long long opcnt0;
    int have_opcnt;
} disk_row;

static disk_row disks[MAX_DISKS];
static size_t ndisks = 0;

static void make_desc(struct dsc$descriptor_s *d, char *s, unsigned short len)
{
    d->dsc$w_length = len;
    d->dsc$b_dtype = DSC$K_DTYPE_T;
    d->dsc$b_class = DSC$K_CLASS_S;
    d->dsc$a_pointer = s;
}

static void enumerate(void)
{
    unsigned int devclass = DC$_DISK;
    unsigned int ctx[2] = { 0, 0 };
    probe_ile3 ile[2];

    memset(ile, 0, sizeof ile);
    ile[0].len = 4;
    ile[0].code = DVS$_DEVCLASS;
    ile[0].buf = &devclass;
    ile[0].retlen = 0;

    printf("\n$DEVICE_SCAN for DC$_DISK\n");
    for (;;) {
        char name[65];
        unsigned short len = 0;
        struct dsc$descriptor_s d;
        unsigned int st;

        make_desc(&d, name, 64);
        st = sys$device_scan((void *) &d, &len, 0, (void *) ile, (void *) ctx);
        if (st == SS$_NOMOREDEV || st == SS$_NOSUCHDEV)
            break;
        if (!(st & 1)) {
            printf("  scan error %s\n", probe_msg(st));
            probe_fail("$DEVICE_SCAN");
            break;
        }
        if (ndisks < MAX_DISKS) {
            memcpy(disks[ndisks].name, name, len);
            disks[ndisks].name[len] = '\0';
            ndisks++;
        }
    }
    printf("  %u disk%s found\n", (unsigned) ndisks, ndisks == 1 ? "" : "s");
    if (ndisks > 0)
        probe_ok("$DEVICE_SCAN finds disks");
    else
        probe_fail("$DEVICE_SCAN found no disks");
}

static unsigned int getdvi_one(const char *dev, const probe_item *it,
                               unsigned char *buf, unsigned short *retlen)
{
    struct dsc$descriptor_s d;
    unsigned short iosb[4] = { 0, 0, 0, 0 };
    probe_ile3 ile[2];
    unsigned int st;

    make_desc(&d, (char *) dev, (unsigned short) strlen(dev));
    memset(ile, 0, sizeof ile);
    ile[0].len = it->size;
    ile[0].code = (unsigned short) it->code;
    ile[0].buf = buf;
    ile[0].retlen = retlen;

    st = sys$getdviw(EFN$C_ENF, 0, (void *) &d, (void *) ile, (void *) iosb,
                     0, 0, 0);
    if ((st & 1) && !(iosb[0] & 1))
        st = iosb[0];
    return st;
}

static void describe(void)
{
    size_t k, i;

    for (k = 0; k < ndisks; k++) {
        printf("\n%s\n", disks[k].name);
        for (i = 0; i < DVI_ITEMS_COUNT; i++) {
            const probe_item *it = &dvi_items[i];
            unsigned char buf[256];
            unsigned short retlen = 0;
            unsigned int st;

            if (it->code == PROBE_UNDECLARED) {
                /* Say it once, not once per disk. */
                if (k == 0)
                    printf("  --    %-22s not declared in <dvidef.h>\n", it->name);
                continue;
            }
            memset(buf, 0, sizeof buf);
            st = getdvi_one(disks[k].name, it, buf, &retlen);
            if (!(st & 1)) {
                printf("  no    %-22s %s\n", it->name, probe_msg(st));
                continue;
            }
            printf("  ok    %-22s ", it->name);
            probe_print_value(it, buf, retlen);
            printf("\n");
            if (strcmp(it->name, "DVI$_OPCNT") == 0) {
                disks[k].opcnt0 = probe_le(buf, 4);
                disks[k].have_opcnt = 1;
            }
        }
    }
}

static void opcnt_delta(void)
{
    size_t k, i;
    const probe_item *op = NULL;

    for (i = 0; i < DVI_ITEMS_COUNT; i++)
        if (strcmp(dvi_items[i].name, "DVI$_OPCNT") == 0 &&
            dvi_items[i].code != PROBE_UNDECLARED)
            op = &dvi_items[i];
    if (op == NULL)
        return;

    printf("\nDVI$_OPCNT again after 5 s\n");
    sleep(5);
    for (k = 0; k < ndisks; k++) {
        unsigned char buf[8];
        unsigned short retlen = 0;

        if (!disks[k].have_opcnt)
            continue;
        memset(buf, 0, sizeof buf);
        if (getdvi_one(disks[k].name, op, buf, &retlen) & 1) {
            unsigned long long v = probe_le(buf, 4);

            printf("  %-24s %12llu -> %12llu  (+%lld)\n", disks[k].name,
                   disks[k].opcnt0, v, (long long) (v - disks[k].opcnt0));
        }
    }
}

int main(void)
{
    probe_banner("probe_dvi");
    if (!probe_check_ile())
        return probe_summary();
    enumerate();
    describe();
    opcnt_delta();
    return probe_summary();
}
