# vmsotel probes, Linux side.
#
#   make            build everything that can be built here
#   make check      run every probe here: the system-service probes
#                   against the stub, probe_otlp against a fake
#                   collector that validates the payload against the
#                   official OTLP protobuf schema
#
# The system-service probes only mean anything on OpenVMS. Here they
# link against stub/vmsstub.c, which exists so their logic runs before
# it costs a round trip -- the same reason vmsguard runs its gateway
# against a stub libpcap.

CC      ?= cc
STRICT  = -std=c99 -pedantic -Wall -Wextra -Werror
# '$' in identifiers is the one extension VMS code cannot avoid, and
# -pedantic has no switch for it alone, so the VMS-only probes drop
# -pedantic and keep the rest. probe_otlp is portable and keeps it.
VMSISH  = -std=c99 -Wall -Wextra -Werror -fdollars-in-identifiers -Istub

PYTHON ?= python3

B = build
VMS_PROBES = $(B)/probe_syi $(B)/probe_rmi $(B)/probe_jpi $(B)/probe_dvi
ALL = $(VMS_PROBES) $(B)/probe_otlp $(B)/probe_otlp_tls

all: $(ALL)

$(B):
	mkdir -p $(B)

$(B)/vmsstub.o: stub/vmsstub.c stub/*.h | $(B)
	$(CC) $(VMSISH) -c -o $@ stub/vmsstub.c

$(B)/vmsprobe.o: probes/vmsprobe.c probes/vmsprobe.h | $(B)
	$(CC) $(VMSISH) -c -o $@ probes/vmsprobe.c

$(B)/probe_%: probes/probe_%.c probes/vmsprobe.h probes/items_*.h $(B)/vmsprobe.o $(B)/vmsstub.o | $(B)
	$(CC) $(VMSISH) -o $@ $< $(B)/vmsprobe.o $(B)/vmsstub.o

$(B)/probe_otlp: probes/probe_otlp.c | $(B)
	$(CC) $(STRICT) -o $@ $<

$(B)/probe_otlp_tls: probes/probe_otlp.c | $(B)
	$(CC) $(STRICT) -DWITH_TLS -o $@ $< -lssl -lcrypto

# The generated tables are committed; regenerate them when the lists
# in gen_items.py change.
items:
	cd probes && python3 -I gen_items.py
	cd stub && python3 -I gen_stub_headers.py

check: all
	for p in $(VMS_PROBES); do echo "== $$p"; $$p || exit 1; done
	$(PYTHON) -I tools/fake_collector.py --selftest $(B)/probe_otlp $(B)/probe_otlp_tls

clean:
	rm -rf $(B)

.PHONY: all check clean items
