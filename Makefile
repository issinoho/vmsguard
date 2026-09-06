# vmsguard — POSIX reference build
#
# This builds the protocol core, tools and tests on Linux/POSIX, where
# iteration is fast and diagnostics are good.
#
# The OpenVMS build uses build_vms.com (or descrip.mms) against these
# same sources — see docs/building-vms.md. Neither has been run on a
# real system yet.
#
# -std=c99 -pedantic is deliberate: the OpenVMS C compiler is VSI C
# V7.7-3 (GEM-based, not Clang), so C11 constructs must not creep in.
# Violations should surface here rather than on OpenVMS.

CC      ?= cc
CFLAGS  ?= -std=c99 -pedantic -Wall -Wextra -O2
CFLAGS  += -Isrc/proto -Isrc/platform -Isrc/client -Isrc/tun
# glibc hides getaddrinfo, IPV6_V6ONLY and gettimeofday under strict
# -std=c99 unless a feature-test macro asks for them. This is a property
# of this build host, not of the code: the OpenVMS build does not need it.
CFLAGS  += -D_DEFAULT_SOURCE
LDLIBS  ?= -lcrypto

PROTO_SRC = src/proto/blake2s.c \
            src/proto/wg_crypto.c \
            src/proto/wg_proto.c \
            src/proto/wg_noise.c \
            src/proto/wg_key.c

PLATFORM_SRC = src/platform/posix/wg_platform_posix.c
CLIENT_SRC   = src/client/wg_client.c

PROTO_OBJ    = $(PROTO_SRC:.c=.o)
PLATFORM_OBJ = $(PLATFORM_SRC:.c=.o)
CLIENT_OBJ   = $(CLIENT_SRC:.c=.o)

TUN_SRC = src/tun/slip.c src/tun/hdlc.c src/tun/ethip.c \
          src/tun/rawinject.c
TUN_OBJ = $(TUN_SRC:.c=.o)

TESTS   = build/test_proto build/test_slip build/test_hdlc \
          build/test_ethip
TOOLS   = build/vmsguard-interop build/vmsguard-responder \
          build/vmsguard-key

.PHONY: all test loopback clean

all: $(TESTS) $(TOOLS)

build:
	mkdir -p build

build/test_proto: tests/test_proto.c $(PROTO_OBJ) | build
	$(CC) $(CFLAGS) -o $@ tests/test_proto.c $(PROTO_OBJ) $(LDLIBS)

build/vmsguard-interop: tools/interop/interop.c $(PROTO_OBJ) $(PLATFORM_OBJ) $(CLIENT_OBJ) | build
	$(CC) $(CFLAGS) -o $@ tools/interop/interop.c \
	    $(PROTO_OBJ) $(PLATFORM_OBJ) $(CLIENT_OBJ) $(LDLIBS)

build/vmsguard-responder: tools/interop/responder.c $(PROTO_OBJ) $(PLATFORM_OBJ) | build
	$(CC) $(CFLAGS) -o $@ tools/interop/responder.c \
	    $(PROTO_OBJ) $(PLATFORM_OBJ) $(LDLIBS)

build/vmsguard-key: tools/keys/keys.c $(PROTO_OBJ) | build
	$(CC) $(CFLAGS) -o $@ tools/keys/keys.c $(PROTO_OBJ) $(LDLIBS)

build/test_slip: tests/test_slip.c $(TUN_OBJ) | build
	$(CC) $(CFLAGS) -o $@ tests/test_slip.c $(TUN_OBJ)

build/test_hdlc: tests/test_hdlc.c $(TUN_OBJ) | build
	$(CC) $(CFLAGS) -o $@ tests/test_hdlc.c $(TUN_OBJ)

build/test_ethip: tests/test_ethip.c src/tun/ethip.o | build
	$(CC) $(CFLAGS) -o $@ tests/test_ethip.c src/tun/ethip.o

test: $(TESTS)
	@./build/test_proto
	@./build/test_slip
	@./build/test_hdlc
	@./build/test_ethip

loopback: $(TOOLS)
	@sh tools/interop/loopback.sh

clean:
	rm -f $(PROTO_OBJ) $(PLATFORM_OBJ) $(CLIENT_OBJ) $(TUN_OBJ)
	rm -rf build

$(PROTO_OBJ): src/proto/blake2s.h src/proto/wg_crypto.h \
              src/proto/wg_proto.h src/proto/wg_noise.h \
              src/proto/wg_key.h
$(PLATFORM_OBJ): src/platform/wg_platform.h
$(CLIENT_OBJ): src/client/wg_client.h src/platform/wg_platform.h \
               src/proto/wg_noise.h
$(TUN_OBJ): src/tun/slip.h src/tun/hdlc.h src/tun/ethip.h \
            src/tun/rawinject.h
