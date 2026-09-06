# vmsguard — POSIX reference build
#
# This builds the platform-agnostic protocol core and its tests on
# Linux/POSIX, where iteration is fast and diagnostics are good. The
# OpenVMS build uses descrip.mms against the same sources in src/proto.
#
# -std=c99 -pedantic is deliberate: the OpenVMS C compiler is VSI C
# V7.7-3 (GEM-based, not Clang), so C11 constructs must not creep in.
# Violations should surface here rather than on OpenVMS.

CC      ?= cc
CFLAGS  ?= -std=c99 -pedantic -Wall -Wextra -O2
CFLAGS  += -Isrc/proto
LDLIBS  ?= -lcrypto

PROTO_SRC = src/proto/blake2s.c \
            src/proto/wg_crypto.c \
            src/proto/wg_proto.c \
            src/proto/wg_noise.c \
            src/proto/wg_key.c

PROTO_OBJ = $(PROTO_SRC:.c=.o)

TESTS     = build/test_proto

.PHONY: all test clean

all: $(TESTS)

build:
	mkdir -p build

build/test_proto: tests/test_proto.c $(PROTO_OBJ) | build
	$(CC) $(CFLAGS) -o $@ tests/test_proto.c $(PROTO_OBJ) $(LDLIBS)

test: $(TESTS)
	@./build/test_proto

clean:
	rm -f $(PROTO_OBJ)
	rm -rf build

$(PROTO_OBJ): src/proto/blake2s.h src/proto/wg_crypto.h \
              src/proto/wg_proto.h src/proto/wg_noise.h \
              src/proto/wg_key.h
