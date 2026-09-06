# descrip.mms — MMS description file for vmsguard on OpenVMS x86-64
#
# UNTESTED, and less certain than build_vms.com: that procedure uses
# only CC and LINK, whereas this file depends on MMS syntax that has not
# been verified on a real system. Try build_vms.com first, and treat a
# failure here as an MMS-syntax problem rather than a code problem.
#
# Usage:
#     $ MMS                build everything
#     $ MMS TEST           build and run the protocol tests
#     $ MMS CLEAN          remove build products
#
# Configuration is at the top. Confirm the OpenSSL names with:
#     $ SHOW LOGICAL SSL3$*
#     $ DIRECTORY SYS$SHARE:SSL3$*

SSL_INCLUDE = SSL3$INCLUDE
SSL_LIBRARY = SSL3$LIBCRYPTO_SHR

# _SOCKADDR_LEN selects the BSD 4.4 socket structures, which is what
# provides sockaddr_in6 and sockaddr_storage (Sockets API manual,
# section 1.4.1). The platform layer will not compile without it.
#
# VSI C V7.7 is GEM-based rather than Clang, so C99 is the ceiling. If
# /STANDARD=C99 rejects something, try /STANDARD=RELAXED.

CFLAGS = /STANDARD=C99 /DEFINE=(_SOCKADDR_LEN) -
         /INCLUDE_DIRECTORY=([.src.proto],[.src.platform],[.src.client],$(SSL_INCLUDE))

# No socket library is named: per section 1.4 of the Sockets API manual,
# linking a sockets program needs nothing beyond LINK, because the
# run-time library TCPIP$IPC_SHR is picked up automatically. Only
# OpenSSL needs an options file.

OPT = [.build]vmsguard.opt

PROTO_OBJS = [.build]blake2s.obj,[.build]wg_crypto.obj,-
             [.build]wg_proto.obj,[.build]wg_noise.obj,[.build]wg_key.obj

PLAT_OBJS   = [.build]wg_platform.obj
CLIENT_OBJS = [.build]wg_client.obj

# Everything is written into [.build], which must exist before the first
# compile. .FIRST runs ahead of any target.

.FIRST
    @- IF F$SEARCH("BUILD.DIR;1") .EQS. "" THEN CREATE/DIRECTORY [.build]

ALL : [.build]vmsguard_key.exe, [.build]vmsguard_interop.exe, -
      [.build]vmsguard_responder.exe, [.build]test_proto.exe
    @ WRITE SYS$OUTPUT "build complete, executables in [.build]"

# ---- protocol core ---------------------------------------------------

[.build]blake2s.obj : [.src.proto]blake2s.c, [.src.proto]blake2s.h
    $(CC)$(CFLAGS)/OBJECT=$@ $(MMS$SOURCE)

[.build]wg_crypto.obj : [.src.proto]wg_crypto.c, [.src.proto]wg_crypto.h
    $(CC)$(CFLAGS)/OBJECT=$@ $(MMS$SOURCE)

[.build]wg_proto.obj : [.src.proto]wg_proto.c, [.src.proto]wg_proto.h
    $(CC)$(CFLAGS)/OBJECT=$@ $(MMS$SOURCE)

[.build]wg_noise.obj : [.src.proto]wg_noise.c, [.src.proto]wg_noise.h
    $(CC)$(CFLAGS)/OBJECT=$@ $(MMS$SOURCE)

[.build]wg_key.obj : [.src.proto]wg_key.c, [.src.proto]wg_key.h
    $(CC)$(CFLAGS)/OBJECT=$@ $(MMS$SOURCE)

# ---- platform and client ---------------------------------------------

# The POSIX implementation is used on purpose: VSI TCP/IP Services
# provides BSD sockets, poll() and getaddrinfo(), all confirmed present
# in the C RTL header inventory. If it will not build, a VMS-specific
# shim belongs in [.src.platform.vms] and this rule changes to point at
# it.

[.build]wg_platform.obj : [.src.platform.posix]wg_platform_posix.c, -
                          [.src.platform]wg_platform.h
    $(CC)$(CFLAGS)/OBJECT=$@ $(MMS$SOURCE)

[.build]wg_client.obj : [.src.client]wg_client.c, [.src.client]wg_client.h
    $(CC)$(CFLAGS)/OBJECT=$@ $(MMS$SOURCE)

# ---- linker options --------------------------------------------------

$(OPT) :
    @ OPEN/WRITE OPTF $(OPT)
    @ WRITE OPTF "$(SSL_LIBRARY)/SHAREABLE"
    @ CLOSE OPTF

# ---- tools -----------------------------------------------------------

[.build]keys.obj : [.tools.keys]keys.c
    $(CC)$(CFLAGS)/OBJECT=$@ $(MMS$SOURCE)

[.build]vmsguard_key.exe : [.build]keys.obj, $(PROTO_OBJS), $(OPT)
    $(LINK)/EXECUTABLE=$@ [.build]keys.obj,$(PROTO_OBJS),$(OPT)/OPTIONS

[.build]interop.obj : [.tools.interop]interop.c
    $(CC)$(CFLAGS)/OBJECT=$@ $(MMS$SOURCE)

[.build]vmsguard_interop.exe : [.build]interop.obj, $(PROTO_OBJS), -
                               $(PLAT_OBJS), $(CLIENT_OBJS), $(OPT)
    $(LINK)/EXECUTABLE=$@ [.build]interop.obj,$(PROTO_OBJS),-
        $(PLAT_OBJS),$(CLIENT_OBJS),$(OPT)/OPTIONS

[.build]responder.obj : [.tools.interop]responder.c
    $(CC)$(CFLAGS)/OBJECT=$@ $(MMS$SOURCE)

[.build]vmsguard_responder.exe : [.build]responder.obj, $(PROTO_OBJS), -
                                 $(PLAT_OBJS), $(OPT)
    $(LINK)/EXECUTABLE=$@ [.build]responder.obj,$(PROTO_OBJS),-
        $(PLAT_OBJS),$(OPT)/OPTIONS

# ---- tests -----------------------------------------------------------

[.build]test_proto.obj : [.tests]test_proto.c
    $(CC)$(CFLAGS)/OBJECT=$@ $(MMS$SOURCE)

[.build]test_proto.exe : [.build]test_proto.obj, $(PROTO_OBJS), $(OPT)
    $(LINK)/EXECUTABLE=$@ [.build]test_proto.obj,$(PROTO_OBJS),$(OPT)/OPTIONS

TEST : [.build]test_proto.exe
    RUN [.build]test_proto.exe

# ---- housekeeping ----------------------------------------------------

CLEAN :
    @- IF F$SEARCH("[.build]*.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]*.obj;*
    @- IF F$SEARCH("[.build]*.exe") .NES. "" THEN DELETE/NOCONFIRM [.build]*.exe;*
    @- IF F$SEARCH("[.build]*.opt") .NES. "" THEN DELETE/NOCONFIRM [.build]*.opt;*
