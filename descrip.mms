! descrip.mms : MMS description file for vmsguard on OpenVMS x86-64
!
! Syntax verified against the VSI DECset Guide to the Module Management
! System, but not yet run on a real system. build_vms.com remains the
! lower-risk option since it uses only CC and LINK.
!
! Usage:
!     $ MMS                build everything
!     $ MMS TEST           build and run the protocol tests
!     $ MMS CLEAN          remove build products
!
! Note on comments: MMS uses "!", and a hyphen as the last character of
! any line, comment included, is treated as a continuation character.
! That is why no divider or comment here ends in a dash.
!
! Configuration is below. The crypto image must be named with an
! explicit path: given a bare name the linker looks in the current
! directory and fails with %ILINK-F-OPENIN. Confirm yours with:
!     $ DIRECTORY SYS$LIBRARY:*LIBCRYPTO*
!
! build_vms.com locates it automatically; MMS cannot, so it is fixed
! here to the path confirmed on the test system.

SSL_INCLUDE = SSL3$INCLUDE
SSL_LIBRARY = SYS$LIBRARY:SSL3$LIBCRYPTO_SHR32

! _SOCKADDR_LEN selects the BSD 4.4 socket structures, which is where
! sockaddr_in6 and sockaddr_storage come from (Sockets API manual,
! section 1.4.1). The platform layer will not compile without it.
!
! PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES is required too. Without it only
! ANSI names get the DECC$ prefix the C RTL actually exports, so every
! POSIX and BSD entry point (socket, close, fcntl, poll, getaddrinfo)
! is left as a bare uppercase symbol and fails to resolve at link time.
!
! POINTER_SIZE must match the OpenSSL image named above: SHR32 is built
! for 32-bit pointers, SHR for 64-bit. Mixing them links cleanly and
! then crashes inside OpenSSL with an access violation at a
! sign-extended address such as FFFFFFFF806F8C30.
!
! VSI C V7.7 is GEM-based rather than Clang, so C99 is the ceiling. If
! /STANDARD=C99 rejects something, try /STANDARD=RELAXED.

CFLAGS = /STANDARD=C99/DEFINE=(_SOCKADDR_LEN)/POINTER_SIZE=32-
/PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES-
/INCLUDE_DIRECTORY=([.src.proto],[.src.platform],[.src.client],$(SSL_INCLUDE))

! No socket library is named on the link line: per section 1.4 of the
! Sockets API manual, linking a sockets program needs nothing beyond
! LINK, because TCPIP$IPC_SHR is picked up automatically. Only OpenSSL
! needs an options file.

OPT = [.build]vmsguard.opt

PROTO_OBJS = [.build]blake2s.obj,[.build]wg_crypto.obj,-
[.build]wg_proto.obj,[.build]wg_noise.obj,[.build]wg_key.obj,-
[.build]wg_conf.obj

PLAT_OBJS = [.build]wg_platform.obj
CLIENT_OBJS = [.build]wg_client.obj

! Everything is written into [.build], which must exist before the first
! compile. .FIRST runs ahead of the actions that update the target.

.FIRST
    @- IF F$SEARCH("BUILD.DIR;1") .EQS. "" THEN CREATE/DIRECTORY [.build]

ALL : [.build]vmsguard_key.exe, [.build]vmsguard_interop.exe, -
[.build]vmsguard_responder.exe, [.build]test_proto.exe
    @ WRITE SYS$OUTPUT "build complete, executables in [.build]"

! ==== protocol core ====

[.build]blake2s.obj : [.src.proto]blake2s.c, [.src.proto]blake2s.h
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]wg_crypto.obj : [.src.proto]wg_crypto.c, [.src.proto]wg_crypto.h
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]wg_proto.obj : [.src.proto]wg_proto.c, [.src.proto]wg_proto.h
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]wg_noise.obj : [.src.proto]wg_noise.c, [.src.proto]wg_noise.h
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]wg_key.obj : [.src.proto]wg_key.c, [.src.proto]wg_key.h
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]wg_conf.obj : [.src.proto]wg_conf.c, [.src.proto]wg_conf.h
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]encap.obj : [.src.tun]encap.c, [.src.tun]encap.h
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

! ethip is linked into interop and responder, which parse the IPv4
! headers they ping with. The rule was missed when those tools gained
! the dependency, so MMS had a target it did not know how to build
! while build_vms.com carried on working -- the exact split the
! three-build-files rule exists to catch.

[.build]ethip.obj : [.src.tun]ethip.c, [.src.tun]ethip.h
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

! ==== platform and client ====
!
! The POSIX implementation is used on purpose: VSI TCP/IP Services
! provides BSD sockets, poll() and getaddrinfo(), all confirmed present
! in the C RTL header inventory. If it will not build, a VMS-specific
! shim belongs in [.src.platform.vms] and this rule points at it
! instead.

[.build]wg_platform.obj : [.src.platform.posix]wg_platform_posix.c, -
[.src.platform]wg_platform.h
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]wg_client.obj : [.src.client]wg_client.c, [.src.client]wg_client.h
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

! ==== linker options file ====

$(OPT) :
    @ OPEN/WRITE OPTF $(OPT)
    @ WRITE OPTF "$(SSL_LIBRARY)/SHAREABLE"
    @ CLOSE OPTF

! ==== tools ====

[.build]keys.obj : [.tools.keys]keys.c
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]vmsguard_key.exe : [.build]keys.obj, $(PROTO_OBJS), $(OPT)
    $(LINK)/EXECUTABLE=$(MMS$TARGET) [.build]keys.obj,$(PROTO_OBJS),-
$(OPT)/OPTIONS

[.build]interop.obj : [.tools.interop]interop.c
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]vmsguard_interop.exe : [.build]interop.obj, $(PROTO_OBJS), -
$(PLAT_OBJS), $(CLIENT_OBJS), [.build]ethip.obj, $(OPT)
    $(LINK)/EXECUTABLE=$(MMS$TARGET) [.build]interop.obj,$(PROTO_OBJS),-
$(PLAT_OBJS),$(CLIENT_OBJS),[.build]ethip.obj,$(OPT)/OPTIONS

[.build]responder.obj : [.tools.interop]responder.c
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]vmsguard_responder.exe : [.build]responder.obj, $(PROTO_OBJS), -
$(PLAT_OBJS), [.build]ethip.obj, $(OPT)
    $(LINK)/EXECUTABLE=$(MMS$TARGET) [.build]responder.obj,-
$(PROTO_OBJS),$(PLAT_OBJS),[.build]ethip.obj,$(OPT)/OPTIONS

! ==== tests ====

[.build]test_proto.obj : [.tests]test_proto.c
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]test_proto.exe : [.build]test_proto.obj, $(PROTO_OBJS), $(OPT)
    $(LINK)/EXECUTABLE=$(MMS$TARGET) [.build]test_proto.obj,-
$(PROTO_OBJS),$(OPT)/OPTIONS

TEST : [.build]test_proto.exe
    RUN [.build]test_proto.exe

! ==== housekeeping ====

CLEAN :
    @- IF F$SEARCH("[.build]*.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]*.obj;*
    @- IF F$SEARCH("[.build]*.exe") .NES. "" THEN DELETE/NOCONFIRM [.build]*.exe;*
    @- IF F$SEARCH("[.build]*.opt") .NES. "" THEN DELETE/NOCONFIRM [.build]*.opt;*
