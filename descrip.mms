! descrip.mms : MMS description file for vmsguard on OpenVMS x86-64
!
! Confirmed working on OpenVMS V9.2-3 x86-64, 2026-09-07. Getting there
! took three fixes, all of the same kind: a rule this file lacked, an
! object it did not link, and an include directory it did not name --
! each present in Makefile and build_vms.com, each missed here, and none
! visible on the Linux side because nothing there runs MMS.
!
! build_vms.com remains the path that builds everything: this file does
! not build the gateway, which needs pcap.
!
! Usage:
!     $ MMS                build everything
!     $ MMS TEST           build and run the protocol tests
!     $ MMS CLEAN          remove build products
!
! Target names are matched case sensitively: MMS receives the command
! line with its case intact, so "MMS clean" failed with %MMS-F-BADTARG
! against a CLEAN written in capitals. Lowercase aliases are defined at
! the foot of this file so either spelling works.
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

! Both names above say 3.x, and VMSGUARD_EXPECT_OPENSSL_3 in CFLAGS
! makes wg_crypto.c refuse to compile if the headers that logical
! actually resolves to are older. Change all three together, or not at
! all. build_vms.com derives the same define from the image it finds.

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

! [.src.tun] is in this list because interop and responder include
! ethip.h and icmp.h. It was missing until MMS was first run for real,
! while build_vms.com had carried it for months -- the same split that
! left ethip.obj without a rule. Keep the two include lists identical.

CFLAGS = /STANDARD=C99/DEFINE=(_SOCKADDR_LEN,VMSGUARD_EXPECT_OPENSSL_3)-
/POINTER_SIZE=32-
/PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES-
/INCLUDE_DIRECTORY=([.src.proto],[.src.platform],[.src.client],-
[.src.tun],$(SSL_INCLUDE))

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

! OPENSSL is what selects the OpenSSL headers, not $(SSL_INCLUDE) in
! the include list. The kits ship their headers flat in [INCLUDE] and
! VSI C turns <openssl/evp.h> into openssl:evp.h, so a system-wide
! OPENSSL pointing at another kit wins over any include directory named
! here. Defining it for the job pins it to the same kit the link names.
! /JOB and not /PROCESS because MMS runs each action in a subprocess,
! which inherits the job table and not the process one.
!
! It is left defined when MMS finishes, which build_vms.com does not do.
! MMS has no reliable hook that runs after a failed build, and a stale
! definition pointing at the kit this file already names is harmless.
! Deassign it by hand if you then build against a different one:
!     $ DEASSIGN/JOB OPENSSL

.FIRST
    @- IF F$SEARCH("BUILD.DIR;1") .EQS. "" THEN CREATE/DIRECTORY [.build]
    @ DEFINE/JOB/NOLOG OPENSSL $(SSL_INCLUDE):

ALL : [.build]vmsguard_key.exe, [.build]vmsguard_interop.exe, -
[.build]vmsguard_responder.exe, [.build]test_proto.exe, -
[.build]test_conf.exe, [.build]test_platform.exe
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

! icmp is linked into the same two tools, for --ping6: an ICMPv6
! checksum covers a pseudo-header of the addresses, so building one
! cannot live in the tool the way the IPv4 echo does.

[.build]icmp.obj : [.src.tun]icmp.c, [.src.tun]icmp.h
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

! Every link is followed by a severity test, because on VMS an
! undefined symbol is a *warning*: the linker writes an image, reports
! success, and the program dies when execution reaches the unresolved
! reference. build_vms.com learned this the hard way and stops on it;
! MMS would otherwise carry on and print "build complete" over a broken
! image. %X10000002 is a plain error status, which aborts the build.
!
! Verified both ways on 2026-09-11, since a check that has only ever
! been seen not to fire is not known to work. A deliberate link against
! an undefined symbol reported %ILINK-W-USEUNDEF, *wrote the image
! anyway*, and left $SEVERITY at 0 -- the condition these lines test. A
! full CLEAN and rebuild then ran all four links with none of them
! firing.

[.build]vmsguard_key.exe : [.build]keys.obj, $(PROTO_OBJS), $(OPT)
    $(LINK)/EXECUTABLE=$(MMS$TARGET) [.build]keys.obj,$(PROTO_OBJS),-
$(OPT)/OPTIONS
    @ IF $SEVERITY .NE. 1 THEN EXIT %X10000002

[.build]interop.obj : [.tools.interop]interop.c
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]vmsguard_interop.exe : [.build]interop.obj, $(PROTO_OBJS), -
$(PLAT_OBJS), $(CLIENT_OBJS), [.build]ethip.obj, -
[.build]icmp.obj, $(OPT)
    $(LINK)/EXECUTABLE=$(MMS$TARGET) [.build]interop.obj,$(PROTO_OBJS),-
$(PLAT_OBJS),$(CLIENT_OBJS),[.build]ethip.obj,-
[.build]icmp.obj,$(OPT)/OPTIONS
    @ IF $SEVERITY .NE. 1 THEN EXIT %X10000002

[.build]responder.obj : [.tools.interop]responder.c
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]vmsguard_responder.exe : [.build]responder.obj, $(PROTO_OBJS), -
$(PLAT_OBJS), [.build]ethip.obj, [.build]icmp.obj, $(OPT)
    $(LINK)/EXECUTABLE=$(MMS$TARGET) [.build]responder.obj,-
$(PROTO_OBJS),$(PLAT_OBJS),[.build]ethip.obj,-
[.build]icmp.obj,$(OPT)/OPTIONS
    @ IF $SEVERITY .NE. 1 THEN EXIT %X10000002

! ==== tests ====

[.build]test_proto.obj : [.tests]test_proto.c
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]test_proto.exe : [.build]test_proto.obj, $(PROTO_OBJS), $(OPT)
    $(LINK)/EXECUTABLE=$(MMS$TARGET) [.build]test_proto.obj,-
$(PROTO_OBJS),$(OPT)/OPTIONS
    @ IF $SEVERITY .NE. 1 THEN EXIT %X10000002

! test_conf and test_platform run under make and under build_vms.com;
! this file was the one that built neither, so a config-parsing or
! endpoint-comparison regression could reach a VMS system that builds
! with MMS and nothing would say so. They need no additions to the
! object lists: test_conf is proto, test_platform is the platform layer
! on its own.

[.build]test_conf.obj : [.tests]test_conf.c
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]test_conf.exe : [.build]test_conf.obj, $(PROTO_OBJS), $(OPT)
    $(LINK)/EXECUTABLE=$(MMS$TARGET) [.build]test_conf.obj,-
$(PROTO_OBJS),$(OPT)/OPTIONS
    @ IF $SEVERITY .NE. 1 THEN EXIT %X10000002

[.build]test_platform.obj : [.tests]test_platform.c
    $(CC)$(CFLAGS)/OBJECT=$(MMS$TARGET) $(MMS$SOURCE)

[.build]test_platform.exe : [.build]test_platform.obj, $(PLAT_OBJS)
    $(LINK)/EXECUTABLE=$(MMS$TARGET) [.build]test_platform.obj,$(PLAT_OBJS)
    @ IF $SEVERITY .NE. 1 THEN EXIT %X10000002

TEST : [.build]test_proto.exe, [.build]test_conf.exe, -
[.build]test_platform.exe
    RUN [.build]test_proto.exe
    RUN [.build]test_conf.exe
    RUN [.build]test_platform.exe

! ==== housekeeping ====

! CLEAN deletes every image in [.build], including the PROBE_*.EXE that
! only build_vms.com builds -- MMS has no rules for them and will not
! put them back. Save them first, or rebuild with @build_vms afterwards.

CLEAN :
    @- IF F$SEARCH("[.build]*.obj") .NES. "" THEN DELETE/NOCONFIRM [.build]*.obj;*
    @- IF F$SEARCH("[.build]*.exe") .NES. "" THEN DELETE/NOCONFIRM [.build]*.exe;*
    @- IF F$SEARCH("[.build]*.opt") .NES. "" THEN DELETE/NOCONFIRM [.build]*.opt;*

! Lowercase aliases. MMS matches target names case sensitively, and
! typing them in lowercase is the natural thing to do.

all : ALL

test : TEST

clean : CLEAN
