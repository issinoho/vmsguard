$! build_vms.com — build vmsguard on OpenVMS x86-64
$!
$! UNTESTED. Written from the VSI TCP/IP Services Sockets API manual and
$! the toolchain inventory in docs/research/, but not yet run on a real
$! system. Expect to adjust the OpenSSL logical names below; everything
$! else should be close.
$!
$! Usage:
$!     @build_vms            build everything
$!     @build_vms CLEAN      delete objects and executables
$!     @build_vms TEST       build, then run the protocol tests
$!
$! Why DCL as well as descrip.mms: this procedure uses nothing but CC
$! and LINK, so it has far fewer ways to go wrong than an MMS
$! description file whose syntax has not been verified. Try this first.
$!
$ on error then goto fail
$ say := write sys$output
$!
$!---------------------------------------------------------------------
$! Configuration — check these first
$!---------------------------------------------------------------------
$!
$! SSL3 is OpenSSL 3.0.x (the LTS branch); SSL31 is 3.1.x.
$!
$ ssl_include = "SSL3$INCLUDE"
$!
$! The crypto shareable image is located rather than assumed. Naming it
$! bare as "SSL3$LIBCRYPTO_SHR" makes the linker look in the current
$! directory when no such logical name is defined, which fails with
$! %ILINK-F-OPENIN. An explicit SYS$SHARE: path avoids that, and the
$! exact file name varies with pointer size, so try each in turn.
$!
$! Confirmed present on the test system as
$! SYS$COMMON:[SYSLIB]SSL3$LIBCRYPTO_SHR.EXE, reached via SYS$LIBRARY:.
$! SYS$SHARE: is checked too since both normally point there, and the
$! _SHR32 variants cover a different pointer size.
$!
$ ssl_library = ""
$ ssl_candidates = "SYS$LIBRARY:SSL3$LIBCRYPTO_SHR," + -
                   "SYS$SHARE:SSL3$LIBCRYPTO_SHR," + -
                   "SYS$LIBRARY:SSL3$LIBCRYPTO_SHR32," + -
                   "SYS$SHARE:SSL3$LIBCRYPTO_SHR32," + -
                   "SYS$LIBRARY:SSL31$LIBCRYPTO_SHR," + -
                   "SYS$LIBRARY:SSL31$LIBCRYPTO_SHR32"
$ i = 0
$ ssl_loop:
$   name = f$element(i, ",", ssl_candidates)
$   if name .eqs. "," then goto ssl_done
$   if f$search(name + ".EXE") .nes. ""
$   then
$       ssl_library = name
$       goto ssl_done
$   endif
$   i = i + 1
$   goto ssl_loop
$ ssl_done:
$!
$ if ssl_library .eqs. ""
$ then
$     say "ERROR: could not find the OpenSSL crypto shareable image."
$     say "Tried each of:"
$     say "  ''ssl_candidates'"
$     say ""
$     say "Find the real name with:"
$     say "  $ directory sys$library:*LIBCRYPTO*"
$     say "then set ssl_library in this procedure to its full path,"
$     say "without the .EXE suffix."
$     exit 2
$ endif
$ say "using OpenSSL image: ''ssl_library'"
$!
$! _SOCKADDR_LEN selects the BSD 4.4 socket structures, which is what
$! provides sockaddr_in6 and sockaddr_storage. Section 1.4.1 of the
$! Sockets API manual. Without it the platform layer will not compile.
$!
$ cc_defines = "/DEFINE=(_SOCKADDR_LEN)"
$!
$! VSI C V7.7 is GEM-based, not Clang, so C99 is the ceiling. If
$! /STANDARD=C99 rejects something, try /STANDARD=RELAXED.
$!
$ cc_standard = "/STANDARD=C99"
$!
$! Built by concatenation rather than a continued line: a "-" inside a
$! quoted string would fold the next line's leading spaces into the
$! string and corrupt the include list.
$ cc_includes = "/INCLUDE_DIRECTORY=([.src.proto],[.src.platform]," + -
                "[.src.client]," + ssl_include + ")"
$!
$ cc_flags = cc_standard + cc_defines + cc_includes
$!
$!---------------------------------------------------------------------
$! Housekeeping
$!---------------------------------------------------------------------
$!
$ if p1 .eqs. "CLEAN"
$ then
$     say "cleaning"
$     if f$search("[.build]*.obj") .nes. "" then delete/noconfirm [.build]*.obj;*
$     if f$search("[.build]*.exe") .nes. "" then delete/noconfirm [.build]*.exe;*
$     if f$search("[.build]*.opt") .nes. "" then delete/noconfirm [.build]*.opt;*
$     say "done"
$     exit 1
$ endif
$!
$! A subdirectory [.build] appears as BUILD.DIR in the current
$! directory, which is what to test for.
$ if f$search("BUILD.DIR;1") .eqs. "" then create/directory [.build]
$!
$!---------------------------------------------------------------------
$! Compile
$!---------------------------------------------------------------------
$!
$ say "compiling protocol core"
$ cc 'cc_flags'/OBJECT=[.build]blake2s.obj    [.src.proto]blake2s.c
$ cc 'cc_flags'/OBJECT=[.build]wg_crypto.obj  [.src.proto]wg_crypto.c
$ cc 'cc_flags'/OBJECT=[.build]wg_proto.obj   [.src.proto]wg_proto.c
$ cc 'cc_flags'/OBJECT=[.build]wg_noise.obj   [.src.proto]wg_noise.c
$ cc 'cc_flags'/OBJECT=[.build]wg_key.obj     [.src.proto]wg_key.c
$!
$ say "compiling platform layer"
$! The POSIX implementation is tried first on purpose: VSI TCP/IP
$! Services provides BSD sockets, poll() and getaddrinfo(), all
$! confirmed present in the C RTL header inventory. If it will not
$! build, a VMS-specific shim belongs in [.src.platform.vms].
$ cc 'cc_flags'/OBJECT=[.build]wg_platform.obj -
     [.src.platform.posix]wg_platform_posix.c
$!
$ say "compiling client"
$ cc 'cc_flags'/OBJECT=[.build]wg_client.obj  [.src.client]wg_client.c
$!
$!---------------------------------------------------------------------
$! Linker options file for the OpenSSL shareable image
$!---------------------------------------------------------------------
$!
$ say "writing linker options"
$ open/write opt [.build]vmsguard.opt
$ write opt "''ssl_library'/SHAREABLE"
$ close opt
$!
$! Note: no socket library is named here. Per section 1.4 of the Sockets
$! API manual, linking a sockets program needs nothing beyond LINK — the
$! run-time library TCPIP$IPC_SHR is picked up automatically.
$!
$ proto_objs = "[.build]blake2s.obj,[.build]wg_crypto.obj," + -
               "[.build]wg_proto.obj,[.build]wg_noise.obj," + -
               "[.build]wg_key.obj"
$ plat_objs  = "[.build]wg_platform.obj"
$ client_objs = "[.build]wg_client.obj"
$!
$!---------------------------------------------------------------------
$! Build the tools
$!---------------------------------------------------------------------
$!
$! Executable names use underscores rather than the hyphens the POSIX
$! build uses, since hyphens are awkward to type in DCL.
$!
$ say "building vmsguard_key"
$ cc 'cc_flags'/OBJECT=[.build]keys.obj [.tools.keys]keys.c
$ link/executable=[.build]vmsguard_key.exe -
      [.build]keys.obj,'proto_objs',[.build]vmsguard.opt/OPTIONS
$!
$ say "building vmsguard_interop"
$ cc 'cc_flags'/OBJECT=[.build]interop.obj [.tools.interop]interop.c
$ link/executable=[.build]vmsguard_interop.exe -
      [.build]interop.obj,'proto_objs','plat_objs','client_objs',-
      [.build]vmsguard.opt/OPTIONS
$!
$ say "building vmsguard_responder"
$ cc 'cc_flags'/OBJECT=[.build]responder.obj [.tools.interop]responder.c
$ link/executable=[.build]vmsguard_responder.exe -
      [.build]responder.obj,'proto_objs','plat_objs',-
      [.build]vmsguard.opt/OPTIONS
$!
$ say "building test_proto"
$ cc 'cc_flags'/OBJECT=[.build]test_proto.obj [.tests]test_proto.c
$ link/executable=[.build]test_proto.exe -
      [.build]test_proto.obj,'proto_objs',[.build]vmsguard.opt/OPTIONS
$!
$ say ""
$ say "build complete, executables in [.build]"
$ say ""
$ say "  $ run [.build]test_proto          protocol self-tests"
$ say "  $ vg_key := $sys$disk:[.build]vmsguard_key.exe"
$ say "  $ vg_key genkey                   generate a private key"
$ say ""
$!
$ if p1 .eqs. "TEST"
$ then
$     say "running protocol tests"
$     say ""
$     run [.build]test_proto
$ endif
$!
$ exit 1
$!
$ fail:
$ say "BUILD FAILED"
$ exit 2
