$! build_vms.com — build vmsguard on OpenVMS x86-64
$!
$! Verified on OpenVMS V9.2-3 x86-64 with VSI C V7.7-003 and OpenSSL
$! 3.0.21. The one setting most likely to need changing on another
$! system is pointer_size, below.
$!
$! Usage:
$!     @build_vms            build everything
$!     @build_vms CLEAN      delete objects and executables
$!     @build_vms TEST       build, then run the self-tests
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
$! Pointer size. VSI C defaults to 32-bit pointers, and the OpenSSL
$! shareable images come in matching flavours: SSL3$LIBCRYPTO_SHR32 is
$! built for 32-bit pointers, SSL3$LIBCRYPTO_SHR for 64-bit. The two
$! must agree.
$!
$! Mixing them produces an access violation inside the OpenSSL image at
$! an address like FFFFFFFF806F8C30 — a 32-bit pointer sign-extended to
$! 64 bits. If you see that, this setting and the image below disagree.
$!
$! If the image for your chosen size is not installed, change this to
$! the other value rather than linking the mismatched one.
$!
$ pointer_size = "32"
$!
$ if pointer_size .eqs. "32"
$ then
$     ssl_candidates = "SYS$LIBRARY:SSL3$LIBCRYPTO_SHR32," + -
                       "SYS$SHARE:SSL3$LIBCRYPTO_SHR32," + -
                       "SYS$LIBRARY:SSL31$LIBCRYPTO_SHR32"
$ else
$     ssl_candidates = "SYS$LIBRARY:SSL3$LIBCRYPTO_SHR," + -
                       "SYS$SHARE:SSL3$LIBCRYPTO_SHR," + -
                       "SYS$LIBRARY:SSL31$LIBCRYPTO_SHR"
$ endif
$!
$ ssl_library = ""
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
$     say "ERROR: no OpenSSL crypto image for ''pointer_size'-bit pointers."
$     say "Tried each of:"
$     say "  ''ssl_candidates'"
$     say ""
$     say "See what is installed with:"
$     say "  $ directory sys$library:*LIBCRYPTO*"
$     say ""
$     say "then set pointer_size in this procedure to match what you"
$     say "have. Do not link an image of the other pointer size: it"
$     say "builds cleanly and then crashes inside OpenSSL."
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
$! Without this, only ANSI-standard names get the DECC$ prefix that the
$! C RTL actually exports, so every POSIX and BSD entry point — socket,
$! close, fcntl, poll, getaddrinfo — fails to resolve at link time as a
$! bare uppercase symbol. ANSI-only programs link fine, which is why the
$! test program built while the platform layer did not.
$!
$ cc_prefix = "/PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES"
$!
$! Must match the OpenSSL image selected above.
$!
$ cc_pointer = "/POINTER_SIZE=" + pointer_size
$!
$! Built by concatenation rather than a continued line: a "-" inside a
$! quoted string would fold the next line's leading spaces into the
$! string and corrupt the include list.
$ cc_includes = "/INCLUDE_DIRECTORY=([.src.proto],[.src.platform]," + -
                "[.src.client],[.src.tun]," + ssl_include + ")"
$!
$ cc_flags = cc_standard + cc_defines + cc_prefix + cc_pointer + cc_includes
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
$ cc 'cc_flags'/OBJECT=[.build]wg_conf.obj    [.src.proto]wg_conf.c
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
$! Packet plumbing. Compiled here, before anything links it: these used
$! to be built alongside slip_spike, further down, and the tools linked
$! above them silently picked up undefined symbols.
$!
$ say "compiling packet plumbing"
$ cc 'cc_flags'/OBJECT=[.build]slip.obj [.src.tun]slip.c
$ cc 'cc_flags'/OBJECT=[.build]hdlc.obj [.src.tun]hdlc.c
$ cc 'cc_flags'/OBJECT=[.build]ethip.obj [.src.tun]ethip.c
$ cc 'cc_flags'/OBJECT=[.build]rawinject.obj [.src.tun]rawinject.c
$ cc 'cc_flags'/OBJECT=[.build]nat.obj [.src.tun]nat.c
$ cc 'cc_flags'/OBJECT=[.build]icmp.obj [.src.tun]icmp.c
$ cc 'cc_flags'/OBJECT=[.build]encap.obj [.src.tun]encap.c
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
               "[.build]wg_key.obj,[.build]wg_conf.obj"
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
$ if $severity .ne. 1 then goto linkfail
$!
$ say "building vmsguard_interop"
$ cc 'cc_flags'/OBJECT=[.build]interop.obj [.tools.interop]interop.c
$ link/executable=[.build]vmsguard_interop.exe -
      [.build]interop.obj,'proto_objs','plat_objs','client_objs',-
      [.build]ethip.obj,[.build]icmp.obj,[.build]vmsguard.opt/OPTIONS
$ if $severity .ne. 1 then goto linkfail
$!
$ say "building vmsguard_responder"
$ cc 'cc_flags'/OBJECT=[.build]responder.obj [.tools.interop]responder.c
$ link/executable=[.build]vmsguard_responder.exe -
      [.build]responder.obj,'proto_objs','plat_objs',-
      [.build]ethip.obj,[.build]icmp.obj,[.build]vmsguard.opt/OPTIONS
$ if $severity .ne. 1 then goto linkfail
$!
$ say "building slip_spike"
$ cc 'cc_flags'/OBJECT=[.build]slip_spike.obj [.tools.spike]slip_spike.c
$ link/executable=[.build]slip_spike.exe -
      [.build]slip_spike.obj,[.build]slip.obj,[.build]hdlc.obj
$ if $severity .ne. 1 then goto linkfail
$!
$ say "building test_slip"
$ cc 'cc_flags'/OBJECT=[.build]test_slip.obj [.tests]test_slip.c
$ link/executable=[.build]test_slip.exe -
      [.build]test_slip.obj,[.build]slip.obj
$ if $severity .ne. 1 then goto linkfail
$!
$ say "building test_icmp"
$ cc 'cc_flags'/OBJECT=[.build]test_icmp.obj [.tests]test_icmp.c
$ link/executable=[.build]test_icmp.exe -
      [.build]test_icmp.obj,[.build]icmp.obj,[.build]ethip.obj
$ if $severity .ne. 1 then goto linkfail
$!
$ say "building test_nat"
$ cc 'cc_flags'/OBJECT=[.build]test_nat.obj [.tests]test_nat.c
$ link/executable=[.build]test_nat.exe -
      [.build]test_nat.obj,[.build]nat.obj,[.build]ethip.obj
$ if $severity .ne. 1 then goto linkfail
$!
$ say "building test_encap"
$ cc 'cc_flags'/OBJECT=[.build]test_encap.obj [.tests]test_encap.c
$ link/executable=[.build]test_encap.exe -
      [.build]test_encap.obj,[.build]encap.obj
$ if $severity .ne. 1 then goto linkfail
$!
$ say "building test_ethip"
$ cc 'cc_flags'/OBJECT=[.build]test_ethip.obj [.tests]test_ethip.c
$ link/executable=[.build]test_ethip.exe -
      [.build]test_ethip.obj,[.build]ethip.obj
$ if $severity .ne. 1 then goto linkfail
$!
$ say "building test_hdlc"
$ cc 'cc_flags'/OBJECT=[.build]test_hdlc.obj [.tests]test_hdlc.c
$ link/executable=[.build]test_hdlc.exe -
      [.build]test_hdlc.obj,[.build]hdlc.obj
$ if $severity .ne. 1 then goto linkfail
$!
$! ---- probes -------------------------------------------------------
$!
$! These verify the mechanisms the gateway design depends on, rather
$! than assuming them. probe_pcap needs the pcap shareable image; the
$! others need only what is already linked.
$!
$ say "building probes"
$ cc 'cc_flags'/OBJECT=[.build]probe_openssl.obj [.tools.probes]probe_openssl.c
$ link/executable=[.build]probe_openssl.exe -
      [.build]probe_openssl.obj,[.build]vmsguard.opt/OPTIONS
$ if $severity .ne. 1 then goto linkfail
$!
$ cc 'cc_flags'/OBJECT=[.build]probe_sockets.obj [.tools.probes]probe_sockets.c
$ link/executable=[.build]probe_sockets.exe [.build]probe_sockets.obj
$ if $severity .ne. 1 then goto linkfail
$!
$ cc 'cc_flags'/OBJECT=[.build]probe_inject.obj [.tools.probes]probe_inject.c
$ link/executable=[.build]probe_inject.exe -
      [.build]probe_inject.obj,[.build]ethip.obj,[.build]rawinject.obj
$ if $severity .ne. 1 then goto linkfail
$ cc 'cc_flags'/OBJECT=[.build]probe_inject6.obj [.tools.probes]probe_inject6.c
$ link/executable=[.build]probe_inject6.exe -
      [.build]probe_inject6.obj
$ if $severity .ne. 1 then goto linkfail
$ cc 'cc_flags'/OBJECT=[.build]probe_encap.obj [.tools.probes]probe_encap.c
$ link/executable=[.build]probe_encap.exe -
      [.build]probe_encap.obj,[.build]ethip.obj,[.build]rawinject.obj
$ if $severity .ne. 1 then goto linkfail
$!
$ pcap_image = ""
$ if f$search("SYS$LIBRARY:TCPIP$LIBPCAP_SHR.EXE") .nes. "" then -
     pcap_image = "SYS$LIBRARY:TCPIP$LIBPCAP_SHR"
$ if pcap_image .eqs. ""
$ then
$     say "  (no TCPIP$LIBPCAP_SHR found; skipping probe_pcap)"
$ else
$     open/write popt [.build]pcap.opt
$     write popt "''pcap_image'/SHAREABLE"
$     close popt
$     cc 'cc_flags'/OBJECT=[.build]probe_pcap.obj [.tools.probes]probe_pcap.c
$     link/executable=[.build]probe_pcap.exe -
          [.build]probe_pcap.obj,[.build]pcap.opt/OPTIONS
$!
$     say "building vmsguard_gateway"
$     cc 'cc_flags'/OBJECT=[.build]gateway.obj [.tools.gateway]gateway.c
$     link/executable=[.build]vmsguard_gateway.exe -
          [.build]gateway.obj,'proto_objs','plat_objs','client_objs',-
          [.build]ethip.obj,[.build]rawinject.obj,[.build]nat.obj,-
          [.build]icmp.obj,[.build]encap.obj,-
          [.build]vmsguard.opt/OPTIONS,[.build]pcap.opt/OPTIONS
$ endif
$!
$ say "building test_proto"
$ cc 'cc_flags'/OBJECT=[.build]test_proto.obj [.tests]test_proto.c
$ link/executable=[.build]test_proto.exe -
      [.build]test_proto.obj,'proto_objs',[.build]vmsguard.opt/OPTIONS
$ if $severity .ne. 1 then goto linkfail
$!
$ say ""
$ say "build complete, executables in [.build]"
$ say ""
$ say "  $ run [.build]test_proto          protocol self-tests"
$ say "  $ run [.build]test_slip           SLIP framing self-tests"
$ say "  $ gw := $sys$disk:[.build]vmsguard_gateway.exe"
$ say "  $ gw --help                       WireGuard gateway"
$ say ""
$ say "  $ run [.build]probe_openssl      OpenSSL primitives"
$ say "  $ run [.build]probe_sockets       sockets, poll, SOCK_RAW"
$ say "  $ run [.build]probe_pcap          libpcap capture and injection"
$ say "  $ pinj := $sys$disk:[.build]probe_inject.exe"
$ say "  $ pinj --src <ip> --dst <ip>      raw-socket injection"
$ say "  $ pinj6 := $sys$disk:[.build]probe_inject6.exe"
$ say "  $ pinj6 --src <ipv6> --dst <ipv6>  IPv6 injection: can we forge a source?"
$ say "  $ penc := $sys$disk:[.build]probe_encap.exe"
$ say "  $ penc --tunnel-remote .. --tunnel-local .. --inner-src .."
$ say ""
$ say "  $ spike := $sys$disk:[.build]slip_spike.exe"
$ say "  $ spike --raw                     SLIP/PPP over-pty spike"
$ say ""
$ say "  (RUN cannot pass arguments; define a foreign command as above)"
$ say "  $ vg_key := $sys$disk:[.build]vmsguard_key.exe"
$ say "  $ vg_key genkey                   generate a private key"
$ say ""
$!
$ if p1 .eqs. "TEST"
$ then
$     say "running protocol tests"
$     say ""
$     run [.build]test_proto
$     say ""
$     say "running SLIP framing tests"
$     say ""
$     run [.build]test_slip
$     say ""
$     run [.build]test_hdlc
$     say ""
$     run [.build]test_ethip
$     say ""
$     run [.build]test_encap
$     say ""
$     run [.build]test_nat
$     say ""
$     run [.build]test_icmp
$ endif
$!
$ exit 1
$!
$ linkfail:
$ say ""
$ say "BUILD FAILED: the link above reported undefined symbols."
$ say ""
$ say "On OpenVMS an undefined symbol is a link *warning*, not an error:"
$ say "the image is written anyway and crashes when execution reaches"
$ say "the unresolved reference. Which is why this procedure checks."
$ exit 2
$!
$ fail:
$ say "BUILD FAILED"
$ exit 2
