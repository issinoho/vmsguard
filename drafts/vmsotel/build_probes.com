$! build_probes.com -- build and run the vmsotel probes on OpenVMS
$!
$! Usage, from any directory:
$!
$!     @[.drafts.vmsotel]build_probes            build all six probes
$!     @[.drafts.vmsotel]build_probes RUN        build, then run them all
$!     @[.drafts.vmsotel]build_probes HEADERS    list the item codes the
$!                                               system headers declare
$!
$! Capture everything for pasting back with /OUTPUT:
$!
$!     @[.drafts.vmsotel]build_probes/OUTPUT=probes.log RUN
$!
$! A second parameter forces an OpenSSL family for probe_otlp_tls, as
$! in vmsguard's build_vms.com:  @build_probes RUN SSL111
$!
$! Unlike build_vms.com this does not stop at the first failure. The
$! probes are independent, and one that will not compile -- most
$! likely because a header lacks something -- should not keep the
$! other five from answering. Each step is checked and the summary at
$! the end names what failed.
$!
$! Every LINK is checked for warnings. An undefined symbol is only a
$! warning on VMS, and the image it produces builds cleanly and crashes
$! when it reaches the missing routine; such an image is deleted here
$! rather than left to be run.
$!
$ set noon
$ say := write sys$output
$ old_default = f$environment("DEFAULT")
$ here = f$parse(f$environment("PROCEDURE"),,,"DEVICE") + -
         f$parse(f$environment("PROCEDURE"),,,"DIRECTORY")
$ set default 'here'
$ if f$search("build.dir") .eqs. "" then create/directory [.build]
$!
$ say "vmsotel probes, ", f$getsyi("NODENAME"), ", OpenVMS ", -
      f$getsyi("VERSION"), " ", f$getsyi("ARCH_NAME")
$ say ""
$!
$ if p1 .eqs. "HEADERS" then goto headers
$!
$!---------------------------------------------------------------------
$! Compiler settings
$!---------------------------------------------------------------------
$!
$! /STANDARD=C99 for the same reason as vmsguard: it is VSI C's ceiling.
$! /PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES or socket, getaddrinfo and the
$! rest fail to link as bare uppercase names.
$! No /POINTER_SIZE for the system-service probes: their item lists
$! are only correct with 32-bit pointers, which is the default, and
$! each probe checks that at run time.
$!
$ cc_base = "/STANDARD=C99/PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES" + -
            "/INCLUDE_DIRECTORY=([.probes])"
$ built = ""
$ failed = ""
$!
$ say "building"
$ cc 'cc_base' /OBJECT=[.build]vmsprobe.obj [.probes]vmsprobe.c
$ sev = $severity
$ if sev .eq. 2 .or. sev .eq. 4
$ then
$     say "  vmsprobe.c did not compile; no system-service probe can link"
$     failed = " vmsprobe"
$     goto build_otlp
$ endif
$!
$ pflags = ""
$ plink = ",[.build]vmsprobe.obj"
$ pname = "probe_syi"
$ gosub build_one
$ pname = "probe_rmi"
$ gosub build_one
$ pname = "probe_jpi"
$ gosub build_one
$ pname = "probe_dvi"
$ gosub build_one
$!
$ build_otlp:
$! _SOCKADDR_LEN selects the BSD 4.4 socket structures (sockaddr_in6,
$! sockaddr_storage); getaddrinfo needs them.
$ pname = "probe_otlp"
$ psrc = "probe_otlp"
$ pflags = "/DEFINE=(_SOCKADDR_LEN)"
$ plink = ""
$ gosub build_one_src
$!
$!---------------------------------------------------------------------
$! OpenSSL for probe_otlp_tls
$!---------------------------------------------------------------------
$!
$! The image, the crypto image beside it and the headers must all come
$! from one family. The header version is chosen by the logical name
$! OPENSSL and nothing else -- the kits ship headers flat in [INCLUDE]
$! and VSI C turns <openssl/ssl.h> into openssl:ssl.h -- so it is
$! defined here to match the image found, and deassigned on the way out.
$!
$ ssl_candidates = "SYS$LIBRARY:SSL3$LIBSSL_SHR32,SYS$SHARE:SSL3$LIBSSL_SHR32," + -
                   "SYS$LIBRARY:SSL31$LIBSSL_SHR32,SYS$SHARE:SSL31$LIBSSL_SHR32," + -
                   "SYS$LIBRARY:SSL111$LIBSSL_SHR32,SYS$SHARE:SSL111$LIBSSL_SHR32," + -
                   "SYS$LIBRARY:SSL1$LIBSSL_SHR32,SYS$SHARE:SSL1$LIBSSL_SHR32"
$ if p2 .nes. "" then ssl_candidates = "SYS$LIBRARY:" + p2 + "$LIBSSL_SHR32," + -
                                       "SYS$SHARE:" + p2 + "$LIBSSL_SHR32"
$ ssl_lib = ""
$ i = 0
$ ssl_loop:
$   name = f$element(i, ",", ssl_candidates)
$   if name .eqs. "," then goto ssl_done
$   if f$search(name + ".EXE") .nes. ""
$   then
$       ssl_lib = name
$       goto ssl_done
$   endif
$   i = i + 1
$   goto ssl_loop
$ ssl_done:
$ if ssl_lib .eqs. ""
$ then
$     say "  no 32-bit libssl image found; skipping probe_otlp_tls. Installed:"
$     directory/size/date sys$library:*libssl*.exe,sys$share:*libssl*.exe
$     failed = failed + " probe_otlp_tls"
$     goto summary
$ endif
$ colon = f$locate(":", ssl_lib)
$ at_lib = f$locate("$LIBSSL", ssl_lib)
$ ssl_family = f$extract(colon + 1, at_lib - colon - 1, ssl_lib)
$ crypto_lib = f$extract(0, at_lib, ssl_lib) + "$LIBCRYPTO_SHR32"
$ ssl_include = ssl_family + "$INCLUDE"
$ if f$search(crypto_lib + ".EXE") .eqs. "" .or. f$trnlnm(ssl_include) .eqs. ""
$ then
$     say "  found ''ssl_lib' but not ''crypto_lib' or ''ssl_include';"
$     say "  skipping probe_otlp_tls rather than mixing OpenSSL versions"
$     show logical SSL*$INCLUDE
$     failed = failed + " probe_otlp_tls"
$     goto summary
$ endif
$ say "  OpenSSL: ''ssl_lib', ''crypto_lib', headers ''ssl_include'"
$ define/job/nolog OPENSSL 'ssl_include':
$ open/write opt [.build]ssl.opt
$ write opt ssl_lib + "/SHAREABLE"
$ write opt crypto_lib + "/SHAREABLE"
$ close opt
$!
$! The OpenSSL images named above are the 32-bit-pointer builds, so the
$! pointer size is stated, not left to the default.
$ pname = "probe_otlp_tls"
$ psrc = "probe_otlp"
$ pflags = "/POINTER_SIZE=32/DEFINE=(_SOCKADDR_LEN,WITH_TLS)"
$ plink = ",[.build]ssl.opt/OPTIONS"
$ gosub build_one_src
$ deassign/job OPENSSL
$!
$ summary:
$ say ""
$ say "built: ''built'"
$ if failed .nes. "" then say "FAILED:''failed'  -- paste the messages above"
$ if p1 .eqs. "RUN" then goto run
$ goto finish
$!
$!---------------------------------------------------------------------
$! Run
$!---------------------------------------------------------------------
$!
$ run:
$ say ""
$ say "privileges: ", f$getjpi("", "CURPRIV")
$ call run_one probe_syi
$ call run_one probe_rmi
$ call run_one probe_jpi
$!  For comparing JPI$_PPGCNT + GPGCNT with Ph.Mem, which is in pagelets.
$ show system
$ call run_one probe_dvi
$ show device d
$!  Defaults to the collector on the laptop, 192.168.0.218:4318.
$ call run_one probe_otlp
$ call run_one probe_otlp_tls "--tls" "--port" "4319"
$ goto finish
$!
$ run_one: subroutine
$   if f$search("[.build]''p1'.exe") .eqs. ""
$   then
$       write sys$output "=== ''p1': not built, skipped"
$       exit 1
$   endif
$   write sys$output ""
$   write sys$output "=== ''p1'"
$   cmd := $sys$disk:[.build]'p1'.exe
$   cmd 'p2' 'p3' 'p4'
$   write sys$output "=== ''p1' exit status ", $status
$   exit 1
$ endsubroutine
$!
$!---------------------------------------------------------------------
$! Header inventory
$!---------------------------------------------------------------------
$!
$! The probes ask about each item under #ifdef, so a name spelled
$! differently on this version shows as "not declared". This lists what
$! the headers really contain, so a second guess is not needed.
$!
$ headers:
$ lib = "SYS$LIBRARY:SYS$STARLET_C.TLB"
$ say "item codes declared in ''lib'"
$ call one_header SYIDEF "SYI$_" 'lib'
$ call one_header RMIDEF "RMI$_" 'lib'
$ call one_header JPIDEF "JPI$_" 'lib'
$ call one_header DVIDEF "DVI$_" 'lib'
$ goto finish
$!
$ one_header: subroutine
$   library/extract='p1'/output=[.build]'p1'.h 'p3'
$   if .not. $status then exit 1
$   write sys$output ""
$   write sys$output "--- ''p1'"
$   search [.build]'p1'.h "#define ''p2'"
$   exit 1
$ endsubroutine
$!
$!---------------------------------------------------------------------
$! Compile and link one probe, checking both
$!---------------------------------------------------------------------
$!
$ build_one:
$   psrc = pname
$ build_one_src:
$   cc 'cc_base' 'pflags' /OBJECT=[.build]'pname'.obj [.probes]'psrc'.c
$   sev = $severity
$   if sev .eq. 2 .or. sev .eq. 4 then goto build_one_fail
$   if sev .eq. 0 then say "  ''pname' compiled with warnings -- paste them"
$   link /EXECUTABLE=[.build]'pname'.exe [.build]'pname'.obj'plink'
$   if $severity .ne. 1 then goto build_one_fail
$   built = built + " " + pname
$   return
$ build_one_fail:
$   failed = failed + " " + pname
$   if f$search("[.build]''pname'.exe") .nes. "" then -
        delete/nolog [.build]'pname'.exe;*
$   return
$!
$ finish:
$ if f$trnlnm("OPENSSL", "LNM$JOB") .nes. "" then deassign/job OPENSSL
$ set default 'old_default'
$ exit 1
