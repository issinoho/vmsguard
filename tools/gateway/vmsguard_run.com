$! vmsguard_run.com -- run the gateway, for a detached or batch process
$!
$! Not run by hand: vmsguard_start.com submits this. Everything an
$! operator needs to change is in the symbols below.
$!
$! The gateway is given --log rather than relying on the batch log,
$! because it flushes after every line it writes. A batch log is
$! buffered and would show nothing for minutes at a time, which is
$! exactly the wrong behaviour for a process you are checking on.
$!
$ SET NOON
$!
$!---------------------------------------------------------------------
$! Site settings -- edit these
$!---------------------------------------------------------------------
$!
$ vg_exe     = "DISK$TOOLS:[CODE.VMSGUARD.BUILD]VMSGUARD_GATEWAY.EXE"
$ vg_root    = "DISK$TOOLS:[CODE.VMSGUARD]"
$ vg_config  = "SYS$LOGIN:11.CONF"
$ vg_iface   = "IE0"
$ vg_client  = "192.168.0.218/32"
$ vg_exclude = "192.168.0.0/24"
$ vg_log     = vg_root + "VMSGUARD.LOG"
$ vg_stop    = vg_root + "VMSGUARD.STOP"
$!
$! IPv6 forwarding. Leave vg_encap_dst as "" to do without it.
$!
$! A decrypted IPv6 packet cannot be put on the LAN directly, so the
$! gateway wraps it in IPv4 addressed to this machine and lets the stack
$! unwrap and route it. That needs a configured tunnel to match against.
$! See docs/gateway.md.
$!
$! The unit is named rather than left to iptunnel, which numbers upward
$! and does not reuse freed units -- so an unnamed tunnel would come
$! back as a different interface each time and could not be brought up
$! by name afterwards.
$!
$ vg_encap_dst = ""
$ vg_encap_src = "192.168.0.80"
$ vg_encap_if  = "it7"
$!
$!---------------------------------------------------------------------
$!
$ gw := $'vg_exe'
$!
$! The interface name is quoted: DCL lowercases unquoted arguments to a
$! foreign command, and although the gateway folds case when matching
$! it against what pcap reports, quoting says what is meant.
$!
$! The tunnel does not survive a TCP/IP restart, so it is made here
$! rather than assumed to exist. Deleted first in case it does: creating
$! one that is already there fails, and the delete failing when it is
$! not there is expected and ignored.
$!
$! Written flat, with no block IF and no labels inside one: SET NOON is
$! in force above, so each step's status is simply looked at.
$!
$ encap = ""
$ IF vg_encap_dst .EQS. "" THEN GOTO no_ipv6
$!
$ iptunnel delete 'vg_encap_if'
$ iptunnel create -I 'vg_encap_if' 'vg_encap_dst' 'vg_encap_src'
$ tstat = $STATUS
$ IF (tstat .AND. 1) .NE. 1 THEN GOTO tunnel_failed
$!
$ ifconfig "''f$edit(vg_encap_if,"UPCASE")'" ipv6 up
$ IF ($STATUS .AND. 1) .NE. 1 THEN GOTO tunnel_failed
$!
$ encap = "--encap-local ''vg_encap_src' --encap-remote ''vg_encap_dst'"
$ WRITE SYS$OUTPUT "IPv6 forwarding via ''vg_encap_if', ''vg_encap_dst'"
$ GOTO no_ipv6
$!
$ tunnel_failed:
$ WRITE SYS$OUTPUT "could not set up the IPv6 tunnel; the gateway will"
$ WRITE SYS$OUTPUT "run without IPv6 forwarding and will say so"
$ encap = ""
$!
$ no_ipv6:
$!
$ gw "--config" "''vg_config'" -
     "--interface" "''vg_iface'" -
     "--client" "''vg_client'" -
     "--exclude" "''vg_exclude'" -
     "--log" "''vg_log'" -
     "--stop-file" "''vg_stop'" -
     "--status" "300" -
     'encap'
$!
$ EXIT $STATUS
