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
$!---------------------------------------------------------------------
$!
$ gw := $'vg_exe'
$!
$! The interface name is quoted: DCL lowercases unquoted arguments to a
$! foreign command, and although the gateway folds case when matching
$! it against what pcap reports, quoting says what is meant.
$!
$ gw "--config" "''vg_config'" -
     "--interface" "''vg_iface'" -
     "--client" "''vg_client'" -
     "--exclude" "''vg_exclude'" -
     "--log" "''vg_log'" -
     "--stop-file" "''vg_stop'" -
     "--status" "300"
$!
$ EXIT $STATUS
