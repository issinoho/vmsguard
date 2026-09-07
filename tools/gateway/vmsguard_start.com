$! vmsguard_start.com -- start the gateway so it outlives the terminal
$!
$! Submitted as a batch job rather than RUN/DETACHED. Both work, but a
$! batch job inherits the submitting account's privileges, which is
$! what packet capture and the raw socket need -- RUN/DETACHED would
$! require naming every privilege on the command line and getting the
$! quota list right as well.
$!
$! The job runs until vmsguard_stop.com asks it to finish, or until the
$! queue is stopped. It does not restart itself: a gateway that comes
$! back silently after failing is worse than one that stays down, since
$! the log is the only thing that will ever tell you it happened.
$!
$ SET NOON
$ vg_root = "DISK$TOOLS:[CODE.VMSGUARD]"
$!
$ IF F$SEARCH(vg_root + "VMSGUARD.STOP") .NES. "" THEN -
      DELETE/NOLOG 'vg_root'VMSGUARD.STOP;*
$!
$! No /NOTIFY: this runs for days and the submitter will not be logged
$! in to receive it. Check the queue's CPU time limit before relying on
$! this -- SHOW QUEUE/FULL -- because a limit there will stop the gateway
$! at some arbitrary hour with nothing in its own log to explain it.
$!
$ SUBMIT 'vg_root'VMSGUARD_RUN.COM -
        /NOPRINTER -
        /LOG_FILE='vg_root'VMSGUARD_BATCH.LOG
$!
$ WRITE SYS$OUTPUT ""
$ WRITE SYS$OUTPUT "vmsguard submitted."
$ WRITE SYS$OUTPUT "  log     : ''vg_root'VMSGUARD.LOG"
$ WRITE SYS$OUTPUT "  stop    : @''vg_root'VMSGUARD_STOP.COM"
$ WRITE SYS$OUTPUT "  watch   : TYPE/CONTINUOUS ''vg_root'VMSGUARD.LOG"
$ WRITE SYS$OUTPUT ""
$ EXIT
