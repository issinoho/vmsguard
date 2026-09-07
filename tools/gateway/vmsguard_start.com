$! vmsguard_start.com - start the gateway so it outlives the terminal
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
$!
$!=====================================================================
$! Site settings - edit this one
$!=====================================================================
$!
$ vg_root = "DISK$TOOLS:[CODE.VMSGUARD]"
$!
$!=====================================================================
$!
$! Where this procedure lives, which is also where VMSGUARD_RUN.COM
$! lives. Derived rather than assumed: the first version of this file
$! looked for it in vg_root, which is two directories up, and SUBMIT
$! duly failed with RMS-E-FNF.
$!
$ vg_proc = F$ENVIRONMENT("PROCEDURE")
$ vg_com  = F$PARSE(vg_proc,,,"DEVICE") + F$PARSE(vg_proc,,,"DIRECTORY")
$ vg_run  = vg_com + "VMSGUARD_RUN.COM"
$!
$ IF F$SEARCH(vg_run) .EQS. ""
$ THEN
$     WRITE SYS$OUTPUT "vmsguard: cannot find ''vg_run'"
$     EXIT 2
$ ENDIF
$!
$! Clear any stop request left over from last time, or the gateway
$! would see it and shut down again immediately.
$!
$ IF F$SEARCH(vg_root + "VMSGUARD.STOP") .NES. "" THEN -
      DELETE/NOLOG 'vg_root'VMSGUARD.STOP;*
$!
$! No /NOTIFY: this runs for days and the submitter will not be logged
$! in to receive it. Check the queue's CPU time limit before relying on
$! this -- SHOW QUEUE/FULL -- because a limit there will stop the
$! gateway at some arbitrary hour with nothing in its own log to
$! explain it.
$!
$ SUBMIT 'vg_run' -
        /NOPRINTER -
        /LOG_FILE='vg_root'VMSGUARD_BATCH.LOG
$ sub_status = $STATUS
$!
$! SET NOON is on, so a failed SUBMIT does not stop this procedure and
$! the status has to be looked at. Without this the original version
$! printed "vmsguard submitted" directly underneath the error that said
$! it had not been.
$!
$ IF (sub_status .AND. 1) .EQ. 0
$ THEN
$     WRITE SYS$OUTPUT ""
$     WRITE SYS$OUTPUT "vmsguard: SUBMIT failed; nothing is running."
$     EXIT sub_status
$ ENDIF
$!
$ WRITE SYS$OUTPUT ""
$ WRITE SYS$OUTPUT "vmsguard submitted."
$ WRITE SYS$OUTPUT "  log     : ''vg_root'VMSGUARD.LOG"
$ WRITE SYS$OUTPUT "  stop    : @''vg_com'VMSGUARD_STOP.COM"
$ WRITE SYS$OUTPUT "  watch   : TYPE/CONTINUOUS ''vg_root'VMSGUARD.LOG"
$ WRITE SYS$OUTPUT ""
$ EXIT
