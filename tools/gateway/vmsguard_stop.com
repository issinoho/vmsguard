$! vmsguard_stop.com -- ask the gateway to stop, and wait for it
$!
$! Creates the file the gateway watches for. It notices within a second,
$! finishes what it is doing and writes its summary to the log.
$!
$! Deliberately not STOP/IDENTIFICATION: deleting the process skips the
$! exit handler, and with it the summary -- which is the only record of
$! what a run that lasted days actually did.
$!
$ SET NOON
$ vg_root = "DISK$TOOLS:[CODE.VMSGUARD]"
$!
$ CREATE 'vg_root'VMSGUARD.STOP
$ WRITE SYS$OUTPUT "stop requested; waiting for the gateway to finish"
$!
$! It removes the file once it has seen it, so its disappearance is the
$! acknowledgement. Ten seconds is generous: the check runs once a
$! second.
$!
$ count = 0
$ wait_loop:
$   IF F$SEARCH(vg_root + "VMSGUARD.STOP") .EQS. ""
$   THEN
$       WRITE SYS$OUTPUT "gateway acknowledged; see ''vg_root'VMSGUARD.LOG"
$       EXIT
$   ENDIF
$   WAIT 00:00:01
$   count = count + 1
$   IF count .LT. 10 THEN GOTO wait_loop
$!
$ WRITE SYS$OUTPUT "no acknowledgement after 10 seconds."
$ WRITE SYS$OUTPUT "Is it running?  SHOW QUEUE/BATCH/ALL"
$ EXIT
