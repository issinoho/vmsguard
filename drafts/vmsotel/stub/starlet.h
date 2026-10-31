/*
 * Linux stub of the system services the probes call. Arguments are
 * void * where the real starlet.h names a struct; the probes cast to
 * void * at every call so that either declaration accepts them.
 */
#ifndef STUB_STARLET_H
#define STUB_STARLET_H
int sys$getmsg(unsigned int msgid, unsigned short *msglen, void *bufadr,
               unsigned int flags, unsigned char *outadr);
int sys$gettim(void *timadr);
int sys$getsyiw(unsigned int efn, unsigned int *csidadr, void *nodename,
                void *itmlst, void *iosb, void (*astadr)(void), int astprm);
int sys$getrmi(unsigned int efn, unsigned int csidadr, unsigned int nodename,
               void *itmlst, void *iosb, void (*astadr)(void), int astprm);
int sys$synch(unsigned int efn, void *iosb);
int sys$getjpiw(unsigned int efn, unsigned int *pidadr, void *prcnam,
                void *itmlst, void *iosb, void (*astadr)(void), int astprm);
int sys$device_scan(void *return_devnam, unsigned short *retlen,
                    void *search_devnam, void *itmlst, void *contxt);
int sys$getdviw(unsigned int efn, unsigned short chan, void *devnam,
                void *itmlst, void *iosb, void (*astadr)(void), int astprm,
                void *nullarg);
#endif
