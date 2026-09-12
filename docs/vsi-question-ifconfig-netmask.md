# A rejected `ifconfig` deletes the address it refused to change

A question for VSI about `ifconfig` in TCP/IP Services on OpenVMS
x86-64.

Drafted 2026-09-12. Everything below was observed on the system
described; nothing is inferred from documentation.

## Summary

`ifconfig` with a host netmask (`255.255.255.255`) on a point-to-point
interface is refused — and the interface's existing address is removed
in the process. The interface is left with no address at all, rather
than with the configuration it had before the command that failed.

## Environment

| | |
| --- | --- |
| Operating system | VSI OpenVMS x86-64 V9.2-3 |
| TCP/IP Services | interface configured by `iptunnel create` |

## The observation

A configured tunnel, already addressed and working:

```
$ netstat -i
IT2   1280  <Link>      x86vms                    0     0        0     0     0
IT2   1280  10          10.99.0.1                 0     0        0     0     0
```

Reconfiguring it with a host netmask, which is the natural choice for a
point-to-point interface:

```
$ ifconfig "IT2" 10.99.0.1 10.99.0.2 netmask 255.255.255.255 up
%%%%%%%%%%%  OPCOM  12-SEP-2026 09:29:30.20  %%%%%%%%%%%
Message from user INTERnet on X86VMS
%TCPIP-I-FSIPADDRDEL, IT2 10.99.0.1 primary address removed from node X86VMS interface IT2

host address is zero when ipaddr=10.99.0.1 netmask:255.255.255.255
```

The command is refused, and the address is gone:

```
$ netstat -rn
Route Tree for Protocol Family 2:
default          192.168.0.1        UGS         5  1510761  IE0
127.0.0.1        127.0.0.1          UHL        17   705956  LO0
192.168.0/24     192.168.0.80       U           5  1794236  IE0
```

The same command with `netmask 255.255.255.0` is accepted and installs
the interface and host routes as expected, so the address and the
command are otherwise well formed:

```
$ ifconfig "IT2" 10.99.0.1 10.99.0.2 netmask 255.255.255.0 up

$ netstat -rn
10.99.0/24       10.99.0.1          U           1        0  IT2
10.99.0.1        10.99.0.1          UHL         0        0  IT2
```

## The two things we would ask about

**The address should survive a rejected command.** A program
reconfiguring an interface cannot treat a failure as having changed
nothing, which is the usual assumption. Recovering means knowing to
re-apply the previous configuration after an error — and knowing that
only by having been caught by it once.

**Is a host netmask meant to be refused here at all?** `255.255.255.255`
is ordinary for a point-to-point tunnel on other systems, where the
peer address rather than the mask defines the link. If it is genuinely
unsupported, refusing it without side effects would be enough.

A smaller point: `host address is zero when ipaddr=10.99.0.1
netmask:255.255.255.255` is written to the terminal in lower case and
without a facility prefix, unlike the `%TCPIP-I-FSIPADDRDEL` message
beside it, so it does not appear to be a status a program could test.

## What we have not established

- Whether the same happens on a LAN interface, or only on a configured
  tunnel. We tested `ITn` only, since that is what our work needed.
- Whether any of this differs on Alpha or IA-64. Everything here is
  x86-64.

## Related

Two separate reports cover libpcap behaviour on the same interfaces:
[`vsi-question-pcap-tunnel.md`](vsi-question-pcap-tunnel.md) and
[`vsi-question-pcap-ipv4-address.md`](vsi-question-pcap-ipv4-address.md).
