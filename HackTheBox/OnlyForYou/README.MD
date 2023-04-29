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


