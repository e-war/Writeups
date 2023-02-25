# Soccer - HTB
## 05/01/23
## 10.10.11.194
### Recon

```
Nmap scan report for soccer.htb (10.10.11.194)
Host is up (0.011s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad0d84a3fdcc98a478fef94915dae16d (RSA)
|   256 dfd6a39f68269dfc7c6a0c29e961f00c (ECDSA)
|_  256 5797565def793c2fcbdb35fff17c615c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Soccer - Index 
|_http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Thu, 05 Jan 2023 08:15:38 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Thu, 05 Jan 2023 08:15:38 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9091-TCP:V=7.93%I=7%D=1/5%Time=63B68725%P=x86_64-pc-linux-gnu%r(inf
SF:ormix,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\
SF:n\r\n")%r(drda,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x2
SF:0close\r\n\r\n")%r(GetRequest,168,"HTTP/1\.1\x20404\x20Not\x20Found\r\n
SF:Content-Security-Policy:\x20default-src\x20'none'\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nCon
SF:tent-Length:\x20139\r\nDate:\x20Thu,\x2005\x20Jan\x202023\x2008:15:38\x
SF:20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=
SF:\"en\">\n<head>\n<meta\x20charset=\"utf-8\">\n<title>Error</title>\n</h
SF:ead>\n<body>\n<pre>Cannot\x20GET\x20/</pre>\n</body>\n</html>\n")%r(HTT
SF:POptions,16C,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Poli
SF:cy:\x20default-src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\nC
SF:ontent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20143\r
SF:\nDate:\x20Thu,\x2005\x20Jan\x202023\x2008:15:38\x20GMT\r\nConnection:\
SF:x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<met
SF:a\x20charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Ca
SF:nnot\x20OPTIONS\x20/</pre>\n</body>\n</html>\n")%r(RTSPRequest,16C,"HTT
SF:P/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Policy:\x20default-sr
SF:c\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Type:\x20t
SF:ext/html;\x20charset=utf-8\r\nContent-Length:\x20143\r\nDate:\x20Thu,\x
SF:2005\x20Jan\x202023\x2008:15:38\x20GMT\r\nConnection:\x20close\r\n\r\n<
SF:!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<meta\x20charset=\"ut
SF:f-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot\x20OPTIONS\x
SF:20/</pre>\n</body>\n</html>\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F,
SF:"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r
SF:(DNSStatusRequestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnecti
SF:on:\x20close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nConnection:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.99 seconds


```

```
/gobuster dir -u http://soccer.htb/ -w ../Lists/SecLists/Discovery/Web-Content/raft-medium-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                ../Lists/SecLists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/05 08:20:26 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 162]
/.htm                 (Status: 403) [Size: 162]
/.                    (Status: 200) [Size: 6917]
/.htaccess            (Status: 403) [Size: 162] 
/.htc                 (Status: 403) [Size: 162] 
/.html_var_DE         (Status: 403) [Size: 162] 
/.htpasswd            (Status: 403) [Size: 162] 
/.html.               (Status: 403) [Size: 162] 
/.html.html           (Status: 403) [Size: 162] 
/.htpasswds           (Status: 403) [Size: 162] 
/.htm.                (Status: 403) [Size: 162] 
/.htmll               (Status: 403) [Size: 162] 
/.html.old            (Status: 403) [Size: 162] 
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
/.html.bak            (Status: 403) [Size: 162]                              
/.ht                  (Status: 403) [Size: 162]                              
/.htm.htm             (Status: 403) [Size: 162]                              
/.hta                 (Status: 403) [Size: 162]                              
/.htgroup             (Status: 403) [Size: 162]                              
/.html1               (Status: 403) [Size: 162]                              
/.html.LCK            (Status: 403) [Size: 162]                              
/.html.printable      (Status: 403) [Size: 162]                              
/.htm.LCK             (Status: 403) [Size: 162]                              
/.htaccess.bak        (Status: 403) [Size: 162]                              
/.htx                 (Status: 403) [Size: 162]                              
/.htmls               (Status: 403) [Size: 162]                              
/.htlm                (Status: 403) [Size: 162]                              
/.html-               (Status: 403) [Size: 162]                              
/.htm2                (Status: 403) [Size: 162]                              
/.htuser              (Status: 403) [Size: 162]                              
/.htacess             (Status: 403) [Size: 162]                              
/.htm.d               (Status: 403) [Size: 162]                              
/.htm.html            (Status: 403) [Size: 162]                              
/.htm.old             (Status: 403) [Size: 162]                              
/.html.sav            (Status: 403) [Size: 162]                              
/.html_files          (Status: 403) [Size: 162]                              
/.html-1              (Status: 403) [Size: 162]                              
/.html_               (Status: 403) [Size: 162]                              
/.html.orig           (Status: 403) [Size: 162]                              
/.htmlpar             (Status: 403) [Size: 162]                              
/.htmlprint           (Status: 403) [Size: 162]                              
/.hts                 (Status: 403) [Size: 162]                              
                                                                             
===============================================================
2023/01/05 08:21:43 Finished
===============================================================

```
```
./gobuster dir -u http://soccer.htb/tiny/ -w ../Lists/SecLists/Discovery/Web-Content/raft-medium-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb/tiny/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                ../Lists/SecLists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/01/05 08:23:54 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 162]
/.htm                 (Status: 403) [Size: 162]
/uploads              (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/uploads/]


```
tinyfilemanager, points to a login page, html suggests written in PHP
attempts to login posts to: `http://soccer.htb/tiny/tinyfilemanager.php`

looks like online there's a authenticated RCE for a version of tiny, lets work on getting valid credentials.

