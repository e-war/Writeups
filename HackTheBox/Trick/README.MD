# Trick WIP
## Start: 8/11/2022

## IP: 10.10.11.166

### Information gathering
So as promised i'm splitting up my work into seperate sections so i can make sure i don't overlook something and just blindly follow a path that i hope will work until it doesn't and i have to go back to the start of the process again.

#### Services
First as per usual is an nmap scan with services and versions included:

```
nmap -sV -sC -Pn 10.10.11.166

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-08 13:12 GMT
Stats: 0:00:55 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 87.50% done; ETC: 13:13 (0:00:01 remaining)
Nmap scan report for 10.10.11.166
Host is up (0.30s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 80.64 seconds
```
So OpenSSH, a mail server, ISC BIND 9 which is a DNS system, and a nginx web site.


I also did a UDP scan on the host with the nmap -sU flag
```
sudo nmap -sV -sC -Pn 10.10.11.166 -sU                                                                                                                                          
[sudo] password for elliot: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-08 13:15 GMT
Stats: 0:03:35 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 27.43% done; ETC: 13:28 (0:09:31 remaining)
Nmap scan report for 10.10.11.166
Host is up (0.013s latency).
Not shown: 957 closed udp ports (port-unreach), 42 open|filtered udp ports (no-response)
PORT   STATE SERVICE VERSION
53/udp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1324.10 seconds
```
Just ISC BIND again.
So a linux box as seen bind thinks deb10u7 and openSSH thinks deb10u2 and the hostname is debian.localdomain. Debian 10 seems likely. 

This Nginx version doesn't seem to have any known vulnerabilities but some of the other services look like they could make interesting targets (below) 


#### Web Content
Next i'll move onto the web site hosted and gather as much information on any unlinked pages/directories and any subdomains of the site.
For this i'll use gobuster
```
gobuster-linux-amd64/gobuster dir -u http://10.10.11.166/ -w Lists/SecLists/Discovery/Web-Content/raft-medium-words.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.166/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                Lists/SecLists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/11/08 13:47:36 Starting gobuster in directory enumeration mode
===============================================================
/js                   (Status: 301) [Size: 185] [--> http://10.10.11.166/js/]
/css                  (Status: 301) [Size: 185] [--> http://10.10.11.166/css/]
/assets               (Status: 301) [Size: 185] [--> http://10.10.11.166/assets/]
/.                    (Status: 301) [Size: 185] [--> http://10.10.11.166/./]     
                                                                                 
===============================================================
2022/11/08 13:50:06 Finished
===============================================================

```
lets check that assets folder too.
```
./gobuster dir -u http://10.10.11.166/assets/ -w ../Lists/SecLists/Discovery/Web-Content/raft-medium-words.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.166/assets/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                ../Lists/SecLists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/11/08 15:14:08 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 185] [--> http://10.10.11.166/assets/img/]
/.                    (Status: 301) [Size: 185] [--> http://10.10.11.166/assets/./]  
/mp4                  (Status: 301) [Size: 185] [--> http://10.10.11.166/assets/mp4/]
                                                                                     
===============================================================
2022/11/08 15:17:26 Finished
===============================================================

```

```
gobuster-linux-amd64/gobuster vhost --url http://debian.localdomain/ -w Lists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://debian.localdomain/
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     Lists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/11/08 13:48:43 Starting gobuster in VHOST enumeration mode
===============================================================
                                 
===============================================================
2022/11/08 13:52:46 Finished
===============================================================
```

And since we have a DNS system installed, i'll go ahead and run gobuster dns too: [Moved to DNS System](#dns-system)

So not finding much initally, i'm going to take a look at the page to see if i find anything interesting on the site itself.
![Screenshot of homepage](https://github.com/e-war/Writeups/blob/master/HackTheBox/Trick/Screenshots/1Trick_homepage.png)
A "Coming Soon" page with a form for emails, i did try with a 10 min email address but it looks like the webmasters haven't enabled the functionality just yet
![Screenshot of bootstrap email error](https://github.com/e-war/Writeups/blob/master/HackTheBox/Trick/Screenshots/2Trick_email_error.png)

Nothing really super interesting here, and so i'll look elsewhere

#### SSH

##### OpenSSH 7.9p1 Debian 10+deb10u2

- ~https://security-tracker.debian.org/tracker/CVE-2019-6111~ MITM attack replacing files in transmission

#### Mail system

Looks like a simple postfix setup, we can telnet and we don't need authorization to do anything. But we can't send emails to external domains.
```
telnet debian.localdomain 25
Trying 10.10.11.166...
Connected to debian.localdomain.
Escape character is '^]'.
HELO
220 debian.localdomain ESMTP Postfix (Debian/GNU)
501 Syntax: HELO hostname
HELO debian.localdomain
250 debian.localdomain
MAIL FROM test@debian.localdomain
501 5.5.4 Syntax: MAIL FROM:<address>
MAIL FROM:test@debian.localdomain
250 2.1.0 Ok
RCPT TO:jkgemovdoqahscednq@tmmwj.net
454 4.7.1 <jkgemovdoqahscednq@tmmwj.net>: Relay access denied

```
> There may be a way to generate a list of local server usernames using the SFTP server by asking the server to verify the local users email address which is created automatically when the account is...

> There is actually, and it was so simple i made a tool to do it. it's terrible and you shouldn't use it but i thought i may as well get some practice in (https://github.com/e-war/SMTFuzz) 


```
VRFY
501 5.5.4 Syntax: VRFY address [SMTPUTF8]
VRFY root@debian.localdomain
252 2.0.0 root@debian.localdomain
VRFY dave@debian.localdomain
550 5.1.1 <dave@debian.localdomain>: Recipient address rejected: User unknown in local recipient table
```

And we can send from the root mail account to itself, which is good to know
```
RSET
250 2.0.0 Ok
HELO debian.localdomain
250 debian.localdomain
MAIL FROM:root@debian.localdomain
250 2.1.0 Ok
RCPT TO:root@debian.localdomain 
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
Date: Tue, 8 November 2022 
From: root@debian.localdomain
Subject: test
To: root@debian.localdomain 
TEST!!!
.
250 2.0.0 Ok: queued as 05C95409A4
```

But that's about all i think i can get out of the SMTP system, i'll take a quick look at the DNS system next

#### DNS System

##### ISC BIND 9.11.5-P4-5.1
- https://vulmon.com/vulnerabilitydetails?qid=CVE-2021-25216&scoretype=cvssv3
- https://www.cvedetails.com/cve/CVE-2021-25216/

So ISC BIND... I have to say i'm not the best with DNS lookups, gobuster doesn't really yield much for subdomains of the host:
```
gobuster-linux-amd64/gobuster dns -d debian.localdomain. -r debian.localdomain. -w ./Lists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     debian.localdomain.
[+] Threads:    10
[+] Resolver:   debian.localdomain.
[+] Timeout:    1s
[+] Wordlist:   ./Lists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
===============================================================
2022/11/08 14:20:01 Starting gobuster in DNS enumeration mode
===============================================================
                                 
===============================================================
2022/11/08 14:32:32 Finished
===============================================================
```

well lets try and query the DNS server directly...
For this im gonna use dig, i'm still learning it at the moment but a simple reverse query with the `-x` flag reveals a dns record of trick.htb. (@ just specifies the server so we don't use our actual DNS)
```
dig -x 10.10.11.166 @10.10.11.166                                                                                                                                                             10 ✘ 

; <<>> DiG 9.18.8 <<>> -x 10.10.11.166 @10.10.11.166
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 63555
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: faacaf2c3ede4870e45b9367636cdc9c9cd9bbd75a6e794f (good)
;; QUESTION SECTION:
;166.11.10.10.in-addr.arpa.     IN      PTR

;; ANSWER SECTION:
166.11.10.10.in-addr.arpa. 604800 IN    PTR     trick.htb.

;; AUTHORITY SECTION:
11.10.10.in-addr.arpa.  604800  IN      NS      trick.htb.

;; ADDITIONAL SECTION:
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1

;; Query time: 13 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (UDP)
;; WHEN: Thu Nov 10 11:12:28 GMT 2022
;; MSG SIZE  rcvd: 163
```
So actually this server is known both as:
-   trick.htb.
-   debian.localdomain.

So lets add trick.htb to our host file and now i'll use dig (+dns) in a way i haven't before, with the `axfr` addition, AXFR is a query for the DNS Zone, which is a copy of ALL the subdomains (+ records), it's used for when you want another dns server to copy a master copy of the zone, and it's usually protected to only allow certain known IP address' to get it. But this server doesn't! (For the record, if it did you can try IP spoofing and failing that i would've just gone back to gobuster with our new domain name and try a wordlist again.)  

```
dig @10.10.11.166 trick.htb axfr                                                                                                                                                                 

; <<>> DiG 9.18.8 <<>> @10.10.11.166 trick.htb axfr
; (1 server found)
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
preprod-payroll.trick.htb. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 83 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (TCP)
;; WHEN: Thu Nov 10 11:26:38 GMT 2022
;; XFR size: 6 records (messages 1, bytes 231)
```
Well would you look at that! A subdomain we didn't spot before `preprod-payroll.trick.htb` Sounds like something worth checking out

#### Web content: Round 2
Doing a quick rescan with nmap doesn't show any new services hidden behind the domain, but it does show us one which has changed.
```
80/tcp open  http    nginx 1.14.2
| http-title: Admin | Employee's Payroll Management System
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.14.2
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
![Employee payroll admin site](https://github.com/e-war/Writeups/blob/master/HackTheBox/Trick/Screenshots/3Trick_Second_site.png)
A PHP site! A PHP admin site! Well of course we have to check this out, but first of all, lets rerun those gobusters!
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://preprod-payroll.trick.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/elliot/Programs/Security/Lists/SecLists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/11/10 11:38:10 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 185] [--> http://preprod-payroll.trick.htb/assets/]
/database             (Status: 301) [Size: 185] [--> http://preprod-payroll.trick.htb/database/]
/.                    (Status: 301) [Size: 185] [--> http://preprod-payroll.trick.htb/./]       
                                                                                                
===============================================================
2022/11/10 11:40:32 Finished
===============================================================
```
nice nice, so some database being used here too.. hopefully that means SQLi might be an avaliable path to get in


### Vulnerability & Exploit analysis 
We already have a few leads in terms of OpenSSH and ISC BIND, a good source of already exploited vulnerabilities is a tool called `searchsploit` which i believe just searches the entire exploitdb database

```
searchsploit OpenSSH                                                                                                                                    ✔ 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                   location: login.php                                                                                                                 |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Debian OpenSSH - (Authenticated) Remote SELinux Privilege Escalation                                                                                                              | linux/remote/6094.txt
Dropbear / OpenSSH Server - 'MAX_UNAUTH_CLIENTS' Denial of Service                                                                                                                | multiple/dos/1572.pl
FreeBSD OpenSSH 3.5p1 - Remote Command Execution                                                                                                                                  | freebsd/remote/17462.txt
glibc-2.2 / openssh-2.3.0p1 / glibc 2.1.9x - File Read                                                                                                                            | linux/local/258.sh
Novell Netware 6.5 - OpenSSH Remote Stack Overflow                                                                                                                                | novell/dos/14866.txt
OpenSSH 1.2 - '.scp' File Create/Overwrite                                                                                                                                        | linux/remote/20253.sh
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                                                                          | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                                                                                    | linux/remote/45210.py
OpenSSH 2.x/3.0.1/3.0.2 - Channel Code Off-by-One                                                                                                                                 | unix/remote/21314.txt
OpenSSH 2.x/3.x - Kerberos 4 TGT/AFS Token Buffer Overflow                                                                                                                        | linux/remote/21402.txt
OpenSSH 3.x - Challenge-Response Buffer Overflow (1)                                                                                                                              | unix/remote/21578.txt
OpenSSH 3.x - Challenge-Response Buffer Overflow (2)                                                                                                                              | unix/remote/21579.txt
OpenSSH 4.3 p1 - Duplicated Block Remote Denial of Service                                                                                                                        | multiple/dos/2444.sh
OpenSSH 6.8 < 6.9 - 'PTY' Local Privilege Escalation                                                                                                                              | linux/local/41173.c
OpenSSH 7.2 - Denial of Service                                                                                                                                                   | linux/dos/40888.py
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection                                                                                                                           | multiple/remote/39569.py
OpenSSH 7.2p2 - Username Enumeration                                                                                                                                              | linux/remote/40136.py
OpenSSH < 6.6 SFTP (x64) - Command Execution                                                                                                                                      | linux_x86-64/remote/45000.c
OpenSSH < 6.6 SFTP - Command Execution                                                                                                                                            | linux/remote/45001.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                                                                              | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                                                                          | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                                                                              | linux/remote/45939.py
OpenSSH SCP Client - Write Arbitrary Files                                                                                                                                        | multiple/remote/46516.py
OpenSSH/PAM 3.6.1p1 - 'gossh.sh' Remote Users Ident                                                                                                                               | linux/remote/26.sh
OpenSSH/PAM 3.6.1p1 - Remote Users Discovery Tool                                                                                                                                 | linux/remote/25.c
OpenSSHd 7.2p2 - Username Enumeration                                                                                                                                             | linux/remote/40113.txt
Portable OpenSSH 3.6.1p-PAM/4.1-SuSE - Timing Attack                                                                                                                              | multiple/remote/3303.sh
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```
```
searchsploit postfix                                                                                                                                    ✔ 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                    |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
gld 1.4 - Postfix Greylisting Daemon Remote Format String                                                                                                                         | linux/remote/934.c
Postfix 1.1.x - Denial of Service (1)                                                                                                                                             | linux/dos/22981.c
Postfix 1.1.x - Denial of Service (2)                                                                                                                                             | linux/dos/22982.pl
Postfix 2.6-20080814 - 'symlink' Local Privilege Escalation                                                                                                                       | linux/local/6337.sh
Postfix < 2.4.9/2.5.5/2.6-20080902 - '.forward' Local Denial of Service                                                                                                           | multiple/dos/6472.c
Postfix SMTP 4.2.x < 4.2.48 - 'Shellshock' Remote Command Injection                                                                                                               | linux/remote/34896.py
Salim Gasmi GLD (Greylisting Daemon) - Postfix Buffer Overflow (Metasploit)                                                                                                       | linux/remote/16841.rb
Salim Gasmi GLD (Greylisting Daemon) 1.0 < 1.4 - Postfix Greylisting Buffer Overflow (Metasploit)                                                                                 | linux/remote/10023.rb
Salim Gasmi GLD (Greylisting Daemon) 1.x - Postfix Greylisting Daemon Buffer Overflow                                                                                             | linux/remote/25392.c
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

```
searchsploit ISC BIND 9                                                                                                                       6 ✘  19s  
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                    |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ISC BIND (Linux/BSD) - Remote Buffer Overflow (1)                                                                                                                                 | linux/remote/19111.c
ISC BIND (Multiple OSes) - Remote Buffer Overflow (2)                                                                                                                             | linux/remote/19112.c
ISC BIND 4.9.7 -T1B - named SIGINT / SIGIOT Symlink                                                                                                                               | linux/local/19072.txt
ISC BIND 4.9.7/8.x - Traffic Amplification and NS Route Discovery                                                                                                                 | multiple/remote/19749.txt
ISC BIND 8 - Remote Cache Poisoning (1)                                                                                                                                           | linux/remote/30535.pl
ISC BIND 8 - Remote Cache Poisoning (2)                                                                                                                                           | linux/remote/30536.pl
ISC BIND 8.1 - Host Remote Buffer Overflow                                                                                                                                        | unix/remote/20374.c
ISC BIND 8.2.2 / IRIX 6.5.17 / Solaris 7.0 - NXT Overflow / Denial of Service                                                                                                     | unix/dos/19615.c
ISC BIND 8.2.2-P5 - Denial of Service                                                                                                                                             | linux/dos/20388.txt
ISC BIND 8.2.x - 'TSIG' Remote Stack Overflow (1)                                                                                                                                 | linux/remote/277.c
ISC BIND 8.2.x - 'TSIG' Remote Stack Overflow (2)                                                                                                                                 | linux/remote/279.c
ISC BIND 8.2.x - 'TSIG' Remote Stack Overflow (3)                                                                                                                                 | solaris/remote/280.c
ISC BIND 8.2.x - 'TSIG' Remote Stack Overflow (4)                                                                                                                                 | linux/remote/282.c
ISC BIND 8.3.x - OPT Record Large UDP Denial of Service                                                                                                                           | linux/dos/22011.c
ISC BIND 9 - Denial of Service                                                                                                                                                    | multiple/dos/40453.py
ISC BIND 9 - Remote Dynamic Update Message Denial of Service (PoC)                                                                                                                | multiple/dos/9300.c
ISC BIND 9 - TKEY (PoC)                                                                                                                                                           | multiple/dos/37721.c
ISC BIND 9 - TKEY Remote Denial of Service (PoC)                                                                                                                                  | multiple/dos/37723.py
Microsoft Windows Kernel - 'win32k!NtQueryCompositionSurfaceBinding' Stack Memory Disclosure                                                                                      | windows/dos/42750.cpp
Zabbix 2.0.5 - Cleartext ldap_bind_Password Password Disclosure (Metasploit)                                                                                                      | php/webapps/36157.rb
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```
Well there's certainly a lot there, unfortunately none which applies directly to our version numbers exactly, so there may not be any public exploits currently avaliable for us to use, which means either writing one ourselves from the CVE's found earlier (i may try this sometime in the future but not just yet) or to just continue with attempting to exploit the services we can directly.

### Exploitation

#### SMTP
So first just because i want to use the tool i wrote i'll do a username fuzz against the SMTP service
```
############ FUZZING debian.localdomain ####
# Found 7 /( 495 / 822 )
# Please be patient, this program is slow:
# Trying: anonymous
# Verified Users:
#"root@debian.localdomain"
#"BACKUP@debian.localdomain"
#"MAIL@debian.localdomain"
#"NEWS@debian.localdomain"
#"POSTMASTER@debian.localdomain"
#"ROOT@debian.localdomain"
#"SYS@debian.localdomain"
```
so some interesting usernames, i'm sure that showed up in there log files too! 

#### Web Content

Ok so lets take a look at that admin site, as usual i'll quickly try some SQLi on this admin login to see if we can bypass
![Employee payroll admin site](https://github.com/e-war/Writeups/blob/master/HackTheBox/Trick/Screenshots/3Trick_Second_site.png)
![attempting sqli](https://github.com/e-war/Writeups/blob/master/HackTheBox/Trick/Screenshots/4Trick_SQLi.png)
![sqli fails but interesting info leaks](https://github.com/e-war/Writeups/blob/master/HackTheBox/Trick/Screenshots/5Trick_SQLi_response.png)

Hmm interesting, so it looks like SQL may not be typically injected on, but we get something interesting leaked back to us, along with the number 3, if i was a lazy developer (hehe) i might implement a feature where a returned number is actually a reference to whether or not you sent the right username + password combo

![analysing login post request](https://github.com/e-war/Writeups/blob/master/HackTheBox/Trick/Screenshots/6Trick_login_request.png)
![analysing login post request 2](https://github.com/e-war/Writeups/blob/master/HackTheBox/Trick/Screenshots/7Trick_login_response.png)
![analysing login post request 3](https://github.com/e-war/Writeups/blob/master/HackTheBox/Trick/Screenshots/8Ttrick_login_response_edited.png)
![analysing login post request 4](https://github.com/e-war/Writeups/blob/master/HackTheBox/Trick/Screenshots/9Trick_login_forwarded.png)

Aha! So we are now forwareded to `index.php?page=home`

![analysing login post request 5](https://github.com/e-war/Writeups/blob/master/HackTheBox/Trick/Screenshots/10Trick_redirected.png)
But it seems like just after this we are redirected yet again to the login page... But what's this? The page is still rendered even with it being a 302 code!
We can simply edit the status code in this response and view the page as normal, i've set up a filter in burpsuite to do this automatically

![burpsuite settings](https://github.com/e-war/Writeups/blob/master/HackTheBox/Trick/Screenshots/11Trick_Burpsettings.png)
![Second site access](https://github.com/e-war/Writeups/blob/master/HackTheBox/Trick/Screenshots/12Trick_Second_site_landing.png)

###### SAVE
```
POST /ajax.php?action=save_employee HTTP/1.1
Host: preprod-payroll.trick.htb
Content-Length: 93
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.63 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://preprod-payroll.trick.htb
Referer: http://preprod-payroll.trick.htb/index.php?page=employee
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: PHPSESSID=temjs3d2tirbi0snvh7uqcnedf
Connection: close

id=&firstname=Good&middlename=&lastname=Hackker&department_id=1&position_id=1&salary=10000000
```