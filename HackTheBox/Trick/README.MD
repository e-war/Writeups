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
sudo nmap -sV -sC -Pn 10.10.11.166 -sU                                                                                                                                               1 ✘ 
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

So looking up these services online now seems like a good idea to see if there are any versions here out of date or even vulnerable
##### OpenSSH 7.9p1 Debian 10+deb10u2
- https://security-tracker.debian.org/tracker/CVE-2019-6111

##### ISC BIND 9.11.5-P4-5.1
- https://vulmon.com/vulnerabilitydetails?qid=CVE-2021-25216&scoretype=cvssv3


This Nginx version doesn't seem to have any known vulnerabilities 
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
There may be a way to generate a list of local server usernames using the SFTP server by asking the server to verify the local users email address which is created automatically when the account is 
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

```
nslookup debian. debian.localdomain
Server:         debian.localdomain
Address:        10.10.11.166#53

** server can't find debian: REFUSED
```
Well thats rude! They're refusing to allow us to search, no wonder gobuster found nothing..

### Vulnerability & Exploit analysis 
We already have a few leads in terms of OpenSSH and ISC BIND, a good source of already exploited vulnerabilities is a tool called `searchsploit` which i believe just searches the entire exploitdb database

```
searchsploit OpenSSH                                                                                                                                    ✔ 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                    |  Path
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
