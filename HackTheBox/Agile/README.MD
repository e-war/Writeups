# HTB - Agile
## Start: 13/05/23
## IP: 10.10.11.203

## Info Gathering
### NMAP
```
nmap -sV -sC 10.10.11.203  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-13 15:40 BST
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 15:41 (0:00:06 remaining)
Nmap scan report for 10.10.11.203
Host is up (0.011s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f4bcee21d71f1aa26572212d5ba6f700 (ECDSA)
|_  256 65c1480d88cbb975a02ca5e6377e5106 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://superpass.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Added the host superpass.htb to hosts file.

### Burpsuite

Checking the website, a "military grade" encrypted password vault, registering an account is easy, passwords can be added via the web site and then downloaded again as a .csv file.

There is a Local File Inclusion vulnerability within this csv download code which allows the change of the `fn` url variable to a file or directory reletive to `/tmp` as seen in the screenshot.

![LFI vulnerability via superpass.htb/download?fn=../etc/passwd](https://github.com/e-war/Writeups/blob/master/HackTheBox/Agile/Screenshots/LFI.png?raw=true)

I can also crash the input which shows us a full path to some of the running python files, with the LFI i will read these files to get a better understanding of the code to see if more vulnerabilities exist.

![Crashing input to view python file paths](https://github.com/e-war/Writeups/blob/master/HackTheBox/Agile/Screenshots/LFI2.png?raw=true)

![Viewing python files](https://github.com/e-war/Writeups/blob/master/HackTheBox/Agile/Screenshots/LFI3.png?raw=true)