# Shoppy WIP
## Start: 27/10/2022

### IP: 10.10.11.180

So first, nmap, scan is below
```
$nmap -sV -sC 10.10.11.180 -Pn 
Nmap scan report for 10.10.11.180
Host is up (0.035s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e:5e:83:51:d9:9f:89:ea:47:1a:12:eb:81:f9:22:c0 (RSA)
|   256 58:57:ee:eb:06:50:03:7c:84:63:d7:a3:41:5b:1a:d5 (ECDSA)
|_  256 3e:9d:0a:42:90:44:38:60:b3:b6:2c:e9:bd:9a:67:54 (ED25519)
80/tcp open  http    nginx 1.23.1
|_http-title: Did not follow redirect to http://shoppy.htb
|_http-server-header: nginx/1.23.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
pop shoppy.htb into host file and away we go using burp to the website, where we're met by a waiting page followed by a redirect to the main page:
![Picture of wait page](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/1Shoppy_Wait.png)
![Picture of main page](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/2Shoppy_main.png)