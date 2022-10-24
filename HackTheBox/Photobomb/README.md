# Photobomb


IP Address: 10.10.11.182

Ok so first things first, nmap

```
$> nmap 10.10.11.182 -sV -sC -Pn                                                                                                                           ✔ 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-24 19:53 BST
Nmap scan report for 10.10.11.182
Host is up (0.029s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.38 seconds

```

Ok standard server with SSH and a webbed site which seems to wanting to point us to photobomb.htb, which ill add to my hosts file just for ease of use
![Picture of homepage](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/home.png)
Page links to a "printer" page admin panel with a username and password
![Picture of admin prompt](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/login.png)
Well looking at the home page source code it seems some careless admin has just given the login out anyway
![Picture of leaked privs](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/login.png)
So pH0t0 : b0Mb! ok.
![Picture of successful login](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/printer_success.png)
So this page looks to ask us to select a picture and a size / filetype to download for printing purposes.
It does this by making a post request to the same site at /printer, so lets make one manually, as we can specifiy the file name, can we potentially use this to view other files?