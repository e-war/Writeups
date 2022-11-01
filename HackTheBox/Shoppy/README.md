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
Ok, a boring countdown, are there any interesting scripts? 
```
<script src="js/jquery.js"></script>
<script src="js/plugins.js"></script>
<script src="js/jquery.countdown.min.js"></script>
<script src="js/main.js"></script>

```
Nothing really stands out when viewing these however so next bit of info gathering is testing out if there are some hidden directories we can search for, typically i use gobuster for this

```
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shoppy.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/elliot/Programs/Security/SecLists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] Exclude Length:          169
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/10/28 20:10:50 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 302) [Size: 28] [--> /login]
/images               (Status: 301) [Size: 179] [--> /images/]
/login                (Status: 200) [Size: 1074]              
/js                   (Status: 301) [Size: 171] [--> /js/]    
/css                  (Status: 301) [Size: 173] [--> /css/]   
/assets               (Status: 301) [Size: 179] [--> /assets/]
/Admin                (Status: 302) [Size: 28] [--> /login]   
/Login                (Status: 200) [Size: 1074]              
/fonts                (Status: 301) [Size: 177] [--> /fonts/] 
/ADMIN                (Status: 302) [Size: 28] [--> /login]   
/exports              (Status: 301) [Size: 181] [--> /exports/]
/LogIn                (Status: 200) [Size: 1074]               
/LOGIN                (Status: 200) [Size: 1074]               
                                                               
===============================================================
2022/10/28 20:14:13 Finished
===============================================================
```
Well would you look at that, an /admin which redirects to the /login page and an /exports page too, although this only redirects to a path which cant be fetched..
Lets take a look at that admin page anyway
![Picture of admin login page](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/3Shoppy_admin.png)
admin:admin is probably too good to hope for, but looks like if we put a quote mark in the page it times out! This is a decent chance of being the result of breaking some database query which looks up the account and password, this could mean that with correct symbol placement we could modify the query and allow any password to be accepted for any user account.

So the steps being:
    -   Determine database using specific inputs
    -   Determine database query
    -   Craft breakout string


i can't be sure as we can't really get a response from the server aside from the timeout error we recieve when the sql query breaks.

![SQL 1](ttps://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/4Shoppy_SQL1.png)

![SQL 2](ttps://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/5Shoppy_SQL2.png)


`admin'&&'` includes quote marks returns the normal "wrong credentials" error which means that the system is reading this as valid sql.

A database query for sql might look like
`'WHERE user.username == "" && user.password == ""'`

So by entering a command such as the one below:
`admin'||'`

Would result in `'WHERE user.username == admin'||' && user.password == ""'`
Which means where username == admin OR (&& password == password), which removes the password from being a neccessary element as we only need the username or the password.

So lets give that a try...
![Crafted String](ttps://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/6Shoppy_Crafted.png)

![Login Bypassed](ttps://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/7Shoppy_admin_bypass.png)
