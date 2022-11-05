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

![SQL 1](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/4Shoppy_SQL1.png)

![SQL 2](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/5Shoppy_SQL2.png)


`admin'&&'` includes quote marks returns the normal "wrong credentials" error which means that the system is reading this as valid sql.

A database query for sql might look like
`'WHERE user.username == "" && user.password == ""'`

So by entering a command such as the one below:
`admin'||'`

Would result in `'WHERE user.username == admin'||' && user.password == ""'`
Which means where username == admin OR (&& password == password), which removes the password from being a neccessary element as we only need the username or the password.

So lets give that a try...
![Crafted String](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/6Shoppy_Crafted.png)

![Login Bypassed](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/7Shoppy_admin_bypass.png)
Bingo

So what does this admin page offer us? An ability to search for a user and retrieve a json object which includes the ID, name, and a hashed password...
![Search for admin user](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/8Shoppy_Search_user.png)
![Search for admin user 2](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/9Shoppy_admin_results.png)

While i did initally try sqlmap on the previous sql injection site (which didn't work due to the timeout each time the sql failed), i believe we may have a better chance of running it against this internal admin search as we actually recieve an error message when the sql breaks (which it still can when including a quote mark)

![sqlmap](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/10sqlmap.png)
And while running sqlmap i refreshed the results page, and it seems one of the sqlmap probe requests has triggered all items to be read onto screen!
![shoppy all results](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/11Shoppy_all_results.png)

So we have a new user to look into, Josh, the passwords here look like md5 encrypted hashes which is good as they are simply cracked, and even most online rainbow tables make short work of hashes, putting the admin password into these tables doesn't really give much but josh's password seems to be easily gotten:

![MD5 Decrypt](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/12MD5_decrypt.png)

Josh: remembermethisway

Unfortunately josh doesn't have any extra permissions on this site above admin, nor does this password work for an ssh connection.. So maybe I'm missing something on this site, while nmap does give a good idea of what servers are running, it only tells us about the default web server and doesn't give any DNS or VHOST information, so i chose to run gobuster again, instead using the VHOST command to see if there are some subdomains that i might've missed..
```
gobuster vhost -u shoppy.htb -w ~/Programs/Security/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt                                                                                                              
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://shoppy.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /home/elliot/Programs/Security/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/11/05 13:05:48 Starting gobuster in VHOST enumeration mode
===============================================================
Found: mattermost.shoppy.htb (Status: 200) [Size: 3122]
                                                       
===============================================================
2022/11/05 13:11:01 Finished

```

So i did miss something, so it might be a good idea to perform a dns enumeration just after finding the webserver in nmap next time
So going to mattermost.shoppy.htb we see a mattermost page, a internal messaging system like slack it looks like, might as well try the credentials we found earlier for josh..

![Mattermost login](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/13Mattermost_login.png)

![Mattermost logged in](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/14Mattermost_loggedin.png)

Excellent, we have gained access to the internal chat system, there looks to be a few rooms for chats, but in the "Deploy machine" chat we see more credentials leaked:
jaeger: Sh0ppyBest@pp!

![Mattermost login creds](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/15Mattermost_login_creds.png)

they're discussing deployment on a machine, which might be the server we're looking at breaking into so its possible these credentials could work on the SSH connection, lets give that a try..


![SSH Login](https://github.com/e-war/Writeups/blob/master/HackTheBox/Shoppy/Screenshots/16SSH_Login.png)

### User access obtained

