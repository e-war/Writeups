# HTB -  MetaTWO
# IP: 10.10.11.186
# Start: 26/02/23

## Info gathering

### Nmap

#### metatwo.htb
```
nmap -sV -sC metatwo.htb- Pn                                                                                                                                                                 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-26 12:06 GMT
Nmap scan report for metatwo.htb (10.10.11.186)
Host is up (0.012s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4b44617d2102d8fec1dc927fecd79ee (RSA)
|   256 2aea2fcb23e8c529409cab866dcd4411 (ECDSA)
|_  256 fd78c0b0e22016fa050debd83f12a4ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.93%I=7%D=2/26%Time=63FB4B3D%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,8F,"220\x20ProFTPD\x20Server\x20\(Debian\)\x20\[::ffff:10\.10\
SF:.11\.186\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cre
SF:ative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creative
SF:\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
Interesting:
- FTP port (proFTP)
- webserver redirects to metapress.htb

#### metapress.htb

same as previous run aside from http site
```
80/tcp open  http    nginx 1.18.0
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-generator: WordPress 5.6.2
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: nginx/1.18.0
|_http-title: MetaPress &#8211; Official company site
```
Interesting:
- Wordpress site
- robots.txt tells us of an interesting folder
- sessionid can be read by scripts, potentially allowing token stealing
- path /evox/about may be valid

### Web access

#### http://metapress.htb/ mirrors http://metapress.htb/hello-world

Basic under construction page

interesting links:
- http://metapress.htb/wp-json/
- http://metapress.htb/xmlrpc.php?rsd
- http://metapress.htb/wp-includes/wlwmanifest.xml


#### http://metapress.htb/events

Event form with fillable fields

Interesting:
- POST /wp-admin/admin-ajax.php filling out form (wordpress plugin most likely)

#### http://metapress.htb/about-us/

Under construction about page

Interesting:
- Search button -> http://metapress.htb/?s=

#### Other pages:

These were found by performing an empty search on the /?s page

- http://metapress.htb/cancel-payment/
- http://metapress.htb/cancel-appointment/
- http://metapress.htb/sample-page/ (link to http://metapress.htb/wp-admin/)
- http://metapress.htb/thank-you/ (calls to /wp-content/plugins/bookingpress-appointment-booking)

#### Next steps

ok so it's a wordpress site, that much is clear.
I know about potentially brute forcing through xmlrpc.php, but first i'd like some more info, so i'll use wpscan.

```
wpscan --url http://metapress.htb -e vp,vt --plugins-detection mixed  

[+] WordPress version 5.6.2 identified (Insecure, released on 2021-02-22).
[+] WordPress theme in use: twentytwentyone
 | Location: http://metapress.htb/wp-content/themes/twentytwentyone/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://metapress.htb/wp-content/themes/twentytwentyone/readme.txt
 | [!] The version is out of date, the latest version is 1.7


```