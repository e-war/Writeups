# HTB - Inject
## 22/03/2023 - ...
## 10.10.11.204
## Recon
### NMAP
```
nmap -sV -sC inject.htb                                            
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-01 16:15 BST
Nmap scan report for inject.htb (10.10.11.204)
Host is up (0.012s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 caf10c515a596277f0a80c5c7c8ddaf8 (RSA)
|   256 d51c81c97b076b1cc1b429254b52219f (ECDSA)
|_  256 db1d8ceb9472b0d3ed44b96c93a7f91d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
