# HTB - Pilgrimage
# IP: 10.10.11.219
# Methodology
Investigate > Research > Assess > Exploit > Review

# Investigate
## NMAP
```bash
nmap -sV -sC pilgrimage.htb
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20:be:60:d2:95:f6:28:c1:b7:e9:e8:17:06:f1:68:f3 (RSA)
|   256 0e:b6:a6:a8:c9:9b:41:73:74:6e:70:18:0d:5f:e0:af (ECDSA)
|_  256 d1:4e:29:3c:70:86:69:b4:d7:2c:c8:0b:48:6e:98:04 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Pilgrimage - Shrink Your Images
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-git: 
|   10.10.11.219:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web content

"SAVE SPACE AND SHRINK IT!
A free online image shrinker. Create an account to save your images!" - Website

A site is hosted which allowes simple user registration and the ability to upload and "shrink" image files. Like the nmap scan tells i can access a .git folder beyond the web file path. 
Deploying sites by git is potentially something i could see a company doing if they didn't know better.

Although the directories aren't browseable, accessing files directly works fine. Therefore looking through a .git folder structure is probably good time spent rather than having a tool do it for me.

# Research
## Web content
### .git Directory scraping
`GET /.git/COMMIT_EDITMSG`
```
Pilgrimage image shrinking service initial commit.
# Please enter the commit message for your changes. Lines starting
# with '#' will be ignored, and an empty message aborts the commit.
#
# Author:    emily <emily@pilgrimage.htb>
#
# On branch master
#
# Initial commit
#
# Changes to be committed:
#	new file:   assets/bulletproof.php
#	new file:   assets/css/animate.css
#	new file:   assets/css/custom.css
#	new file:   assets/css/flex-slider.css
#	new file:   assets/css/fontawesome.css
#	new file:   assets/css/owl.css
#	new file:   assets/css/templatemo-woox-travel.css
#	new file:   assets/images/banner-04.jpg
#	new file:   assets/images/cta-bg.jpg
#	new file:   assets/js/custom.js
#	new file:   assets/js/isotope.js
#	new file:   assets/js/isotope.min.js
#	new file:   assets/js/owl-carousel.js
#	new file:   assets/js/popup.js
#	new file:   assets/js/tabs.js
#	new file:   assets/webfonts/fa-brands-400.ttf
#	new file:   assets/webfonts/fa-brands-400.woff2
#	new file:   assets/webfonts/fa-regular-400.ttf
#	new file:   assets/webfonts/fa-regular-400.woff2
#	new file:   assets/webfonts/fa-solid-900.ttf
#	new file:   assets/webfonts/fa-solid-900.woff2
#	new file:   assets/webfonts/fa-v4compatibility.ttf
#	new file:   assets/webfonts/fa-v4compatibility.woff2
#	new file:   dashboard.php
#	new file:   index.php
#	new file:   login.php
#	new file:   logout.php
#	new file:   magick
#	new file:   register.php
#	new file:   vendor/bootstrap/css/bootstrap.min.css
#	new file:   vendor/bootstrap/js/bootstrap.min.js
#	new file:   vendor/jquery/jquery.js
#	new file:   vendor/jquery/jquery.min.js
#	new file:   vendor/jquery/jquery.min.map
#	new file:   vendor/jquery/jquery.slim.js
#	new file:   vendor/jquery/jquery.slim.min.js
#	new file:   vendor/jquery/jquery.slim.min.map
#
```

There are a few automated tools to rebuild .git repos from a public site, however a lot of them rely on the page having readable directories which when the site blocks these attempts fails so i think i'll attempt to create one from scratch which only uses static readable files which i assume it can access.

# Assess

## Automated .git directory rebuilding 
As previously mentioned there are a few tools which can help rebuild a .git repo from scratch but i'm trying to test myself so i ended up writing my own at about 80 lines. 

It's a pretty simple challenge which you from a few static files use gits own utility to generate the hashes of missing files, which gives a path to the remote repo to download. Finally using git ls-files and git checkout `filename` is enough to recreate the source from scratch.

# Exploit
## Automated .git scraping
```
python3 ./git-rebuild.py http://pilgrimage.htb/.git/
Initializing folder...
hint: Using 'master' as the name for the initial branch. This default branch name
hint: is subject to change. To configure the initial branch name to use in all
hint: of your new repositories, which will suppress this warning, call:
hint: 
hint:   git config --global init.defaultBranch <name>
hint: 
hint: Names commonly chosen instead of 'master' are 'main', 'trunk' and
hint: 'development'. The just-created branch can be renamed via this command:
hint: 
hint:   git branch -m <name>
Initialized empty Git repository in /home/elliot/Development/Security/PY/git-rebuilder/pilgrimage.htb/.git/
Collecting static files from remote .git repo...
getting... http://pilgrimage.htb/.git/HEAD
getting... http://pilgrimage.htb/.git/config
getting... http://pilgrimage.htb/.git/index
getting... http://pilgrimage.htb/.git/.gitignore
HTTP Error 404: Not Found
Reading refs location...
refs/heads/master

http://pilgrimage.htb/.git/refs/heads/master

getting... http://pilgrimage.htb/.git/refs/heads/master

Reading initial hash...
e1a40beebc7035212efdcb15476f9c994e3634a7
Getting hash file...
getting... http://pilgrimage.htb/.git/objects/e1/a40beebc7035212efdcb15476f9c994e3634a7
using git to find missing hashes...
File List:

['assets/bulletproof.php', 'assets/css/animate.css', 'assets/css/custom.css', 'assets/css/flex-slider.css', 'assets/css/fontawesome.css', 'assets/css/owl.css', 'assets/css/templatemo-woox-travel.css', 'assets/images/banner-04.jpg', 'assets/images/cta-bg.jpg', 'assets/js/custom.js', 'assets/js/isotope.js', 'assets/js/isotope.min.js', 'assets/js/owl-carousel.js', 'assets/js/popup.js', 'assets/js/tabs.js', 'assets/webfonts/fa-brands-400.ttf', 'assets/webfonts/fa-brands-400.woff2', 'assets/webfonts/fa-regular-400.ttf', 'assets/webfonts/fa-regular-400.woff2', 'assets/webfonts/fa-solid-900.ttf', 'assets/webfonts/fa-solid-900.woff2', 'assets/webfonts/fa-v4compatibility.ttf', 'assets/webfonts/fa-v4compatibility.woff2', 'dashboard.php', 'index.php', 'login.php', 'logout.php', 'magick', 'register.php', 'vendor/bootstrap/css/bootstrap.min.css', 'vendor/bootstrap/js/bootstrap.min.js', 'vendor/jquery/jquery.js', 'vendor/jquery/jquery.min.js', 'vendor/jquery/jquery.min.map', 'vendor/jquery/jquery.slim.js', 'vendor/jquery/jquery.slim.min.js', 'vendor/jquery/jquery.slim.min.map', '']
Getting Listed files... (This is the loud part so i'll let you stop here if you want..)

...

assets/js/custom.js
assets/js/isotope.js
assets/js/isotope.min.js
assets/js/owl-carousel.js
assets/js/popup.js
assets/js/tabs.js
assets/webfonts/fa-brands-400.ttf
assets/webfonts/fa-brands-400.woff2
assets/webfonts/fa-regular-400.ttf
assets/webfonts/fa-regular-400.woff2
assets/webfonts/fa-solid-900.ttf
assets/webfonts/fa-solid-900.woff2
assets/webfonts/fa-v4compatibility.ttf
assets/webfonts/fa-v4compatibility.woff2
dashboard.php
index.php
login.php
logout.php
magick
register.php
vendor/bootstrap/css/bootstrap.min.css
vendor/bootstrap/js/bootstrap.min.js
vendor/jquery/jquery.js
vendor/jquery/jquery.min.js
vendor/jquery/jquery.min.map
vendor/jquery/jquery.slim.js
vendor/jquery/jquery.slim.min.js
vendor/jquery/jquery.slim.min.map

Rebuild finished. Please check folder now.
```
Completed source code retrieval.
# Review
## .git rebuilding
It was a pretty simple challenge to rebuild the git repo even though directory viewing was turned off. It'll also made me think twice about simply leaving source material hanging around on production environments..

Now i have source code i will need to [investigate](#investigate) to see if there are any vulnerabilities.