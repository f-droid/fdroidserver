#!/usr/bin/env python3
#
# implementing a version check of known bad OpenSSL versions, for example:
# https://support.google.com/faqs/answer/6376725?hl=en
#
# This is used in update.has_known_vulnerability()

import re
import requests

# this list was generated using:
# for f in `curl  | grep -Eo '[0-9]\.[0-9]\.[0-9][a-z]?' | sort -u`; do echo "'$f',"; done
versions = [
]

r = requests.get('https://www.openssl.org/news/changelog.html', timeout=300)

safe = set()
bad = set()

for m in re.findall(b'[0-9]\.[0-9]\.[0-9][a-z]?', r.content):
    version = str(m, encoding='utf-8')
    if (version.startswith('1.0.1') and len(version) > 5 and version[5] >= 'r') \
      or (version.startswith('1.0.2') and len(version) > 5 and version[5] >= 'f') \
      or re.match(r'[1-9]\.[1-9]\.[0-9].*', version):
        safe.add(version)
    else:
        bad.add(version)

print('safe:', sorted(safe))
print('bad:', sorted(bad))
