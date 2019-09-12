#!/usr/bin/env python3

import os
import re
import requests
import sys
from bs4 import BeautifulSoup
from distutils.version import LooseVersion

while True:
    r = requests.get('https://gradle.org/release-checksums/')
    if r.status_code == 200:
        break

soup = BeautifulSoup(r.text, 'html.parser')

version_pat = re.compile(r'[0-9]+(\.[0-9]+)+')

versions = dict()
for a in soup.find_all('a'):
    if a.parent.name != 'p':
        continue
    name = a.get('name')
    if not name:
        continue
    m = version_pat.search(name)
    if m:
        ul = a.parent.find_next_sibling('ul')
        versions[m.group()] = a.parent.find_next_sibling('ul').find('li').find('code').text.strip()

errors = 0
makebuildserver = os.path.join(os.path.dirname(__file__), os.pardir, 'makebuildserver')
with open(makebuildserver) as fp:
    contents = fp.read()
to_compile = re.search(r'CACHE_FILES = [^\]]+\]', contents, flags=re.DOTALL | re.MULTILINE).group()
code = compile(to_compile, makebuildserver, 'exec')
config = {}
exec(code, None, config)  # nosec this is just a CI script
makebuildserver_versions = []
for url, checksum in config['CACHE_FILES']:
    if 'gradle.org' in url:
        m = version_pat.search(url.split('/')[-1])
        if m:
            makebuildserver_versions.append(m.group())
            if checksum != versions[m.group()]:
                print('ERROR: checksum mismatch:', checksum, versions[m.group()])
                errors += 1

# error if makebuildserver is missing the latest version
for version in sorted(versions.keys()):
    if version not in makebuildserver_versions \
       and LooseVersion(version) > LooseVersion(sorted(makebuildserver_versions)[-1]):
        errors += 1
        print("    ('https://services.gradle.org/distributions/gradle-" + version + "-bin.zip',\n"
              "     '" + versions[version] + "'),")

print('makebuildserver has gradle v' + sorted(makebuildserver_versions)[-1])
sys.exit(errors)
