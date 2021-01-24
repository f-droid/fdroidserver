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
    makebuildserver_current = fp.read()
to_compile = re.search(r'CACHE_FILES = [^\]]+\]', makebuildserver_current).group()
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
        add_before = """    ('https://dl.google.com/android/ndk/android-ndk-r10e-linux-x86_64.bin',"""
        new = to_compile.replace(
            add_before,
            "    ('https://services.gradle.org/distributions/gradle-" + version + "-bin.zip',\n"
            "     '" + versions[version] + "'),\n" + add_before
        )
        makebuildserver_current = makebuildserver_current.replace(to_compile, new)

with open('makebuildserver', 'w') as fp:
    fp.write(makebuildserver_current)

# write out update to gradlew-fdroid
with open('gradlew-fdroid') as fp:
    gradlew_fdroid = fp.read()
current = ''
get_sha_pat = re.compile(r""" +'([0-9][0-9.]+[0-9])'\)\s+echo '([0-9a-f]{64})' ;;\n""")
for m in get_sha_pat.finditer(gradlew_fdroid):
    current += m.group()
new = ''
for version in sorted(versions.keys(), key=LooseVersion):
    sha256 = versions[version]
    spaces = ''
    for i in range(6 - len(version)):
        spaces += ' '
    new += """        '%s')%s echo '%s' ;;\n""" % (version, spaces, sha256)
gradlew_fdroid = gradlew_fdroid.replace(current, new)
plugin_v = ' '.join(sorted(versions.keys(), key=LooseVersion, reverse=True))
plugin_v_pat = re.compile(r'\nplugin_v=\(([0-9. ]+)\)')
with open('gradlew-fdroid', 'w') as fp:
    fp.write(plugin_v_pat.sub('\nplugin_v=(%s)' % plugin_v, gradlew_fdroid))

print('makebuildserver has gradle v' + sorted(makebuildserver_versions)[-1])
sys.exit(errors)
