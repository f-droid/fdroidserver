#!/usr/bin/env python3

import os
import re
import requests
import subprocess
import sys
from colorama import Fore, Style
from packaging.version import Version


checksums = None
versions = dict()

while not checksums:
    r = requests.get(
        'https://gitlab.com/fdroid/gradle-transparency-log/-/raw/master/checksums.json',
        timeout=300,
    )
    if r.status_code == 200:
        checksums = r.json()

gradle_bin_pat = re.compile(r'gradle-([0-9][0-9.]+[0-9])-bin.zip')
for url, d in checksums.items():
    m = gradle_bin_pat.search(url)
    if m:
        versions[m.group(1)] = d[0]['sha256']

errors = 0
makebuildserver = os.path.join(os.path.dirname(__file__), os.pardir, 'makebuildserver')
with open(makebuildserver) as fp:
    makebuildserver_current = fp.read()
to_compile = re.search(r'CACHE_FILES = [^\]]+\]', makebuildserver_current).group()
code = compile(to_compile, makebuildserver, 'exec')
config = {}
exec(code, None, config)  # nosec this is just a CI script
makebuildserver_versions = []
version_pat = re.compile(r'[0-9]+(\.[0-9]+)+')
for url, checksum in config['CACHE_FILES']:
    if 'gradle.org' in url:
        m = version_pat.search(url.split('/')[-1])
        if m:
            makebuildserver_versions.append(m.group())
            if checksum != versions[m.group()]:
                print(Fore.RED
                      + 'ERROR: checksum mismatch:', checksum, versions[m.group()]
                      + Style.RESET_ALL)
                errors += 1

# error if makebuildserver is missing the latest version
for version in sorted(versions.keys()):
    if version not in makebuildserver_versions \
       and Version(version) > Version(sorted(makebuildserver_versions)[-1]):
        add_before = """    ('https://dl.google.com/android/ndk/android-ndk-r10e-linux-x86_64.bin',"""
        new = to_compile.replace(
            add_before,
            "    ('https://services.gradle.org/distributions/gradle-" + version + "-bin.zip',\n"
            "     '" + versions[version] + "'),\n" + add_before
        )
        makebuildserver_current = makebuildserver_current.replace(to_compile, new)

with open('makebuildserver', 'w') as fp:
    fp.write(makebuildserver_current)

p = subprocess.run(['git', '--no-pager', 'diff'])
errors += p.returncode
sys.exit(errors)
