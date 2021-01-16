#!/usr/bin/python3
#
# add completed translations from weblate to MANIFEST.in

import json
import os
import re
import requests
import sys


projectbasedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
localedir = os.path.join(projectbasedir, 'locale')
print(projectbasedir)

cached_file = os.path.join(localedir, 'fdroidserver.json')
if os.path.exists(cached_file):
    with open(cached_file) as fp:
        data = json.load(fp)
else:
    url = 'https://hosted.weblate.org/exports/stats/f-droid/fdroidserver/?format=json'
    r = requests.get(url)
    r.raise_for_status()
    data = r.json()

active = set()
print('name                               locale   translated approved error-free')
for locale in sorted(data, key=lambda locale: locale['code']):
    print('%26s' % locale['name'],
          '%8s' % locale['code'],
          '%0.1f%%' % locale['translated_percent'],
          '%0.1f%%' % locale['approved_percent'],
          '%0.1f%%' % (100 - locale['failing_percent']),
          sep='\t')
    if locale['translated_percent'] >= 90 and locale['failing'] < 5:
        active.add(locale['code'])

manifest_file = os.path.join(projectbasedir, 'MANIFEST.in')
with open(manifest_file) as fp:
    for line in fp.readlines():
        m = re.match(r'include locale/([^/]+)/.*', line)
        if m:
            active.add(m.group(1))

manifest_lines = set()
for locale in active:
    manifest_lines.add('include locale/%s/LC_MESSAGES/fdroidserver.mo\n' % locale)

with open(manifest_file, 'a') as fp:
    for line in manifest_lines:
        if line:
            fp.write(line)

os.system('sort -u -o %s %s' % (manifest_file, manifest_file))
