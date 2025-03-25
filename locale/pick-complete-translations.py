#!/usr/bin/python3
#
# add completed translations from weblate to MANIFEST.in

import git
import json
import os
import re
import requests
import subprocess


projectbasedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
localedir = os.path.join(projectbasedir, 'locale')
print(projectbasedir)

cached_file = os.path.join(localedir, 'fdroidserver.json')
if os.path.exists(cached_file):
    with open(cached_file) as fp:
        data = json.load(fp)
else:
    url = 'https://hosted.weblate.org/api/components/f-droid/fdroidserver/statistics/?format=json'
    r = requests.get(url)
    r.raise_for_status()
    data = r.json()['results']

active = set()
print('name                               locale   translated approved error-free')
for locale in sorted(data, key=lambda locale: locale['code']):
    print(
        '%26s' % locale['name'],
        '%8s' % locale['code'],
        '%0.1f%%' % locale['translated_percent'],
        '%0.1f%%' % locale['approved_percent'],
        '%0.1f%%' % (100 - locale['failing_percent']),
        sep='\t',
    )
    if locale['translated_percent'] >= 90 and locale['failing'] < 5:
        active.add(locale['code'])

manifest_file = os.path.join(projectbasedir, 'MANIFEST.in')
with open(manifest_file) as fp:
    manifest_in = fp.read()
for m in re.findall(r'include locale/([^/]+)/LC_MESSAGES/fdroidserver.po', manifest_in):
    active.add(m)

repo = git.Repo(projectbasedir)
weblate = repo.remotes.weblate
weblate.fetch()
upstream = repo.remotes.upstream
upstream.fetch()

if 'merge_weblate' in repo.heads:
    merge_weblate = repo.heads['merge_weblate']
    repo.create_tag(
        'previous_merge_weblate',
        ref=merge_weblate,
        message=('Automatically created by %s' % __file__),
    )
else:
    merge_weblate = repo.create_head('merge_weblate')
merge_weblate.set_commit(upstream.refs.master)
merge_weblate.checkout()

active = sorted(active)
manifest_lines = set()
for locale in active:
    po_file = f'locale/{locale}/LC_MESSAGES/fdroidserver.po'
    manifest_lines.add(f'include {po_file}\n')
    for commit in repo.iter_commits(
        str(weblate.refs.master) + '...' + str(upstream.refs.master),
        paths=[po_file],
        max_count=10,
        reverse=True,
    ):
        print(f'{locale}: git cherry-pick', commit)
        repo.git.cherry_pick(commit)

with open(manifest_file, 'a') as fp:
    for line in manifest_lines:
        if line:
            fp.write(line)

# first filter duplicates
subprocess.run(['sort', '-u', '-o', manifest_file, manifest_file])
# then use a stable sort order
subprocess.run(
    ['sort', '--ignore-case', '--stable', '-o', manifest_file, manifest_file],
    env={'LC_ALL': 'C'},
)

print('\tIf all else fails, try:')
print('\tgit checkout -B merge_weblate weblate/master')
print('\tgit rebase -i upstream/master')
print('\t# select all in editor and cut all commit lines')
print('\twl-paste | grep -Eo ".* \((%s)\) .*" | wl-copy' % '|'.join(active))
print('\t# paste into editor, and make rebase\n')
