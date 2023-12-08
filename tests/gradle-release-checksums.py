#!/usr/bin/env python3

import git
import gitlab
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

# write out update to gradlew-fdroid
with open('gradlew-fdroid') as fp:
    gradlew_fdroid = fp.read()
current = ''
get_sha_pat = re.compile(r""" +'([0-9][0-9.]+[0-9])'\)\s+echo '([0-9a-f]{64})' ;;\n""")
for m in get_sha_pat.finditer(gradlew_fdroid):
    current += m.group()
    checksum = m.group(2)
    if checksum != versions[m.group(1)]:
        print(Fore.RED
              + 'ERROR: checksum mismatch:', checksum, versions[m.group(1)]
              + Style.RESET_ALL)
        errors += 1
new = ''
for version in sorted(versions.keys(), key=Version):
    sha256 = versions[version]
    spaces = ''
    for i in range(6 - len(version)):
        spaces += ' '
    new += """        '%s')%s echo '%s' ;;\n""" % (version, spaces, sha256)
gradlew_fdroid = gradlew_fdroid.replace(current, new)
plugin_v = ' '.join(sorted(versions.keys(), key=Version, reverse=True))
plugin_v_pat = re.compile(r'\nplugin_v=\(([0-9. ]+)\)')
with open('gradlew-fdroid', 'w') as fp:
    fp.write(plugin_v_pat.sub('\nplugin_v=(%s)' % plugin_v, gradlew_fdroid))

if os.getenv('CI_PROJECT_NAMESPACE') != 'fdroid':
    p = subprocess.run(['git', '--no-pager', 'diff'])
    print(p.stdout)
    sys.exit(errors)

# This only runs after commits are pushed to fdroid/fdroidserver
git_repo = git.repo.Repo('.')
modified = git_repo.git().ls_files(modified=True).split()
if git_repo.is_dirty() and ('gradlew-fdroid' in modified or 'makebuildserver' in modified):
    private_token = os.getenv('PERSONAL_ACCESS_TOKEN')
    if not private_token:
        print(Fore.RED
              + 'ERROR: GitLab Token not found in PERSONAL_ACCESS_TOKEN!'
              + Style.RESET_ALL)
        sys.exit(1)

    branch = git_repo.create_head(os.path.basename(__file__), force=True)
    branch.checkout()
    git_repo.index.add(['gradlew-fdroid', 'makebuildserver'])
    author = git.Actor('fdroid-bot', 'fdroid-bot@f-droid.org')
    git_repo.index.commit('gradle v' + version, author=author)
    project_path = 'fdroid-bot/' + os.getenv('CI_PROJECT_NAME')
    url = ('https://gitlab-ci-token:%s@%s/%s.git'
           % (os.getenv('PERSONAL_ACCESS_TOKEN'), os.getenv('CI_SERVER_HOST'), project_path))
    remote_name = 'fdroid-bot'
    try:
        remote = git_repo.create_remote(remote_name, url)
    # See https://github.com/PyCQA/pylint/issues/2856 .
    # pylint: disable-next=no-member
    except git.exc.GitCommandError:
        remote = git.remote.Remote(git_repo, remote_name)
        remote.set_url(url)
    remote.push(force=True)
    git.remote.Remote.rm(git_repo, remote_name)

    gl = gitlab.Gitlab(os.getenv('CI_SERVER_URL'), api_version=4,
                       private_token=private_token)
    project = gl.projects.get(project_path, lazy=True)
    description = (
        'see <https://gitlab.com/fdroid/gradle-transparency-log/-/blob/master/checksums.json>'
        '\n\n<p><small>generated by <a href="%s/-/jobs/%s">GitLab CI Job #%s</a></small></p>'
        % (os.getenv('CI_PROJECT_URL'), os.getenv('CI_JOB_ID'), os.getenv('CI_JOB_ID'))
    )
    try:
        mr = project.mergerequests.create({
            'source_branch': branch.name,
            'target_project_id': 36527,  # fdroid/fdroidserver
            'target_branch': 'master',
            'title': 'update to gradle v' + version,
            'description': description,
            'labels': ['fdroid-bot', 'gradle'],
            'remove_source_branch': True,
        })
        mr.save()
    except gitlab.exceptions.GitlabCreateError as e:
        if e.response_code == 409:  # Another open merge request already exists for this source branch
            print(e.error_message)
        else:
            raise e
