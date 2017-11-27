#!/usr/bin/env python3
#
# nightly.py - part of the FDroid server tools
# Copyright (C) 2017 Hans-Christoph Steiner <hans@eds.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import base64
import datetime
import git
import hashlib
import logging
import os
import paramiko
import platform
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlparse
from argparse import ArgumentParser

from . import _
from . import common


# hard coded defaults for Android ~/.android/debug.keystore files
# https://developers.google.com/android/guides/client-auth
KEYSTORE_FILE = os.path.join(os.getenv('HOME'), '.android', 'debug.keystore')
PASSWORD = 'android'
KEY_ALIAS = 'androiddebugkey'
DISTINGUISHED_NAME = 'CN=Android Debug,O=Android,C=US'

# standard suffix for naming fdroid git repos
NIGHTLY = '-nightly'


def _ssh_key_from_debug_keystore():
    tmp_dir = tempfile.mkdtemp(prefix='.')
    privkey = os.path.join(tmp_dir, '.privkey')
    key_pem = os.path.join(tmp_dir, '.key.pem')
    p12 = os.path.join(tmp_dir, '.keystore.p12')
    subprocess.check_call([common.config['keytool'], '-importkeystore',
                           '-srckeystore', KEYSTORE_FILE, '-srcalias', KEY_ALIAS,
                           '-srcstorepass', PASSWORD, '-srckeypass', PASSWORD,
                           '-destkeystore', p12, '-destalias', KEY_ALIAS,
                           '-deststorepass', PASSWORD, '-destkeypass', PASSWORD,
                           '-deststoretype', 'PKCS12'])
    subprocess.check_call(['openssl', 'pkcs12', '-in', p12, '-out', key_pem,
                           '-passin', 'pass:' + PASSWORD, '-passout', 'pass:' + PASSWORD])
    subprocess.check_call(['openssl', 'rsa', '-in', key_pem, '-out', privkey,
                           '-passin', 'pass:' + PASSWORD])
    os.remove(key_pem)
    os.remove(p12)
    os.chmod(privkey, 0o600)  # os.umask() should cover this, but just in case

    rsakey = paramiko.RSAKey.from_private_key_file(privkey)
    fingerprint = base64.b64encode(hashlib.sha256(rsakey.asbytes()).digest()).decode('ascii').rstrip('=')
    ssh_private_key_file = os.path.join(tmp_dir, 'debug_keystore_' + fingerprint + '_id_rsa')
    os.rename(privkey, ssh_private_key_file)

    pub = rsakey.get_name() + ' ' + rsakey.get_base64() + ' ' + ssh_private_key_file
    with open(ssh_private_key_file + '.pub', 'w') as fp:
        fp.write(pub)

    logging.info(_('\nSSH Public Key to be used as Deploy Key:') + '\n' + pub)

    return ssh_private_key_file


def main():

    parser = ArgumentParser(usage="%(prog)s")
    common.setup_global_opts(parser)
    parser.add_argument("--show-secret-var", action="store_true", default=False,
                        help=_("Print the secret variable to the terminal for easy copy/paste"))
    parser.add_argument("--file", default='app/build/outputs/apk/*.apk',
                        help=_('The the file to be included in the repo (path or glob)'))
    parser.add_argument("--no-checksum", action="store_true", default=False,
                        help=_("Don't use rsync checksums"))
    # TODO add --with-btlog
    options = parser.parse_args()
    common.read_config(None)

    # force a tighter umask since this writes private key material
    umask = os.umask(0o077)

    if 'CI' in os.environ:
        v = os.getenv('DEBUG_KEYSTORE')
        debug_keystore = None
        if v:
            debug_keystore = base64.b64decode(v)
        if not debug_keystore:
            logging.error(_('DEBUG_KEYSTORE is not set or the value is incomplete'))
            sys.exit(1)
        os.makedirs(os.path.dirname(KEYSTORE_FILE), exist_ok=True)
        if os.path.exists(KEYSTORE_FILE):
            logging.warning(_('overwriting existing {path}').format(path=KEYSTORE_FILE))
        with open(KEYSTORE_FILE, 'wb') as fp:
            fp.write(debug_keystore)

        repo_basedir = os.path.join(os.getcwd(), 'fdroid')
        repodir = os.path.join(repo_basedir, 'repo')
        cibase = os.getcwd()
        os.makedirs(repodir, exist_ok=True)

        if 'CI_PROJECT_PATH' in os.environ and 'CI_PROJECT_URL' in os.environ:
            # we are in GitLab CI
            repo_git_base = os.getenv('CI_PROJECT_PATH') + NIGHTLY
            clone_url = os.getenv('CI_PROJECT_URL') + NIGHTLY
            repo_base = clone_url + '/raw/master/fdroid'
            servergitmirror = 'git@' + urlparse(clone_url).netloc + ':' + repo_git_base
            deploy_key_url = clone_url + '/settings/repository'
            git_user_name = os.getenv('GITLAB_USER_NAME')
            git_user_email = os.getenv('GITLAB_USER_EMAIL')
        elif 'TRAVIS_REPO_SLUG' in os.environ:
            # we are in Travis CI
            repo_git_base = os.getenv('TRAVIS_REPO_SLUG') + NIGHTLY
            clone_url = 'https://github.com/' + repo_git_base
            _branch = os.getenv('TRAVIS_BRANCH')
            repo_base = 'https://raw.githubusercontent.com/' + repo_git_base + '/' + _branch + '/fdroid'
            servergitmirror = 'git@github.com:' + repo_git_base
            deploy_key_url = ('https://github.com/' + repo_git_base + '/settings/keys'
                              + '\nhttps://developer.github.com/v3/guides/managing-deploy-keys/#deploy-keys')
            git_user_name = repo_git_base
            git_user_email = os.getenv('USER') + '@' + platform.node()
        elif 'CIRCLE_REPOSITORY_URL' in os.environ \
             and 'CIRCLE_PROJECT_USERNAME' in os.environ \
             and 'CIRCLE_PROJECT_REPONAME' in os.environ:
            # we are in Circle CI
            repo_git_base = (os.getenv('CIRCLE_PROJECT_USERNAME')
                             + '/' + os.getenv('CIRCLE_PROJECT_REPONAME') + NIGHTLY)
            clone_url = os.getenv('CIRCLE_REPOSITORY_URL') + NIGHTLY
            repo_base = clone_url + '/raw/master/fdroid'
            servergitmirror = 'git@' + urlparse(clone_url).netloc + ':' + repo_git_base
            deploy_key_url = ('https://github.com/' + repo_git_base + '/settings/keys'
                              + '\nhttps://developer.github.com/v3/guides/managing-deploy-keys/#deploy-keys')
            git_user_name = os.getenv('CIRCLE_USERNAME')
            git_user_email = git_user_name + '@' + platform.node()
        else:
            print(_('ERROR: unsupported CI type, patches welcome!'))
            sys.exit(1)

        repo_url = repo_base + '/repo'
        git_mirror_path = os.path.join(repo_basedir, 'git-mirror')
        git_mirror_repodir = os.path.join(git_mirror_path, 'fdroid', 'repo')
        if not os.path.isdir(git_mirror_repodir):
            logging.debug(_('cloning {url}').format(url=clone_url))
            try:
                git.Repo.clone_from(clone_url, git_mirror_path)
            except Exception:
                pass
        if not os.path.isdir(git_mirror_repodir):
            os.makedirs(git_mirror_repodir, mode=0o755)

        mirror_git_repo = git.Repo.init(git_mirror_path)
        writer = mirror_git_repo.config_writer()
        writer.set_value('user', 'name', git_user_name)
        writer.set_value('user', 'email', git_user_email)
        writer.release()
        for remote in mirror_git_repo.remotes:
            mirror_git_repo.delete_remote(remote)

        readme_path = os.path.join(git_mirror_path, 'README.md')
        readme = '''
# {repo_git_base}

[![{repo_url}](icon.png)]({repo_url})

Last updated: {date}'''.format(repo_git_base=repo_git_base,
                               repo_url=repo_url,
                               date=datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))
        with open(readme_path, 'w') as fp:
            fp.write(readme)
        mirror_git_repo.git.add(all=True)
        mirror_git_repo.index.commit("update README")

        icon_path = os.path.join(repo_basedir, 'icon.png')
        try:
            import qrcode
            img = qrcode.make('Some data here')
            with open(icon_path, 'wb') as fp:
                fp.write(img)
        except Exception:
            exampleicon = os.path.join(common.get_examples_dir(), 'fdroid-icon.png')
            shutil.copy(exampleicon, icon_path)
        mirror_git_repo.git.add(all=True)
        mirror_git_repo.index.commit("update repo/website icon")

        os.chdir(repo_basedir)
        common.local_rsync(options, git_mirror_repodir + '/', 'repo/')

        ssh_private_key_file = _ssh_key_from_debug_keystore()
        # this is needed for GitPython to find the SSH key
        ssh_dir = os.path.join(os.getenv('HOME'), '.ssh')
        os.makedirs(ssh_dir, exist_ok=True)
        ssh_config = os.path.join(ssh_dir, 'config')
        logging.debug(_('adding IdentityFile to {path}').format(path=ssh_config))
        with open(ssh_config, 'a') as fp:
            fp.write('\n\nHost *\n\tIdentityFile %s\n' % ssh_private_key_file)

        config = ''
        config += "identity_file = '%s'\n" % ssh_private_key_file
        config += "repo_name = '%s'\n" % repo_git_base
        config += "repo_url = '%s'\n" % repo_url
        config += "repo_icon = 'icon.png'\n"
        config += "archive_name = '%s'\n" % (repo_git_base + ' archive')
        config += "archive_url = '%s'\n" % (repo_base + '/archive')
        config += "archive_icon = 'icon.png'\n"
        config += "servergitmirrors = '%s'\n" % servergitmirror
        config += "keystore = '%s'\n" % KEYSTORE_FILE
        config += "repo_keyalias = '%s'\n" % KEY_ALIAS
        config += "keystorepass = '%s'\n" % PASSWORD
        config += "keypass = '%s'\n" % PASSWORD
        config += "keydname = '%s'\n" % DISTINGUISHED_NAME
        config += "make_current_version_link = False\n"
        config += "accepted_formats = ('txt', 'yml')\n"
        # TODO add update_stats = True
        with open('config.py', 'w') as fp:
            fp.write(config)
        os.chmod('config.py', 0o600)

        for root, dirs, files in os.walk(cibase):
            for d in ('fdroid', '.git', '.gradle'):
                if d in dirs:
                    dirs.remove(d)
            for f in files:
                if f.endswith('-debug.apk'):
                    apkfilename = os.path.join(root, f)
                    logging.debug(_('copying {apkfilename} into {path}')
                                  .format(apkfilename=apkfilename, path=repodir))
                    destapk = os.path.join(repodir, os.path.basename(f))
                    shutil.copyfile(apkfilename, destapk)
                    shutil.copystat(apkfilename, destapk)
                    os.chmod(destapk, 0o644)

        if options.verbose:
            logging.debug(_('attempting bare ssh connection to test deploy key:'))
            try:
                subprocess.check_call(['ssh', '-Tvi', ssh_private_key_file,
                                       '-oIdentitiesOnly=yes', '-oStrictHostKeyChecking=no',
                                       servergitmirror.split(':')[0]])
            except subprocess.CalledProcessError:
                pass

        subprocess.check_call(['fdroid', 'update', '--rename-apks', '--verbose'], cwd=repo_basedir)
        try:
            subprocess.check_call(['fdroid', 'server', 'update', '--verbose'], cwd=repo_basedir)
        except subprocess.CalledProcessError:
            logging.error(_('cannot publish update, did you set the deploy key?')
                          + '\n' + deploy_key_url)
            sys.exit(1)
        if shutil.rmtree.avoids_symlink_attacks:
            shutil.rmtree(os.path.dirname(ssh_private_key_file))

    else:
        ssh_dir = os.path.join(os.getenv('HOME'), '.ssh')
        os.makedirs(os.path.dirname(ssh_dir), exist_ok=True)
        privkey = _ssh_key_from_debug_keystore()
        ssh_private_key_file = os.path.join(ssh_dir, os.path.basename(privkey))
        os.rename(privkey, ssh_private_key_file)
        os.rename(privkey + '.pub', ssh_private_key_file + '.pub')
        if shutil.rmtree.avoids_symlink_attacks:
            shutil.rmtree(os.path.dirname(privkey))

        if options.show_secret_var:
            with open(KEYSTORE_FILE, 'rb') as fp:
                debug_keystore = base64.standard_b64encode(fp.read()).decode('ascii')
            print(_('\n{path} encoded for the DEBUG_KEYSTORE secret variable:')
                  .format(path=KEYSTORE_FILE))
            print(debug_keystore)

    os.umask(umask)


if __name__ == "__main__":
    main()
