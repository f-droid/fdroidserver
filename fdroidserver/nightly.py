#!/usr/bin/env python3
"""Set up an app build for a nightly build repo."""
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
import ssl
import subprocess
import sys
import tempfile
import yaml
from urllib.parse import urlparse
from argparse import ArgumentParser
from typing import Optional

from . import _
from . import common
from .exception import VCSException

# hard coded defaults for Android ~/.android/debug.keystore files
# https://developers.google.com/android/guides/client-auth
KEYSTORE_FILE = os.path.join(os.getenv('HOME'), '.android', 'debug.keystore')
PASSWORD = 'android'  # nosec B105 standard hardcoded password for debug keystores
KEY_ALIAS = 'androiddebugkey'
DISTINGUISHED_NAME = 'CN=Android Debug,O=Android,C=US'

# standard suffix for naming fdroid git repos
NIGHTLY = '-nightly'


def _get_keystore_secret_var(keystore: str) -> str:
    """Get keystore secret as base64.

    Parameters
    ----------
    keystore
        The path of the keystore.

    Returns
    -------
    base64_secret
        The keystore secret as base64 string.
    """
    with open(keystore, 'rb') as fp:
        return base64.standard_b64encode(fp.read()).decode('ascii')


def _ssh_key_from_debug_keystore(keystore: Optional[str] = None) -> str:
    """Convert a debug keystore to an SSH private key.

    This leaves the original keystore file in place.

    Parameters
    ----------
    keystore
        The keystore to convert to a SSH private key.

    Returns
    -------
    key_path
        The SSH private key file path in the temporary directory.
    """
    if keystore is None:
        # set this here so it can be overridden in the tests
        # TODO convert this to a class to get rid of this nonsense
        keystore = KEYSTORE_FILE
    tmp_dir = tempfile.mkdtemp(prefix='.')
    privkey = os.path.join(tmp_dir, '.privkey')
    key_pem = os.path.join(tmp_dir, '.key.pem')
    p12 = os.path.join(tmp_dir, '.keystore.p12')
    _config = dict()
    common.fill_config_defaults(_config)
    subprocess.check_call(
        [
            _config['keytool'],
            '-importkeystore',
            '-srckeystore',
            keystore,
            '-srcalias',
            KEY_ALIAS,
            '-srcstorepass',
            PASSWORD,
            '-srckeypass',
            PASSWORD,
            '-destkeystore',
            p12,
            '-destalias',
            KEY_ALIAS,
            '-deststorepass',
            PASSWORD,
            '-destkeypass',
            PASSWORD,
            '-deststoretype',
            'PKCS12',
        ],
        env={'LC_ALL': 'C.UTF-8'},
    )
    subprocess.check_call(
        [
            'openssl',
            'pkcs12',
            '-in',
            p12,
            '-out',
            key_pem,
            '-passin',
            'pass:' + PASSWORD,
            '-passout',
            'pass:' + PASSWORD,
        ],
        env={'LC_ALL': 'C.UTF-8'},
    )

    # OpenSSL 3.0 changed the default output format from PKCS#1 to
    # PKCS#8, which paramiko does not support.
    # https://www.openssl.org/docs/man3.0/man1/openssl-rsa.html#traditional
    # https://github.com/paramiko/paramiko/issues/1015
    openssl_rsa_cmd = ['openssl', 'rsa']
    if ssl.OPENSSL_VERSION_INFO[0] >= 3:
        openssl_rsa_cmd += ['-traditional']
    subprocess.check_call(
        openssl_rsa_cmd
        + [
            '-in',
            key_pem,
            '-out',
            privkey,
            '-passin',
            'pass:' + PASSWORD,
        ],
        env={'LC_ALL': 'C.UTF-8'},
    )
    os.remove(key_pem)
    os.remove(p12)
    os.chmod(privkey, 0o600)  # os.umask() should cover this, but just in case

    rsakey = paramiko.RSAKey.from_private_key_file(privkey)
    fingerprint = (
        base64.b64encode(hashlib.sha256(rsakey.asbytes()).digest())
        .decode('ascii')
        .rstrip('=')
    )
    ssh_private_key_file = os.path.join(
        tmp_dir, 'debug_keystore_' + fingerprint.replace('/', '_') + '_id_rsa'
    )
    shutil.move(privkey, ssh_private_key_file)

    pub = rsakey.get_name() + ' ' + rsakey.get_base64() + ' ' + ssh_private_key_file
    with open(ssh_private_key_file + '.pub', 'w') as fp:
        fp.write(pub)

    logging.info(_('\nSSH public key to be used as deploy key:') + '\n' + pub)

    return ssh_private_key_file


def get_repo_base_url(clone_url: str, repo_git_base: str, force_type: Optional[str] = None) -> str:
    """Generate the base URL for the F-Droid repository.

    Parameters
    ----------
    clone_url
        The URL to clone the Git repository.
    repo_git_base
        The project path of the Git repository at the Git forge.
    force_type
        The Git forge of the project.

    Returns
    -------
    repo_base_url
        The base URL of the F-Droid repository.
    """
    if force_type is None:
        force_type = urlparse(clone_url).netloc
    if force_type == 'gitlab.com':
        return clone_url + '/-/raw/master/fdroid'
    if force_type == 'github.com':
        return 'https://raw.githubusercontent.com/%s/master/fdroid' % repo_git_base
    print(_('ERROR: unsupported git host "%s", patches welcome!') % force_type)
    sys.exit(1)


def main():
    """Deploy to F-Droid repository or generate SSH private key from keystore.

    The behaviour of this function is influenced by the configuration file as
    well as command line parameters.

    Raises
    ------
    :exc:`~fdroidserver.exception.VCSException`
        If the nightly Git repository could not be cloned during an attempt to
        deploy.
    """
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument(
        "--keystore",
        default=KEYSTORE_FILE,
        help=_("Specify which debug keystore file to use."),
    )
    parser.add_argument(
        "--show-secret-var",
        action="store_true",
        default=False,
        help=_("Print the secret variable to the terminal for easy copy/paste"),
    )
    parser.add_argument(
        "--keep-private-keys",
        action="store_true",
        default=False,
        help=_("Do not remove the private keys generated from the keystore"),
    )
    parser.add_argument(
        "--no-deploy",
        action="store_true",
        default=False,
        help=_("Do not deploy the new files to the repo"),
    )
    parser.add_argument(
        "--file",
        default='app/build/outputs/apk/*.apk',
        help=_('The file to be included in the repo (path or glob)'),
    )
    parser.add_argument(
        "--no-checksum",
        action="store_true",
        default=False,
        help=_("Don't use rsync checksums"),
    )
    archive_older_unset = -1
    parser.add_argument(
        "--archive-older",
        type=int,
        default=archive_older_unset,
        help=_("Set maximum releases in repo before older ones are archived"),
    )
    # TODO add --with-btlog
    options = common.parse_args(parser)

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

        # the 'master' branch is hardcoded in fdroidserver/deploy.py
        if 'CI_PROJECT_PATH' in os.environ and 'CI_PROJECT_URL' in os.environ:
            # we are in GitLab CI
            repo_git_base = os.getenv('CI_PROJECT_PATH') + NIGHTLY
            clone_url = os.getenv('CI_PROJECT_URL') + NIGHTLY
            repo_base = get_repo_base_url(clone_url, repo_git_base, force_type='gitlab.com')
            servergitmirror = 'git@' + urlparse(clone_url).netloc + ':' + repo_git_base
            deploy_key_url = clone_url + '/-/settings/repository#js-deploy-keys-settings'
            git_user_name = os.getenv('GITLAB_USER_NAME')
            git_user_email = os.getenv('GITLAB_USER_EMAIL')
        elif 'TRAVIS_REPO_SLUG' in os.environ:
            # we are in Travis CI
            repo_git_base = os.getenv('TRAVIS_REPO_SLUG') + NIGHTLY
            clone_url = 'https://github.com/' + repo_git_base
            repo_base = get_repo_base_url(clone_url, repo_git_base, force_type='github.com')
            servergitmirror = 'git@github.com:' + repo_git_base
            deploy_key_url = ('https://github.com/' + repo_git_base + '/settings/keys'
                              + '\nhttps://developer.github.com/v3/guides/managing-deploy-keys/#deploy-keys')
            git_user_name = repo_git_base
            git_user_email = os.getenv('USER') + '@' + platform.node()
        elif (
            'CIRCLE_REPOSITORY_URL' in os.environ
            and 'CIRCLE_PROJECT_USERNAME' in os.environ
            and 'CIRCLE_PROJECT_REPONAME' in os.environ
        ):
            # we are in Circle CI
            repo_git_base = (os.getenv('CIRCLE_PROJECT_USERNAME')
                             + '/' + os.getenv('CIRCLE_PROJECT_REPONAME') + NIGHTLY)
            clone_url = os.getenv('CIRCLE_REPOSITORY_URL') + NIGHTLY
            repo_base = get_repo_base_url(clone_url, repo_git_base, force_type='github.com')
            servergitmirror = 'git@' + urlparse(clone_url).netloc + ':' + repo_git_base
            deploy_key_url = ('https://github.com/' + repo_git_base + '/settings/keys'
                              + '\nhttps://developer.github.com/v3/guides/managing-deploy-keys/#deploy-keys')
            git_user_name = os.getenv('CIRCLE_USERNAME')
            git_user_email = git_user_name + '@' + platform.node()
        elif 'GITHUB_ACTIONS' in os.environ:
            # we are in Github actions
            repo_git_base = (os.getenv('GITHUB_REPOSITORY') + NIGHTLY)
            clone_url = (os.getenv('GITHUB_SERVER_URL') + '/' + repo_git_base)
            repo_base = get_repo_base_url(clone_url, repo_git_base, force_type='github.com')
            servergitmirror = 'git@' + urlparse(clone_url).netloc + ':' + repo_git_base
            deploy_key_url = ('https://github.com/' + repo_git_base + '/settings/keys'
                              + '\nhttps://developer.github.com/v3/guides/managing-deploy-keys/#deploy-keys')
            git_user_name = os.getenv('GITHUB_ACTOR')
            git_user_email = git_user_name + '@' + platform.node()
        else:
            print(_('ERROR: unsupported CI type, patches welcome!'))
            sys.exit(1)

        repo_url = repo_base + '/repo'
        git_mirror_path = os.path.join(repo_basedir, 'git-mirror')
        git_mirror_fdroiddir = os.path.join(git_mirror_path, 'fdroid')
        git_mirror_repodir = os.path.join(git_mirror_fdroiddir, 'repo')
        git_mirror_metadatadir = os.path.join(git_mirror_fdroiddir, 'metadata')
        git_mirror_statsdir = os.path.join(git_mirror_fdroiddir, 'stats')
        if not os.path.isdir(git_mirror_repodir):
            logging.debug(_('cloning {url}').format(url=clone_url))
            vcs = common.getvcs('git', clone_url, git_mirror_path)
            p = vcs.git(['clone', '--', vcs.remote, str(vcs.local)])
            if p.returncode != 0:
                print('WARNING: only public git repos are supported!')
                raise VCSException('git clone %s failed:' % clone_url, p.output)
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

This is an app repository for nightly versions.
You can use it with the [F-Droid](https://f-droid.org/) Android app.

[![{repo_url}]({repo_url}/icons/icon.png)](https://fdroid.link/#{repo_url})

Last updated: {date}'''.format(repo_git_base=repo_git_base,
                               repo_url=repo_url,
                               date=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'))
        with open(readme_path, 'w') as fp:
            fp.write(readme)
        mirror_git_repo.git.add(all=True)
        mirror_git_repo.index.commit("update README")

        mirror_git_repo.git.add(all=True)
        mirror_git_repo.index.commit("update repo/website icon")

        os.chdir(repo_basedir)
        if os.path.isdir(git_mirror_repodir):
            common.local_rsync(options, [git_mirror_repodir + '/'], 'repo/')
        if os.path.isdir(git_mirror_metadatadir):
            common.local_rsync(options, [git_mirror_metadatadir + '/'], 'metadata/')
        if os.path.isdir(git_mirror_statsdir):
            common.local_rsync(options, [git_mirror_statsdir + '/'], 'stats/')

        ssh_private_key_file = _ssh_key_from_debug_keystore()
        # this is needed for GitPython to find the SSH key
        ssh_dir = os.path.join(os.getenv('HOME'), '.ssh')
        os.makedirs(ssh_dir, exist_ok=True)
        ssh_config = os.path.join(ssh_dir, 'config')
        logging.debug(_('adding IdentityFile to {path}').format(path=ssh_config))
        with open(ssh_config, 'a') as fp:
            fp.write('\n\nHost *\n\tIdentityFile %s\n' % ssh_private_key_file)

        if options.archive_older == archive_older_unset:
            fdroid_size = common.get_dir_size(git_mirror_fdroiddir)
            max_size = common.GITLAB_COM_PAGES_MAX_SIZE
            if fdroid_size < max_size:
                options.archive_older = 20
            else:
                options.archive_older = 3
                print(
                    'WARNING: repo is %s over the GitLab Pages limit (%s)'
                    % (fdroid_size - max_size, max_size)
                )
                print('Setting --archive-older to 3')

        config = {
            'identity_file': ssh_private_key_file,
            'repo_name': repo_git_base,
            'repo_url': repo_url,
            'repo_description': 'Nightly builds from %s' % git_user_email,
            'archive_name': repo_git_base + ' archive',
            'archive_url': repo_base + '/archive',
            'archive_description': 'Old nightly builds that have been archived.',
            'archive_older': options.archive_older,
            'servergitmirrors': [{"url": servergitmirror}],
            'keystore': KEYSTORE_FILE,
            'repo_keyalias': KEY_ALIAS,
            'keystorepass': PASSWORD,
            'keypass': PASSWORD,
            'keydname': DISTINGUISHED_NAME,
            'make_current_version_link': False,
        }
        with open('config.yml', 'w') as fp:
            yaml.dump(config, fp, default_flow_style=False)
        os.chmod('config.yml', 0o600)
        config = common.read_config()
        common.assert_config_keystore(config)

        logging.debug(
            _('Run over {cibase} to find -debug.apk. and skip repo_basedir {repo_basedir}').format(
                cibase=cibase,
                repo_basedir=repo_basedir
            )
        )

        for root, dirs, files in os.walk(cibase):
            for d in ('.git', '.gradle'):
                if d in dirs:
                    dirs.remove(d)
            if root == cibase and 'fdroid' in dirs:
                dirs.remove('fdroid')

            for f in files:
                if f.endswith('-debug.apk'):
                    apkfilename = os.path.join(root, f)
                    logging.debug(
                        _('Stripping mystery signature from {apkfilename}').format(
                            apkfilename=apkfilename
                        )
                    )
                    destapk = os.path.join(repodir, os.path.basename(f))
                    os.chmod(apkfilename, 0o644)
                    logging.debug(
                        _(
                            'Resigning {apkfilename} with provided debug.keystore'
                        ).format(apkfilename=os.path.basename(apkfilename))
                    )
                    common.sign_apk(apkfilename, destapk, KEY_ALIAS)

        if options.verbose:
            logging.debug(_('attempting bare SSH connection to test deploy key:'))
            try:
                subprocess.check_call(
                    [
                        'ssh',
                        '-Tvi',
                        ssh_private_key_file,
                        '-oIdentitiesOnly=yes',
                        '-oStrictHostKeyChecking=no',
                        servergitmirror.split(':')[0],
                    ]
                )
            except subprocess.CalledProcessError:
                pass

        app_url = clone_url[: -len(NIGHTLY)]
        template = dict()
        template['AuthorName'] = clone_url.split('/')[4]
        template['AuthorWebSite'] = '/'.join(clone_url.split('/')[:4])
        template['Categories'] = ['nightly']
        template['SourceCode'] = app_url
        template['IssueTracker'] = app_url + '/issues'
        template['Summary'] = 'Nightly build of ' + urlparse(app_url).path[1:]
        template['Description'] = template['Summary']
        with open('template.yml', 'w') as fp:
            yaml.dump(template, fp)

        subprocess.check_call(
            ['fdroid', 'update', '--rename-apks', '--create-metadata', '--verbose'],
            cwd=repo_basedir,
        )
        common.local_rsync(
            options, [repo_basedir + '/metadata/'], git_mirror_metadatadir + '/'
        )
        stats = repo_basedir + '/stats/'
        if os.path.exists(stats):
            common.local_rsync(options, [stats], git_mirror_statsdir + '/')
        mirror_git_repo.git.add(all=True)
        mirror_git_repo.index.commit("update app metadata")

        if not options.no_deploy:
            try:
                cmd = ['fdroid', 'deploy', '--verbose', '--no-keep-git-mirror-archive']
                subprocess.check_call(cmd, cwd=repo_basedir)
            except subprocess.CalledProcessError:
                logging.error(
                    _('cannot publish update, did you set the deploy key?')
                    + '\n'
                    + deploy_key_url
                )
                sys.exit(1)

        if not options.keep_private_keys:
            os.remove(KEYSTORE_FILE)
            if shutil.rmtree.avoids_symlink_attacks:
                shutil.rmtree(os.path.dirname(ssh_private_key_file))

    else:
        if not os.path.isfile(options.keystore):
            androiddir = os.path.dirname(options.keystore)
            if not os.path.exists(androiddir):
                os.mkdir(androiddir)
                logging.info(_('created {path}').format(path=androiddir))
            logging.error(_('{path} does not exist!  Create it by running:').format(path=options.keystore)
                          + '\n    keytool -genkey -v -keystore ' + options.keystore + ' -storepass android \\'
                          + '\n     -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000 \\'
                          + '\n     -dname "CN=Android Debug,O=Android,C=US"')
            sys.exit(1)
        ssh_dir = os.path.join(os.getenv('HOME'), '.ssh')
        privkey = _ssh_key_from_debug_keystore(options.keystore)
        if os.path.exists(ssh_dir):
            ssh_private_key_file = os.path.join(ssh_dir, os.path.basename(privkey))
            shutil.move(privkey, ssh_private_key_file)
            shutil.move(privkey + '.pub', ssh_private_key_file + '.pub')
        if shutil.rmtree.avoids_symlink_attacks:
            shutil.rmtree(os.path.dirname(privkey))

        if options.show_secret_var:
            debug_keystore = _get_keystore_secret_var(options.keystore)
            print(
                _('\n{path} encoded for the DEBUG_KEYSTORE secret variable:').format(
                    path=options.keystore
                )
            )
            print(debug_keystore)

    os.umask(umask)


if __name__ == "__main__":
    main()
