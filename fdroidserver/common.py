# -*- coding: utf-8 -*-
#
# common.py - part of the FDroid server tools
# Copyright (C) 2010-13, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
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

import os
import sys
import re
import shutil
import glob
import stat
import subprocess
import time
import operator
import Queue
import threading
import magic
import logging
from distutils.version import LooseVersion

import metadata

config = None
options = None
env = None


def get_default_config():
    return {
        'sdk_path': os.getenv("ANDROID_HOME") or "",
        'ndk_path': os.getenv("ANDROID_NDK") or "",
        'build_tools': "20.0.0",
        'ant': "ant",
        'mvn3': "mvn",
        'gradle': 'gradle',
        'sync_from_local_copy_dir': False,
        'update_stats': False,
        'stats_to_carbon': False,
        'repo_maxage': 0,
        'build_server_always': False,
        'keystore': os.path.join(os.getenv("HOME"), '.local', 'share', 'fdroidserver', 'keystore.jks'),
        'smartcardoptions': [],
        'char_limits': {
            'Summary': 50,
            'Description': 1500
        },
        'keyaliases': {},
        'repo_url': "https://MyFirstFDroidRepo.org/fdroid/repo",
        'repo_name': "My First FDroid Repo Demo",
        'repo_icon': "fdroid-icon.png",
        'repo_description': '''
            This is a repository of apps to be used with FDroid. Applications in this
            repository are either official binaries built by the original application
            developers, or are binaries built from source by the admin of f-droid.org
            using the tools on https://gitlab.com/u/fdroid.
            ''',
        'archive_older': 0,
    }


def read_config(opts, config_file='config.py'):
    """Read the repository config

    The config is read from config_file, which is in the current directory when
    any of the repo management commands are used.
    """
    global config, options, env

    if config is not None:
        return config
    if not os.path.isfile(config_file):
        logging.critical("Missing config file - is this a repo directory?")
        sys.exit(2)

    options = opts

    config = {}

    logging.debug("Reading %s" % config_file)
    execfile(config_file, config)

    # smartcardoptions must be a list since its command line args for Popen
    if 'smartcardoptions' in config:
        config['smartcardoptions'] = config['smartcardoptions'].split(' ')
    elif 'keystore' in config and config['keystore'] == 'NONE':
        # keystore='NONE' means use smartcard, these are required defaults
        config['smartcardoptions'] = ['-storetype', 'PKCS11', '-providerName',
                                      'SunPKCS11-OpenSC', '-providerClass',
                                      'sun.security.pkcs11.SunPKCS11',
                                      '-providerArg', 'opensc-fdroid.cfg']

    if any(k in config for k in ["keystore", "keystorepass", "keypass"]):
        st = os.stat(config_file)
        if st.st_mode & stat.S_IRWXG or st.st_mode & stat.S_IRWXO:
            logging.warn("unsafe permissions on {0} (should be 0600)!".format(config_file))

    defconfig = get_default_config()
    for k, v in defconfig.items():
        if k not in config:
            config[k] = v

    # Expand environment variables
    for k, v in config.items():
        if type(v) != str:
            continue
        v = os.path.expanduser(v)
        config[k] = os.path.expandvars(v)

    if not test_sdk_exists(config):
        sys.exit(3)

    if not test_build_tools_exists(config):
        sys.exit(3)

    bin_paths = {
        'aapt': [
            os.path.join(config['sdk_path'], 'build-tools', config['build_tools'], 'aapt'),
            ],
        'zipalign': [
            os.path.join(config['sdk_path'], 'tools', 'zipalign'),
            os.path.join(config['sdk_path'], 'build-tools', config['build_tools'], 'zipalign'),
            ],
        'android': [
            os.path.join(config['sdk_path'], 'tools', 'android'),
            ],
        'adb': [
            os.path.join(config['sdk_path'], 'platform-tools', 'adb'),
            ],
        }

    for b, paths in bin_paths.items():
        config[b] = None
        for path in paths:
            if os.path.isfile(path):
                config[b] = path
                break
        if config[b] is None:
            logging.warn("Could not find %s in any of the following paths:\n%s" % (
                b, '\n'.join(paths)))

    # There is no standard, so just set up the most common environment
    # variables
    env = os.environ
    for n in ['ANDROID_HOME', 'ANDROID_SDK']:
        env[n] = config['sdk_path']
    for n in ['ANDROID_NDK', 'NDK']:
        env[n] = config['ndk_path']

    for k in ["keystorepass", "keypass"]:
        if k in config:
            write_password_file(k)

    for k in ["repo_description", "archive_description"]:
        if k in config:
            config[k] = clean_description(config[k])

    if 'serverwebroot' in config:
        if isinstance(config['serverwebroot'], basestring):
            roots = [config['serverwebroot']]
        elif all(isinstance(item, basestring) for item in config['serverwebroot']):
            roots = config['serverwebroot']
        else:
            raise TypeError('only accepts strings, lists, and tuples')
        rootlist = []
        for rootstr in roots:
            # since this is used with rsync, where trailing slashes have
            # meaning, ensure there is always a trailing slash
            if rootstr[-1] != '/':
                rootstr += '/'
            rootlist.append(rootstr.replace('//', '/'))
        config['serverwebroot'] = rootlist

    return config


def test_sdk_exists(c):
    if c['sdk_path'] is None:
        # c['sdk_path'] is set to the value of ANDROID_HOME by default
        logging.error('No Android SDK found! ANDROID_HOME is not set and sdk_path is not in config.py!')
        logging.error('You can use ANDROID_HOME to set the path to your SDK, i.e.:')
        logging.error('\texport ANDROID_HOME=/opt/android-sdk')
        return False
    if not os.path.exists(c['sdk_path']):
        logging.critical('Android SDK path "' + c['sdk_path'] + '" does not exist!')
        return False
    if not os.path.isdir(c['sdk_path']):
        logging.critical('Android SDK path "' + c['sdk_path'] + '" is not a directory!')
        return False
    for d in ['build-tools', 'platform-tools', 'tools']:
        if not os.path.isdir(os.path.join(c['sdk_path'], d)):
            logging.critical('Android SDK path "%s" does not contain "%s/"!' % (
                c['sdk_path'], d))
            return False
    return True


def test_build_tools_exists(c):
    if not test_sdk_exists(c):
        return False
    build_tools = os.path.join(c['sdk_path'], 'build-tools')
    versioned_build_tools = os.path.join(build_tools, c['build_tools'])
    if not os.path.isdir(versioned_build_tools):
        logging.critical('Android Build Tools path "'
                         + versioned_build_tools + '" does not exist!')
        return False
    return True


def write_password_file(pwtype, password=None):
    '''
    writes out passwords to a protected file instead of passing passwords as
    command line argments
    '''
    filename = '.fdroid.' + pwtype + '.txt'
    fd = os.open(filename, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0600)
    if password is None:
        os.write(fd, config[pwtype])
    else:
        os.write(fd, password)
    os.close(fd)
    config[pwtype + 'file'] = filename


# Given the arguments in the form of multiple appid:[vc] strings, this returns
# a dictionary with the set of vercodes specified for each package.
def read_pkg_args(args, allow_vercodes=False):

    vercodes = {}
    if not args:
        return vercodes

    for p in args:
        if allow_vercodes and ':' in p:
            package, vercode = p.split(':')
        else:
            package, vercode = p, None
        if package not in vercodes:
            vercodes[package] = [vercode] if vercode else []
            continue
        elif vercode and vercode not in vercodes[package]:
            vercodes[package] += [vercode] if vercode else []

    return vercodes


# On top of what read_pkg_args does, this returns the whole app metadata, but
# limiting the builds list to the builds matching the vercodes specified.
def read_app_args(args, allapps, allow_vercodes=False):

    vercodes = read_pkg_args(args, allow_vercodes)

    if not vercodes:
        return allapps

    apps = [app for app in allapps if app['id'] in vercodes]

    if len(apps) != len(vercodes):
        allids = [app["id"] for app in allapps]
        for p in vercodes:
            if p not in allids:
                logging.critical("No such package: %s" % p)
        raise FDroidException("Found invalid app ids in arguments")
    if not apps:
        raise FDroidException("No packages specified")

    error = False
    for app in apps:
        vc = vercodes[app['id']]
        if not vc:
            continue
        app['builds'] = [b for b in app['builds'] if b['vercode'] in vc]
        if len(app['builds']) != len(vercodes[app['id']]):
            error = True
            allvcs = [b['vercode'] for b in app['builds']]
            for v in vercodes[app['id']]:
                if v not in allvcs:
                    logging.critical("No such vercode %s for app %s" % (v, app['id']))

    if error:
        raise FDroidException("Found invalid vercodes for some apps")

    return apps


def has_extension(filename, extension):
    name, ext = os.path.splitext(filename)
    ext = ext.lower()[1:]
    return ext == extension

apk_regex = None


def clean_description(description):
    'Remove unneeded newlines and spaces from a block of description text'
    returnstring = ''
    # this is split up by paragraph to make removing the newlines easier
    for paragraph in re.split(r'\n\n', description):
        paragraph = re.sub('\r', '', paragraph)
        paragraph = re.sub('\n', ' ', paragraph)
        paragraph = re.sub(' {2,}', ' ', paragraph)
        paragraph = re.sub('^\s*(\w)', r'\1', paragraph)
        returnstring += paragraph + '\n\n'
    return returnstring.rstrip('\n')


def apknameinfo(filename):
    global apk_regex
    filename = os.path.basename(filename)
    if apk_regex is None:
        apk_regex = re.compile(r"^(.+)_([0-9]+)\.apk$")
    m = apk_regex.match(filename)
    try:
        result = (m.group(1), m.group(2))
    except AttributeError:
        raise FDroidException("Invalid apk name: %s" % filename)
    return result


def getapkname(app, build):
    return "%s_%s.apk" % (app['id'], build['vercode'])


def getsrcname(app, build):
    return "%s_%s_src.tar.gz" % (app['id'], build['vercode'])


def getappname(app):
    if app['Name']:
        return app['Name']
    if app['Auto Name']:
        return app['Auto Name']
    return app['id']


def getcvname(app):
    return '%s (%s)' % (app['Current Version'], app['Current Version Code'])


def getvcs(vcstype, remote, local):
    if vcstype == 'git':
        return vcs_git(remote, local)
    if vcstype == 'git-svn':
        return vcs_gitsvn(remote, local)
    if vcstype == 'hg':
        return vcs_hg(remote, local)
    if vcstype == 'bzr':
        return vcs_bzr(remote, local)
    if vcstype == 'srclib':
        if local != os.path.join('build', 'srclib', remote):
            raise VCSException("Error: srclib paths are hard-coded!")
        return getsrclib(remote, os.path.join('build', 'srclib'), raw=True)
    if vcstype == 'svn':
        raise VCSException("Deprecated vcs type 'svn' - please use 'git-svn' instead")
    raise VCSException("Invalid vcs type " + vcstype)


def getsrclibvcs(name):
    if name not in metadata.srclibs:
        raise VCSException("Missing srclib " + name)
    return metadata.srclibs[name]['Repo Type']


class vcs:
    def __init__(self, remote, local):

        # svn, git-svn and bzr may require auth
        self.username = None
        if self.repotype() in ('git-svn', 'bzr'):
            if '@' in remote:
                self.username, remote = remote.split('@')
                if ':' not in self.username:
                    raise VCSException("Password required with username")
                self.username, self.password = self.username.split(':')

        self.remote = remote
        self.local = local
        self.clone_failed = False
        self.refreshed = False
        self.srclib = None

    def repotype(self):
        return None

    # Take the local repository to a clean version of the given revision, which
    # is specificed in the VCS's native format. Beforehand, the repository can
    # be dirty, or even non-existent. If the repository does already exist
    # locally, it will be updated from the origin, but only once in the
    # lifetime of the vcs object.
    # None is acceptable for 'rev' if you know you are cloning a clean copy of
    # the repo - otherwise it must specify a valid revision.
    def gotorevision(self, rev):

        if self.clone_failed:
            raise VCSException("Downloading the repository already failed once, not trying again.")

        # The .fdroidvcs-id file for a repo tells us what VCS type
        # and remote that directory was created from, allowing us to drop it
        # automatically if either of those things changes.
        fdpath = os.path.join(self.local, '..',
                              '.fdroidvcs-' + os.path.basename(self.local))
        cdata = self.repotype() + ' ' + self.remote
        writeback = True
        deleterepo = False
        if os.path.exists(self.local):
            if os.path.exists(fdpath):
                with open(fdpath, 'r') as f:
                    fsdata = f.read().strip()
                if fsdata == cdata:
                    writeback = False
                else:
                    deleterepo = True
                    logging.info(
                        "Repository details for %s changed - deleting" % (
                            self.local))
            else:
                deleterepo = True
                logging.info("Repository details for %s missing - deleting" % (
                    self.local))
        if deleterepo:
            shutil.rmtree(self.local)

        exc = None

        try:
            self.gotorevisionx(rev)
        except FDroidException, e:
            exc = e

        # If necessary, write the .fdroidvcs file.
        if writeback and not self.clone_failed:
            with open(fdpath, 'w') as f:
                f.write(cdata)

        if exc is not None:
            raise exc

    # Derived classes need to implement this. It's called once basic checking
    # has been performend.
    def gotorevisionx(self, rev):
        raise VCSException("This VCS type doesn't define gotorevisionx")

    # Initialise and update submodules
    def initsubmodules(self):
        raise VCSException('Submodules not supported for this vcs type')

    # Get a list of all known tags
    def gettags(self):
        raise VCSException('gettags not supported for this vcs type')

    # Get a list of latest number tags
    def latesttags(self, number):
        raise VCSException('latesttags not supported for this vcs type')

    # Get current commit reference (hash, revision, etc)
    def getref(self):
        raise VCSException('getref not supported for this vcs type')

    # Returns the srclib (name, path) used in setting up the current
    # revision, or None.
    def getsrclib(self):
        return self.srclib


class vcs_git(vcs):

    def repotype(self):
        return 'git'

    # If the local directory exists, but is somehow not a git repository, git
    # will traverse up the directory tree until it finds one that is (i.e.
    # fdroidserver) and then we'll proceed to destroy it! This is called as
    # a safety check.
    def checkrepo(self):
        p = SilentPopen(['git', 'rev-parse', '--show-toplevel'], cwd=self.local)
        result = p.output.rstrip()
        if not result.endswith(self.local):
            raise VCSException('Repository mismatch')

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            # Brand new checkout
            p = FDroidPopen(['git', 'clone', self.remote, self.local])
            if p.returncode != 0:
                self.clone_failed = True
                raise VCSException("Git clone failed", p.output)
            self.checkrepo()
        else:
            self.checkrepo()
            # Discard any working tree changes
            p = SilentPopen(['git', 'reset', '--hard'], cwd=self.local)
            if p.returncode != 0:
                raise VCSException("Git reset failed", p.output)
            # Remove untracked files now, in case they're tracked in the target
            # revision (it happens!)
            p = SilentPopen(['git', 'clean', '-dffx'], cwd=self.local)
            if p.returncode != 0:
                raise VCSException("Git clean failed", p.output)
            if not self.refreshed:
                # Get latest commits and tags from remote
                p = FDroidPopen(['git', 'fetch', 'origin'], cwd=self.local)
                if p.returncode != 0:
                    raise VCSException("Git fetch failed", p.output)
                p = SilentPopen(['git', 'fetch', '--prune', '--tags', 'origin'], cwd=self.local)
                if p.returncode != 0:
                    raise VCSException("Git fetch failed", p.output)
                # Recreate origin/HEAD as git clone would do it, in case it disappeared
                p = SilentPopen(['git', 'remote', 'set-head', 'origin', '--auto'], cwd=self.local)
                if p.returncode != 0:
                    lines = p.output.splitlines()
                    if 'Multiple remote HEAD branches' not in lines[0]:
                        raise VCSException("Git remote set-head failed", p.output)
                    branch = lines[1].split(' ')[-1]
                    p2 = SilentPopen(['git', 'remote', 'set-head', 'origin', branch], cwd=self.local)
                    if p2.returncode != 0:
                        raise VCSException("Git remote set-head failed", p.output + '\n' + p2.output)
                self.refreshed = True
        # origin/HEAD is the HEAD of the remote, e.g. the "default branch" on
        # a github repo. Most of the time this is the same as origin/master.
        rev = rev or 'origin/HEAD'
        p = SilentPopen(['git', 'checkout', '-f', rev], cwd=self.local)
        if p.returncode != 0:
            raise VCSException("Git checkout of '%s' failed" % rev, p.output)
        # Get rid of any uncontrolled files left behind
        p = SilentPopen(['git', 'clean', '-dffx'], cwd=self.local)
        if p.returncode != 0:
            raise VCSException("Git clean failed", p.output)

    def initsubmodules(self):
        self.checkrepo()
        submfile = os.path.join(self.local, '.gitmodules')
        if not os.path.isfile(submfile):
            raise VCSException("No git submodules available")

        # fix submodules not accessible without an account and public key auth
        with open(submfile, 'r') as f:
            lines = f.readlines()
        with open(submfile, 'w') as f:
            for line in lines:
                if 'git@github.com' in line:
                    line = line.replace('git@github.com:', 'https://github.com/')
                f.write(line)

        for cmd in [
                ['git', 'reset', '--hard'],
                ['git', 'clean', '-dffx'],
                ]:
            p = SilentPopen(['git', 'submodule', 'foreach', '--recursive'] + cmd, cwd=self.local)
            if p.returncode != 0:
                raise VCSException("Git submodule reset failed", p.output)
        p = SilentPopen(['git', 'submodule', 'sync'], cwd=self.local)
        if p.returncode != 0:
            raise VCSException("Git submodule sync failed", p.output)
        p = FDroidPopen(['git', 'submodule', 'update', '--init', '--force', '--recursive'], cwd=self.local)
        if p.returncode != 0:
            raise VCSException("Git submodule update failed", p.output)

    def gettags(self):
        self.checkrepo()
        p = SilentPopen(['git', 'tag'], cwd=self.local)
        return p.output.splitlines()

    def latesttags(self, alltags, number):
        self.checkrepo()
        p = SilentPopen(['echo "' + '\n'.join(alltags) + '" | '
                        + 'xargs -I@ git log --format=format:"%at @%n" -1 @ | '
                        + 'sort -n | awk \'{print $2}\''],
                        cwd=self.local, shell=True)
        return p.output.splitlines()[-number:]


class vcs_gitsvn(vcs):

    def repotype(self):
        return 'git-svn'

    # Damn git-svn tries to use a graphical password prompt, so we have to
    # trick it into taking the password from stdin
    def userargs(self):
        if self.username is None:
            return ('', '')
        return ('echo "%s" | DISPLAY="" ' % self.password, ' --username "%s"' % self.username)

    # If the local directory exists, but is somehow not a git repository, git
    # will traverse up the directory tree until it finds one that is (i.e.
    # fdroidserver) and then we'll proceed to destory it! This is called as
    # a safety check.
    def checkrepo(self):
        p = SilentPopen(['git', 'rev-parse', '--show-toplevel'], cwd=self.local)
        result = p.output.rstrip()
        if not result.endswith(self.local):
            raise VCSException('Repository mismatch')

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            # Brand new checkout
            gitsvn_cmd = '%sgit svn clone%s' % self.userargs()
            if ';' in self.remote:
                remote_split = self.remote.split(';')
                for i in remote_split[1:]:
                    if i.startswith('trunk='):
                        gitsvn_cmd += ' -T %s' % i[6:]
                    elif i.startswith('tags='):
                        gitsvn_cmd += ' -t %s' % i[5:]
                    elif i.startswith('branches='):
                        gitsvn_cmd += ' -b %s' % i[9:]
                p = SilentPopen([gitsvn_cmd + " %s %s" % (remote_split[0], self.local)], shell=True)
                if p.returncode != 0:
                    self.clone_failed = True
                    raise VCSException("Git clone failed", p.output)
            else:
                p = SilentPopen([gitsvn_cmd + " %s %s" % (self.remote, self.local)], shell=True)
                if p.returncode != 0:
                    self.clone_failed = True
                    raise VCSException("Git clone failed", p.output)
            self.checkrepo()
        else:
            self.checkrepo()
            # Discard any working tree changes
            p = SilentPopen(['git', 'reset', '--hard'], cwd=self.local)
            if p.returncode != 0:
                raise VCSException("Git reset failed", p.output)
            # Remove untracked files now, in case they're tracked in the target
            # revision (it happens!)
            p = SilentPopen(['git', 'clean', '-dffx'], cwd=self.local)
            if p.returncode != 0:
                raise VCSException("Git clean failed", p.output)
            if not self.refreshed:
                # Get new commits, branches and tags from repo
                p = SilentPopen(['%sgit svn fetch %s' % self.userargs()], cwd=self.local, shell=True)
                if p.returncode != 0:
                    raise VCSException("Git svn fetch failed")
                p = SilentPopen(['%sgit svn rebase %s' % self.userargs()], cwd=self.local, shell=True)
                if p.returncode != 0:
                    raise VCSException("Git svn rebase failed", p.output)
                self.refreshed = True

        rev = rev or 'master'
        if rev:
            nospaces_rev = rev.replace(' ', '%20')
            # Try finding a svn tag
            for treeish in ['origin/', '']:
                p = SilentPopen(['git', 'checkout', treeish + 'tags/' + nospaces_rev],
                                cwd=self.local)
                if p.returncode == 0:
                    break
            if p.returncode != 0:
                # No tag found, normal svn rev translation
                # Translate svn rev into git format
                rev_split = rev.split('/')

                p = None
                for treeish in ['origin/', '']:
                    if len(rev_split) > 1:
                        treeish += rev_split[0]
                        svn_rev = rev_split[1]

                    else:
                        # if no branch is specified, then assume trunk (i.e. 'master' branch):
                        treeish += 'master'
                        svn_rev = rev

                    svn_rev = svn_rev if svn_rev[0] == 'r' else 'r' + svn_rev

                    p = SilentPopen(['git', 'svn', 'find-rev', '--before', svn_rev, treeish],
                                    cwd=self.local)
                    git_rev = p.output.rstrip()

                    if p.returncode == 0 and git_rev:
                        break

                if p.returncode != 0 or not git_rev:
                    # Try a plain git checkout as a last resort
                    p = SilentPopen(['git', 'checkout', rev], cwd=self.local)
                    if p.returncode != 0:
                        raise VCSException("No git treeish found and direct git checkout of '%s' failed" % rev, p.output)
                else:
                    # Check out the git rev equivalent to the svn rev
                    p = SilentPopen(['git', 'checkout', git_rev], cwd=self.local)
                    if p.returncode != 0:
                        raise VCSException("Git svn checkout of '%s' failed" % rev, p.output)

        # Get rid of any uncontrolled files left behind
        p = SilentPopen(['git', 'clean', '-dffx'], cwd=self.local)
        if p.returncode != 0:
            raise VCSException("Git clean failed", p.output)

    def gettags(self):
        self.checkrepo()
        for treeish in ['origin/', '']:
            d = os.path.join(self.local, '.git', 'svn', 'refs', 'remotes', treeish, 'tags')
            if os.path.isdir(d):
                return os.listdir(d)

    def getref(self):
        self.checkrepo()
        p = SilentPopen(['git', 'svn', 'find-rev', 'HEAD'], cwd=self.local)
        if p.returncode != 0:
            return None
        return p.output.strip()


class vcs_hg(vcs):

    def repotype(self):
        return 'hg'

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            p = SilentPopen(['hg', 'clone', self.remote, self.local])
            if p.returncode != 0:
                self.clone_failed = True
                raise VCSException("Hg clone failed", p.output)
        else:
            p = SilentPopen(['hg status -uS | xargs rm -rf'], cwd=self.local, shell=True)
            if p.returncode != 0:
                raise VCSException("Hg clean failed", p.output)
            if not self.refreshed:
                p = SilentPopen(['hg', 'pull'], cwd=self.local)
                if p.returncode != 0:
                    raise VCSException("Hg pull failed", p.output)
                self.refreshed = True

        rev = rev or 'default'
        if not rev:
            return
        p = SilentPopen(['hg', 'update', '-C', rev], cwd=self.local)
        if p.returncode != 0:
            raise VCSException("Hg checkout of '%s' failed" % rev, p.output)
        p = SilentPopen(['hg', 'purge', '--all'], cwd=self.local)
        # Also delete untracked files, we have to enable purge extension for that:
        if "'purge' is provided by the following extension" in p.output:
            with open(os.path.join(self.local, '.hg', 'hgrc'), "a") as myfile:
                myfile.write("\n[extensions]\nhgext.purge=\n")
            p = SilentPopen(['hg', 'purge', '--all'], cwd=self.local)
            if p.returncode != 0:
                raise VCSException("HG purge failed", p.output)
        elif p.returncode != 0:
            raise VCSException("HG purge failed", p.output)

    def gettags(self):
        p = SilentPopen(['hg', 'tags', '-q'], cwd=self.local)
        return p.output.splitlines()[1:]


class vcs_bzr(vcs):

    def repotype(self):
        return 'bzr'

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            p = SilentPopen(['bzr', 'branch', self.remote, self.local])
            if p.returncode != 0:
                self.clone_failed = True
                raise VCSException("Bzr branch failed", p.output)
        else:
            p = SilentPopen(['bzr', 'clean-tree', '--force', '--unknown', '--ignored'], cwd=self.local)
            if p.returncode != 0:
                raise VCSException("Bzr revert failed", p.output)
            if not self.refreshed:
                p = SilentPopen(['bzr', 'pull'], cwd=self.local)
                if p.returncode != 0:
                    raise VCSException("Bzr update failed", p.output)
                self.refreshed = True

        revargs = list(['-r', rev] if rev else [])
        p = SilentPopen(['bzr', 'revert'] + revargs, cwd=self.local)
        if p.returncode != 0:
            raise VCSException("Bzr revert of '%s' failed" % rev, p.output)

    def gettags(self):
        p = SilentPopen(['bzr', 'tags'], cwd=self.local)
        return [tag.split('   ')[0].strip() for tag in
                p.output.splitlines()]


def retrieve_string(app_dir, string, xmlfiles=None):

    res_dirs = [
        os.path.join(app_dir, 'res'),
        os.path.join(app_dir, 'src', 'main'),
        ]

    if xmlfiles is None:
        xmlfiles = []
        for res_dir in res_dirs:
            for r, d, f in os.walk(res_dir):
                if os.path.basename(r) == 'values':
                    xmlfiles += [os.path.join(r, x) for x in f if x.endswith('.xml')]

    string_search = None
    if string.startswith('@string/'):
        string_search = re.compile(r'.*name="' + string[8:] + '".*?>([^<]+?)<.*').search
    elif string.startswith('&') and string.endswith(';'):
        string_search = re.compile(r'.*<!ENTITY.*' + string[1:-1] + '.*?"([^"]+?)".*>').search

    if string_search is not None:
        for xmlfile in xmlfiles:
            for line in file(xmlfile):
                matches = string_search(line)
                if matches:
                    return retrieve_string(app_dir, matches.group(1), xmlfiles)
        return None

    return string.replace("\\'", "'")


# Return list of existing files that will be used to find the highest vercode
def manifest_paths(app_dir, flavour):

    possible_manifests = \
        [os.path.join(app_dir, 'AndroidManifest.xml'),
         os.path.join(app_dir, 'src', 'main', 'AndroidManifest.xml'),
         os.path.join(app_dir, 'src', 'AndroidManifest.xml'),
         os.path.join(app_dir, 'build.gradle')]

    if flavour:
        possible_manifests.append(
            os.path.join(app_dir, 'src', flavour, 'AndroidManifest.xml'))

    return [path for path in possible_manifests if os.path.isfile(path)]


# Retrieve the package name. Returns the name, or None if not found.
def fetch_real_name(app_dir, flavour):
    app_search = re.compile(r'.*<application.*').search
    name_search = re.compile(r'.*android:label="([^"]+)".*').search
    app_found = False
    for f in manifest_paths(app_dir, flavour):
        if not has_extension(f, 'xml'):
            continue
        logging.debug("fetch_real_name: Checking manifest at " + f)
        for line in file(f):
            if not app_found:
                if app_search(line):
                    app_found = True
            if app_found:
                matches = name_search(line)
                if matches:
                    stringname = matches.group(1)
                    logging.debug("fetch_real_name: using string " + stringname)
                    result = retrieve_string(app_dir, stringname)
                    if result:
                        result = result.strip()
                    return result
    return None


# Retrieve the version name
def version_name(original, app_dir, flavour):
    for f in manifest_paths(app_dir, flavour):
        if not has_extension(f, 'xml'):
            continue
        string = retrieve_string(app_dir, original)
        if string:
            return string
    return original


def get_library_references(root_dir):
    libraries = []
    proppath = os.path.join(root_dir, 'project.properties')
    if not os.path.isfile(proppath):
        return libraries
    with open(proppath) as f:
        for line in f.readlines():
            if not line.startswith('android.library.reference.'):
                continue
            path = line.split('=')[1].strip()
            relpath = os.path.join(root_dir, path)
            if not os.path.isdir(relpath):
                continue
            logging.debug("Found subproject at %s" % path)
            libraries.append(path)
    return libraries


def ant_subprojects(root_dir):
    subprojects = get_library_references(root_dir)
    for subpath in subprojects:
        subrelpath = os.path.join(root_dir, subpath)
        for p in get_library_references(subrelpath):
            relp = os.path.normpath(os.path.join(subpath, p))
            if relp not in subprojects:
                subprojects.insert(0, relp)
    return subprojects


def remove_debuggable_flags(root_dir):
    # Remove forced debuggable flags
    logging.debug("Removing debuggable flags from %s" % root_dir)
    for root, dirs, files in os.walk(root_dir):
        if 'AndroidManifest.xml' in files:
            path = os.path.join(root, 'AndroidManifest.xml')
            p = SilentPopen(['sed', '-i', 's/android:debuggable="[^"]*"//g', path])
            if p.returncode != 0:
                raise BuildException("Failed to remove debuggable flags of %s" % path)


# Extract some information from the AndroidManifest.xml at the given path.
# Returns (version, vercode, package), any or all of which might be None.
# All values returned are strings.
def parse_androidmanifests(paths, ignoreversions=None):

    if not paths:
        return (None, None, None)

    vcsearch = re.compile(r'.*:versionCode="([0-9]+?)".*').search
    vnsearch = re.compile(r'.*:versionName="([^"]+?)".*').search
    psearch = re.compile(r'.*package="([^"]+)".*').search

    vcsearch_g = re.compile(r'.*versionCode *=* *["\']*([0-9]+)["\']*').search
    vnsearch_g = re.compile(r'.*versionName *=* *(["\'])((?:(?=(\\?))\3.)*?)\1.*').search
    psearch_g = re.compile(r'.*packageName *=* *["\']([^"]+)["\'].*').search

    ignoresearch = re.compile(ignoreversions).search if ignoreversions else None

    max_version = None
    max_vercode = None
    max_package = None

    for path in paths:

        gradle = has_extension(path, 'gradle')
        version = None
        vercode = None
        # Remember package name, may be defined separately from version+vercode
        package = max_package

        for line in file(path):
            if not package:
                if gradle:
                    matches = psearch_g(line)
                else:
                    matches = psearch(line)
                if matches:
                    package = matches.group(1)
            if not version:
                if gradle:
                    matches = vnsearch_g(line)
                else:
                    matches = vnsearch(line)
                if matches:
                    version = matches.group(2 if gradle else 1)
            if not vercode:
                if gradle:
                    matches = vcsearch_g(line)
                else:
                    matches = vcsearch(line)
                if matches:
                    vercode = matches.group(1)

        # Always grab the package name and version name in case they are not
        # together with the highest version code
        if max_package is None and package is not None:
            max_package = package
        if max_version is None and version is not None:
            max_version = version

        if max_vercode is None or (vercode is not None and vercode > max_vercode):
            if not ignoresearch or not ignoresearch(version):
                if version is not None:
                    max_version = version
                if vercode is not None:
                    max_vercode = vercode
                if package is not None:
                    max_package = package
            else:
                max_version = "Ignore"

    if max_version is None:
        max_version = "Unknown"

    return (max_version, max_vercode, max_package)


class FDroidException(Exception):
    def __init__(self, value, detail=None):
        self.value = value
        self.detail = detail

    def get_wikitext(self):
        ret = repr(self.value) + "\n"
        if self.detail:
            ret += "=detail=\n"
            ret += "<pre>\n"
            txt = self.detail[-8192:] if len(self.detail) > 8192 else self.detail
            ret += str(txt)
            ret += "</pre>\n"
        return ret

    def __str__(self):
        ret = self.value
        if self.detail:
            ret += "\n==== detail begin ====\n%s\n==== detail end ====" % self.detail.strip()
        return ret


class VCSException(FDroidException):
    pass


class BuildException(FDroidException):
    pass


# Get the specified source library.
# Returns the path to it. Normally this is the path to be used when referencing
# it, which may be a subdirectory of the actual project. If you want the base
# directory of the project, pass 'basepath=True'.
def getsrclib(spec, srclib_dir, srclibpaths=[], subdir=None,
              basepath=False, raw=False, prepare=True, preponly=False):

    number = None
    subdir = None
    if raw:
        name = spec
        ref = None
    else:
        name, ref = spec.split('@')
        if ':' in name:
            number, name = name.split(':', 1)
        if '/' in name:
            name, subdir = name.split('/', 1)

    if name not in metadata.srclibs:
        raise VCSException('srclib ' + name + ' not found.')

    srclib = metadata.srclibs[name]

    sdir = os.path.join(srclib_dir, name)

    if not preponly:
        vcs = getvcs(srclib["Repo Type"], srclib["Repo"], sdir)
        vcs.srclib = (name, number, sdir)
        if ref:
            vcs.gotorevision(ref)

        if raw:
            return vcs

    libdir = None
    if subdir:
        libdir = os.path.join(sdir, subdir)
    elif srclib["Subdir"]:
        for subdir in srclib["Subdir"]:
            libdir_candidate = os.path.join(sdir, subdir)
            if os.path.exists(libdir_candidate):
                libdir = libdir_candidate
                break

    if libdir is None:
        libdir = sdir

    if srclib["Srclibs"]:
        n = 1
        for lib in srclib["Srclibs"].replace(';', ',').split(','):
            s_tuple = None
            for t in srclibpaths:
                if t[0] == lib:
                    s_tuple = t
                    break
            if s_tuple is None:
                raise VCSException('Missing recursive srclib %s for %s' % (
                    lib, name))
            place_srclib(libdir, n, s_tuple[2])
            n += 1

    remove_signing_keys(sdir)
    remove_debuggable_flags(sdir)

    if prepare:

        if srclib["Prepare"]:
            cmd = replace_config_vars(srclib["Prepare"])

            p = FDroidPopen(['bash', '-x', '-c', cmd], cwd=libdir)
            if p.returncode != 0:
                raise BuildException("Error running prepare command for srclib %s"
                                     % name, p.output)

    if basepath:
        libdir = sdir

    return (name, number, libdir)


# Prepare the source code for a particular build
#  'vcs'         - the appropriate vcs object for the application
#  'app'         - the application details from the metadata
#  'build'       - the build details from the metadata
#  'build_dir'   - the path to the build directory, usually
#                   'build/app.id'
#  'srclib_dir'  - the path to the source libraries directory, usually
#                   'build/srclib'
#  'extlib_dir'  - the path to the external libraries directory, usually
#                   'build/extlib'
# Returns the (root, srclibpaths) where:
#   'root' is the root directory, which may be the same as 'build_dir' or may
#          be a subdirectory of it.
#   'srclibpaths' is information on the srclibs being used
def prepare_source(vcs, app, build, build_dir, srclib_dir, extlib_dir, onserver=False):

    # Optionally, the actual app source can be in a subdirectory
    if build['subdir']:
        root_dir = os.path.join(build_dir, build['subdir'])
    else:
        root_dir = build_dir

    # Get a working copy of the right revision
    logging.info("Getting source for revision " + build['commit'])
    vcs.gotorevision(build['commit'])

    # Initialise submodules if requred
    if build['submodules']:
        logging.info("Initialising submodules")
        vcs.initsubmodules()

    # Check that a subdir (if we're using one) exists. This has to happen
    # after the checkout, since it might not exist elsewhere
    if not os.path.exists(root_dir):
        raise BuildException('Missing subdir ' + root_dir)

    # Run an init command if one is required
    if build['init']:
        cmd = replace_config_vars(build['init'])
        logging.info("Running 'init' commands in %s" % root_dir)

        p = FDroidPopen(['bash', '-x', '-c', cmd], cwd=root_dir)
        if p.returncode != 0:
            raise BuildException("Error running init command for %s:%s" %
                                 (app['id'], build['version']), p.output)

    # Apply patches if any
    if build['patch']:
        logging.info("Applying patches")
        for patch in build['patch']:
            patch = patch.strip()
            logging.info("Applying " + patch)
            patch_path = os.path.join('metadata', app['id'], patch)
            p = FDroidPopen(['patch', '-p1', '-i', os.path.abspath(patch_path)], cwd=build_dir)
            if p.returncode != 0:
                raise BuildException("Failed to apply patch %s" % patch_path)

    # Get required source libraries
    srclibpaths = []
    if build['srclibs']:
        logging.info("Collecting source libraries")
        for lib in build['srclibs']:
            srclibpaths.append(getsrclib(lib, srclib_dir, srclibpaths,
                                         preponly=onserver))

    for name, number, libpath in srclibpaths:
        place_srclib(root_dir, int(number) if number else None, libpath)

    basesrclib = vcs.getsrclib()
    # If one was used for the main source, add that too.
    if basesrclib:
        srclibpaths.append(basesrclib)

    # Update the local.properties file
    localprops = [os.path.join(build_dir, 'local.properties')]
    if build['subdir']:
        localprops += [os.path.join(root_dir, 'local.properties')]
    for path in localprops:
        if not os.path.isfile(path):
            continue
        logging.info("Updating properties file at %s" % path)
        f = open(path, 'r')
        props = f.read()
        f.close()
        props += '\n'
        # Fix old-fashioned 'sdk-location' by copying
        # from sdk.dir, if necessary
        if build['oldsdkloc']:
            sdkloc = re.match(r".*^sdk.dir=(\S+)$.*", props,
                              re.S | re.M).group(1)
            props += "sdk-location=%s\n" % sdkloc
        else:
            props += "sdk.dir=%s\n" % config['sdk_path']
            props += "sdk-location=%s\n" % config['sdk_path']
        if 'ndk_path' in config:
            # Add ndk location
            props += "ndk.dir=%s\n" % config['ndk_path']
            props += "ndk-location=%s\n" % config['ndk_path']
        # Add java.encoding if necessary
        if build['encoding']:
            props += "java.encoding=%s\n" % build['encoding']
        f = open(path, 'w')
        f.write(props)
        f.close()

    flavour = None
    if build['type'] == 'gradle':
        flavour = build['gradle']
        if flavour in ['main', 'yes', '']:
            flavour = None

        version_regex = re.compile(r".*'com\.android\.tools\.build:gradle:([^\.]+\.[^\.]+).*'.*")
        gradlepluginver = None

        gradle_files = [os.path.join(root_dir, 'build.gradle')]

        # Parent dir build.gradle
        parent_dir = os.path.normpath(os.path.join(root_dir, '..'))
        if parent_dir.startswith(build_dir):
            gradle_files.append(os.path.join(parent_dir, 'build.gradle'))

        for path in gradle_files:
            if gradlepluginver:
                break
            if not os.path.isfile(path):
                continue
            with open(path) as f:
                for line in f:
                    match = version_regex.match(line)
                    if match:
                        gradlepluginver = match.group(1)
                        break

        if gradlepluginver:
            build['gradlepluginver'] = LooseVersion(gradlepluginver)
        else:
            logging.warn("Could not fetch the gradle plugin version, defaulting to 0.11")
            build['gradlepluginver'] = LooseVersion('0.11')

        if build['target']:
            n = build["target"].split('-')[1]
            SilentPopen(['sed', '-i',
                         's@compileSdkVersion *[0-9]*@compileSdkVersion ' + n + '@g',
                         'build.gradle'],
                        cwd=root_dir)

    # Remove forced debuggable flags
    remove_debuggable_flags(root_dir)

    # Insert version code and number into the manifest if necessary
    if build['forceversion']:
        logging.info("Changing the version name")
        for path in manifest_paths(root_dir, flavour):
            if not os.path.isfile(path):
                continue
            if has_extension(path, 'xml'):
                p = SilentPopen(['sed', '-i',
                                 's/android:versionName="[^"]*"/android:versionName="'
                                 + build['version'] + '"/g',
                                 path])
                if p.returncode != 0:
                    raise BuildException("Failed to amend manifest")
            elif has_extension(path, 'gradle'):
                p = SilentPopen(['sed', '-i',
                                 's/versionName *=* *"[^"]*"/versionName = "'
                                 + build['version'] + '"/g',
                                 path])
                if p.returncode != 0:
                    raise BuildException("Failed to amend build.gradle")
    if build['forcevercode']:
        logging.info("Changing the version code")
        for path in manifest_paths(root_dir, flavour):
            if not os.path.isfile(path):
                continue
            if has_extension(path, 'xml'):
                p = SilentPopen(['sed', '-i',
                                 's/android:versionCode="[^"]*"/android:versionCode="'
                                 + build['vercode'] + '"/g',
                                 path])
                if p.returncode != 0:
                    raise BuildException("Failed to amend manifest")
            elif has_extension(path, 'gradle'):
                p = SilentPopen(['sed', '-i',
                                 's/versionCode *=* *[0-9]*/versionCode = '
                                 + build['vercode'] + '/g',
                                 path])
                if p.returncode != 0:
                    raise BuildException("Failed to amend build.gradle")

    # Delete unwanted files
    if build['rm']:
        logging.info("Removing specified files")
        for part in getpaths(build_dir, build, 'rm'):
            dest = os.path.join(build_dir, part)
            logging.info("Removing {0}".format(part))
            if os.path.lexists(dest):
                if os.path.islink(dest):
                    SilentPopen(['unlink ' + dest], shell=True)
                else:
                    SilentPopen(['rm -rf ' + dest], shell=True)
            else:
                logging.info("...but it didn't exist")

    remove_signing_keys(build_dir)

    # Add required external libraries
    if build['extlibs']:
        logging.info("Collecting prebuilt libraries")
        libsdir = os.path.join(root_dir, 'libs')
        if not os.path.exists(libsdir):
            os.mkdir(libsdir)
        for lib in build['extlibs']:
            lib = lib.strip()
            logging.info("...installing extlib {0}".format(lib))
            libf = os.path.basename(lib)
            libsrc = os.path.join(extlib_dir, lib)
            if not os.path.exists(libsrc):
                raise BuildException("Missing extlib file {0}".format(libsrc))
            shutil.copyfile(libsrc, os.path.join(libsdir, libf))

    # Run a pre-build command if one is required
    if build['prebuild']:
        logging.info("Running 'prebuild' commands in %s" % root_dir)

        cmd = replace_config_vars(build['prebuild'])

        # Substitute source library paths into prebuild commands
        for name, number, libpath in srclibpaths:
            libpath = os.path.relpath(libpath, root_dir)
            cmd = cmd.replace('$$' + name + '$$', libpath)

        p = FDroidPopen(['bash', '-x', '-c', cmd], cwd=root_dir)
        if p.returncode != 0:
            raise BuildException("Error running prebuild command for %s:%s" %
                                 (app['id'], build['version']), p.output)

    # Generate (or update) the ant build file, build.xml...
    if build['update'] and build['update'] != ['no'] and build['type'] == 'ant':
        parms = [config['android'], 'update', 'lib-project']
        lparms = [config['android'], 'update', 'project']

        if build['target']:
            parms += ['-t', build['target']]
            lparms += ['-t', build['target']]
        if build['update'] == ['auto']:
            update_dirs = ant_subprojects(root_dir) + ['.']
        else:
            update_dirs = build['update']

        for d in update_dirs:
            subdir = os.path.join(root_dir, d)
            if d == '.':
                logging.debug("Updating main project")
                cmd = parms + ['-p', d]
            else:
                logging.debug("Updating subproject %s" % d)
                cmd = lparms + ['-p', d]
            p = FDroidPopen(cmd, cwd=root_dir)
            # Check to see whether an error was returned without a proper exit
            # code (this is the case for the 'no target set or target invalid'
            # error)
            if p.returncode != 0 or p.output.startswith("Error: "):
                raise BuildException("Failed to update project at %s" % d, p.output)
            # Clean update dirs via ant
            if d != '.':
                logging.info("Cleaning subproject %s" % d)
                p = FDroidPopen(['ant', 'clean'], cwd=subdir)

    return (root_dir, srclibpaths)


# Split and extend via globbing the paths from a field
def getpaths(build_dir, build, field):
    paths = []
    for p in build[field]:
        p = p.strip()
        full_path = os.path.join(build_dir, p)
        full_path = os.path.normpath(full_path)
        paths += [r[len(build_dir) + 1:] for r in glob.glob(full_path)]
    return paths


# Scan the source code in the given directory (and all subdirectories)
# and return the number of fatal problems encountered
def scan_source(build_dir, root_dir, thisbuild):

    count = 0

    # Common known non-free blobs (always lower case):
    usual_suspects = [
        re.compile(r'flurryagent', re.IGNORECASE),
        re.compile(r'paypal.*mpl', re.IGNORECASE),
        re.compile(r'google.*analytics', re.IGNORECASE),
        re.compile(r'admob.*sdk.*android', re.IGNORECASE),
        re.compile(r'google.*ad.*view', re.IGNORECASE),
        re.compile(r'google.*admob', re.IGNORECASE),
        re.compile(r'google.*play.*services', re.IGNORECASE),
        re.compile(r'crittercism', re.IGNORECASE),
        re.compile(r'heyzap', re.IGNORECASE),
        re.compile(r'jpct.*ae', re.IGNORECASE),
        re.compile(r'youtube.*android.*player.*api', re.IGNORECASE),
        re.compile(r'bugsense', re.IGNORECASE),
        re.compile(r'crashlytics', re.IGNORECASE),
        re.compile(r'ouya.*sdk', re.IGNORECASE),
        re.compile(r'libspen23', re.IGNORECASE),
        ]

    scanignore = getpaths(build_dir, thisbuild, 'scanignore')
    scandelete = getpaths(build_dir, thisbuild, 'scandelete')

    try:
        ms = magic.open(magic.MIME_TYPE)
        ms.load()
    except AttributeError:
        ms = None

    def toignore(fd):
        for i in scanignore:
            if fd.startswith(i):
                return True
        return False

    def todelete(fd):
        for i in scandelete:
            if fd.startswith(i):
                return True
        return False

    def removeproblem(what, fd, fp):
        logging.info('Removing %s at %s' % (what, fd))
        os.remove(fp)

    def warnproblem(what, fd):
        logging.warn('Found %s at %s' % (what, fd))

    def handleproblem(what, fd, fp):
        if todelete(fd):
            removeproblem(what, fd, fp)
        else:
            logging.error('Found %s at %s' % (what, fd))
            return True
        return False

    # Iterate through all files in the source code
    for r, d, f in os.walk(build_dir, topdown=True):

        # It's topdown, so checking the basename is enough
        for ignoredir in ('.hg', '.git', '.svn', '.bzr'):
            if ignoredir in d:
                d.remove(ignoredir)

        for curfile in f:

            # Path (relative) to the file
            fp = os.path.join(r, curfile)
            fd = fp[len(build_dir) + 1:]

            # Check if this file has been explicitly excluded from scanning
            if toignore(fd):
                continue

            try:
                mime = magic.from_file(fp, mime=True) if ms is None else ms.file(fp)
            except UnicodeError:
                warnproblem('malformed magic number', fd)

            if mime == 'application/x-sharedlib':
                count += handleproblem('shared library', fd, fp)

            elif mime == 'application/x-archive':
                count += handleproblem('static library', fd, fp)

            elif mime == 'application/x-executable':
                count += handleproblem('binary executable', fd, fp)

            elif mime == 'application/x-java-applet':
                count += handleproblem('Java compiled class', fd, fp)

            elif mime in (
                    'application/jar',
                    'application/zip',
                    'application/java-archive',
                    'application/octet-stream',
                    'binary',
                    ):

                if has_extension(fp, 'apk'):
                    removeproblem('APK file', fd, fp)

                elif has_extension(fp, 'jar'):

                    if any(suspect.match(curfile) for suspect in usual_suspects):
                        count += handleproblem('usual supect', fd, fp)
                    else:
                        warnproblem('JAR file', fd)

                elif has_extension(fp, 'zip'):
                    warnproblem('ZIP file', fd)

                else:
                    warnproblem('unknown compressed or binary file', fd)

            elif has_extension(fp, 'java'):
                for line in file(fp):
                    if 'DexClassLoader' in line:
                        count += handleproblem('DexClassLoader', fd, fp)
                        break
    if ms is not None:
        ms.close()

    # Presence of a jni directory without buildjni=yes might
    # indicate a problem (if it's not a problem, explicitly use
    # buildjni=no to bypass this check)
    if (os.path.exists(os.path.join(root_dir, 'jni')) and
            not thisbuild['buildjni']):
        logging.error('Found jni directory, but buildjni is not enabled. Set it to \'no\' to ignore.')
        count += 1

    return count


class KnownApks:

    def __init__(self):
        self.path = os.path.join('stats', 'known_apks.txt')
        self.apks = {}
        if os.path.exists(self.path):
            for line in file(self.path):
                t = line.rstrip().split(' ')
                if len(t) == 2:
                    self.apks[t[0]] = (t[1], None)
                else:
                    self.apks[t[0]] = (t[1], time.strptime(t[2], '%Y-%m-%d'))
        self.changed = False

    def writeifchanged(self):
        if self.changed:
            if not os.path.exists('stats'):
                os.mkdir('stats')
            f = open(self.path, 'w')
            lst = []
            for apk, app in self.apks.iteritems():
                appid, added = app
                line = apk + ' ' + appid
                if added:
                    line += ' ' + time.strftime('%Y-%m-%d', added)
                lst.append(line)
            for line in sorted(lst):
                f.write(line + '\n')
            f.close()

    # Record an apk (if it's new, otherwise does nothing)
    # Returns the date it was added.
    def recordapk(self, apk, app):
        if apk not in self.apks:
            self.apks[apk] = (app, time.gmtime(time.time()))
            self.changed = True
        _, added = self.apks[apk]
        return added

    # Look up information - given the 'apkname', returns (app id, date added/None).
    # Or returns None for an unknown apk.
    def getapp(self, apkname):
        if apkname in self.apks:
            return self.apks[apkname]
        return None

    # Get the most recent 'num' apps added to the repo, as a list of package ids
    # with the most recent first.
    def getlatest(self, num):
        apps = {}
        for apk, app in self.apks.iteritems():
            appid, added = app
            if added:
                if appid in apps:
                    if apps[appid] > added:
                        apps[appid] = added
                else:
                    apps[appid] = added
        sortedapps = sorted(apps.iteritems(), key=operator.itemgetter(1))[-num:]
        lst = [app for app, _ in sortedapps]
        lst.reverse()
        return lst


def isApkDebuggable(apkfile, config):
    """Returns True if the given apk file is debuggable

    :param apkfile: full path to the apk to check"""

    p = SilentPopen([os.path.join(config['sdk_path'], 'build-tools',
                                  config['build_tools'], 'aapt'),
                     'dump', 'xmltree', apkfile, 'AndroidManifest.xml'])
    if p.returncode != 0:
        logging.critical("Failed to get apk manifest information")
        sys.exit(1)
    for line in p.output.splitlines():
        if 'android:debuggable' in line and not line.endswith('0x0'):
            return True
    return False


class AsynchronousFileReader(threading.Thread):
    '''
    Helper class to implement asynchronous reading of a file
    in a separate thread. Pushes read lines on a queue to
    be consumed in another thread.
    '''

    def __init__(self, fd, queue):
        assert isinstance(queue, Queue.Queue)
        assert callable(fd.readline)
        threading.Thread.__init__(self)
        self._fd = fd
        self._queue = queue

    def run(self):
        '''The body of the tread: read lines and put them on the queue.'''
        for line in iter(self._fd.readline, ''):
            self._queue.put(line)

    def eof(self):
        '''Check whether there is no more content to expect.'''
        return not self.is_alive() and self._queue.empty()


class PopenResult:
    returncode = None
    output = ''


def SilentPopen(commands, cwd=None, shell=False):
    return FDroidPopen(commands, cwd=cwd, shell=shell, output=False)


def FDroidPopen(commands, cwd=None, shell=False, output=True):
    """
    Run a command and capture the possibly huge output.

    :param commands: command and argument list like in subprocess.Popen
    :param cwd: optionally specifies a working directory
    :returns: A PopenResult.
    """

    global env

    if cwd:
        cwd = os.path.normpath(cwd)
        logging.debug("Directory: %s" % cwd)
    logging.debug("> %s" % ' '.join(commands))

    result = PopenResult()
    p = subprocess.Popen(commands, cwd=cwd, shell=shell, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    stdout_queue = Queue.Queue()
    stdout_reader = AsynchronousFileReader(p.stdout, stdout_queue)
    stdout_reader.start()

    # Check the queue for output (until there is no more to get)
    while not stdout_reader.eof():
        while not stdout_queue.empty():
            line = stdout_queue.get()
            if output and options.verbose:
                # Output directly to console
                sys.stderr.write(line)
                sys.stderr.flush()
            result.output += line

        time.sleep(0.1)

    p.wait()
    result.returncode = p.returncode
    return result


def remove_signing_keys(build_dir):
    comment = re.compile(r'[ ]*//')
    signing_configs = re.compile(r'^[\t ]*signingConfigs[ \t]*{[ \t]*$')
    line_matches = [
        re.compile(r'^[\t ]*signingConfig [^ ]*$'),
        re.compile(r'.*android\.signingConfigs\.[^{]*$'),
        re.compile(r'.*variant\.outputFile = .*'),
        re.compile(r'.*\.readLine\(.*'),
        ]
    for root, dirs, files in os.walk(build_dir):
        if 'build.gradle' in files:
            path = os.path.join(root, 'build.gradle')

            with open(path, "r") as o:
                lines = o.readlines()

            changed = False

            opened = 0
            with open(path, "w") as o:
                for line in lines:
                    if comment.match(line):
                        continue

                    if opened > 0:
                        opened += line.count('{')
                        opened -= line.count('}')
                        continue

                    if signing_configs.match(line):
                        changed = True
                        opened += 1
                        continue

                    if any(s.match(line) for s in line_matches):
                        changed = True
                        continue

                    if opened == 0:
                        o.write(line)

            if changed:
                logging.info("Cleaned build.gradle of keysigning configs at %s" % path)

        for propfile in [
                'project.properties',
                'build.properties',
                'default.properties',
                'ant.properties',
                ]:
            if propfile in files:
                path = os.path.join(root, propfile)

                with open(path, "r") as o:
                    lines = o.readlines()

                changed = False

                with open(path, "w") as o:
                    for line in lines:
                        if any(line.startswith(s) for s in ('key.store', 'key.alias')):
                            changed = True
                            continue

                        o.write(line)

                if changed:
                    logging.info("Cleaned %s of keysigning configs at %s" % (propfile, path))


def replace_config_vars(cmd):
    cmd = cmd.replace('$$SDK$$', config['sdk_path'])
    cmd = cmd.replace('$$NDK$$', config['ndk_path'])
    cmd = cmd.replace('$$MVN3$$', config['mvn3'])
    return cmd


def place_srclib(root_dir, number, libpath):
    if not number:
        return
    relpath = os.path.relpath(libpath, root_dir)
    proppath = os.path.join(root_dir, 'project.properties')

    lines = []
    if os.path.isfile(proppath):
        with open(proppath, "r") as o:
            lines = o.readlines()

    with open(proppath, "w") as o:
        placed = False
        for line in lines:
            if line.startswith('android.library.reference.%d=' % number):
                o.write('android.library.reference.%d=%s\n' % (number, relpath))
                placed = True
            else:
                o.write(line)
        if not placed:
            o.write('android.library.reference.%d=%s\n' % (number, relpath))
