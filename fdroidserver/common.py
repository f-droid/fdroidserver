#!/usr/bin/env python3
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

# common.py is imported by all modules, so do not import third-party
# libraries here as they will become a requirement for all commands.

import io
import os
import sys
import re
import shutil
import glob
import stat
import subprocess
import time
import operator
import logging
import hashlib
import socket
import base64
import xml.etree.ElementTree as XMLElementTree

from queue import Queue

from zipfile import ZipFile

import fdroidserver.metadata
from .asynchronousfilereader import AsynchronousFileReader


XMLElementTree.register_namespace('android', 'http://schemas.android.com/apk/res/android')

config = None
options = None
env = None
orig_path = None


default_config = {
    'sdk_path': "$ANDROID_HOME",
    'ndk_paths': {
        'r9b': None,
        'r10e': "$ANDROID_NDK",
    },
    'build_tools': "23.0.3",
    'force_build_tools': False,
    'java_paths': None,
    'ant': "ant",
    'mvn3': "mvn",
    'gradle': 'gradle',
    'accepted_formats': ['txt', 'yml'],
    'sync_from_local_copy_dir': False,
    'per_app_repos': False,
    'make_current_version_link': True,
    'current_version_name_source': 'Name',
    'update_stats': False,
    'stats_ignore': [],
    'stats_server': None,
    'stats_user': None,
    'stats_to_carbon': False,
    'repo_maxage': 0,
    'build_server_always': False,
    'keystore': 'keystore.jks',
    'smartcardoptions': [],
    'char_limits': {
        'Summary': 80,
        'Description': 4000,
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


def setup_global_opts(parser):
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                        help="Spew out even more information than normal")
    parser.add_argument("-q", "--quiet", action="store_true", default=False,
                        help="Restrict output to warnings and errors")


def fill_config_defaults(thisconfig):
    for k, v in default_config.items():
        if k not in thisconfig:
            thisconfig[k] = v

    # Expand paths (~users and $vars)
    def expand_path(path):
        if path is None:
            return None
        orig = path
        path = os.path.expanduser(path)
        path = os.path.expandvars(path)
        if orig == path:
            return None
        return path

    for k in ['sdk_path', 'ant', 'mvn3', 'gradle', 'keystore', 'repo_icon']:
        v = thisconfig[k]
        exp = expand_path(v)
        if exp is not None:
            thisconfig[k] = exp
            thisconfig[k + '_orig'] = v

    # find all installed JDKs for keytool, jarsigner, and JAVA[6-9]_HOME env vars
    if thisconfig['java_paths'] is None:
        thisconfig['java_paths'] = dict()
        pathlist = []
        pathlist += glob.glob('/usr/lib/jvm/j*[6-9]*')
        pathlist += glob.glob('/usr/java/jdk1.[6-9]*')
        pathlist += glob.glob('/System/Library/Java/JavaVirtualMachines/1.[6-9].0.jdk')
        pathlist += glob.glob('/Library/Java/JavaVirtualMachines/*jdk*[6-9]*')
        if os.getenv('JAVA_HOME') is not None:
            pathlist += os.getenv('JAVA_HOME')
        if os.getenv('PROGRAMFILES') is not None:
            pathlist += glob.glob(os.path.join(os.getenv('PROGRAMFILES'), 'Java', 'jdk1.[6-9].*'))
        for d in sorted(pathlist):
            if os.path.islink(d):
                continue
            j = os.path.basename(d)
            # the last one found will be the canonical one, so order appropriately
            for regex in [
                    r'^1\.([6-9])\.0\.jdk$',  # OSX
                    r'^jdk1\.([6-9])\.0_[0-9]+.jdk$',  # OSX and Oracle tarball
                    r'^jdk1\.([6-9])\.0_[0-9]+$',  # Oracle Windows
                    r'^jdk([6-9])-openjdk$',  # Arch
                    r'^java-([6-9])-openjdk$',  # Arch
                    r'^java-([6-9])-jdk$',  # Arch (oracle)
                    r'^java-1\.([6-9])\.0-.*$',  # RedHat
                    r'^java-([6-9])-oracle$',  # Debian WebUpd8
                    r'^jdk-([6-9])-oracle-.*$',  # Debian make-jpkg
                    r'^java-([6-9])-openjdk-[^c][^o][^m].*$',  # Debian
                    ]:
                m = re.match(regex, j)
                if not m:
                    continue
                osxhome = os.path.join(d, 'Contents', 'Home')
                if os.path.exists(osxhome):
                    thisconfig['java_paths'][m.group(1)] = osxhome
                else:
                    thisconfig['java_paths'][m.group(1)] = d

    for java_version in ('7', '8', '9'):
        if java_version not in thisconfig['java_paths']:
            continue
        java_home = thisconfig['java_paths'][java_version]
        jarsigner = os.path.join(java_home, 'bin', 'jarsigner')
        if os.path.exists(jarsigner):
            thisconfig['jarsigner'] = jarsigner
            thisconfig['keytool'] = os.path.join(java_home, 'bin', 'keytool')
            break  # Java7 is preferred, so quit if found

    for k in ['ndk_paths', 'java_paths']:
        d = thisconfig[k]
        for k2 in d.copy():
            v = d[k2]
            exp = expand_path(v)
            if exp is not None:
                thisconfig[k][k2] = exp
                thisconfig[k][k2 + '_orig'] = v


def regsub_file(pattern, repl, path):
    with open(path, 'rb') as f:
        text = f.read()
    text = re.sub(bytes(pattern, 'utf8'), bytes(repl, 'utf8'), text)
    with open(path, 'wb') as f:
        f.write(text)


def read_config(opts, config_file='config.py'):
    """Read the repository config

    The config is read from config_file, which is in the current
    directory when any of the repo management commands are used. If
    there is a local metadata file in the git repo, then config.py is
    not required, just use defaults.

    """
    global config, options

    if config is not None:
        return config

    options = opts

    config = {}

    if os.path.isfile(config_file):
        logging.debug("Reading %s" % config_file)
        with io.open(config_file, "rb") as f:
            code = compile(f.read(), config_file, 'exec')
            exec(code, None, config)
    elif len(get_local_metadata_files()) == 0:
        logging.critical("Missing config file - is this a repo directory?")
        sys.exit(2)

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

    fill_config_defaults(config)

    for k in ["keystorepass", "keypass"]:
        if k in config:
            write_password_file(k)

    for k in ["repo_description", "archive_description"]:
        if k in config:
            config[k] = clean_description(config[k])

    if 'serverwebroot' in config:
        if isinstance(config['serverwebroot'], str):
            roots = [config['serverwebroot']]
        elif all(isinstance(item, str) for item in config['serverwebroot']):
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


def find_sdk_tools_cmd(cmd):
    '''find a working path to a tool from the Android SDK'''

    tooldirs = []
    if config is not None and 'sdk_path' in config and os.path.exists(config['sdk_path']):
        # try to find a working path to this command, in all the recent possible paths
        if 'build_tools' in config:
            build_tools = os.path.join(config['sdk_path'], 'build-tools')
            # if 'build_tools' was manually set and exists, check only that one
            configed_build_tools = os.path.join(build_tools, config['build_tools'])
            if os.path.exists(configed_build_tools):
                tooldirs.append(configed_build_tools)
            else:
                # no configed version, so hunt known paths for it
                for f in sorted(os.listdir(build_tools), reverse=True):
                    if os.path.isdir(os.path.join(build_tools, f)):
                        tooldirs.append(os.path.join(build_tools, f))
                tooldirs.append(build_tools)
        sdk_tools = os.path.join(config['sdk_path'], 'tools')
        if os.path.exists(sdk_tools):
            tooldirs.append(sdk_tools)
        sdk_platform_tools = os.path.join(config['sdk_path'], 'platform-tools')
        if os.path.exists(sdk_platform_tools):
            tooldirs.append(sdk_platform_tools)
    tooldirs.append('/usr/bin')
    for d in tooldirs:
        if os.path.isfile(os.path.join(d, cmd)):
            return os.path.join(d, cmd)
    # did not find the command, exit with error message
    ensure_build_tools_exists(config)


def test_sdk_exists(thisconfig):
    if 'sdk_path' not in thisconfig:
        if 'aapt' in thisconfig and os.path.isfile(thisconfig['aapt']):
            return True
        else:
            logging.error("'sdk_path' not set in config.py!")
            return False
    if thisconfig['sdk_path'] == default_config['sdk_path']:
        logging.error('No Android SDK found!')
        logging.error('You can use ANDROID_HOME to set the path to your SDK, i.e.:')
        logging.error('\texport ANDROID_HOME=/opt/android-sdk')
        return False
    if not os.path.exists(thisconfig['sdk_path']):
        logging.critical('Android SDK path "' + thisconfig['sdk_path'] + '" does not exist!')
        return False
    if not os.path.isdir(thisconfig['sdk_path']):
        logging.critical('Android SDK path "' + thisconfig['sdk_path'] + '" is not a directory!')
        return False
    for d in ['build-tools', 'platform-tools', 'tools']:
        if not os.path.isdir(os.path.join(thisconfig['sdk_path'], d)):
            logging.critical('Android SDK path "%s" does not contain "%s/"!' % (
                thisconfig['sdk_path'], d))
            return False
    return True


def ensure_build_tools_exists(thisconfig):
    if not test_sdk_exists(thisconfig):
        sys.exit(3)
    build_tools = os.path.join(thisconfig['sdk_path'], 'build-tools')
    versioned_build_tools = os.path.join(build_tools, thisconfig['build_tools'])
    if not os.path.isdir(versioned_build_tools):
        logging.critical('Android Build Tools path "'
                         + versioned_build_tools + '" does not exist!')
        sys.exit(3)


def write_password_file(pwtype, password=None):
    '''
    writes out passwords to a protected file instead of passing passwords as
    command line argments
    '''
    filename = '.fdroid.' + pwtype + '.txt'
    fd = os.open(filename, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    if password is None:
        os.write(fd, config[pwtype].encode('utf-8'))
    else:
        os.write(fd, password.encode('utf-8'))
    os.close(fd)
    config[pwtype + 'file'] = filename


def get_local_metadata_files():
    '''get any metadata files local to an app's source repo

    This tries to ignore anything that does not count as app metdata,
    including emacs cruft ending in ~ and the .fdroid.key*pass.txt files.

    '''
    return glob.glob('.fdroid.[a-jl-z]*[a-rt-z]')


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

    apps = {}
    for appid, app in allapps.items():
        if appid in vercodes:
            apps[appid] = app

    if len(apps) != len(vercodes):
        for p in vercodes:
            if p not in allapps:
                logging.critical("No such package: %s" % p)
        raise FDroidException("Found invalid app ids in arguments")
    if not apps:
        raise FDroidException("No packages specified")

    error = False
    for appid, app in apps.items():
        vc = vercodes[appid]
        if not vc:
            continue
        app.builds = [b for b in app.builds if b.vercode in vc]
        if len(app.builds) != len(vercodes[appid]):
            error = True
            allvcs = [b.vercode for b in app.builds]
            for v in vercodes[appid]:
                if v not in allvcs:
                    logging.critical("No such vercode %s for app %s" % (v, appid))

    if error:
        raise FDroidException("Found invalid vercodes for some apps")

    return apps


def get_extension(filename):
    base, ext = os.path.splitext(filename)
    if not ext:
        return base, ''
    return base, ext.lower()[1:]


def has_extension(filename, ext):
    _, f_ext = get_extension(filename)
    return ext == f_ext


apk_regex = re.compile(r"^(.+)_([0-9]+)\.apk$")


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
    filename = os.path.basename(filename)
    m = apk_regex.match(filename)
    try:
        result = (m.group(1), m.group(2))
    except AttributeError:
        raise FDroidException("Invalid apk name: %s" % filename)
    return result


def getapkname(app, build):
    return "%s_%s.apk" % (app.id, build.vercode)


def getsrcname(app, build):
    return "%s_%s_src.tar.gz" % (app.id, build.vercode)


def getappname(app):
    if app.Name:
        return app.Name
    if app.AutoName:
        return app.AutoName
    return app.id


def getcvname(app):
    return '%s (%s)' % (app.CurrentVersion, app.CurrentVersionCode)


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
    if name not in fdroidserver.metadata.srclibs:
        raise VCSException("Missing srclib " + name)
    return fdroidserver.metadata.srclibs[name]['Repo Type']


class vcs:

    def __init__(self, remote, local):

        # svn, git-svn and bzr may require auth
        self.username = None
        if self.repotype() in ('git-svn', 'bzr'):
            if '@' in remote:
                if self.repotype == 'git-svn':
                    raise VCSException("Authentication is not supported for git-svn")
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
    def gotorevision(self, rev, refresh=True):

        if self.clone_failed:
            raise VCSException("Downloading the repository already failed once, not trying again.")

        # The .fdroidvcs-id file for a repo tells us what VCS type
        # and remote that directory was created from, allowing us to drop it
        # automatically if either of those things changes.
        fdpath = os.path.join(self.local, '..',
                              '.fdroidvcs-' + os.path.basename(self.local))
        fdpath = os.path.normpath(fdpath)
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
                    logging.info("Repository details for %s changed - deleting" % (
                        self.local))
            else:
                deleterepo = True
                logging.info("Repository details for %s missing - deleting" % (
                    self.local))
        if deleterepo:
            shutil.rmtree(self.local)

        exc = None
        if not refresh:
            self.refreshed = True

        try:
            self.gotorevisionx(rev)
        except FDroidException as e:
            exc = e

        # If necessary, write the .fdroidvcs file.
        if writeback and not self.clone_failed:
            os.makedirs(os.path.dirname(fdpath), exist_ok=True)
            with open(fdpath, 'w+') as f:
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
        if not self._gettags:
            raise VCSException('gettags not supported for this vcs type')
        rtags = []
        for tag in self._gettags():
            if re.match('[-A-Za-z0-9_. /]+$', tag):
                rtags.append(tag)
        return rtags

    # Get a list of all the known tags, sorted from newest to oldest
    def latesttags(self):
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
        p = FDroidPopen(['git', 'rev-parse', '--show-toplevel'], cwd=self.local, output=False)
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
            p = FDroidPopen(['git', 'submodule', 'foreach', '--recursive',
                             'git', 'reset', '--hard'], cwd=self.local, output=False)
            if p.returncode != 0:
                raise VCSException("Git reset failed", p.output)
            # Remove untracked files now, in case they're tracked in the target
            # revision (it happens!)
            p = FDroidPopen(['git', 'submodule', 'foreach', '--recursive',
                             'git', 'clean', '-dffx'], cwd=self.local, output=False)
            if p.returncode != 0:
                raise VCSException("Git clean failed", p.output)
            if not self.refreshed:
                # Get latest commits and tags from remote
                p = FDroidPopen(['git', 'fetch', 'origin'], cwd=self.local)
                if p.returncode != 0:
                    raise VCSException("Git fetch failed", p.output)
                p = FDroidPopen(['git', 'fetch', '--prune', '--tags', 'origin'], cwd=self.local, output=False)
                if p.returncode != 0:
                    raise VCSException("Git fetch failed", p.output)
                # Recreate origin/HEAD as git clone would do it, in case it disappeared
                p = FDroidPopen(['git', 'remote', 'set-head', 'origin', '--auto'], cwd=self.local, output=False)
                if p.returncode != 0:
                    lines = p.output.splitlines()
                    if 'Multiple remote HEAD branches' not in lines[0]:
                        raise VCSException("Git remote set-head failed", p.output)
                    branch = lines[1].split(' ')[-1]
                    p2 = FDroidPopen(['git', 'remote', 'set-head', 'origin', branch], cwd=self.local, output=False)
                    if p2.returncode != 0:
                        raise VCSException("Git remote set-head failed", p.output + '\n' + p2.output)
                self.refreshed = True
        # origin/HEAD is the HEAD of the remote, e.g. the "default branch" on
        # a github repo. Most of the time this is the same as origin/master.
        rev = rev or 'origin/HEAD'
        p = FDroidPopen(['git', 'checkout', '-f', rev], cwd=self.local, output=False)
        if p.returncode != 0:
            raise VCSException("Git checkout of '%s' failed" % rev, p.output)
        # Get rid of any uncontrolled files left behind
        p = FDroidPopen(['git', 'clean', '-dffx'], cwd=self.local, output=False)
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
                if 'git@gitlab.com' in line:
                    line = line.replace('git@gitlab.com:', 'https://gitlab.com/')
                f.write(line)

        p = FDroidPopen(['git', 'submodule', 'sync'], cwd=self.local, output=False)
        if p.returncode != 0:
            raise VCSException("Git submodule sync failed", p.output)
        p = FDroidPopen(['git', 'submodule', 'update', '--init', '--force', '--recursive'], cwd=self.local)
        if p.returncode != 0:
            raise VCSException("Git submodule update failed", p.output)

    def _gettags(self):
        self.checkrepo()
        p = FDroidPopen(['git', 'tag'], cwd=self.local, output=False)
        return p.output.splitlines()

    tag_format = re.compile(r'tag: ([^),]*)')

    def latesttags(self):
        self.checkrepo()
        p = FDroidPopen(['git', 'log', '--tags',
                         '--simplify-by-decoration', '--pretty=format:%d'],
                        cwd=self.local, output=False)
        tags = []
        for line in p.output.splitlines():
            for tag in self.tag_format.findall(line):
                tags.append(tag)
        return tags


class vcs_gitsvn(vcs):

    def repotype(self):
        return 'git-svn'

    # If the local directory exists, but is somehow not a git repository, git
    # will traverse up the directory tree until it finds one that is (i.e.
    # fdroidserver) and then we'll proceed to destory it! This is called as
    # a safety check.
    def checkrepo(self):
        p = FDroidPopen(['git', 'rev-parse', '--show-toplevel'], cwd=self.local, output=False)
        result = p.output.rstrip()
        if not result.endswith(self.local):
            raise VCSException('Repository mismatch')

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            # Brand new checkout
            gitsvn_args = ['git', 'svn', 'clone']
            if ';' in self.remote:
                remote_split = self.remote.split(';')
                for i in remote_split[1:]:
                    if i.startswith('trunk='):
                        gitsvn_args.extend(['-T', i[6:]])
                    elif i.startswith('tags='):
                        gitsvn_args.extend(['-t', i[5:]])
                    elif i.startswith('branches='):
                        gitsvn_args.extend(['-b', i[9:]])
                gitsvn_args.extend([remote_split[0], self.local])
                p = FDroidPopen(gitsvn_args, output=False)
                if p.returncode != 0:
                    self.clone_failed = True
                    raise VCSException("Git svn clone failed", p.output)
            else:
                gitsvn_args.extend([self.remote, self.local])
                p = FDroidPopen(gitsvn_args, output=False)
                if p.returncode != 0:
                    self.clone_failed = True
                    raise VCSException("Git svn clone failed", p.output)
            self.checkrepo()
        else:
            self.checkrepo()
            # Discard any working tree changes
            p = FDroidPopen(['git', 'reset', '--hard'], cwd=self.local, output=False)
            if p.returncode != 0:
                raise VCSException("Git reset failed", p.output)
            # Remove untracked files now, in case they're tracked in the target
            # revision (it happens!)
            p = FDroidPopen(['git', 'clean', '-dffx'], cwd=self.local, output=False)
            if p.returncode != 0:
                raise VCSException("Git clean failed", p.output)
            if not self.refreshed:
                # Get new commits, branches and tags from repo
                p = FDroidPopen(['git', 'svn', 'fetch'], cwd=self.local, output=False)
                if p.returncode != 0:
                    raise VCSException("Git svn fetch failed")
                p = FDroidPopen(['git', 'svn', 'rebase'], cwd=self.local, output=False)
                if p.returncode != 0:
                    raise VCSException("Git svn rebase failed", p.output)
                self.refreshed = True

        rev = rev or 'master'
        if rev:
            nospaces_rev = rev.replace(' ', '%20')
            # Try finding a svn tag
            for treeish in ['origin/', '']:
                p = FDroidPopen(['git', 'checkout', treeish + 'tags/' + nospaces_rev], cwd=self.local, output=False)
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

                    p = FDroidPopen(['git', 'svn', 'find-rev', '--before', svn_rev, treeish], cwd=self.local, output=False)
                    git_rev = p.output.rstrip()

                    if p.returncode == 0 and git_rev:
                        break

                if p.returncode != 0 or not git_rev:
                    # Try a plain git checkout as a last resort
                    p = FDroidPopen(['git', 'checkout', rev], cwd=self.local, output=False)
                    if p.returncode != 0:
                        raise VCSException("No git treeish found and direct git checkout of '%s' failed" % rev, p.output)
                else:
                    # Check out the git rev equivalent to the svn rev
                    p = FDroidPopen(['git', 'checkout', git_rev], cwd=self.local, output=False)
                    if p.returncode != 0:
                        raise VCSException("Git checkout of '%s' failed" % rev, p.output)

        # Get rid of any uncontrolled files left behind
        p = FDroidPopen(['git', 'clean', '-dffx'], cwd=self.local, output=False)
        if p.returncode != 0:
            raise VCSException("Git clean failed", p.output)

    def _gettags(self):
        self.checkrepo()
        for treeish in ['origin/', '']:
            d = os.path.join(self.local, '.git', 'svn', 'refs', 'remotes', treeish, 'tags')
            if os.path.isdir(d):
                return os.listdir(d)

    def getref(self):
        self.checkrepo()
        p = FDroidPopen(['git', 'svn', 'find-rev', 'HEAD'], cwd=self.local, output=False)
        if p.returncode != 0:
            return None
        return p.output.strip()


class vcs_hg(vcs):

    def repotype(self):
        return 'hg'

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            p = FDroidPopen(['hg', 'clone', self.remote, self.local], output=False)
            if p.returncode != 0:
                self.clone_failed = True
                raise VCSException("Hg clone failed", p.output)
        else:
            p = FDroidPopen(['hg', 'status', '-uS'], cwd=self.local, output=False)
            if p.returncode != 0:
                raise VCSException("Hg status failed", p.output)
            for line in p.output.splitlines():
                if not line.startswith('? '):
                    raise VCSException("Unexpected output from hg status -uS: " + line)
                FDroidPopen(['rm', '-rf', line[2:]], cwd=self.local, output=False)
            if not self.refreshed:
                p = FDroidPopen(['hg', 'pull'], cwd=self.local, output=False)
                if p.returncode != 0:
                    raise VCSException("Hg pull failed", p.output)
                self.refreshed = True

        rev = rev or 'default'
        if not rev:
            return
        p = FDroidPopen(['hg', 'update', '-C', rev], cwd=self.local, output=False)
        if p.returncode != 0:
            raise VCSException("Hg checkout of '%s' failed" % rev, p.output)
        p = FDroidPopen(['hg', 'purge', '--all'], cwd=self.local, output=False)
        # Also delete untracked files, we have to enable purge extension for that:
        if "'purge' is provided by the following extension" in p.output:
            with open(os.path.join(self.local, '.hg', 'hgrc'), "a") as myfile:
                myfile.write("\n[extensions]\nhgext.purge=\n")
            p = FDroidPopen(['hg', 'purge', '--all'], cwd=self.local, output=False)
            if p.returncode != 0:
                raise VCSException("HG purge failed", p.output)
        elif p.returncode != 0:
            raise VCSException("HG purge failed", p.output)

    def _gettags(self):
        p = FDroidPopen(['hg', 'tags', '-q'], cwd=self.local, output=False)
        return p.output.splitlines()[1:]


class vcs_bzr(vcs):

    def repotype(self):
        return 'bzr'

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            p = FDroidPopen(['bzr', 'branch', self.remote, self.local], output=False)
            if p.returncode != 0:
                self.clone_failed = True
                raise VCSException("Bzr branch failed", p.output)
        else:
            p = FDroidPopen(['bzr', 'clean-tree', '--force', '--unknown', '--ignored'], cwd=self.local, output=False)
            if p.returncode != 0:
                raise VCSException("Bzr revert failed", p.output)
            if not self.refreshed:
                p = FDroidPopen(['bzr', 'pull'], cwd=self.local, output=False)
                if p.returncode != 0:
                    raise VCSException("Bzr update failed", p.output)
                self.refreshed = True

        revargs = list(['-r', rev] if rev else [])
        p = FDroidPopen(['bzr', 'revert'] + revargs, cwd=self.local, output=False)
        if p.returncode != 0:
            raise VCSException("Bzr revert of '%s' failed" % rev, p.output)

    def _gettags(self):
        p = FDroidPopen(['bzr', 'tags'], cwd=self.local, output=False)
        return [tag.split('   ')[0].strip() for tag in
                p.output.splitlines()]


def unescape_string(string):
    if len(string) < 2:
        return string
    if string[0] == '"' and string[-1] == '"':
        return string[1:-1]

    return string.replace("\\'", "'")


def retrieve_string(app_dir, string, xmlfiles=None):

    if not string.startswith('@string/'):
        return unescape_string(string)

    if xmlfiles is None:
        xmlfiles = []
        for res_dir in [
            os.path.join(app_dir, 'res'),
            os.path.join(app_dir, 'src', 'main', 'res'),
        ]:
            for r, d, f in os.walk(res_dir):
                if os.path.basename(r) == 'values':
                    xmlfiles += [os.path.join(r, x) for x in f if x.endswith('.xml')]

    name = string[len('@string/'):]

    def element_content(element):
        if element.text is None:
            return ""
        s = XMLElementTree.tostring(element, encoding='utf-8', method='text')
        return s.decode('utf-8').strip()

    for path in xmlfiles:
        if not os.path.isfile(path):
            continue
        xml = parse_xml(path)
        element = xml.find('string[@name="' + name + '"]')
        if element is not None:
            content = element_content(element)
            return retrieve_string(app_dir, content, xmlfiles)

    return ''


def retrieve_string_singleline(app_dir, string, xmlfiles=None):
    return retrieve_string(app_dir, string, xmlfiles).replace('\n', ' ').strip()


# Return list of existing files that will be used to find the highest vercode
def manifest_paths(app_dir, flavours):

    possible_manifests = \
        [os.path.join(app_dir, 'AndroidManifest.xml'),
         os.path.join(app_dir, 'src', 'main', 'AndroidManifest.xml'),
         os.path.join(app_dir, 'src', 'AndroidManifest.xml'),
         os.path.join(app_dir, 'build.gradle')]

    for flavour in flavours:
        if flavour == 'yes':
            continue
        possible_manifests.append(
            os.path.join(app_dir, 'src', flavour, 'AndroidManifest.xml'))

    return [path for path in possible_manifests if os.path.isfile(path)]


# Retrieve the package name. Returns the name, or None if not found.
def fetch_real_name(app_dir, flavours):
    for path in manifest_paths(app_dir, flavours):
        if not has_extension(path, 'xml') or not os.path.isfile(path):
            continue
        logging.debug("fetch_real_name: Checking manifest at " + path)
        xml = parse_xml(path)
        app = xml.find('application')
        if app is None:
            continue
        if "{http://schemas.android.com/apk/res/android}label" not in app.attrib:
            continue
        label = app.attrib["{http://schemas.android.com/apk/res/android}label"]
        result = retrieve_string_singleline(app_dir, label)
        if result:
            result = result.strip()
        return result
    return None


def get_library_references(root_dir):
    libraries = []
    proppath = os.path.join(root_dir, 'project.properties')
    if not os.path.isfile(proppath):
        return libraries
    with open(proppath, 'r', encoding='iso-8859-1') as f:
        for line in f:
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
            regsub_file(r'android:debuggable="[^"]*"',
                        '',
                        os.path.join(root, 'AndroidManifest.xml'))


vcsearch_g = re.compile(r'.*versionCode *=* *["\']*([0-9]+)["\']*').search
vnsearch_g = re.compile(r'.*versionName *=* *(["\'])((?:(?=(\\?))\3.)*?)\1.*').search
psearch_g = re.compile(r'.*(packageName|applicationId) *=* *["\']([^"]+)["\'].*').search


def app_matches_packagename(app, package):
    if not package:
        return False
    appid = app.UpdateCheckName or app.id
    if appid is None or appid == "Ignore":
        return True
    return appid == package


# Extract some information from the AndroidManifest.xml at the given path.
# Returns (version, vercode, package), any or all of which might be None.
# All values returned are strings.
def parse_androidmanifests(paths, app):

    ignoreversions = app.UpdateCheckIgnore
    ignoresearch = re.compile(ignoreversions).search if ignoreversions else None

    if not paths:
        return (None, None, None)

    max_version = None
    max_vercode = None
    max_package = None

    for path in paths:

        if not os.path.isfile(path):
            continue

        logging.debug("Parsing manifest at {0}".format(path))
        gradle = has_extension(path, 'gradle')
        version = None
        vercode = None
        package = None

        if gradle:
            with open(path, 'r') as f:
                for line in f:
                    if gradle_comment.match(line):
                        continue
                    # Grab first occurence of each to avoid running into
                    # alternative flavours and builds.
                    if not package:
                        matches = psearch_g(line)
                        if matches:
                            s = matches.group(2)
                            if app_matches_packagename(app, s):
                                package = s
                    if not version:
                        matches = vnsearch_g(line)
                        if matches:
                            version = matches.group(2)
                    if not vercode:
                        matches = vcsearch_g(line)
                        if matches:
                            vercode = matches.group(1)
        else:
            try:
                xml = parse_xml(path)
                if "package" in xml.attrib:
                    s = xml.attrib["package"]
                    if app_matches_packagename(app, s):
                        package = s
                if "{http://schemas.android.com/apk/res/android}versionName" in xml.attrib:
                    version = xml.attrib["{http://schemas.android.com/apk/res/android}versionName"]
                    base_dir = os.path.dirname(path)
                    version = retrieve_string_singleline(base_dir, version)
                if "{http://schemas.android.com/apk/res/android}versionCode" in xml.attrib:
                    a = xml.attrib["{http://schemas.android.com/apk/res/android}versionCode"]
                    if string_is_integer(a):
                        vercode = a
            except Exception:
                logging.warning("Problem with xml at {0}".format(path))

        # Remember package name, may be defined separately from version+vercode
        if package is None:
            package = max_package

        logging.debug("..got package={0}, version={1}, vercode={2}"
                      .format(package, version, vercode))

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

    if max_package and not is_valid_package_name(max_package):
        raise FDroidException("Invalid package name {0}".format(max_package))

    return (max_version, max_vercode, max_package)


def is_valid_package_name(name):
    return re.match("[A-Za-z_][A-Za-z_0-9.]+$", name)


class FDroidException(Exception):

    def __init__(self, value, detail=None):
        self.value = value
        self.detail = detail

    def shortened_detail(self):
        if len(self.detail) < 16000:
            return self.detail
        return '[...]\n' + self.detail[-16000:]

    def get_wikitext(self):
        ret = repr(self.value) + "\n"
        if self.detail:
            ret += "=detail=\n"
            ret += "<pre>\n" + self.shortened_detail() + "</pre>\n"
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
def getsrclib(spec, srclib_dir, subdir=None, basepath=False,
              raw=False, prepare=True, preponly=False, refresh=True,
              build=None):

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

    if name not in fdroidserver.metadata.srclibs:
        raise VCSException('srclib ' + name + ' not found.')

    srclib = fdroidserver.metadata.srclibs[name]

    sdir = os.path.join(srclib_dir, name)

    if not preponly:
        vcs = getvcs(srclib["Repo Type"], srclib["Repo"], sdir)
        vcs.srclib = (name, number, sdir)
        if ref:
            vcs.gotorevision(ref, refresh)

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

    remove_signing_keys(sdir)
    remove_debuggable_flags(sdir)

    if prepare:

        if srclib["Prepare"]:
            cmd = replace_config_vars(srclib["Prepare"], build)

            p = FDroidPopen(['bash', '-x', '-c', cmd], cwd=libdir)
            if p.returncode != 0:
                raise BuildException("Error running prepare command for srclib %s"
                                     % name, p.output)

    if basepath:
        libdir = sdir

    return (name, number, libdir)

gradle_version_regex = re.compile(r"[^/]*'com\.android\.tools\.build:gradle:([^\.]+\.[^\.]+).*'.*")


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
def prepare_source(vcs, app, build, build_dir, srclib_dir, extlib_dir, onserver=False, refresh=True):

    # Optionally, the actual app source can be in a subdirectory
    if build.subdir:
        root_dir = os.path.join(build_dir, build.subdir)
    else:
        root_dir = build_dir

    # Get a working copy of the right revision
    logging.info("Getting source for revision " + build.commit)
    vcs.gotorevision(build.commit, refresh)

    # Initialise submodules if required
    if build.submodules:
        logging.info("Initialising submodules")
        vcs.initsubmodules()

    # Check that a subdir (if we're using one) exists. This has to happen
    # after the checkout, since it might not exist elsewhere
    if not os.path.exists(root_dir):
        raise BuildException('Missing subdir ' + root_dir)

    # Run an init command if one is required
    if build.init:
        cmd = replace_config_vars(build.init, build)
        logging.info("Running 'init' commands in %s" % root_dir)

        p = FDroidPopen(['bash', '-x', '-c', cmd], cwd=root_dir)
        if p.returncode != 0:
            raise BuildException("Error running init command for %s:%s" %
                                 (app.id, build.version), p.output)

    # Apply patches if any
    if build.patch:
        logging.info("Applying patches")
        for patch in build.patch:
            patch = patch.strip()
            logging.info("Applying " + patch)
            patch_path = os.path.join('metadata', app.id, patch)
            p = FDroidPopen(['patch', '-p1', '-i', os.path.abspath(patch_path)], cwd=build_dir)
            if p.returncode != 0:
                raise BuildException("Failed to apply patch %s" % patch_path)

    # Get required source libraries
    srclibpaths = []
    if build.srclibs:
        logging.info("Collecting source libraries")
        for lib in build.srclibs:
            srclibpaths.append(getsrclib(lib, srclib_dir, build, preponly=onserver,
                                         refresh=refresh, build=build))

    for name, number, libpath in srclibpaths:
        place_srclib(root_dir, int(number) if number else None, libpath)

    basesrclib = vcs.getsrclib()
    # If one was used for the main source, add that too.
    if basesrclib:
        srclibpaths.append(basesrclib)

    # Update the local.properties file
    localprops = [os.path.join(build_dir, 'local.properties')]
    if build.subdir:
        parts = build.subdir.split(os.sep)
        cur = build_dir
        for d in parts:
            cur = os.path.join(cur, d)
            localprops += [os.path.join(cur, 'local.properties')]
    for path in localprops:
        props = ""
        if os.path.isfile(path):
            logging.info("Updating local.properties file at %s" % path)
            with open(path, 'r', encoding='iso-8859-1') as f:
                props += f.read()
            props += '\n'
        else:
            logging.info("Creating local.properties file at %s" % path)
        # Fix old-fashioned 'sdk-location' by copying
        # from sdk.dir, if necessary
        if build.oldsdkloc:
            sdkloc = re.match(r".*^sdk.dir=(\S+)$.*", props,
                              re.S | re.M).group(1)
            props += "sdk-location=%s\n" % sdkloc
        else:
            props += "sdk.dir=%s\n" % config['sdk_path']
            props += "sdk-location=%s\n" % config['sdk_path']
        ndk_path = build.ndk_path()
        if ndk_path:
            # Add ndk location
            props += "ndk.dir=%s\n" % ndk_path
            props += "ndk-location=%s\n" % ndk_path
        # Add java.encoding if necessary
        if build.encoding:
            props += "java.encoding=%s\n" % build.encoding
        with open(path, 'w', encoding='iso-8859-1') as f:
            f.write(props)

    flavours = []
    if build.build_method() == 'gradle':
        flavours = build.gradle

        if build.target:
            n = build.target.split('-')[1]
            regsub_file(r'compileSdkVersion[ =]+[0-9]+',
                        r'compileSdkVersion %s' % n,
                        os.path.join(root_dir, 'build.gradle'))

    # Remove forced debuggable flags
    remove_debuggable_flags(root_dir)

    # Insert version code and number into the manifest if necessary
    if build.forceversion:
        logging.info("Changing the version name")
        for path in manifest_paths(root_dir, flavours):
            if not os.path.isfile(path):
                continue
            if has_extension(path, 'xml'):
                regsub_file(r'android:versionName="[^"]*"',
                            r'android:versionName="%s"' % build.version,
                            path)
            elif has_extension(path, 'gradle'):
                regsub_file(r"""(\s*)versionName[\s'"=]+.*""",
                            r"""\1versionName '%s'""" % build.version,
                            path)

    if build.forcevercode:
        logging.info("Changing the version code")
        for path in manifest_paths(root_dir, flavours):
            if not os.path.isfile(path):
                continue
            if has_extension(path, 'xml'):
                regsub_file(r'android:versionCode="[^"]*"',
                            r'android:versionCode="%s"' % build.vercode,
                            path)
            elif has_extension(path, 'gradle'):
                regsub_file(r'versionCode[ =]+[0-9]+',
                            r'versionCode %s' % build.vercode,
                            path)

    # Delete unwanted files
    if build.rm:
        logging.info("Removing specified files")
        for part in getpaths(build_dir, build.rm):
            dest = os.path.join(build_dir, part)
            logging.info("Removing {0}".format(part))
            if os.path.lexists(dest):
                if os.path.islink(dest):
                    FDroidPopen(['unlink', dest], output=False)
                else:
                    FDroidPopen(['rm', '-rf', dest], output=False)
            else:
                logging.info("...but it didn't exist")

    remove_signing_keys(build_dir)

    # Add required external libraries
    if build.extlibs:
        logging.info("Collecting prebuilt libraries")
        libsdir = os.path.join(root_dir, 'libs')
        if not os.path.exists(libsdir):
            os.mkdir(libsdir)
        for lib in build.extlibs:
            lib = lib.strip()
            logging.info("...installing extlib {0}".format(lib))
            libf = os.path.basename(lib)
            libsrc = os.path.join(extlib_dir, lib)
            if not os.path.exists(libsrc):
                raise BuildException("Missing extlib file {0}".format(libsrc))
            shutil.copyfile(libsrc, os.path.join(libsdir, libf))

    # Run a pre-build command if one is required
    if build.prebuild:
        logging.info("Running 'prebuild' commands in %s" % root_dir)

        cmd = replace_config_vars(build.prebuild, build)

        # Substitute source library paths into prebuild commands
        for name, number, libpath in srclibpaths:
            libpath = os.path.relpath(libpath, root_dir)
            cmd = cmd.replace('$$' + name + '$$', libpath)

        p = FDroidPopen(['bash', '-x', '-c', cmd], cwd=root_dir)
        if p.returncode != 0:
            raise BuildException("Error running prebuild command for %s:%s" %
                                 (app.id, build.version), p.output)

    # Generate (or update) the ant build file, build.xml...
    if build.build_method() == 'ant' and build.update != ['no']:
        parms = ['android', 'update', 'lib-project']
        lparms = ['android', 'update', 'project']

        if build.target:
            parms += ['-t', build.target]
            lparms += ['-t', build.target]
        if build.update:
            update_dirs = build.update
        else:
            update_dirs = ant_subprojects(root_dir) + ['.']

        for d in update_dirs:
            subdir = os.path.join(root_dir, d)
            if d == '.':
                logging.debug("Updating main project")
                cmd = parms + ['-p', d]
            else:
                logging.debug("Updating subproject %s" % d)
                cmd = lparms + ['-p', d]
            p = SdkToolsPopen(cmd, cwd=root_dir)
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


# Extend via globbing the paths from a field and return them as a map from
# original path to resulting paths
def getpaths_map(build_dir, globpaths):
    paths = dict()
    for p in globpaths:
        p = p.strip()
        full_path = os.path.join(build_dir, p)
        full_path = os.path.normpath(full_path)
        paths[p] = [r[len(build_dir) + 1:] for r in glob.glob(full_path)]
        if not paths[p]:
            raise FDroidException("glob path '%s' did not match any files/dirs" % p)
    return paths


# Extend via globbing the paths from a field and return them as a set
def getpaths(build_dir, globpaths):
    paths_map = getpaths_map(build_dir, globpaths)
    paths = set()
    for k, v in paths_map.items():
        for p in v:
            paths.add(p)
    return paths


def natural_key(s):
    return [int(sp) if sp.isdigit() else sp for sp in re.split(r'(\d+)', s)]


class KnownApks:

    def __init__(self):
        self.path = os.path.join('stats', 'known_apks.txt')
        self.apks = {}
        if os.path.isfile(self.path):
            with open(self.path, 'r', encoding='utf8') as f:
                for line in f:
                    t = line.rstrip().split(' ')
                    if len(t) == 2:
                        self.apks[t[0]] = (t[1], None)
                    else:
                        self.apks[t[0]] = (t[1], time.strptime(t[2], '%Y-%m-%d'))
        self.changed = False

    def writeifchanged(self):
        if not self.changed:
            return

        if not os.path.exists('stats'):
            os.mkdir('stats')

        lst = []
        for apk, app in self.apks.items():
            appid, added = app
            line = apk + ' ' + appid
            if added:
                line += ' ' + time.strftime('%Y-%m-%d', added)
            lst.append(line)

        with open(self.path, 'w', encoding='utf8') as f:
            for line in sorted(lst, key=natural_key):
                f.write(line + '\n')

    # Record an apk (if it's new, otherwise does nothing)
    # Returns the date it was added.
    def recordapk(self, apk, app, default_date=None):
        if apk not in self.apks:
            if default_date is None:
                default_date = time.gmtime(time.time())
            self.apks[apk] = (app, default_date)
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
        for apk, app in self.apks.items():
            appid, added = app
            if added:
                if appid in apps:
                    if apps[appid] > added:
                        apps[appid] = added
                else:
                    apps[appid] = added
        sortedapps = sorted(apps.items(), key=operator.itemgetter(1))[-num:]
        lst = [app for app, _ in sortedapps]
        lst.reverse()
        return lst


def isApkDebuggable(apkfile, config):
    """Returns True if the given apk file is debuggable

    :param apkfile: full path to the apk to check"""

    p = SdkToolsPopen(['aapt', 'dump', 'xmltree', apkfile, 'AndroidManifest.xml'],
                      output=False)
    if p.returncode != 0:
        logging.critical("Failed to get apk manifest information")
        sys.exit(1)
    for line in p.output.splitlines():
        if 'android:debuggable' in line and not line.endswith('0x0'):
            return True
    return False


class PopenResult:
    def __init__(self):
        self.returncode = None
        self.output = None


def SdkToolsPopen(commands, cwd=None, output=True):
    cmd = commands[0]
    if cmd not in config:
        config[cmd] = find_sdk_tools_cmd(commands[0])
    abscmd = config[cmd]
    if abscmd is None:
        logging.critical("Could not find '%s' on your system" % cmd)
        sys.exit(1)
    return FDroidPopen([abscmd] + commands[1:],
                       cwd=cwd, output=output)


def FDroidPopenBytes(commands, cwd=None, output=True, stderr_to_stdout=True):
    """
    Run a command and capture the possibly huge output as bytes.

    :param commands: command and argument list like in subprocess.Popen
    :param cwd: optionally specifies a working directory
    :returns: A PopenResult.
    """

    global env
    if env is None:
        set_FDroidPopen_env()

    if cwd:
        cwd = os.path.normpath(cwd)
        logging.debug("Directory: %s" % cwd)
    logging.debug("> %s" % ' '.join(commands))

    stderr_param = subprocess.STDOUT if stderr_to_stdout else subprocess.PIPE
    result = PopenResult()
    p = None
    try:
        p = subprocess.Popen(commands, cwd=cwd, shell=False, env=env,
                             stdout=subprocess.PIPE, stderr=stderr_param)
    except OSError as e:
        raise BuildException("OSError while trying to execute " +
                             ' '.join(commands) + ': ' + str(e))

    if not stderr_to_stdout and options.verbose:
        stderr_queue = Queue()
        stderr_reader = AsynchronousFileReader(p.stderr, stderr_queue)

        while not stderr_reader.eof():
            while not stderr_queue.empty():
                line = stderr_queue.get()
                sys.stderr.buffer.write(line)
                sys.stderr.flush()

            time.sleep(0.1)

    stdout_queue = Queue()
    stdout_reader = AsynchronousFileReader(p.stdout, stdout_queue)
    buf = io.BytesIO()

    # Check the queue for output (until there is no more to get)
    while not stdout_reader.eof():
        while not stdout_queue.empty():
            line = stdout_queue.get()
            if output and options.verbose:
                # Output directly to console
                sys.stderr.buffer.write(line)
                sys.stderr.flush()
            buf.write(line)

        time.sleep(0.1)

    result.returncode = p.wait()
    result.output = buf.getvalue()
    buf.close()
    return result


def FDroidPopen(commands, cwd=None, output=True, stderr_to_stdout=True):
    """
    Run a command and capture the possibly huge output as a str.

    :param commands: command and argument list like in subprocess.Popen
    :param cwd: optionally specifies a working directory
    :returns: A PopenResult.
    """
    result = FDroidPopenBytes(commands, cwd, output, stderr_to_stdout)
    result.output = result.output.decode('utf-8')
    return result


gradle_comment = re.compile(r'[ ]*//')
gradle_signing_configs = re.compile(r'^[\t ]*signingConfigs[ \t]*{[ \t]*$')
gradle_line_matches = [
    re.compile(r'^[\t ]*signingConfig [^ ]*$'),
    re.compile(r'.*android\.signingConfigs\.[^{]*$'),
    re.compile(r'.*\.readLine\(.*'),
]


def remove_signing_keys(build_dir):
    for root, dirs, files in os.walk(build_dir):
        if 'build.gradle' in files:
            path = os.path.join(root, 'build.gradle')

            with open(path, "r", encoding='utf8') as o:
                lines = o.readlines()

            changed = False

            opened = 0
            i = 0
            with open(path, "w", encoding='utf8') as o:
                while i < len(lines):
                    line = lines[i]
                    i += 1
                    while line.endswith('\\\n'):
                        line = line.rstrip('\\\n') + lines[i]
                        i += 1

                    if gradle_comment.match(line):
                        o.write(line)
                        continue

                    if opened > 0:
                        opened += line.count('{')
                        opened -= line.count('}')
                        continue

                    if gradle_signing_configs.match(line):
                        changed = True
                        opened += 1
                        continue

                    if any(s.match(line) for s in gradle_line_matches):
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
                'ant.properties', ]:
            if propfile in files:
                path = os.path.join(root, propfile)

                with open(path, "r", encoding='iso-8859-1') as o:
                    lines = o.readlines()

                changed = False

                with open(path, "w", encoding='iso-8859-1') as o:
                    for line in lines:
                        if any(line.startswith(s) for s in ('key.store', 'key.alias')):
                            changed = True
                            continue

                        o.write(line)

                if changed:
                    logging.info("Cleaned %s of keysigning configs at %s" % (propfile, path))


def set_FDroidPopen_env(build=None):
    '''
    set up the environment variables for the build environment

    There is only a weak standard, the variables used by gradle, so also set
    up the most commonly used environment variables for SDK and NDK
    '''
    global env, orig_path

    if env is None:
        env = os.environ
        orig_path = env['PATH']
        for n in ['ANDROID_HOME', 'ANDROID_SDK']:
            env[n] = config['sdk_path']
        for k, v in config['java_paths'].items():
            env['JAVA%s_HOME' % k] = v

    if build is not None:
        path = build.ndk_path()
        paths = orig_path.split(os.pathsep)
        if path not in paths:
            paths = [path] + paths
            env['PATH'] = os.pathsep.join(paths)
        for n in ['ANDROID_NDK', 'NDK', 'ANDROID_NDK_HOME']:
            env[n] = build.ndk_path()


def replace_config_vars(cmd, build):
    cmd = cmd.replace('$$SDK$$', config['sdk_path'])
    cmd = cmd.replace('$$NDK$$', build.ndk_path())
    cmd = cmd.replace('$$MVN3$$', config['mvn3'])
    if build is not None:
        cmd = cmd.replace('$$COMMIT$$', build.commit)
        cmd = cmd.replace('$$VERSION$$', build.version)
        cmd = cmd.replace('$$VERCODE$$', build.vercode)
    return cmd


def place_srclib(root_dir, number, libpath):
    if not number:
        return
    relpath = os.path.relpath(libpath, root_dir)
    proppath = os.path.join(root_dir, 'project.properties')

    lines = []
    if os.path.isfile(proppath):
        with open(proppath, "r", encoding='iso-8859-1') as o:
            lines = o.readlines()

    with open(proppath, "w", encoding='iso-8859-1') as o:
        placed = False
        for line in lines:
            if line.startswith('android.library.reference.%d=' % number):
                o.write('android.library.reference.%d=%s\n' % (number, relpath))
                placed = True
            else:
                o.write(line)
        if not placed:
            o.write('android.library.reference.%d=%s\n' % (number, relpath))

apk_sigfile = re.compile(r'META-INF/[0-9A-Za-z]+\.(SF|RSA|DSA|EC)')


def verify_apks(signed_apk, unsigned_apk, tmp_dir):
    """Verify that two apks are the same

    One of the inputs is signed, the other is unsigned. The signature metadata
    is transferred from the signed to the unsigned apk, and then jarsigner is
    used to verify that the signature from the signed apk is also varlid for
    the unsigned one.
    :param signed_apk: Path to a signed apk file
    :param unsigned_apk: Path to an unsigned apk file expected to match it
    :param tmp_dir: Path to directory for temporary files
    :returns: None if the verification is successful, otherwise a string
              describing what went wrong.
    """
    with ZipFile(signed_apk) as signed_apk_as_zip:
        meta_inf_files = ['META-INF/MANIFEST.MF']
        for f in signed_apk_as_zip.namelist():
            if apk_sigfile.match(f):
                meta_inf_files.append(f)
        if len(meta_inf_files) < 3:
            return "Signature files missing from {0}".format(signed_apk)
        signed_apk_as_zip.extractall(tmp_dir, meta_inf_files)
    with ZipFile(unsigned_apk, mode='a') as unsigned_apk_as_zip:
        for meta_inf_file in meta_inf_files:
            unsigned_apk_as_zip.write(os.path.join(tmp_dir, meta_inf_file), arcname=meta_inf_file)

    if subprocess.call([config['jarsigner'], '-verify', unsigned_apk]) != 0:
        logging.info("...NOT verified - {0}".format(signed_apk))
        return compare_apks(signed_apk, unsigned_apk, tmp_dir)
    logging.info("...successfully verified")
    return None

apk_badchars = re.compile('''[/ :;'"]''')


def compare_apks(apk1, apk2, tmp_dir):
    """Compare two apks

    Returns None if the apk content is the same (apart from the signing key),
    otherwise a string describing what's different, or what went wrong when
    trying to do the comparison.
    """

    apk1dir = os.path.join(tmp_dir, apk_badchars.sub('_', apk1[0:-4]))  # trim .apk
    apk2dir = os.path.join(tmp_dir, apk_badchars.sub('_', apk2[0:-4]))  # trim .apk
    for d in [apk1dir, apk2dir]:
        if os.path.exists(d):
            shutil.rmtree(d)
        os.mkdir(d)
        os.mkdir(os.path.join(d, 'jar-xf'))

    if subprocess.call(['jar', 'xf',
                        os.path.abspath(apk1)],
                       cwd=os.path.join(apk1dir, 'jar-xf')) != 0:
        return("Failed to unpack " + apk1)
    if subprocess.call(['jar', 'xf',
                        os.path.abspath(apk2)],
                       cwd=os.path.join(apk2dir, 'jar-xf')) != 0:
        return("Failed to unpack " + apk2)

    # try to find apktool in the path, if it hasn't been manually configed
    if 'apktool' not in config:
        tmp = find_command('apktool')
        if tmp is not None:
            config['apktool'] = tmp
    if 'apktool' in config:
        if subprocess.call([config['apktool'], 'd', os.path.abspath(apk1), '--output', 'apktool'],
                           cwd=apk1dir) != 0:
            return("Failed to unpack " + apk1)
        if subprocess.call([config['apktool'], 'd', os.path.abspath(apk2), '--output', 'apktool'],
                           cwd=apk2dir) != 0:
            return("Failed to unpack " + apk2)

    p = FDroidPopen(['diff', '-r', apk1dir, apk2dir], output=False)
    lines = p.output.splitlines()
    if len(lines) != 1 or 'META-INF' not in lines[0]:
        meld = find_command('meld')
        if meld is not None:
            p = FDroidPopen(['meld', apk1dir, apk2dir], output=False)
        return("Unexpected diff output - " + p.output)

    # since everything verifies, delete the comparison to keep cruft down
    shutil.rmtree(apk1dir)
    shutil.rmtree(apk2dir)

    # If we get here, it seems like they're the same!
    return None


def find_command(command):
    '''find the full path of a command, or None if it can't be found in the PATH'''

    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(command)
    if fpath:
        if is_exe(command):
            return command
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, command)
            if is_exe(exe_file):
                return exe_file

    return None


def genpassword():
    '''generate a random password for when generating keys'''
    h = hashlib.sha256()
    h.update(os.urandom(16))  # salt
    h.update(socket.getfqdn().encode('utf-8'))
    passwd = base64.b64encode(h.digest()).strip()
    return passwd.decode('utf-8')


def genkeystore(localconfig):
    '''Generate a new key with random passwords and add it to new keystore'''
    logging.info('Generating a new key in "' + localconfig['keystore'] + '"...')
    keystoredir = os.path.dirname(localconfig['keystore'])
    if keystoredir is None or keystoredir == '':
        keystoredir = os.path.join(os.getcwd(), keystoredir)
    if not os.path.exists(keystoredir):
        os.makedirs(keystoredir, mode=0o700)

    write_password_file("keystorepass", localconfig['keystorepass'])
    write_password_file("keypass", localconfig['keypass'])
    p = FDroidPopen([config['keytool'], '-genkey',
                     '-keystore', localconfig['keystore'],
                     '-alias', localconfig['repo_keyalias'],
                     '-keyalg', 'RSA', '-keysize', '4096',
                     '-sigalg', 'SHA256withRSA',
                     '-validity', '10000',
                     '-storepass:file', config['keystorepassfile'],
                     '-keypass:file', config['keypassfile'],
                     '-dname', localconfig['keydname']])
    # TODO keypass should be sent via stdin
    if p.returncode != 0:
        raise BuildException("Failed to generate key", p.output)
    os.chmod(localconfig['keystore'], 0o0600)
    # now show the lovely key that was just generated
    p = FDroidPopen([config['keytool'], '-list', '-v',
                     '-keystore', localconfig['keystore'],
                     '-alias', localconfig['repo_keyalias'],
                     '-storepass:file', config['keystorepassfile']])
    logging.info(p.output.strip() + '\n\n')


def write_to_config(thisconfig, key, value=None):
    '''write a key/value to the local config.py'''
    if value is None:
        origkey = key + '_orig'
        value = thisconfig[origkey] if origkey in thisconfig else thisconfig[key]
    with open('config.py', 'r', encoding='utf8') as f:
        data = f.read()
    pattern = '\n[\s#]*' + key + '\s*=\s*"[^"]*"'
    repl = '\n' + key + ' = "' + value + '"'
    data = re.sub(pattern, repl, data)
    # if this key is not in the file, append it
    if not re.match('\s*' + key + '\s*=\s*"', data):
        data += repl
    # make sure the file ends with a carraige return
    if not re.match('\n$', data):
        data += '\n'
    with open('config.py', 'w', encoding='utf8') as f:
        f.writelines(data)


def parse_xml(path):
    return XMLElementTree.parse(path).getroot()


def string_is_integer(string):
    try:
        int(string)
        return True
    except ValueError:
        return False


def get_per_app_repos():
    '''per-app repos are dirs named with the packageName of a single app'''

    # Android packageNames are Java packages, they may contain uppercase or
    # lowercase letters ('A' through 'Z'), numbers, and underscores
    # ('_'). However, individual package name parts may only start with
    # letters. https://developer.android.com/guide/topics/manifest/manifest-element.html#package
    p = re.compile('^([a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)*)?$')

    repos = []
    for root, dirs, files in os.walk(os.getcwd()):
        for d in dirs:
            print('checking', root, 'for', d)
            if d in ('archive', 'metadata', 'repo', 'srclibs', 'tmp'):
                # standard parts of an fdroid repo, so never packageNames
                continue
            elif p.match(d) \
                    and os.path.exists(os.path.join(d, 'fdroid', 'repo', 'index.jar')):
                repos.append(d)
        break
    return repos
