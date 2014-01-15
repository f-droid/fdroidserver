# -*- coding: utf-8 -*-
#
# common.py - part of the FDroid server tools
# Copyright (C) 2010-13, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013 Daniel Martí <mvdan@mvdan.cc>
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

import glob, os, sys, re
import shutil
import stat
import subprocess
import time
import operator
import Queue
import threading
import magic
from distutils.spawn import find_executable

import metadata

config = None
options = None

def read_config(opts, config_file='config.py'):
    """Read the repository config

    The config is read from config_file, which is in the current directory when
    any of the repo management commands are used.
    """
    global config, options

    if config is not None:
        return config
    if not os.path.isfile(config_file):
        print "Missing config file - is this a repo directory?"
        sys.exit(2)

    options = opts
    if not hasattr(options, 'verbose'):
        options.verbose = False

    defconfig = {
        'build_server_always': False,
        'mvn3': "mvn3",
        'archive_older': 0,
        'gradle': 'gradle',
        'update_stats': False,
        'archive_older': 0,
        'max_icon_size': 72,
        'stats_to_carbon': False,
        'repo_maxage': 0,
        'char_limits': {
            'Summary' : 50,
            'Description' : 1500
        }

    }
    config = {}

    if options.verbose:
        print "Reading %s..." % config_file
    execfile(config_file, config)

    if any(k in config for k in ["keystore", "keystorepass", "keypass"]):
        st = os.stat(config_file)
        if st.st_mode & stat.S_IRWXG or st.st_mode & stat.S_IRWXO:
            print "WARNING: unsafe permissions on {0} (should be 0600)!".format(config_file)

    # Expand environment variables
    for k, v in config.items():
        if type(v) != str:
            continue
        v = os.path.expanduser(v)
        config[k] = os.path.expandvars(v)

    # Check that commands and binaries do exist
    for key in ('mvn3', 'gradle'):
        if key not in config:
            continue
        val = config[key]
        executable = find_executable(val)
        if not executable:
            print "ERROR: No such command or binary for %s: %s" % (key, val)
            sys.exit(3)

    # Check that directories exist
    for key in ('sdk_path', 'ndk_path', 'build_tools'):
        if key not in config:
            continue
        val = config[key]
        if key == 'build_tools':
            if 'sdk_path' not in config:
                print "ERROR: sdk_path needs to be set for build_tools"
                sys.exit(3)
            val = os.path.join(config['sdk_path'], 'build-tools', val)
        if not os.path.isdir(val):
            print "ERROR: No such directory found for %s: %s" % (key, val)
            sys.exit(3)

    for k, v in defconfig.items():
        if k not in config:
            config[k] = v

    return config

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

    if not apps:
        raise Exception("No packages specified")
    if len(apps) != len(vercodes):
        allids = [app["id"] for app in allapps]
        for p in vercodes:
            if p not in allids:
                print "No such package: %s" % p
        raise Exception("Found invalid app ids in arguments")

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
                    print "No such vercode %s for app %s" % (v, app['id'])

    if error:
        raise Exception("Found invalid vercodes for some apps")

    return apps

def has_extension(filename, extension):
    name, ext = os.path.splitext(filename)
    ext = ext.lower()[1:]
    return ext == extension

apk_regex = None

def apknameinfo(filename):
    global apk_regex
    filename = os.path.basename(filename)
    if apk_regex is None:
        apk_regex = re.compile(r"^(.+)_([0-9]+)\.apk$")
    m = apk_regex.match(filename)
    try:
        result = (m.group(1), m.group(2))
    except AttributeError:
        raise Exception("Invalid apk name: %s" % filename)
    return result

def getapkname(app, build):
    return "%s_%s.apk" % (app['id'], build['vercode'])

def getsrcname(app, build):
    return "%s_%s_src.tar.gz" % (app['id'], build['vercode'])

def getappname(app):
    if app['Name']:
        return '%s (%s)' % (app['Name'], app['id'])
    if app['Auto Name']:
        return '%s (%s)' % (app['Auto Name'], app['id'])
    return app['id']

def getcvname(app):
    return '%s (%s)' % (app['Current Version'], app['Current Version Code'])

def getvcs(vcstype, remote, local):
    if vcstype == 'git':
        return vcs_git(remote, local)
    if vcstype == 'svn':
        return vcs_svn(remote, local)
    if vcstype == 'git-svn':
        return vcs_gitsvn(remote, local)
    if vcstype == 'hg':
        return vcs_hg(remote, local)
    if vcstype == 'bzr':
        return vcs_bzr(remote, local)
    if vcstype == 'srclib':
        if local != 'build/srclib/' + remote:
            raise VCSException("Error: srclib paths are hard-coded!")
        return getsrclib(remote, 'build/srclib', raw=True)
    raise VCSException("Invalid vcs type " + vcstype)

def getsrclibvcs(name):
    srclib_path = os.path.join('srclibs', name + ".txt")
    if not os.path.exists(srclib_path):
        raise VCSException("Missing srclib " + name)
    return metadata.parse_srclib(srclib_path)['Repo Type']

class vcs:
    def __init__(self, remote, local):

        # svn, git-svn and bzr may require auth
        self.username = None
        if self.repotype() in ('svn', 'git-svn', 'bzr'):
            if '@' in remote:
                self.username, remote = remote.split('@')
                if ':' not in self.username:
                    raise VCSException("Password required with username")
                self.username, self.password = self.username.split(':')

        self.remote = remote
        self.local = local
        self.refreshed = False
        self.srclib = None

    # Take the local repository to a clean version of the given revision, which
    # is specificed in the VCS's native format. Beforehand, the repository can
    # be dirty, or even non-existent. If the repository does already exist
    # locally, it will be updated from the origin, but only once in the
    # lifetime of the vcs object.
    # None is acceptable for 'rev' if you know you are cloning a clean copy of
    # the repo - otherwise it must specify a valid revision.
    def gotorevision(self, rev):

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
                    fsdata = f.read()
                if fsdata == cdata:
                    writeback = False
                else:
                    deleterepo = True
                    print "*** Repository details changed - deleting ***"
            else:
                deleterepo = True
                print "*** Repository details missing - deleting ***"
        if deleterepo:
            shutil.rmtree(self.local)

        self.gotorevisionx(rev)

        # If necessary, write the .fdroidvcs file.
        if writeback:
            with open(fdpath, 'w') as f:
                f.write(cdata)

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
        p = subprocess.Popen(['git', 'rev-parse', '--show-toplevel'],
                stdout=subprocess.PIPE, cwd=self.local)
        result = p.communicate()[0].rstrip()
        if not result.endswith(self.local):
            raise VCSException('Repository mismatch')

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            # Brand new checkout...
            if subprocess.call(['git', 'clone', self.remote, self.local]) != 0:
                raise VCSException("Git clone failed")
            self.checkrepo()
        else:
            self.checkrepo()
            # Discard any working tree changes...
            if subprocess.call(['git', 'reset', '--hard'], cwd=self.local) != 0:
                raise VCSException("Git reset failed")
            # Remove untracked files now, in case they're tracked in the target
            # revision (it happens!)...
            if subprocess.call(['git', 'clean', '-dffx'], cwd=self.local) != 0:
                raise VCSException("Git clean failed")
            if not self.refreshed:
                # Get latest commits and tags from remote...
                if subprocess.call(['git', 'fetch', 'origin'],
                        cwd=self.local) != 0:
                    raise VCSException("Git fetch failed")
                if subprocess.call(['git', 'fetch', '--tags', 'origin'],
                        cwd=self.local) != 0:
                    raise VCSException("Git fetch failed")
                self.refreshed = True
        # Check out the appropriate revision...
        rev = str(rev if rev else 'origin/master')
        if subprocess.call(['git', 'checkout', '-f', rev], cwd=self.local) != 0:
            raise VCSException("Git checkout failed")
        # Get rid of any uncontrolled files left behind...
        if subprocess.call(['git', 'clean', '-dffx'], cwd=self.local) != 0:
            raise VCSException("Git clean failed")

    def initsubmodules(self):
        self.checkrepo()
        if subprocess.call(['git', 'submodule', 'init'],
                cwd=self.local) != 0:
            raise VCSException("Git submodule init failed")
        if subprocess.call(['git', 'submodule', 'update'],
                cwd=self.local) != 0:
            raise VCSException("Git submodule update failed")
        if subprocess.call(['git', 'submodule', 'foreach',
            'git', 'reset', '--hard'],
                cwd=self.local) != 0:
            raise VCSException("Git submodule reset failed")
        if subprocess.call(['git', 'submodule', 'foreach',
            'git', 'clean', '-dffx'],
                cwd=self.local) != 0:
            raise VCSException("Git submodule clean failed")

    def gettags(self):
        self.checkrepo()
        p = subprocess.Popen(['git', 'tag'],
                stdout=subprocess.PIPE, cwd=self.local)
        return p.communicate()[0].splitlines()


class vcs_gitsvn(vcs):

    def repotype(self):
        return 'git-svn'

    # Damn git-svn tries to use a graphical password prompt, so we have to
    # trick it into taking the password from stdin
    def userargs(self):
        if self.username is None:
            return ('', '')
        return ('echo "%s" | DISPLAY="" ' % self.password, '--username "%s"' % self.username)

    # If the local directory exists, but is somehow not a git repository, git
    # will traverse up the directory tree until it finds one that is (i.e.
    # fdroidserver) and then we'll proceed to destory it! This is called as
    # a safety check.
    def checkrepo(self):
        p = subprocess.Popen(['git', 'rev-parse', '--show-toplevel'],
                stdout=subprocess.PIPE, cwd=self.local)
        result = p.communicate()[0].rstrip()
        if not result.endswith(self.local):
            raise VCSException('Repository mismatch')

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            # Brand new checkout...
            gitsvn_cmd = '%sgit svn clone %s' % self.userargs()
            if ';' in self.remote:
                remote_split = self.remote.split(';')
                for i in remote_split[1:]:
                    if i.startswith('trunk='):
                        gitsvn_cmd += ' -T %s' % i[6:]
                    elif i.startswith('tags='):
                        gitsvn_cmd += ' -t %s' % i[5:]
                    elif i.startswith('branches='):
                        gitsvn_cmd += ' -b %s' % i[9:]
                if subprocess.call([gitsvn_cmd + " %s %s" % (remote_split[0], self.local)],
                        shell=True) != 0:
                    raise VCSException("Git clone failed")
            else:
                if subprocess.call([gitsvn_cmd + " %s %s" % (self.remote, self.local)],
                        shell=True) != 0:
                    raise VCSException("Git clone failed")
            self.checkrepo()
        else:
            self.checkrepo()
            # Discard any working tree changes...
            if subprocess.call(['git', 'reset', '--hard'], cwd=self.local) != 0:
                raise VCSException("Git reset failed")
            # Remove untracked files now, in case they're tracked in the target
            # revision (it happens!)...
            if subprocess.call(['git', 'clean', '-dffx'], cwd=self.local) != 0:
                raise VCSException("Git clean failed")
            if not self.refreshed:
                # Get new commits and tags from repo...
                if subprocess.call(['%sgit svn rebase %s' % self.userargs()],
                        cwd=self.local, shell=True) != 0:
                    raise VCSException("Git svn rebase failed")
                self.refreshed = True

        rev = str(rev if rev else 'master')
        if rev:
            nospaces_rev = rev.replace(' ', '%20')
            # Try finding a svn tag
            p = subprocess.Popen(['git', 'checkout', 'tags/' + nospaces_rev],
                    cwd=self.local, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate()
            if p.returncode == 0:
                print out
            else:
                # No tag found, normal svn rev translation
                # Translate svn rev into git format
                p = subprocess.Popen(['git', 'svn', 'find-rev', 'r' + rev],
                    cwd=self.local, stdout=subprocess.PIPE)
                git_rev = p.communicate()[0].rstrip()
                if p.returncode != 0 or not git_rev:
                    # Try a plain git checkout as a last resort
                    p = subprocess.Popen(['git', 'checkout', rev], cwd=self.local,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out, err = p.communicate()
                    if p.returncode == 0:
                        print out
                    else:
                        raise VCSException("No git treeish found and direct git checkout failed")
                else:
                    # Check out the git rev equivalent to the svn rev
                    p = subprocess.Popen(['git', 'checkout', git_rev], cwd=self.local,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out, err = p.communicate()
                    if p.returncode == 0:
                        print out
                    else:
                        raise VCSException("Git svn checkout failed")
        # Get rid of any uncontrolled files left behind...
        if subprocess.call(['git', 'clean', '-dffx'], cwd=self.local) != 0:
            raise VCSException("Git clean failed")

    def gettags(self):
        self.checkrepo()
        return os.listdir(os.path.join(self.local, '.git/svn/refs/remotes/tags'))

    def getref(self):
        self.checkrepo()
        p = subprocess.Popen(['git', 'svn', 'find-rev', 'HEAD'],
                stdout=subprocess.PIPE, cwd=self.local)
        return p.communicate()[0].strip()

class vcs_svn(vcs):

    def repotype(self):
        return 'svn'

    def userargs(self):
        if self.username is None:
            return ['--non-interactive']
        return ['--username', self.username,
                '--password', self.password,
                '--non-interactive']

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            if subprocess.call(['svn', 'checkout', self.remote, self.local] +
                    self.userargs()) != 0:
                raise VCSException("Svn checkout failed")
        else:
            for svncommand in (
                    'svn revert -R .',
                    r"svn status | awk '/\?/ {print $2}' | xargs rm -rf"):
                if subprocess.call(svncommand, cwd=self.local, shell=True) != 0:
                    raise VCSException("Svn reset ({0}) failed in {1}".format(svncommand, self.local))
            if not self.refreshed:
                if subprocess.call(['svn', 'update'] +
                        self.userargs(), cwd=self.local) != 0:
                    raise VCSException("Svn update failed")
                self.refreshed = True

        revargs = list(['-r', rev] if rev else [])
        if subprocess.call(['svn', 'update', '--force'] + revargs +
                self.userargs(), cwd=self.local) != 0:
            raise VCSException("Svn update failed")

    def getref(self):
        p = subprocess.Popen(['svn', 'info'],
                stdout=subprocess.PIPE, cwd=self.local)
        for line in p.communicate()[0].splitlines():
            if line and line.startswith('Last Changed Rev: '):
                return line[18:]

class vcs_hg(vcs):

    def repotype(self):
        return 'hg'

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            if subprocess.call(['hg', 'clone', self.remote, self.local]) !=0:
                raise VCSException("Hg clone failed")
        else:
            if subprocess.call('hg status -uS | xargs rm -rf',
                    cwd=self.local, shell=True) != 0:
                raise VCSException("Hg clean failed")
            if not self.refreshed:
                if subprocess.call(['hg', 'pull'],
                        cwd=self.local) != 0:
                    raise VCSException("Hg pull failed")
                self.refreshed = True

        rev = str(rev if rev else 'default')
        if not rev:
            return
        if subprocess.call(['hg', 'update', '-C', rev],
                cwd=self.local) != 0:
            raise VCSException("Hg checkout failed")
        p = subprocess.Popen(['hg', 'purge', '--all'], stdout=subprocess.PIPE,
                             cwd=self.local)
        result = p.communicate()[0]
        # Also delete untracked files, we have to enable purge extension for that:
        if "'purge' is provided by the following extension" in result:
            with open(self.local+"/.hg/hgrc", "a") as myfile:
                myfile.write("\n[extensions]\nhgext.purge=")
            if subprocess.call(['hg', 'purge', '--all'],
                    cwd=self.local) != 0:
                raise VCSException("HG purge failed")
        else:
            raise VCSException("HG purge failed")

    def gettags(self):
        p = subprocess.Popen(['hg', 'tags', '-q'],
                stdout=subprocess.PIPE, cwd=self.local)
        return p.communicate()[0].splitlines()[1:]


class vcs_bzr(vcs):

    def repotype(self):
        return 'bzr'

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            if subprocess.call(['bzr', 'branch', self.remote, self.local]) != 0:
                raise VCSException("Bzr branch failed")
        else:
            if subprocess.call(['bzr', 'clean-tree', '--force',
                    '--unknown', '--ignored'], cwd=self.local) != 0:
                raise VCSException("Bzr revert failed")
            if not self.refreshed:
                if subprocess.call(['bzr', 'pull'],
                        cwd=self.local) != 0:
                    raise VCSException("Bzr update failed")
                self.refreshed = True

        revargs = list(['-r', rev] if rev else [])
        if subprocess.call(['bzr', 'revert'] + revargs,
                cwd=self.local) != 0:
            raise VCSException("Bzr revert failed")

    def gettags(self):
        p = subprocess.Popen(['bzr', 'tags'],
                stdout=subprocess.PIPE, cwd=self.local)
        return [tag.split('   ')[0].strip() for tag in
                p.communicate()[0].splitlines()]

def retrieve_string(xml_dir, string):
    if string.startswith('@string/'):
        string_search = re.compile(r'.*"'+string[8:]+'".*?>([^<]+?)<.*').search
        for xmlfile in glob.glob(os.path.join(xml_dir, '*.xml')):
            for line in file(xmlfile):
                matches = string_search(line)
                if matches:
                    return retrieve_string(xml_dir, matches.group(1))
    elif string.startswith('&') and string.endswith(';'):
        string_search = re.compile(r'.*<!ENTITY.*'+string[1:-1]+'.*?"([^"]+?)".*>').search
        for xmlfile in glob.glob(os.path.join(xml_dir, '*.xml')):
            for line in file(xmlfile):
                matches = string_search(line)
                if matches:
                    return retrieve_string(xml_dir, matches.group(1))

    return string.replace("\\'","'")

# Return list of existing files that will be used to find the highest vercode
def manifest_paths(app_dir, flavour):

    possible_manifests = [ os.path.join(app_dir, 'AndroidManifest.xml'),
            os.path.join(app_dir, 'src', 'main', 'AndroidManifest.xml'),
            os.path.join(app_dir, 'build.gradle') ]

    if flavour:
        possible_manifests.append(
                os.path.join(app_dir, 'src', flavour, 'AndroidManifest.xml'))

    return [path for path in possible_manifests if os.path.isfile(path)]

# Retrieve the package name
def fetch_real_name(app_dir, flavour):
    app_search = re.compile(r'.*<application.*').search
    name_search = re.compile(r'.*android:label="([^"]+)".*').search
    app_found = False
    for f in manifest_paths(app_dir, flavour):
        if not has_extension(f, 'xml'):
            continue
        xml_dir = os.path.join(f[:-19], 'res', 'values')
        for line in file(f):
            if not app_found:
                if app_search(line):
                    app_found = True
            if app_found:
                matches = name_search(line)
                if matches:
                    return retrieve_string(xml_dir, matches.group(1))
    return ''

# Retrieve the version name
def version_name(original, app_dir, flavour):
    for f in manifest_paths(app_dir, flavour):
        if not has_extension(f, 'xml'):
            continue
        xml_dir = os.path.join(f[:-19], 'res', 'values')
        string = retrieve_string(xml_dir, original)
        if string:
            return string
    return original

def ant_subprojects(root_dir):
    subprojects = []
    proppath = os.path.join(root_dir, 'project.properties')
    if not os.path.isfile(proppath):
        return subprojects
    with open(proppath) as f:
        for line in f.readlines():
            if not line.startswith('android.library.reference.'):
                continue
            path = line.split('=')[1].strip()
            relpath = os.path.join(root_dir, path)
            if not os.path.isdir(relpath):
                continue
            if options.verbose:
                print "Found subproject %s..." % path
            subprojects.append(path)
    return subprojects

# Extract some information from the AndroidManifest.xml at the given path.
# Returns (version, vercode, package), any or all of which might be None.
# All values returned are strings.
def parse_androidmanifests(paths):

    if not paths:
        return (None, None, None)

    vcsearch = re.compile(r'.*android:versionCode="([0-9]+?)".*').search
    vnsearch = re.compile(r'.*android:versionName="([^"]+?)".*').search
    psearch = re.compile(r'.*package="([^"]+)".*').search

    vcsearch_g = re.compile(r'.*versionCode[ ]*[=]*[ ]*["\']*([0-9]+)["\']*').search
    vnsearch_g = re.compile(r'.*versionName[ ]*[=]*[ ]*(["\'])((?:(?=(\\?))\3.)*?)\1.*').search
    psearch_g = re.compile(r'.*packageName[ ]*[=]*[ ]*["\']([^"]+)["\'].*').search

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

        # Better some package name than nothing
        if max_package is None:
            max_package = package

        if max_vercode is None or (vercode is not None and vercode > max_vercode):
            max_version = version
            max_vercode = vercode
            max_package = package

    if max_version is None:
        max_version = "Unknown"

    return (max_version, max_vercode, max_package)

class BuildException(Exception):
    def __init__(self, value, stdout = None, stderr = None):
        self.value = value
        self.stdout = stdout
        self.stderr = stderr

    def get_wikitext(self):
        ret = repr(self.value) + "\n"
        if self.stdout:
            ret += "=stdout=\n"
            ret += "<pre>\n"
            ret += str(self.stdout)
            ret += "</pre>\n"
        if self.stderr:
            ret += "=stderr=\n"
            ret += "<pre>\n"
            ret += str(self.stderr)
            ret += "</pre>\n"
        return ret

    def __str__(self):
        ret = repr(self.value)
        if self.stdout:
            ret += "\n==== stdout begin ====\n%s\n==== stdout end ====" % self.stdout.strip()
        if self.stderr:
            ret += "\n==== stderr begin ====\n%s\n==== stderr end ====" % self.stderr.strip()
        return ret

class VCSException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

# Get the specified source library.
# Returns the path to it. Normally this is the path to be used when referencing
# it, which may be a subdirectory of the actual project. If you want the base
# directory of the project, pass 'basepath=True'.
def getsrclib(spec, srclib_dir, srclibpaths=[], subdir=None, target=None,
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
            name, subdir = name.split('/',1)

    srclib_path = os.path.join('srclibs', name + ".txt")

    if not os.path.exists(srclib_path):
        raise BuildException('srclib ' + name + ' not found.')

    srclib = metadata.parse_srclib(srclib_path)

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
        n=1
        for lib in srclib["Srclibs"].split(','):
            s_tuple = None
            for t in srclibpaths:
                if t[0] == lib:
                    s_tuple = t
                    break
            if s_tuple is None:
                raise BuildException('Missing recursive srclib %s for %s' % (
                    lib, name))
            place_srclib(libdir, n, s_tuple[2])
            n+=1

    if prepare:

        if srclib["Prepare"]:
            cmd = replace_config_vars(srclib["Prepare"])

            p = FDroidPopen(['bash', '-x', '-c', cmd], cwd=libdir)
            if p.returncode != 0:
                raise BuildException("Error running prepare command for srclib %s"
                        % name, p.stdout, p.stderr)

        if srclib["Update Project"] == "Yes":
            print "Updating srclib %s at path %s" % (name, libdir)
            cmd = [os.path.join(config['sdk_path'], 'tools', 'android'),
                'update', 'project', '-p', libdir]
            if target:
                cmd += ['-t', target]
            p = FDroidPopen(cmd)
            # Check to see whether an error was returned without a proper exit
            # code (this is the case for the 'no target set or target invalid'
            # error)
            if p.returncode != 0 or (p.stderr != "" and
                    p.stderr.startswith("Error: ")):
                raise BuildException("Failed to update srclib project {0}"
                        .format(name), p.stdout, p.stderr)

            remove_signing_keys(libdir)

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

    # Optionally, the actual app source can be in a subdirectory...
    if 'subdir' in build:
        root_dir = os.path.join(build_dir, build['subdir'])
    else:
        root_dir = build_dir

    # Get a working copy of the right revision...
    print "Getting source for revision " + build['commit']
    vcs.gotorevision(build['commit'])

    # Check that a subdir (if we're using one) exists. This has to happen
    # after the checkout, since it might not exist elsewhere...
    if not os.path.exists(root_dir):
        raise BuildException('Missing subdir ' + root_dir)

    # Initialise submodules if requred...
    if build['submodules']:
        if options.verbose:
            print "Initialising submodules..."
        vcs.initsubmodules()

    # Run an init command if one is required...
    if 'init' in build:
        cmd = replace_config_vars(build['init'])
        if options.verbose:
            print "Running 'init' commands in %s" % root_dir

        p = FDroidPopen(['bash', '-x', '-c', cmd], cwd=root_dir)
        if p.returncode != 0:
            raise BuildException("Error running init command for %s:%s" %
                    (app['id'], build['version']), p.stdout, p.stderr)

    # Generate (or update) the ant build file, build.xml...
    updatemode = build.get('update', 'auto')
    if (updatemode != 'no' and build['type'] == 'ant'):
        parms = [os.path.join(config['sdk_path'], 'tools', 'android'),
                'update', 'project']
        if 'target' in build and build['target']:
            parms += ['-t', build['target']]
        update_dirs = None
        if updatemode == 'auto':
            update_dirs = ['.'] + ant_subprojects(root_dir)
        else:
            update_dirs = [d.strip() for d in updatemode.split(';')]
        # Force build.xml update if necessary...
        if updatemode == 'force' or 'target' in build:
            if updatemode == 'force':
                update_dirs = ['.']
            buildxml = os.path.join(root_dir, 'build.xml')
            if os.path.exists(buildxml):
                print 'Force-removing old build.xml'
                os.remove(buildxml)

        for d in update_dirs:
            subdir = os.path.join(root_dir, d)
            # Clean update dirs via ant
            p = FDroidPopen(['ant', 'clean'], cwd=subdir)
            dparms = parms + ['-p', d]
            if options.verbose:
                if d == '.':
                    print "Updating main project..."
                else:
                    print "Updating subproject %s..." % d
            p = FDroidPopen(dparms, cwd=root_dir)
            # Check to see whether an error was returned without a proper exit
            # code (this is the case for the 'no target set or target invalid'
            # error)
            if p.returncode != 0 or (p.stderr != "" and
                    p.stderr.startswith("Error: ")):
                raise BuildException("Failed to update project at %s" % d,
                        p.stdout, p.stderr)

    # Update the local.properties file...
    localprops = [ os.path.join(build_dir, 'local.properties') ]
    if 'subdir' in build:
        localprops += [ os.path.join(root_dir, 'local.properties') ]
    for path in localprops:
        if not os.path.isfile(path):
            continue
        if options.verbose:
            print "Updating properties file at %s" % path
        f = open(path, 'r')
        props = f.read()
        f.close()
        props += '\n'
        # Fix old-fashioned 'sdk-location' by copying
        # from sdk.dir, if necessary...
        if build['oldsdkloc']:
            sdkloc = re.match(r".*^sdk.dir=(\S+)$.*", props,
                re.S|re.M).group(1)
            props += "sdk-location=%s\n" % sdkloc
        else:
            props += "sdk.dir=%s\n" % config['sdk_path']
            props += "sdk-location=%s\n" % ['sdk_path']
        # Add ndk location...
        props += "ndk.dir=%s\n" % config['ndk_path']
        props += "ndk-location=%s\n" % config['ndk_path']
        # Add java.encoding if necessary...
        if 'encoding' in build:
            props += "java.encoding=%s\n" % build['encoding']
        f = open(path, 'w')
        f.write(props)
        f.close()

    flavour = None
    if build['type'] == 'gradle':
        flavour = build['gradle'].split('@')[0]
        if flavour in ['main', 'yes', '']:
            flavour = None

    # Remove forced debuggable flags
    print "Removing debuggable flags..."
    for path in manifest_paths(root_dir, flavour):
        if not os.path.isfile(path):
            continue
        if subprocess.call(['sed','-i',
            's/android:debuggable="[^"]*"//g', path]) != 0:
            raise BuildException("Failed to remove debuggable flags")

    # Insert version code and number into the manifest if necessary...
    if build['forceversion']:
        print "Changing the version name..."
        for path in manifest_paths(root_dir, flavour):
            if not os.path.isfile(path):
                continue
            if has_extension(path, 'xml'):
                if subprocess.call(['sed','-i',
                    's/android:versionName="[^"]*"/android:versionName="' + build['version'] + '"/g',
                    path]) != 0:
                    raise BuildException("Failed to amend manifest")
            elif has_extension(path, 'gradle'):
                if subprocess.call(['sed','-i',
                    's/versionName[ ]*=[ ]*"[^"]*"/versionName = "' + build['version'] + '"/g',
                    path]) != 0:
                    raise BuildException("Failed to amend build.gradle")
    if build['forcevercode']:
        print "Changing the version code..."
        for path in manifest_paths(root_dir, flavour):
            if not os.path.isfile(path):
                continue
            if has_extension(path, 'xml'):
                if subprocess.call(['sed','-i',
                    's/android:versionCode="[^"]*"/android:versionCode="' + build['vercode'] + '"/g',
                    path]) != 0:
                    raise BuildException("Failed to amend manifest")
            elif has_extension(path, 'gradle'):
                if subprocess.call(['sed','-i',
                    's/versionCode[ ]*=[ ]*[0-9]*/versionCode = ' + build['vercode'] + '/g',
                    path]) != 0:
                    raise BuildException("Failed to amend build.gradle")

    # Delete unwanted files...
    if 'rm' in build:
        for part in build['rm'].split(';'):
            dest = os.path.join(build_dir, part.strip())
            rdest = os.path.abspath(dest)
            if options.verbose:
                print "Removing {0}".format(rdest)
            if not rdest.startswith(os.path.abspath(build_dir)):
                raise BuildException("rm for {1} is outside build root {0}".format(
                    os.path.abspath(build_dir),os.path.abspath(dest)))
            if rdest == os.path.abspath(build_dir):
                raise BuildException("rm removes whole build directory")
            if os.path.lexists(rdest):
                if os.path.islink(rdest):
                    subprocess.call('unlink ' + rdest, shell=True)
                else:
                    subprocess.call('rm -rf ' + rdest, shell=True)
            else:
                if options.verbose:
                    print "...but it didn't exist"

    # Fix apostrophes translation files if necessary...
    if build['fixapos']:
        for root, dirs, files in os.walk(os.path.join(root_dir, 'res')):
            for filename in files:
                if has_extension(filename, 'xml'):
                    if subprocess.call(['sed','-i','s@' +
                        r"\([^\\]\)'@\1\\'" +
                        '@g',
                        os.path.join(root, filename)]) != 0:
                        raise BuildException("Failed to amend " + filename)

    # Fix translation files if necessary...
    if build['fixtrans']:
        for root, dirs, files in os.walk(os.path.join(root_dir, 'res')):
            for filename in files:
                if has_extension(filename, 'xml'):
                    f = open(os.path.join(root, filename))
                    changed = False
                    outlines = []
                    for line in f:
                        num = 1
                        index = 0
                        oldline = line
                        while True:
                            index = line.find("%", index)
                            if index == -1:
                                break
                            next = line[index+1:index+2]
                            if next == "s" or next == "d":
                                line = (line[:index+1] +
                                        str(num) + "$" +
                                        line[index+1:])
                                num += 1
                                index += 3
                            else:
                                index += 1
                        # We only want to insert the positional arguments
                        # when there is more than one argument...
                        if oldline != line:
                            if num > 2:
                                changed = True
                            else:
                                line = oldline
                        outlines.append(line)
                    f.close()
                    if changed:
                        f = open(os.path.join(root, filename), 'w')
                        f.writelines(outlines)
                        f.close()

    remove_signing_keys(build_dir)

    # Add required external libraries...
    if 'extlibs' in build:
        print "Collecting prebuilt libraries..."
        libsdir = os.path.join(root_dir, 'libs')
        if not os.path.exists(libsdir):
            os.mkdir(libsdir)
        for lib in build['extlibs'].split(';'):
            lib = lib.strip()
            if options.verbose:
                print "...installing extlib {0}".format(lib)
            libf = os.path.basename(lib)
            libsrc = os.path.join(extlib_dir, lib)
            if not os.path.exists(libsrc):
                raise BuildException("Missing extlib file {0}".format(libsrc))
            shutil.copyfile(libsrc, os.path.join(libsdir, libf))

    # Get required source libraries...
    srclibpaths = []
    if 'srclibs' in build:
        target=build['target'] if 'target' in build else None
        print "Collecting source libraries..."
        for lib in build['srclibs'].split(';'):
            srclibpaths.append(getsrclib(lib, srclib_dir, srclibpaths,
                target=target, preponly=onserver))

    # Apply patches if any
    if 'patch' in build:
        for patch in build['patch'].split(';'):
            patch = patch.strip()
            print "Applying " + patch
            patch_path = os.path.join('metadata', app['id'], patch)
            if subprocess.call(['patch', '-p1',
                            '-i', os.path.abspath(patch_path)], cwd=build_dir) != 0:
                raise BuildException("Failed to apply patch %s" % patch_path)

    for name, number, libpath in srclibpaths:
        place_srclib(root_dir, int(number) if number else None, libpath)

    basesrclib = vcs.getsrclib()
    # If one was used for the main source, add that too.
    if basesrclib:
        srclibpaths.append(basesrclib)

    # Run a pre-build command if one is required...
    if 'prebuild' in build:
        cmd = replace_config_vars(build['prebuild'])

        # Substitute source library paths into prebuild commands...
        for name, number, libpath in srclibpaths:
            libpath = os.path.relpath(libpath, root_dir)
            cmd = cmd.replace('$$' + name + '$$', libpath)

        if options.verbose:
            print "Running 'prebuild' commands in %s" % root_dir

        p = FDroidPopen(['bash', '-x', '-c', cmd], cwd=root_dir)
        if p.returncode != 0:
            raise BuildException("Error running prebuild command for %s:%s" %
                    (app['id'], build['version']), p.stdout, p.stderr)

    return (root_dir, srclibpaths)

# Scan the source code in the given directory (and all subdirectories)
# and return a list of potential problems.
def scan_source(build_dir, root_dir, thisbuild):

    problems = []

    # Common known non-free blobs (always lower case):
    usual_suspects = ['flurryagent',
                      'paypal_mpl',
                      'libgoogleanalytics',
                      'admob-sdk-android',
                      'googleadview',
                      'googleadmobadssdk',
                      'google-play-services',
                      'crittercism',
                      'heyzap',
                      'jpct-ae',
                      'youtubeandroidplayerapi',
                      'bugsense',
                      'crashlytics',
                      'ouya-sdk']

    def getpaths(field):
        paths = []
        if field not in thisbuild:
            return paths
        for p in thisbuild[field].split(';'):
            p = p.strip()
            if p == '.':
                p = '/'
            elif p.startswith('./'):
                p = p[1:]
            elif not p.startswith('/'):
                p = '/' + p;
            if p not in paths:
                paths.append(p)
        return paths

    scanignore = getpaths('scanignore')
    scandelete = getpaths('scandelete')

    ms = magic.open(magic.MIME_TYPE)
    ms.load()

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
        print 'Removing %s at %s' % (what, fd)
        os.remove(fp)

    def handleproblem(what, fd, fp):
        if todelete(fd):
            removeproblem(what, fd, fp)
        else:
            problems.append('Found %s at %s' % (what, fd))

    def warnproblem(what, fd, fp):
        print 'Warning: Found %s at %s' % (what, fd)

    # Iterate through all files in the source code...
    for r,d,f in os.walk(build_dir):
        for curfile in f:

            if '/.hg' in r or '/.git' in r or '/.svn' in r:
                continue

            # Path (relative) to the file...
            fp = os.path.join(r, curfile)
            fd = fp[len(build_dir):]

            # Check if this file has been explicitly excluded from scanning...
            if toignore(fd):
                continue

            for suspect in usual_suspects:
                if suspect in curfile.lower():
                    handleproblem('usual supect', fd, fp)

            mime = ms.file(fp)
            if mime == 'application/x-sharedlib':
                handleproblem('shared library', fd, fp)
            elif mime == 'application/x-archive':
                handleproblem('static library', fd, fp)
            elif mime == 'application/x-executable':
                handleproblem('binary executable', fd, fp)
            elif mime == 'application/jar' and has_extension(fp, 'apk'):
                removeproblem('APK file', fd, fp)
            elif mime == 'application/jar' and has_extension(fp, 'jar'):
                warnproblem('JAR file', fd, fp)

            elif has_extension(fp, 'java'):
                for line in file(fp):
                    if 'DexClassLoader' in line:
                        handleproblem('DexClassLoader', fd, fp)
                        break
    ms.close()

    # Presence of a jni directory without buildjni=yes might
    # indicate a problem... (if it's not a problem, explicitly use
    # buildjni=no to bypass this check)
    if (os.path.exists(os.path.join(root_dir, 'jni')) and
            thisbuild.get('buildjni') is None):
        msg = 'Found jni directory, but buildjni is not enabled'
        problems.append(msg)

    return problems


class KnownApks:

    def __init__(self):
        self.path = os.path.join('stats', 'known_apks.txt')
        self.apks = {}
        if os.path.exists(self.path):
            for line in file( self.path):
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
        if not apk in self.apks:
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
        lst = [app for app,added in sortedapps]
        lst.reverse()
        return lst

def isApkDebuggable(apkfile, config):
    """Returns True if the given apk file is debuggable

    :param apkfile: full path to the apk to check"""

    p = subprocess.Popen([os.path.join(config['sdk_path'],
        'build-tools', config['build_tools'], 'aapt'),
        'dump', 'xmltree', apkfile, 'AndroidManifest.xml'],
        stdout=subprocess.PIPE)
    output = p.communicate()[0]
    if p.returncode != 0:
        print "ERROR: Failed to get apk manifest information"
        sys.exit(1)
    for line in output.splitlines():
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
    stdout = ''
    stderr = ''
    stdout_apk = ''

def FDroidPopen(commands, cwd=None):
    """
    Runs a command the FDroid way and returns return code and output

    :param commands and cwd like in subprocess.Popen
    """

    if options.verbose:
        if cwd:
            print "Directory: %s" % cwd
        print " > %s" % ' '.join(commands)

    result = PopenResult()
    p = subprocess.Popen(commands, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout_queue = Queue.Queue()
    stdout_reader = AsynchronousFileReader(p.stdout, stdout_queue)
    stdout_reader.start()
    stderr_queue = Queue.Queue()
    stderr_reader = AsynchronousFileReader(p.stderr, stderr_queue)
    stderr_reader.start()

    # Check the queues for output (until there is no more to get)
    while not stdout_reader.eof() or not stderr_reader.eof():
        # Show what we received from standard output
        while not stdout_queue.empty():
            line = stdout_queue.get()
            if options.verbose:
                # Output directly to console
                sys.stdout.write(line)
                sys.stdout.flush()
            result.stdout += line

        # Show what we received from standard error
        while not stderr_queue.empty():
            line = stderr_queue.get()
            if options.verbose:
                # Output directly to console
                sys.stderr.write(line)
                sys.stderr.flush()
            result.stderr += line
        time.sleep(0.1)

    p.communicate()
    result.returncode = p.returncode
    return result

def remove_signing_keys(build_dir):
    comment = re.compile(r'[ ]*//')
    signing_configs = re.compile(r'[\t ]*signingConfigs[ \t]*{[ \t]*$')
    r_open = re.compile(r'.*{[\t ]*$')
    r_close = re.compile(r'.*}[\t ]*$')
    for root, dirs, files in os.walk(build_dir):
        if 'build.gradle' in files:
            path = os.path.join(root, 'build.gradle')
            changed = False

            with open(path, "r") as o:
                lines = o.readlines()

            opened = 0
            with open(path, "w") as o:
                for line in lines:
                    if comment.match(line):
                        pass
                    elif signing_configs.match(line):
                        opened = 1
                        changed = True
                    elif opened > 0:
                        if r_open.match(line):
                            opened += 1
                        elif r_close.match(line):
                            opened -= 1
                    elif any(s in line for s in (
                            ' signingConfig ',
                            'android.signingConfigs.',
                            'variant.outputFile = ',
                            '.readLine(')):
                        changed = True
                    else:
                        o.write(line)

            if changed and options.verbose:
                print "Cleaned build.gradle of keysigning configs at %s" % path

        for propfile in ('build.properties', 'default.properties', 'ant.properties'):
            if propfile in files:
                path = os.path.join(root, propfile)
                changed = False

                with open(path, "r") as o:
                    lines = o.readlines()

                with open(path, "w") as o:
                    for line in lines:
                        if line.startswith('key.store'):
                            changed = True
                        else:
                            o.write(line)

                if changed and options.verbose:
                    print "Cleaned %s of keysigning configs at %s" % (propfile,path)

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

    with open(proppath, "r") as o:
        lines = o.readlines()

    with open(proppath, "w") as o:
        placed = False
        for line in lines:
            if line.startswith('android.library.reference.%d=' % number):
                o.write('android.library.reference.%d=%s\n' % (number,relpath))
                placed = True
            else:
                o.write(line)
        if not placed:
            o.write('android.library.reference.%d=%s\n' % (number,relpath))

