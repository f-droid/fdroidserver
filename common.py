# -*- coding: utf-8 -*-
#
# common.py - part of the FDroid server tools
# Copyright (C) 2010-12, Ciaran Gultnieks, ciaran@ciarang.com
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
import subprocess
import time
import operator

def getvcs(vcstype, remote, local):
    if vcstype == 'git':
        return vcs_git(remote, local)
    elif vcstype == 'svn':
        return vcs_svn(remote, local)
    elif vcstype == 'git-svn':
        return vcs_gitsvn(remote, local)
    elif vcstype == 'hg':
        return vcs_hg(remote, local)
    elif vcstype == 'bzr':
        return vcs_bzr(remote, local)
    elif vcstype == 'srclib':
        return vcs_srclib(remote, local)
    raise VCSException("Invalid vcs type " + vcstype)

class vcs:
    def __init__(self, remote, local):

        # It's possible to sneak a username and password in with
        # the remote address... (this really only applies to svn
        # and we should probably be more specific!)
        index = remote.find('@')
        if index != -1:
            self.username = remote[:index]
            remote = remote[index+1:]
            index = self.username.find(':')
            if index == -1:
                raise VCSException("Password required with username")
            self.password = self.username[index+1:]
            self.username = self.username[:index]
        else:
            self.username = None

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
        raise VCSException("This VCS type doesn't define gotorevision")

    # Initialise and update submodules
    def initsubmodules(self):
        raise VCSException('Submodules not supported for this vcs type')

    # Returns the srclib (name, path) used in setting up the current
    # revision, or None.
    def getsrclib(self):
        return self.srclib

class vcs_git(vcs):

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

    def gotorevision(self, rev):
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
        if rev:
            if subprocess.call(['git', 'checkout', rev], cwd=self.local) != 0:
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


class vcs_gitsvn(vcs):

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

    def gotorevision(self, rev):
        if not os.path.exists(self.local):
            # Brand new checkout...
            if subprocess.call(['git', 'svn', 'clone', self.remote, self.local]) != 0:
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
                if subprocess.call(['git', 'svn', 'rebase'],
                        cwd=self.local) != 0:
                    raise VCSException("Git svn rebase failed")
                self.refreshed = True
        if rev:
            # Figure out the git commit id corresponding to the svn revision...
            p = subprocess.Popen(['git', 'svn', 'find-rev', 'r' + rev],
                cwd=self.local, stdout=subprocess.PIPE)
            rev = p.communicate()[0].rstrip()
            if p.returncode != 0:
                raise VCSException("Failed to get git treeish from svn rev")
            # Check out the appropriate revision...
            if subprocess.call(['git', 'checkout', rev], cwd=self.local) != 0:
                raise VCSException("Git checkout failed")
        # Get rid of any uncontrolled files left behind...
        if subprocess.call(['git', 'clean', '-dffx'], cwd=self.local) != 0:
            raise VCSException("Git clean failed")

class vcs_svn(vcs):

    def userargs(self):
        if self.username is None:
            return ['--non-interactive']
        return ['--username', self.username, 
                '--password', self.password,
                '--non-interactive']

    def gotorevision(self, rev):
        if not os.path.exists(self.local):
            if subprocess.call(['svn', 'checkout', self.remote, self.local] +
                    self.userargs()) != 0:
                raise VCSException("Svn checkout failed")
        else:
            for svncommand in (
                    'svn revert -R .',
                    r"svn status | awk '/\?/ {print $2}' | xargs rm -rf"):
                if subprocess.call(svncommand, cwd=self.local,
                        shell=True) != 0:
                    raise VCSException("Svn reset failed")
            if not self.refreshed:
                if subprocess.call(['svn', 'update'] +
                        self.userargs(), cwd=self.local) != 0:
                    raise VCSException("Svn update failed")
                self.refreshed = True
        if rev:
            revargs = ['-r', rev]
            if subprocess.call(['svn', 'update', '--force'] + revargs +
                    self.userargs(), cwd=self.local) != 0:
                raise VCSException("Svn update failed")


class vcs_hg(vcs):

    def gotorevision(self, rev):
        if not os.path.exists(self.local):
            if subprocess.call(['hg', 'clone', self.remote, self.local]) !=0:
                raise VCSException("Hg clone failed")
        else:
            if subprocess.call('hg status -u | xargs rm -rf',
                    cwd=self.local, shell=True) != 0:
                raise VCSException("Hg clean failed")
            if not self.refreshed:
                if subprocess.call(['hg', 'pull'],
                        cwd=self.local) != 0:
                    raise VCSException("Hg pull failed")
                self.refreshed = True
        if rev:
            revargs = [rev]
            if subprocess.call(['hg', 'checkout', '-C'] + revargs,
                    cwd=self.local) != 0:
                raise VCSException("Hg checkout failed")


class vcs_bzr(vcs):

    def gotorevision(self, rev):
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
        if rev:
            revargs = ['-r', rev]
            if subprocess.call(['bzr', 'revert'] + revargs,
                    cwd=self.local) != 0:
                raise VCSException("Bzr revert failed")

class vcs_srclib(vcs):

    def gotorevision(self, rev):

        # Yuk...
        extlib_dir = 'build/extlib'

        if os.path.exists(self.local):
            shutil.rmtree(self.local)

        if self.remote.find(':') != -1:
            srclib, path = self.remote.split(':')
        else:
            srclib = self.remote
            path = None
        libdir = getsrclib(srclib + '@' + rev, extlib_dir)
        self.srclib = (srclib, libdir)
        if path:
            libdir = os.path.join(libdir, path)
        shutil.copytree(libdir, self.local)
        return self.local


# Get the type expected for a given metadata field.
def metafieldtype(name):
    if name == 'Description':
        return 'multiline'
    if name == 'Requires Root':
        return 'flag'
    if name == 'Build Version':
        return 'build'
    if name == 'Use Built':
        return 'obsolete'
    return 'string'


# Parse metadata for a single application.
#
#  'metafile' - the filename to read. The package id for the application comes
#               from this filename. Pass None to get a blank entry.
#
# Returns a dictionary containing all the details of the application. There are
# two major kinds of information in the dictionary. Keys beginning with capital
# letters correspond directory to identically named keys in the metadata file.
# Keys beginning with lower case letters are generated in one way or another,
# and are not found verbatim in the metadata.
#
# Known keys not originating from the metadata are:
#
#  'id'               - the application's package ID
#  'builds'           - a list of dictionaries containing build information
#                       for each defined build
#  'comments'         - a list of comments from the metadata file. Each is
#                       a tuple of the form (field, comment) where field is
#                       the name of the field it preceded in the metadata
#                       file. Where field is None, the comment goes at the
#                       end of the file. Alternatively, 'build:version' is
#                       for a comment before a particular build version.
#  'descriptionlines' - original lines of description as formatted in the
#                       metadata file.
#
def parse_metadata(metafile, **kw):

    def parse_buildline(lines):
        value = "".join(lines)
        parts = [p.replace("\\,", ",")
                 for p in re.split(r"(?<!\\),", value)]
        if len(parts) < 3:
            raise MetaDataException("Invalid build format: " + value + " in " + metafile.name)
        thisbuild = {}
        thisbuild['origlines'] = lines
        thisbuild['version'] = parts[0]
        thisbuild['vercode'] = parts[1]
        thisbuild['commit'] = parts[2]
        for p in parts[3:]:
            pk, pv = p.split('=', 1)
            thisbuild[pk] = pv
        return thisbuild

    def add_comments(key):
        for comment in curcomments:
            thisinfo['comments'].append((key, comment))
        del curcomments[:]

    thisinfo = {}
    if metafile:
        if not isinstance(metafile, file):
            metafile = open(metafile, "r")
        thisinfo['id'] = metafile.name[9:-4]
        if kw.get("verbose", False):
            print "Reading metadata for " + thisinfo['id']
    else:
        thisinfo['id'] = None

    # Defaults for fields that come from metadata...
    thisinfo['Name'] = None
    thisinfo['Category'] = 'None'
    thisinfo['Description'] = []
    thisinfo['Summary'] = ''
    thisinfo['License'] = 'Unknown'
    thisinfo['Web Site'] = ''
    thisinfo['Source Code'] = ''
    thisinfo['Issue Tracker'] = ''
    thisinfo['Donate'] = None
    thisinfo['Disabled'] = None
    thisinfo['AntiFeatures'] = None
    thisinfo['Update Check Mode'] = 'Market'
    thisinfo['Current Version'] = ''
    thisinfo['Current Version Code'] = '0'
    thisinfo['Repo Type'] = ''
    thisinfo['Repo'] = ''
    thisinfo['Requires Root'] = False

    # General defaults...
    thisinfo['builds'] = []
    thisinfo['comments'] = []

    if metafile is None:
        return thisinfo

    mode = 0
    buildlines = []
    curcomments = []

    for line in metafile:
        line = line.rstrip('\r\n')
        if mode == 0:
            if len(line) == 0:
                continue
            if line.startswith("#"):
                curcomments.append(line)
                continue
            index = line.find(':')
            if index == -1:
                raise MetaDataException("Invalid metadata in " + metafile.name + " at: " + line)
            field = line[:index]
            value = line[index+1:]

            # Translate obsolete fields...
            if field == 'Market Version':
                field = 'Current Version'
            if field == 'Market Version Code':
                field = 'Current Version Code'

            fieldtype = metafieldtype(field)
            if fieldtype != 'build':
                add_comments(field)
            if fieldtype == 'multiline':
                mode = 1
                thisinfo[field] = []
                if len(value) > 0:
                    raise MetaDataException("Unexpected text on same line as " + field + " in " + metafile.name)
            elif fieldtype == 'string':
                thisinfo[field] = value
            elif fieldtype == 'flag':
                if value == 'Yes':
                    thisinfo[field] = True
                elif value == 'No':
                    thisinfo[field] = False
                else:
                    raise MetaDataException("Expected Yes or No for " + field + " in " + metafile.name)
            elif fieldtype == 'build':
                if value.endswith("\\"):
                    mode = 2
                    buildlines = [value[:-1]]
                else:
                    thisinfo['builds'].append(parse_buildline([value]))
                    add_comments('build:' + thisinfo['builds'][-1]['version'])
            elif fieldtype == 'obsolete':
                pass        # Just throw it away!
            else:
                raise MetaDataException("Unrecognised field type for " + field + " in " + metafile.name)
        elif mode == 1:     # Multiline field
            if line == '.':
                mode = 0
            else:
                thisinfo[field].append(line)
        elif mode == 2:     # Line continuation mode in Build Version
            if line.endswith("\\"):
                buildlines.append(line[:-1])
            else:
                buildlines.append(line)
                thisinfo['builds'].append(
                    parse_buildline(buildlines))
                add_comments('build:' + thisinfo['builds'][-1]['version'])
                mode = 0
    add_comments(None)

    # Mode at end of file should always be 0...
    if mode == 1:
        raise MetaDataException(field + " not terminated in " + metafile.name)
    elif mode == 2:
        raise MetaDataException("Unterminated continuation in " + metafile.name)

    if len(thisinfo['Description']) == 0:
        thisinfo['Description'].append('No description available')

    # Ensure all AntiFeatures are recognised...
    if thisinfo['AntiFeatures']:
        parts = thisinfo['AntiFeatures'].split(",")
        for part in parts:
            if (part != "Ads" and
                part != "Tracking" and
                part != "NonFreeNet" and
                part != "NonFreeDep" and
                part != "NonFreeAdd"):
                raise MetaDataException("Unrecognised antifeature '" + part + "' in " \
                            + metafile.name)

    return thisinfo

# Write a metadata file.
#
# 'dest'    - The path to the output file
# 'app'     - The app data
def write_metadata(dest, app):

    def writecomments(key):
        for pf, comment in app['comments']:
            if pf == key:
                mf.write(comment + '\n')

    def writefield(field, value=None):
        writecomments(field)
        if value is None:
            value = app[field]
        mf.write(field + ':' + value + '\n')

    mf = open(dest, 'w')
    if app['Disabled']:
        writefield('Disabled')
    if app['AntiFeatures']:
        writefield('AntiFeatures')
    writefield('Category')
    writefield('License')
    writefield('Web Site')
    writefield('Source Code')
    writefield('Issue Tracker')
    if app['Donate']:
        writefield('Donate')
    mf.write('\n')
    if app['Name']:
        writefield('Name')
    writefield('Summary')
    writefield('Description', '')
    for line in app['Description']:
        mf.write(line + '\n')
    mf.write('.\n')
    mf.write('\n')
    if app['Requires Root']:
        writefield('Requires Root', 'Yes')
        mf.write('\n')
    if len(app['Repo Type']) > 0:
        writefield('Repo Type')
        writefield('Repo')
        mf.write('\n')
    for build in app['builds']:
        writecomments('build:' + build['version'])
        mf.write('Build Version:')
        if build.has_key('origlines'):
            # Keeping the original formatting if we loaded it from a file...
            mf.write('\\\n'.join(build['origlines']) + '\n')
        else:
            mf.write(build['version'] + ',' + build['vercode'] + ',' + 
                    build['commit'])
            for key,value in build.iteritems():
                if key not in ['version', 'vercode', 'commit']:
                    mf.write(',' + key + '=' + value)
            mf.write('\n')
    if len(app['builds']) > 0:
        mf.write('\n')
    writefield('Update Check Mode')
    if len(app['Current Version']) > 0:
        writefield('Current Version')
        writefield('Current Version Code')
    mf.write('\n')
    writecomments(None)
    mf.close()


# Read all metadata. Returns a list of 'app' objects (which are dictionaries as
# returned by the parse_metadata function.
def read_metadata(verbose=False):
    apps = []
    for metafile in sorted(glob.glob(os.path.join('metadata', '*.txt'))):
        if verbose:
            print "Reading " + metafile
        apps.append(parse_metadata(metafile, verbose=verbose))
    return apps


# Parse multiple lines of description as written in a metadata file, returning
# a single string.
def parse_description(lines):
    text = ''
    for line in lines:
        if len(line) == 0:
            text += '\n\n'
        else:
            if not text.endswith('\n') and len(text) > 0:
                text += ' '
            text += line
    return text


# Extract some information from the AndroidManifest.xml at the given path.
# Returns (version, vercode, package), any or all of which might be None.
def parse_androidmanifest(manifest):

    vcsearch = re.compile(r'.*android:versionCode="([^"]+)".*').search
    vnsearch = re.compile(r'.*android:versionName="([^"]+)".*').search
    psearch = re.compile(r'.*package="([^"]+)".*').search
    version = None
    vercode = None
    package = None
    for line in file(manifest):
        if not package:
            matches = psearch(line)
            if matches:
                package = matches.group(1)
        if not version:
            matches = vnsearch(line)
            if matches:
                version = matches.group(1)
        if not vercode:
            matches = vcsearch(line)
            if matches:
                vercode = matches.group(1)
    return (version, vercode, package)


class BuildException(Exception):
    def __init__(self, value, stdout = None, stderr = None):
        self.value = value
        self.stdout = stdout
        self.stderr = stderr

    def __str__(self):
        ret = repr(self.value)
        if self.stdout:
            ret = ret + "\n==== stdout begin ====\n" + str(self.stdout) + "\n==== stdout end ===="
        if self.stderr:
            ret = ret + "\n==== stderr begin ====\n" + str(self.stderr) + "\n==== stderr end ===="
        return ret

class VCSException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class MetaDataException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


# Get the specified source library.
# Returns the path to it.
# TODO: These are currently just hard-coded in this method. It will be a
# metadata-driven system eventually, but not yet.
def getsrclib(spec, extlib_dir):
    name, ref = spec.split('@')

    if name == 'GreenDroid':
        sdir = os.path.join(extlib_dir, 'GreenDroid')
        vcs = getvcs('git',
            'https://github.com/cyrilmottier/GreenDroid.git', sdir)
        vcs.gotorevision(ref)
        return os.path.join(sdir, 'GreenDroid')

    if name == 'ActionBarSherlock':
        sdir = os.path.join(extlib_dir, 'ActionBarSherlock')
        vcs = getvcs('git',
            'https://github.com/JakeWharton/ActionBarSherlock.git', sdir)
        vcs.gotorevision(ref)
        libdir = os.path.join(sdir, 'library')
        if subprocess.call(['android', 'update', 'project', '-p',
            libdir]) != 0:
            raise BuildException('Error updating ActionBarSherlock project')
        return libdir

    if name == 'FacebookSDK':
        sdir = os.path.join(extlib_dir, 'FacebookSDK')
        vcs = getvcs('git',
                'git://github.com/facebook/facebook-android-sdk.git', sdir)
        vcs.gotorevision(ref)
        libdir = os.path.join(sdir, 'facebook')
        if subprocess.call(['android', 'update', 'project', '-p',
            libdir]) != 0:
            raise BuildException('Error updating FacebookSDK project')
        return libdir

    if name == 'OI':
        sdir = os.path.join(extlib_dir, 'OI')
        vcs = getvcs('git-svn',
                'http://openintents.googlecode.com/svn/trunk/', sdir)
        vcs.gotorevision(ref)
        return sdir

    if name == 'JOpenDocument':
        sdir = os.path.join(extlib_dir, 'JOpenDocument')
        vcs = getvcs('git',
                'https://github.com/andiwand/JOpenDocument.git', sdir)
        vcs.gotorevision(ref)
        shutil.rmtree(os.path.join(sdir, 'bin'))
        return sdir

    raise BuildException('Unknown srclib ' + name)


# Prepare the source code for a particular build
#  'vcs'         - the appropriate vcs object for the application
#  'app'         - the application details from the metadata
#  'build'       - the build details from the metadata
#  'build_dir'   - the path to the build directory, usually
#                   'build/app.id'
#  'extlib_dir'  - the path to the external libraries directory, usually
#                   'build/extlib'
#  'sdk_path'    - the path to the Android SDK
#  'ndk_path'    - the path to the Android NDK
#  'javacc_path' - the path to javacc
# Returns the root directory, which may be the same as 'build_dir' or may
# be a subdirectory of it.
def prepare_source(vcs, app, build, build_dir, extlib_dir, sdk_path, ndk_path, javacc_path):

    # Optionally, the actual app source can be in a subdirectory...
    if build.has_key('subdir'):
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
    if build.get('submodules', 'no')  == 'yes':
        vcs.initsubmodules()

    # Run an init command if one is required...
    if build.has_key('init'):
        init = build['init']
        if subprocess.call(init, cwd=root_dir, shell=True) != 0:
            raise BuildException("Error running init command")

    # Generate (or update) the ant build file, build.xml...
    if (build.get('update', 'yes') != 'no' and
        not build.has_key('maven')):
        parms = [os.path.join(sdk_path, 'tools', 'android'),
                'update', 'project', '-p', '.']
        parms.append('--subprojects')
        if build.has_key('target'):
            parms.append('-t')
            parms.append(build['target'])
        # Force build.xml update if necessary...
        if build.get('update', 'yes') == 'force' or build.has_key('target'):
            buildxml = os.path.join(root_dir, 'build.xml')
            if os.path.exists(buildxml):
                print 'Force-removing old build.xml'
                os.remove(buildxml)
        if subprocess.call(parms, cwd=root_dir) != 0:
            raise BuildException("Failed to update project")

    # If the app has ant set up to sign the release, we need to switch
    # that off, because we want the unsigned apk...
    for propfile in ('build.properties', 'default.properties', 'ant.properties'):
        if os.path.exists(os.path.join(root_dir, propfile)):
            if subprocess.call(['sed','-i','s/^key.store/#/',
                                propfile], cwd=root_dir) !=0:
                raise BuildException("Failed to amend %s" % propfile)

    # Update the local.properties file...
    locprops = os.path.join(root_dir, 'local.properties')
    if os.path.exists(locprops):
        f = open(locprops, 'r')
        props = f.read()
        f.close()
        # Fix old-fashioned 'sdk-location' by copying
        # from sdk.dir, if necessary...
        if build.get('oldsdkloc', 'no') == "yes":
            sdkloc = re.match(r".*^sdk.dir=(\S+)$.*", props,
                re.S|re.M).group(1)
            props += "\nsdk-location=" + sdkloc + "\n"
        # Add ndk location...
        props+= "\nndk.dir=" + ndk_path + "\n"
        # Add java.encoding if necessary...
        if build.has_key('encoding'):
            props += "\njava.encoding=" + build['encoding'] + "\n"
        f = open(locprops, 'w')
        f.write(props)
        f.close()

    # Insert version code and number into the manifest if necessary...
    if build.has_key('forceversion'):
        if subprocess.call(['sed','-r','-i',
            's/android:versionName="[^"]+"/android:versionName="' + build['version'] + '"/g',
            'AndroidManifest.xml'], cwd=root_dir) !=0:
            raise BuildException("Failed to amend manifest")
    if build.has_key('forcevercode'):
        if subprocess.call(['sed','-r','-i',
            's/android:versionCode="[^"]+"/android:versionCode="' + build['vercode'] + '"/g',
            'AndroidManifest.xml'], cwd=root_dir) !=0:
            raise BuildException("Failed to amend manifest")

    # Delete unwanted file...
    if build.has_key('rm'):
        dest = os.path.join(build_dir, build['rm'])
        if os.path.exists(dest):
            os.remove(dest)

    # Fix apostrophes translation files if necessary...
    if build.get('fixapos', 'no') == 'yes':
        for root, dirs, files in os.walk(os.path.join(root_dir, 'res')):
            for filename in files:
                if filename.endswith('.xml'):
                    if subprocess.call(['sed','-i','s@' +
                        r"\([^\\]\)'@\1\\'" +
                        '@g',
                        os.path.join(root, filename)]) != 0:
                        raise BuildException("Failed to amend " + filename)

    # Fix translation files if necessary...
    if build.get('fixtrans', 'no') == 'yes':
        for root, dirs, files in os.walk(os.path.join(root_dir, 'res')):
            for filename in files:
                if filename.endswith('.xml'):
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

    # Add required external libraries...
    if build.has_key('extlibs'):
        libsdir = os.path.join(root_dir, 'libs')
        if not os.path.exists(libsdir):
            os.mkdir(libsdir)
        for lib in build['extlibs'].split(';'):
            libf = os.path.basename(lib)
            shutil.copyfile(os.path.join(extlib_dir, lib),
                    os.path.join(libsdir, libf))

    # Get required source libraries...
    srclibpaths = []
    if build.has_key('srclibs'):
        for lib in build['srclibs'].split(';'):
            name, _ = lib.split('@')
            srclibpaths.append((name, getsrclib(lib, extlib_dir)))
    basesrclib = vcs.getsrclib()
    # If one was used for the main source, add that too.
    if basesrclib:
        srclibpaths.append(basesrclib)

    # There should never be gen or bin directories in the source, so just get
    # rid of them...
    for baddir in ['gen', 'bin']:
        badpath = os.path.join(root_dir, baddir)
        if os.path.exists(badpath):
            shutil.rmtree(badpath)

    # Apply patches if any
    if 'patch' in build:
        for patch in build['patch'].split(';'):
            print "Applying " + patch
            patch_path = os.path.join('metadata', app['id'], patch)
            if subprocess.call(['patch', '-p1',
                            '-i', os.path.abspath(patch_path)], cwd=build_dir) != 0:
                raise BuildException("Failed to apply patch %s" % patch_path)

    # Run a pre-build command if one is required...
    if build.has_key('prebuild'):
        prebuild = build['prebuild']
        # Substitute source library paths into prebuild commands...
        for name, libpath in srclibpaths:
            libpath = os.path.relpath(libpath, root_dir)
            prebuild = prebuild.replace('$$' + name + '$$', libpath)
        if subprocess.call(prebuild, cwd=root_dir, shell=True) != 0:
            raise BuildException("Error running pre-build command")

    # Special case init functions for funambol...
    if build.get('initfun', 'no')  == "yes":

        if subprocess.call(['sed','-i','s@' +
            '<taskdef resource="net/sf/antcontrib/antcontrib.properties" />' +
            '@' +
            '<taskdef resource="net/sf/antcontrib/antcontrib.properties">' +
            '<classpath>' +
            '<pathelement location="/usr/share/java/ant-contrib.jar"/>' +
            '</classpath>' +
            '</taskdef>' +
            '@g',
            'build.xml'], cwd=root_dir) !=0:
            raise BuildException("Failed to amend build.xml")

        if subprocess.call(['sed','-i','s@' +
            '\${user.home}/funambol/build/android/build.properties' +
            '@' +
            'build.properties' +
            '@g',
            'build.xml'], cwd=root_dir) !=0:
            raise BuildException("Failed to amend build.xml")

        buildxml = os.path.join(root_dir, 'build.xml')
        f = open(buildxml, 'r')
        xml = f.read()
        f.close()
        xmlout = ""
        mode = 0
        for line in xml.splitlines():
            if mode == 0:
                if line.find("jarsigner") != -1:
                    mode = 1
                else:
                    xmlout += line + "\n"
            else:
                if line.find("/exec") != -1:
                    mode += 1
                    if mode == 3:
                        mode =0
        f = open(buildxml, 'w')
        f.write(xmlout)
        f.close()

        if subprocess.call(['sed','-i','s@' +
            'platforms/android-2.0' +
            '@' +
            'platforms/android-8' +
            '@g',
            'build.xml'], cwd=root_dir) !=0:
            raise BuildException("Failed to amend build.xml")

        shutil.copyfile(
                os.path.join(root_dir, "build.properties.example"),
                os.path.join(root_dir, "build.properties"))

        if subprocess.call(['sed','-i','s@' +
            'javacchome=.*'+
            '@' +
            'javacchome=' + javacc_path +
            '@g',
            'build.properties'], cwd=root_dir) !=0:
            raise BuildException("Failed to amend build.properties")

        if subprocess.call(['sed','-i','s@' +
            'sdk-folder=.*'+
            '@' +
            'sdk-folder=' + sdk_path +
            '@g',
            'build.properties'], cwd=root_dir) !=0:
            raise BuildException("Failed to amend build.properties")

        if subprocess.call(['sed','-i','s@' +
            'android.sdk.version.*'+
            '@' +
            'android.sdk.version=2.0' +
            '@g',
            'build.properties'], cwd=root_dir) !=0:
            raise BuildException("Failed to amend build.properties")

    return root_dir


# Scan the source code in the given directory (and all subdirectories)
# and return a list of potential problems.
def scan_source(build_dir, root_dir, thisbuild):

    problems = []

    # Common known non-free blobs:
    usual_suspects = ['flurryagent',
                      'paypal_mpl',
                      'libgoogleanalytics',
                      'admob-sdk-android',
                      'googleadview',
                      'googleadmobadssdk',
                      'heyzap']

    # Iterate through all files in the source code...
    for r,d,f in os.walk(build_dir):
        for curfile in f:

            if r.find('/.hg/') == -1:

                # Path (relative) to the file...
                fp = os.path.join(r, curfile)

                for suspect in usual_suspects:
                    if curfile.lower().find(suspect) != -1:
                        msg = 'Found probable non-free blob ' + fp
                        problems.append(msg)

                if curfile.endswith('.java'):
                    for line in file(fp):

                        if line.find('DexClassLoader') != -1:
                            msg = 'Found DexClassLoader in ' + fp
                            problems.append(msg)

#                        if line.lower().find('all rights reserved') != -1:
#                            msg = 'All rights reserved in ' + fp
#                            problems.append(msg)

    # Presence of a jni directory without buildjni=yes might
    # indicate a problem...
    if (os.path.exists(os.path.join(root_dir, 'jni')) and 
            thisbuild.get('buildjni', 'no') == 'no'):
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

    def recordapk(self, apk, app):
        if not apk in self.apks:
            self.apks[apk] = (app, time.gmtime(time.time()))
            self.changed = True

    def getapp(self, apkname):
        if apkname in self.apks:
            return self.apks[apkname]
        return None

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
        lst = []
        for app, added in sortedapps:
            lst.append(app)
        lst.reverse()
        return lst

