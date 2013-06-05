# -*- coding: utf-8 -*-
#
# common.py - part of the FDroid server tools
# Copyright (C) 2010-13, Ciaran Gultnieks, ciaran@ciarang.com
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
import cgi

def getvcs(vcstype, remote, local, sdk_path):
    if vcstype == 'git':
        return vcs_git(remote, local, sdk_path)
    if vcstype == 'svn':
        return vcs_svn(remote, local, sdk_path)
    if vcstype == 'git-svn':
        return vcs_gitsvn(remote, local, sdk_path)
    if vcstype == 'hg':
        return vcs_hg(remote, local, sdk_path)
    if vcstype == 'bzr':
        return vcs_bzr(remote, local, sdk_path)
    if vcstype == 'srclib':
        if local != 'build/srclib/' + remote:
            raise VCSException("Error: srclib paths are hard-coded!")
        return getsrclib(remote, 'build/srclib', sdk_path, raw=True)
    raise VCSException("Invalid vcs type " + vcstype)

def getsrclibvcs(name):
    srclib_path = os.path.join('srclibs', name + ".txt")
    if not os.path.exists(srclib_path):
        raise VCSException("Missing srclib " + name)
    return parse_srclib(srclib_path)['Repo Type']

class vcs:
    def __init__(self, remote, local, sdk_path):

        self.sdk_path = sdk_path

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

    def gettags(self):
        self.checkrepo()
        p = subprocess.Popen(['git', 'tag'],
                stdout=subprocess.PIPE, cwd=self.local)
        return p.communicate()[0].splitlines()


class vcs_gitsvn(vcs):

    def repotype(self):
        return 'git-svn'

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
            gitsvn_cmd = ['git', 'svn', 'clone']
            remote_split = self.remote.split(';')
            if len(remote_split) > 1:
                for i in remote_split[1:]:
                    if i.startswith('trunk='):
                        gitsvn_cmd += ['-T', i[6:]]
                    elif i.startswith('tags='):
                        gitsvn_cmd += ['-t', i[5:]]
                    elif i.startswith('branches='):
                        gitsvn_cmd += ['-b', i[9:]]
                if subprocess.call(gitsvn_cmd + [remote_split[0], self.local]) != 0:
                    raise VCSException("Git clone failed")
            else:
                if subprocess.call(gitsvn_cmd + [self.remote, self.local]) != 0:
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
                if p.returncode != 0 or len(git_rev) == 0:
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
                if subprocess.call(svncommand, cwd=self.local,
                        shell=True) != 0:
                    raise VCSException("Svn reset ({0}) failed in {1}".format(svncommand, self.local))
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

    def repotype(self):
        return 'hg'

    def gotorevisionx(self, rev):
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
        if rev:
            revargs = ['-r', rev]
            if subprocess.call(['bzr', 'revert'] + revargs,
                    cwd=self.local) != 0:
                raise VCSException("Bzr revert failed")

    def __init__(self, remote, local, sdk_path):

        self.sdk_path = sdk_path

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
        try:
            testvercode = int(thisbuild['vercode'])
        except:
            raise MetaDataException("Invalid version code for build in " + metafile.name)
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
    thisinfo['FlattrID'] = None
    thisinfo['Bitcoin'] = None
    thisinfo['Disabled'] = None
    thisinfo['AntiFeatures'] = None
    thisinfo['Update Check Mode'] = 'Market'
    thisinfo['Auto Update Mode'] = 'None'
    thisinfo['Current Version'] = ''
    thisinfo['Current Version Code'] = '0'
    thisinfo['Repo Type'] = ''
    thisinfo['Repo'] = ''
    thisinfo['Requires Root'] = False
    thisinfo['No Source Since'] = ''

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
    if app['FlattrID']:
        writefield('FlattrID')
    if app['Bitcoin']:
        writefield('Bitcoin')
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
        if 'origlines' in build:
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
    writefield('Auto Update Mode')
    writefield('Update Check Mode')
    if len(app['Current Version']) > 0:
        writefield('Current Version')
        writefield('Current Version Code')
    mf.write('\n')
    if len(app['No Source Since']) > 0:
        writefield('No Source Since')
        mf.write('\n')
    writecomments(None)
    mf.close()


# Read all metadata. Returns a list of 'app' objects (which are dictionaries as
# returned by the parse_metadata function.
def read_metadata(verbose=False, xref=True):
    apps = []
    for metafile in sorted(glob.glob(os.path.join('metadata', '*.txt'))):
        if verbose:
            print "Reading " + metafile
        apps.append(parse_metadata(metafile, verbose=verbose))

    if xref:
        # Parse all descriptions at load time, just to ensure cross-referencing
        # errors are caught early rather than when they hit the build server.
        def linkres(link):
            for app in apps:
                if app['id'] == link:
                    return ("fdroid.app:" + link, "Dummy name - don't know yet")
            raise MetaDataException("Cannot resolve app id " + link)
        for app in apps:
            try:
                description_html(app['Description'], linkres)
            except Exception, e:
                raise MetaDataException("Problem with description of " + app['id'] +
                        " - " + str(e))

    return apps

# Formatter for descriptions. Create an instance, and call parseline() with
# each line of the description source from the metadata. At the end, call
# end() and then text_plain, text_wiki and text_html will contain the result.
class DescriptionFormatter:
    stNONE = 0
    stPARA = 1
    stUL = 2
    stOL = 3
    bold = False
    ital = False
    state = stNONE
    text_plain = ''
    text_wiki = ''
    text_html = ''
    linkResolver = None
    def __init__(self, linkres):
        self.linkResolver = linkres
    def endcur(self, notstates=None):
        if notstates and self.state in notstates:
            return
        if self.state == self.stPARA:
            self.endpara()
        elif self.state == self.stUL:
            self.endul()
        elif self.state == self.stOL:
            self.endol()
    def endpara(self):
        self.text_plain += '\n'
        self.text_html += '</p>'
        self.state = self.stNONE
    def endul(self):
        self.text_html += '</ul>'
        self.state = self.stNONE
    def endol(self):
        self.text_html += '</ol>'
        self.state = self.stNONE

    def formatted(self, txt, html):
        formatted = ''
        if html:
            txt = cgi.escape(txt)
        while True:
            index = txt.find("''")
            if index == -1:
                return formatted + txt
            formatted += txt[:index]
            txt = txt[index:]
            if txt.startswith("'''"):
                if html:
                    if self.bold:
                        formatted += '</b>'
                    else:
                        formatted += '<b>'
                self.bold = not self.bold
                txt = txt[3:]
            else:
                if html:
                    if self.ital:
                        formatted += '</i>'
                    else:
                        formatted += '<i>'
                self.ital = not self.ital
                txt = txt[2:]


    def linkify(self, txt):
        linkified_plain = ''
        linkified_html = ''
        while True:
            index = txt.find("[")
            if index == -1:
                return (linkified_plain + self.formatted(txt, False), linkified_html + self.formatted(txt, True))
            linkified_plain += self.formatted(txt[:index], False)
            linkified_html += self.formatted(txt[:index], True)
            txt = txt[index:]
            if txt.startswith("[["):
                index = txt.find("]]")
                if index == -1:
                    raise MetaDataException("Unterminated ]]")
                url = txt[2:index]
                if self.linkResolver:
                    url, urltext = self.linkResolver(url)
                else:
                    urltext = url
                linkified_html += '<a href="' + url + '">' + cgi.escape(urltext) + '</a>'
                linkified_plain += urltext
                txt = txt[index+2:]
            else:
                index = txt.find("]")
                if index == -1:
                    raise MetaDataException("Unterminated ]")
                url = txt[1:index]
                index2 = url.find(' ')
                if index2 == -1:
                    urltxt = url
                else:
                    urltxt = url[index2 + 1:]
                    url = url[:index2]
                linkified_html += '<a href="' + url + '">' + cgi.escape(urltxt) + '</a>'
                linkified_plain += urltxt
                if urltxt != url:
                    linkified_plain += ' (' + url + ')'
                txt = txt[index+1:]

    def addtext(self, txt):
        p, h = self.linkify(txt)
        self.text_plain += p
        self.text_html += h

    def parseline(self, line):
        self.text_wiki += line + '\n'
        if len(line) == 0:
            self.endcur()
        elif line.startswith('*'):
            self.endcur([self.stUL])
            if self.state != self.stUL:
                self.text_html += '<ul>'
                self.state = self.stUL
            self.text_html += '<li>'
            self.text_plain += '*'
            self.addtext(line[1:])
            self.text_html += '</li>'
        elif line.startswith('#'):
            self.endcur([self.stOL])
            if self.state != self.stOL:
                self.text_html += '<ol>'
                self.state = self.stOL
            self.text_html += '<li>'
            self.text_plain += '*' #TODO: lazy - put the numbers in!
            self.addtext(line[1:])
            self.text_html += '</li>'
        else:
            self.endcur([self.stPARA])
            if self.state == self.stNONE:
                self.text_html += '<p>'
                self.state = self.stPARA
            elif self.state == self.stPARA:
                self.text_html += ' '
                self.text_plain += ' '
            self.addtext(line)

    def end(self):
        self.endcur()

# Parse multiple lines of description as written in a metadata file, returning
# a single string in plain text format.
def description_plain(lines, linkres):
    ps = DescriptionFormatter(linkres)
    for line in lines:
        ps.parseline(line)
    ps.end()
    return ps.text_plain

# Parse multiple lines of description as written in a metadata file, returning
# a single string in wiki format.
def description_wiki(lines):
    ps = DescriptionFormatter(None)
    for line in lines:
        ps.parseline(line)
    ps.end()
    return ps.text_wiki

# Parse multiple lines of description as written in a metadata file, returning
# a single string in HTML format.
def description_html(lines,linkres):
    ps = DescriptionFormatter(linkres)
    for line in lines:
        ps.parseline(line)
    ps.end()
    return ps.text_html



# Extract some information from the AndroidManifest.xml at the given path.
# Returns (version, vercode, package), any or all of which might be None.
# All values returned are strings.
def parse_androidmanifest(app_dir):

    vcsearch = re.compile(r'.*android:versionCode="([0-9]+?)".*').search
    vnsearch = re.compile(r'.*android:versionName="([^@]+?)".*').search
    psearch = re.compile(r'.*package="([^"]+)".*').search
    vnsearch_xml = re.compile(r'.*"(app_|)version">([^<]+?)<.*').search
    version = None
    vercode = None
    package = None
    for line in file(os.path.join(app_dir, 'AndroidManifest.xml')):
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
    if version:
        return (version, vercode, package)
    for xmlfile in glob.glob(os.path.join(
            app_dir, 'res', 'values', 'strings*transl*.xml')):
        for line in file(xmlfile):
            if not version:
                matches = vnsearch_xml(line)
                if matches:
                    version = matches.group(2)
    if not version:
        for line in file(os.path.join(app_dir, 'res/values/strings.xml')):
            if not version:
                matches = vnsearch_xml(line)
                if matches:
                    version = matches.group(2)
    if not version:
        version = "None"
    return (version, vercode, package)

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

def parse_srclib(metafile, **kw):

    thisinfo = {}
    if metafile and not isinstance(metafile, file):
        metafile = open(metafile, "r")

    # Defaults for fields that come from metadata
    thisinfo['Repo Type'] = ''
    thisinfo['Repo'] = ''
    thisinfo['Subdir'] = None
    thisinfo['Prepare'] = None
    thisinfo['Update Project'] = None

    if metafile is None:
        return thisinfo

    mode = 0
    buildlines = []

    for line in metafile:
        line = line.rstrip('\r\n')
        if len(line) == 0:
            continue
        if line.startswith("#"):
            continue
        index = line.find(':')
        if index == -1:
            raise MetaDataException("Invalid metadata in " + metafile.name + " at: " + line)
        field = line[:index]
        value = line[index+1:]

        if field == "Subdir":
            thisinfo[field] = value.split(',')
        else:
            thisinfo[field] = value

    return thisinfo

# Get the specified source library.
# Returns the path to it. Normally this is the path to be used when referencing
# it, which may be a subdirectory of the actual project. If you want the base
# directory of the project, pass 'basepath=True'.
def getsrclib(spec, srclib_dir, sdk_path, basepath=False, raw=False, prepare=True, preponly=False):

    if raw:
        name = spec
        ref = None
    else:
        name, ref = spec.split('@')

    srclib_path = os.path.join('srclibs', name + ".txt")

    if not os.path.exists(srclib_path):
        raise BuildException('srclib ' + name + ' not found.')

    srclib = parse_srclib(srclib_path)

    sdir = os.path.join(srclib_dir, name)

    if not preponly:
        vcs = getvcs(srclib["Repo Type"], srclib["Repo"], sdir, sdk_path)
        vcs.gotorevision(ref)

        if raw:
            return vcs

    libdir = None

    if srclib["Subdir"] is not None:
        for subdir in srclib["Subdir"]:
            libdir_candidate = os.path.join(sdir, subdir)
            if os.path.exists(libdir_candidate):
                libdir = libdir_candidate
                break

    if libdir is None:
        libdir = sdir

    if prepare:

        if srclib["Prepare"] is not None:
            print "******************************* PREPARE " + srclib["Prepare"] + " **************"
            p = subprocess.Popen(['bash', '-c', srclib["Prepare"]], cwd=libdir,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate()
            if p.returncode != 0:
                raise BuildException("Error running prepare command for srclib "
                        + name, out, err)
        
        if srclib["Update Project"] == "Yes":
            if subprocess.call([os.path.join(sdk_path, 'tools', 'android'),
                'update', 'project', '-p', libdir]) != 0:
                    raise BuildException( 'Error updating ' + name + ' project')

    if basepath:
        return sdir
    return libdir


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
#  'sdk_path'    - the path to the Android SDK
#  'ndk_path'    - the path to the Android NDK
#  'javacc_path' - the path to javacc
#  'mvn3'        - the path to the maven 3 executable
#  'verbose'     - optional: verbose or not (default=False)
# Returns the (root, srclibpaths) where:
#   'root' is the root directory, which may be the same as 'build_dir' or may
#          be a subdirectory of it.
#   'srclibpaths' is information on the srclibs being used
def prepare_source(vcs, app, build, build_dir, srclib_dir, extlib_dir, sdk_path, ndk_path, javacc_path, mvn3, verbose=False, onserver=False):

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
    if build.get('submodules', 'no')  == 'yes':
        if verbose: print "Initialising submodules..."
        vcs.initsubmodules()

    # Run an init command if one is required...
    if 'init' in build:
        init = build['init']
        init = init.replace('$$SDK$$', sdk_path)
        init = init.replace('$$NDK$$', ndk_path)
        init = init.replace('$$MVN$$', mvn3)
        if verbose: print "Doing init: exec '%s' in '%s'"%(init,root_dir)
        if subprocess.call(['bash', '-c', init], cwd=root_dir) != 0:
            raise BuildException("Error running init command")

    # Generate (or update) the ant build file, build.xml...
    updatemode = build.get('update', '.')
    if (updatemode != 'no' and
        'maven' not in build):
        parms = [os.path.join(sdk_path, 'tools', 'android'),
                'update', 'project', '-p', '.']
        parms.append('--subprojects')
        if 'target' in build:
            parms.append('-t')
            parms.append(build['target'])
        update_dirs = updatemode.split(';')
        # Force build.xml update if necessary...
        if updatemode == 'force' or 'target' in build:
            if updatemode == 'force':
                update_dirs = ['.']
            buildxml = os.path.join(root_dir, 'build.xml')
            if os.path.exists(buildxml):
                print 'Force-removing old build.xml'
                os.remove(buildxml)
        for d in update_dirs:
            cwd = os.path.join(root_dir, d)
            if verbose:
                print "Update of '%s': exec '%s' in '%s'"%\
                    (d," ".join(parms),cwd)
            p = subprocess.Popen(parms, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (out, err) = p.communicate()
            if p.returncode != 0:
                raise BuildException("Failed to update project with stdout '%s' and stderr '%s'"%(out,err))
            # check to see whether an error was returned without a proper exit code (this is the case for the 'no target set or target invalid' error)
            if err != "" and err.startswith("Error: "):
                raise BuildException("Failed to update project with stdout '%s' and stderr '%s'"%(out,err))

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
        if 'encoding' in build:
            props += "\njava.encoding=" + build['encoding'] + "\n"
        f = open(locprops, 'w')
        f.write(props)
        f.close()

    # Insert version code and number into the manifest if necessary...
    if 'forceversion' in build:
        if subprocess.call(['sed','-r','-i',
            's/android:versionName="[^"]+"/android:versionName="' + build['version'] + '"/g',
            'AndroidManifest.xml'], cwd=root_dir) !=0:
            raise BuildException("Failed to amend manifest")
    if 'forcevercode' in build:
        if subprocess.call(['sed','-r','-i',
            's/android:versionCode="[^"]+"/android:versionCode="' + build['vercode'] + '"/g',
            'AndroidManifest.xml'], cwd=root_dir) !=0:
            raise BuildException("Failed to amend manifest")

    # Delete unwanted file...
    if 'rm' in build:
        for part in build['rm'].split(';'):
            dest = os.path.join(build_dir, part)
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
    if 'extlibs' in build:
        libsdir = os.path.join(root_dir, 'libs')
        if not os.path.exists(libsdir):
            os.mkdir(libsdir)
        for lib in build['extlibs'].split(';'):
            libf = os.path.basename(lib)
            shutil.copyfile(os.path.join(extlib_dir, lib),
                    os.path.join(libsdir, libf))

    # Get required source libraries...
    srclibpaths = []
    if 'srclibs' in build:
        for lib in build['srclibs'].split(';'):
            name, _ = lib.split('@')
            srclibpaths.append((name, getsrclib(lib, srclib_dir, sdk_path, preponly=onserver)))
    basesrclib = vcs.getsrclib()
    # If one was used for the main source, add that too.
    if basesrclib:
        srclibpaths.append(basesrclib)

    # There should never be bin, gen or native libs directories in the source, so just get
    # rid of them...
    for baddir in ['gen', 'bin', 'obj', 'libs/armeabi-v7a', 'libs/armeabi', 'libs/mips', 'libs/x86']:
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
    if 'prebuild' in build:
        prebuild = build['prebuild']
        # Substitute source library paths into prebuild commands...
        for name, libpath in srclibpaths:
            libpath = os.path.relpath(libpath, root_dir)
            prebuild = prebuild.replace('$$' + name + '$$', libpath)
        prebuild = prebuild.replace('$$SDK$$', sdk_path)
        prebuild = prebuild.replace('$$NDK$$', ndk_path)
        prebuild = prebuild.replace('$$MVN3$$', mvn3)
        p = subprocess.Popen(['bash', '-c', prebuild], cwd=root_dir,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if p.returncode != 0:
            raise BuildException("Error running pre-build command", out, err)

    if build.get('anal-tics', 'no') == 'yes':
        fp = os.path.join(root_dir, 'src', 'com', 'google', 'android', 'apps', 'analytics')
        os.makedirs(fp)
        with open(os.path.join(fp, 'GoogleAnalyticsTracker.java'), 'w') as f:
            f.write("""
            package com.google.android.apps.analytics;
            public class GoogleAnalyticsTracker {
                private static GoogleAnalyticsTracker instance;
                private GoogleAnalyticsTracker() {
                }
                public static GoogleAnalyticsTracker getInstance() {
                    if(instance == null)
                        instance = new GoogleAnalyticsTracker();
                    return instance;
                }
                public void start(String i,int think ,Object not) {
                }
                public void dispatch() {
                }
                public void stop() {
                }
                public void setProductVersion(String uh, String hu) {
                }
                public void trackEvent(String that,String just,String aint,int happening) {
                }
                public void trackPageView(String nope) {
                }
                public void setCustomVar(int mind,String your,String own,int business) {
                }
            }
            """)

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

    return (root_dir, srclibpaths)


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
                      'heyzap',
                      'jpct-ae']

    if 'scanignore' in thisbuild:
        ignore = thisbuild['scanignore'].split(';')
    else:
        ignore = []

    # Iterate through all files in the source code...
    for r,d,f in os.walk(build_dir):
        for curfile in f:

            if '/.hg' in r or '/.git' in r or '/.svn' in r:
                continue

            # Path (relative) to the file...
            fp = os.path.join(r, curfile)

            # Check if this file has been explicitly excluded from scanning...
            ignorethis = False
            for i in ignore:
                if fp.startswith(i):
                    ignorethis = True
                    break
            if ignorethis:
                continue

            for suspect in usual_suspects:
                if suspect in curfile.lower():
                    msg = 'Found probable non-free blob ' + fp
                    problems.append(msg)

            if curfile.endswith('.apk'):
                msg = 'Found apk file, which should not be in the source - ' + fp
                problems.append(msg)

            elif curfile.endswith('.elf'):
                msg = 'Found .elf at ' + fp
                problems.append(msg)

            elif curfile.endswith('.so'):
                msg = 'Found .so at ' + fp
                problems.append(msg)

            elif curfile.endswith('.java'):
                for line in file(fp):
                    if 'DexClassLoader' in line:
                        msg = 'Found DexClassLoader in ' + fp
                        problems.append(msg)

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
        lst = []
        for app, added in sortedapps:
            lst.append(app)
        lst.reverse()
        return lst

def isApkDebuggable(apkfile, sdk_path):
    """Returns True if the given apk file is debuggable

    :param apkfile: full path to the apk to check
    :param sdk_path: path to android sdk"""

    p = subprocess.Popen([os.path.join(sdk_path, 'platform-tools', 'aapt'),
		  'dump', 'xmltree', apkfile, 'AndroidManifest.xml'],
		 stdout=subprocess.PIPE)
    output = p.communicate()[0]
    if p.returncode != 0:
        print "ERROR: Failed to get apk manifest information"
        sys.exit(1)
    for line in output.splitlines():
        if line.find('android:debuggable') != -1 and not line.endswith('0x0'):
            return True
    return False


