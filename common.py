# -*- coding: utf-8 -*-
#
# common.py - part of the FDroid server tools
# Copyright (C) 2010-11, Ciaran Gultnieks, ciaran@ciarang.com
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
import subprocess


def getvcs(vcstype, remote, local):
    if vcstype == 'git':
        return vcs_git(remote, local)
    elif vcstype == 'svn':
        return vcs_svn(remote, local)
    elif vcstype == 'hg':
        return vcs_hg(remote,local)
    elif vcstype == 'bzr':
        return vcs_bzr(remote,local)
    print "Invalid vcs type " + vcstype
    sys.exit(1)

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
                print "Password required with username"
                sys.exit(1)
            self.password = self.username[index+1:]
            self.username = self.username[:index]
        else:
            self.username = None

        self.remote = remote
        self.local = local
                    
    # Refresh the local repository - i.e. get the latest code. This
    # works either by updating if a local copy already exists, or by
    # cloning from scratch if it doesn't.
    def refreshlocal(self):
        if not os.path.exists(self.local):
            self.clone()
        else:
            self.reset()
            self.pull()

    # Clone the remote repository. It must not already exist locally.
    def clone(self):
        assert False    # Must be defined in child

    # Reset the local repository. Remove changes, untracked files, etc.
    # Put the working tree to either the given revision, or to the HEAD
    # if not specified.
    def reset(self, rev=None):
        assert False    # Must be defined in child

    # Get new commits from the remote repository. Local must be clean.
    def pull(self):
        assert False    # Must be defined in child

    # Initialise and update submodules
    def initsubmodules(self):
        assert False    # Not supported unless overridden

class vcs_git(vcs):

    def clone(self):
        if subprocess.call(['git', 'clone', self.remote, self.local]) != 0:
            print "Git clone failed"
            sys.exit(1)

    def reset(self, rev=None):
        if rev is None:
            rev = 'HEAD'
        if subprocess.call(['git', 'reset', '--hard', rev],
                cwd=self.local) != 0:
            print "Git reset failed"
            sys.exit(1)
        if subprocess.call(['git', 'clean', '-dfx'],
                cwd=self.local) != 0:
            print "Git clean failed"
            sys.exit(1)

    def pull(self):
        if subprocess.call(['git', 'pull', 'origin'],
                cwd=self.local) != 0:
            print "Git pull failed"
            sys.exit(1)

    def initsubmodules(self):
        if subprocess.call(['git', 'submodule', 'init'],
                cwd=self.local) != 0:
            print "Git submodule init failed"
            sys.exit(1)
        if subprocess.call(['git', 'submodule', 'update'],
                cwd=self.local) != 0:
            print "Git submodule update failed"
            sys.exit(1)



class vcs_svn(vcs):

    def userargs(self):
        if self.username is None:
            return []
        return ['--username', self.username, 
                '--password', self.password,
                '--non-interactive']

    def clone(self):
        if subprocess.call(['svn', 'checkout', self.remote, self.local] +
                self.userargs()) != 0:
            print "Svn checkout failed"
            sys.exit(1)

    def reset(self, rev=None):
        if rev is None:
            revargs = []
        else:
            revargs = ['-r', rev]
        for svncommand in (
                'svn revert -R .',
                r"svn status | awk '/\?/ {print $2}' | xargs rm -rf"):
            if subprocess.call(svncommand, cwd=self.local,
                    shell=True) != 0:
                print "Svn reset failed"
                sys.exit(1)
        if subprocess.call(['svn', 'update', '--force'] + revargs +
                self.userargs(), cwd=self.local) != 0:
            print "Svn update failed"
            sys.exit(1)

    def pull(self):
        if subprocess.call(['svn', 'update'] +
                self.userargs(), cwd=self.local) != 0:
            print "Svn update failed"
            sys.exit(1)

class vcs_hg(vcs):

    def clone(self):
        if subprocess.call(['hg', 'clone', self.remote, self.local]) !=0:
            print "Hg clone failed"
            sys.exit(1)

    def reset(self, rev=None):
        if rev is None:
            revargs = []
        else:
            revargs = [rev]
        if subprocess.call('hg status -u | xargs rm -rf',
                cwd=self.local, shell=True) != 0:
            print "Hg clean failed"
            sys.exit(1)
        if subprocess.call(['hg', 'checkout', '-C'] + revargs,
                cwd=self.local) != 0:
            print "Hg checkout failed"
            sys.exit(1)

    def pull(self):
        if subprocess.call(['hg', 'pull'],
                cwd=self.local) != 0:
            print "Hg pull failed"
            sys.exit(1)

class vcs_bzr(vcs):

    def clone(self):
        if subprocess.call(['bzr', 'branch', self.remote, self.local]) !=0:
            print "Bzr branch failed"
            sys.exit(1)

    def reset(self, rev=None):
        if rev is None:
            revargs = []
        else:
            revargs = ['-r', rev]
        if subprocess.call(['bzr', 'clean-tree', '--force',
                '--unknown', '--ignored'], cwd=self.local) != 0:
            print "Bzr revert failed"
            sys.exit(1)
        if subprocess.call(['bzr', 'revert'] + revargs,
                cwd=self.local) != 0:
            print "Bzr revert failed"
            sys.exit(1)

    def pull(self):
        if subprocess.call(['bzr', 'pull'],
                cwd=self.local) != 0:
            print "Bzr update failed"
            sys.exit(1)



def parse_metadata(metafile, **kw):

    def parse_buildline(value):
        parts = [p.replace("\\,", ",")
                 for p in re.split(r"(?<!\\),", value)]
        if len(parts) < 3:
            print "Invalid build format: " + value + " in " + metafile.name
            sys.exit(1)
        thisbuild = {}
        thisbuild['version'] = parts[0]
        thisbuild['vercode'] = parts[1]
        thisbuild['commit'] = parts[2]
        for p in parts[3:]:
            pk, pv = p.split('=', 1)
            thisbuild[pk] = pv
        return thisbuild

    if not isinstance(metafile, file):
        metafile = open(metafile, "r")
    thisinfo = {}
    thisinfo['id'] = metafile.name[9:-4]
    if kw.get("verbose", False):
        print "Reading metadata for " + thisinfo['id']
    thisinfo['description'] = ''
    thisinfo['name'] = None
    thisinfo['summary'] = ''
    thisinfo['license'] = 'Unknown'
    thisinfo['web'] = ''
    thisinfo['source'] = ''
    thisinfo['tracker'] = ''
    thisinfo['donate'] = None
    thisinfo['disabled'] = None
    thisinfo['antifeatures'] = None
    thisinfo['marketversion'] = ''
    thisinfo['marketvercode'] = '0'
    thisinfo['repotype'] = ''
    thisinfo['repo'] = ''
    thisinfo['builds'] = []
    thisinfo['requiresroot'] = False
    mode = 0
    buildline = []
    for line in metafile:
        line = line.rstrip('\r\n')
        if line.startswith("#"):
            continue
        if mode == 0:
            if len(line) == 0:
                continue
            index = line.find(':')
            if index == -1:
                print "Invalid metadata in " + metafile.name + " at: " + line
                sys.exit(1)
            field = line[:index]
            value = line[index+1:]
            if field == 'Description':
                mode = 1
            elif field == 'Name':
                thisinfo['name'] = value
            elif field == 'Summary':
                thisinfo['summary'] = value
            elif field == 'Source Code':
                thisinfo['source'] = value
            elif field == 'License':
                thisinfo['license'] = value
            elif field == 'Category':
                thisinfo['category'] = value
            elif field == 'Web Site':
                thisinfo['web'] = value
            elif field == 'Issue Tracker':
                thisinfo['tracker'] = value
            elif field == 'Donate':
                thisinfo['donate'] = value
            elif field == 'Disabled':
                thisinfo['disabled'] = value
            elif field == 'Use Built':
                pass  #Ignoring this - will be removed
            elif field == 'AntiFeatures':
                parts = value.split(",")
                for part in parts:
                    if (part != "Ads" and
                        part != "Tracking" and
                        part != "NonFreeNet" and
                        part != "NonFreeDep" and
                        part != "NonFreeAdd"):
                        print "Unrecognised antifeature '" + part + "' in " \
                            + metafile.name
                        sys.exit(1)
                thisinfo['antifeatures'] = value
            elif field == 'Market Version':
                thisinfo['marketversion'] = value
            elif field == 'Market Version Code':
                thisinfo['marketvercode'] = value
            elif field == 'Repo Type':
                thisinfo['repotype'] = value
            elif field == 'Repo':
                thisinfo['repo'] = value
            elif field == 'Build Version':
                if value.endswith("\\"):
                    mode = 2
                    buildline = [value[:-1]]
                else:
                    thisinfo['builds'].append(parse_buildline(value))
            elif field == "Requires Root":
                if value == "Yes":
                    thisinfo['requiresroot'] = True
            else:
                print "Unrecognised field " + field + " in " + metafile.name
                sys.exit(1)
        elif mode == 1:       # multi-line description
            if line == '.':
                mode = 0
            else:
                if len(line) == 0:
                    thisinfo['description'] += '\n\n'
                else:
                    if (not thisinfo['description'].endswith('\n') and
                        len(thisinfo['description']) > 0):
                        thisinfo['description'] += ' '
                    thisinfo['description'] += line
        elif mode == 2:       # line continuation
            if line.endswith("\\"):
                buildline.append(line[:-1])
            else:
                buildline.append(line)
                thisinfo['builds'].append(
                    parse_buildline("".join(buildline)))
                mode = 0
    if mode == 1:
        print "Description not terminated in " + metafile.name
        sys.exit(1)
    if len(thisinfo['description']) == 0:
        thisinfo['description'] = 'No description available'
    return thisinfo

def read_metadata(verbose=False):
    apps = []
    for metafile in sorted(glob.glob(os.path.join('metadata', '*.txt'))):
        if verbose:
            print "Reading " + metafile
        apps.append(parse_metadata(metafile, verbose=verbose))
    return apps
