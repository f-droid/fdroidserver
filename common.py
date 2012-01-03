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
            raise VCSException("Git clone failed")

    def reset(self, rev=None):
        if rev is None:
            rev = 'origin'
        if subprocess.call(['git', 'reset', '--hard', rev],
                cwd=self.local) != 0:
            raise VCSException("Git reset failed")
        if subprocess.call(['git', 'clean', '-dfx'],
                cwd=self.local) != 0:
            raise VCSException("Git clean failed")

    def pull(self):
        if subprocess.call(['git', 'pull', 'origin'],
                cwd=self.local) != 0:
            raise VCSException("Git pull failed")
        # Might need tags that aren't on a branch.
        if subprocess.call(['git', 'fetch', '--tags', 'origin'],
                cwd=self.local) != 0:
            raise VCSException("Git fetch failed")

    def initsubmodules(self):
        if subprocess.call(['git', 'submodule', 'init'],
                cwd=self.local) != 0:
            raise VCSException("Git submodule init failed")
        if subprocess.call(['git', 'submodule', 'update'],
                cwd=self.local) != 0:
            raise VCSException("Git submodule update failed")



class vcs_svn(vcs):

    def userargs(self):
        if self.username is None:
            return ['--non-interactive']
        return ['--username', self.username, 
                '--password', self.password,
                '--non-interactive']

    def clone(self):
        if subprocess.call(['svn', 'checkout', self.remote, self.local] +
                self.userargs()) != 0:
            raise VCSException("Svn checkout failed")

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
                raise VCSException("Svn reset failed")
        if subprocess.call(['svn', 'update', '--force'] + revargs +
                self.userargs(), cwd=self.local) != 0:
            raise VCSException("Svn update failed")

    def pull(self):
        if subprocess.call(['svn', 'update'] +
                self.userargs(), cwd=self.local) != 0:
            raise VCSException("Svn update failed")

class vcs_hg(vcs):

    def clone(self):
        if subprocess.call(['hg', 'clone', self.remote, self.local]) !=0:
            raise VCSException("Hg clone failed")

    def reset(self, rev=None):
        if rev is None:
            revargs = []
        else:
            revargs = [rev]
        if subprocess.call('hg status -u | xargs rm -rf',
                cwd=self.local, shell=True) != 0:
            raise VCSException("Hg clean failed")
        if subprocess.call(['hg', 'checkout', '-C'] + revargs,
                cwd=self.local) != 0:
            raise VCSException("Hg checkout failed")

    def pull(self):
        if subprocess.call(['hg', 'pull'],
                cwd=self.local) != 0:
            raise VCSException("Hg pull failed")

class vcs_bzr(vcs):

    def clone(self):
        if subprocess.call(['bzr', 'branch', self.remote, self.local]) != 0:
            raise VCSException("Bzr branch failed")

    def reset(self, rev=None):
        if rev is None:
            revargs = []
        else:
            revargs = ['-r', rev]
        if subprocess.call(['bzr', 'clean-tree', '--force',
                '--unknown', '--ignored'], cwd=self.local) != 0:
            raise VCSException("Bzr revert failed")
        if subprocess.call(['bzr', 'revert'] + revargs,
                cwd=self.local) != 0:
            raise VCSException("Bzr revert failed")

    def pull(self):
        if subprocess.call(['bzr', 'pull'],
                cwd=self.local) != 0:
            raise VCSException("Bzr update failed")



def parse_metadata(metafile, **kw):

    def parse_buildline(value):
        parts = [p.replace("\\,", ",")
                 for p in re.split(r"(?<!\\),", value)]
        if len(parts) < 3:
            raise MetaDataException("Invalid build format: " + value + " in " + metafile.name)
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
                raise MetaDataException("Invalid metadata in " + metafile.name + " at: " + line)
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
                        raise MetaDataException("Unrecognised antifeature '" + part + "' in " \
                            + metafile.name)
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
                raise MetaDataException("Unrecognised field " + field + " in " + metafile.name)
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
        raise MetaDataException("Description not terminated in " + metafile.name)
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

class BuildException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

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

