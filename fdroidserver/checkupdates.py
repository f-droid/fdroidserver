#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# checkupdates.py - part of the FDroid server tools
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

import sys
import os
import re
import urllib2
import time
import subprocess
from optparse import OptionParser
import traceback
import HTMLParser
from distutils.version import LooseVersion
import common, metadata
from common import BuildException
from common import VCSException
from metadata import MetaDataException


# Check for a new version by looking at a document retrieved via HTTP.
# The app's Update Check Data field is used to provide the information
# required.
def check_http(app):

    try:

        if not 'Update Check Data' in app:
            raise Exception('Missing Update Check Data')

        urlcode, codeex, urlver, verex = app['Update Check Data'].split('|')

        vercode = "99999999"
        if len(urlcode) > 0:
            print "...requesting {0}".format(urlcode)
            req = urllib2.Request(urlcode, None)
            resp = urllib2.urlopen(req, None, 20)
            page = resp.read()

            m = re.search(codeex, page)
            if not m:
                raise Exception("No RE match for version code")
            vercode = m.group(1)

        version = "??"
        if len(urlver) > 0:
            if urlver != '.':
                print "...requesting {0}".format(urlver)
                req = urllib2.Request(urlver, None)
                resp = urllib2.urlopen(req, None, 20)
                page = resp.read()

            m = re.search(verex, page)
            if not m:
                raise Exception("No RE match for version")
            version = m.group(1)

        return (version, vercode)

    except Exception:
        msg = "Could not complete http check for app %s due to unknown error: %s" % (app['id'], traceback.format_exc())
        return (None, msg)

# Check for a new version by looking at the tags in the source repo.
# Whether this can be used reliably or not depends on
# the development procedures used by the project's developers. Use it with
# caution, because it's inappropriate for many projects.
# Returns (None, "a message") if this didn't work, or (version, vercode) for
# the details of the current version.
def check_tags(app):

    try:

        if app['Repo Type'] == 'srclib':
            build_dir = os.path.join('build', 'srclib', app['Repo'])
            repotype = common.getsrclibvcs(app['Repo'])
        else:
            build_dir = os.path.join('build/', app['id'])
            repotype = app['Repo Type']

        if repotype not in ('git', 'git-svn', 'hg', 'bzr'):
            return (None, 'Tags update mode only works for git, hg, bzr and git-svn repositories currently', None)

        # Set up vcs interface and make sure we have the latest code...
        vcs = common.getvcs(app['Repo Type'], app['Repo'], build_dir)

        vcs.gotorevision(None)

        flavour = None
        if len(app['builds']) > 0:
            if 'subdir' in app['builds'][-1]:
                build_dir = os.path.join(build_dir, app['builds'][-1]['subdir'])
            if 'gradle' in app['builds'][-1]:
                flavour = app['builds'][-1]['gradle']

        htag = None
        hver = None
        hcode = "0"

        for tag in vcs.gettags():
            if options.verbose:
                print "Check tag: '{0}'".format(tag)
            vcs.gotorevision(tag)

            # Only process tags where the manifest exists...
            paths = common.manifest_paths(build_dir, flavour)
            version, vercode, package = common.parse_androidmanifests(paths)
            if package and package == app['id'] and version and vercode:
                print "Manifest exists. Found version %s (%s)" % (
                        version, vercode)
                if int(vercode) > int(hcode):
                    htag = tag
                    hcode = str(int(vercode))
                    hver = version

        if hver:
            return (hver, hcode, htag)
        return (None, "Couldn't find any version information", None)

    except BuildException as be:
        msg = "Could not scan app %s due to BuildException: %s" % (app['id'], be)
        return (None, msg, None)
    except VCSException as vcse:
        msg = "VCS error while scanning app %s: %s" % (app['id'], vcse)
        return (None, msg, None)
    except Exception:
        msg = "Could not scan app %s due to unknown error: %s" % (app['id'], traceback.format_exc())
        return (None, msg, None)

# Check for a new version by looking at the AndroidManifest.xml at the HEAD
# of the source repo. Whether this can be used reliably or not depends on
# the development procedures used by the project's developers. Use it with
# caution, because it's inappropriate for many projects.
# Returns (None, "a message") if this didn't work, or (version, vercode) for
# the details of the current version.
def check_repomanifest(app, branch=None):

    try:

        if app['Repo Type'] == 'srclib':
            build_dir = os.path.join('build', 'srclib', app['Repo'])
            repotype = common.getsrclibvcs(app['Repo'])
        else:
            build_dir = os.path.join('build/', app['id'])
            repotype = app['Repo Type']

        # Set up vcs interface and make sure we have the latest code...
        vcs = common.getvcs(app['Repo Type'], app['Repo'], build_dir)

        if repotype == 'git':
            if branch:
                branch = 'origin/'+branch
            vcs.gotorevision(branch)
        elif repotype == 'git-svn':
            vcs.gotorevision(branch)
        elif repotype == 'svn':
            vcs.gotorevision(None)
        elif repotype == 'hg':
            vcs.gotorevision(branch)
        elif repotype == 'bzr':
            vcs.gotorevision(None)

        flavour = None

        if len(app['builds']) > 0:
            if 'subdir' in app['builds'][-1]:
                build_dir = os.path.join(build_dir, app['builds'][-1]['subdir'])
            if 'gradle' in app['builds'][-1]:
                flavour = app['builds'][-1]['gradle']

        if not os.path.isdir(build_dir):
            return (None, "Subdir '" + app['builds'][-1]['subdir'] + "'is not a valid directory")

        paths = common.manifest_paths(build_dir, flavour)

        version, vercode, package = common.parse_androidmanifests(paths)
        if not package:
            return (None, "Couldn't find package ID")
        if package != app['id']:
            return (None, "Package ID mismatch")
        if not version:
            return (None,"Couldn't find latest version name")
        if not vercode:
            return (None,"Couldn't find latest version code")

        vercode = str(int(vercode))

        print "Manifest exists. Found version %s (%s)" % (version, vercode)

        return (version, vercode)

    except BuildException as be:
        msg = "Could not scan app %s due to BuildException: %s" % (app['id'], be)
        return (None, msg)
    except VCSException as vcse:
        msg = "VCS error while scanning app %s: %s" % (app['id'], vcse)
        return (None, msg)
    except Exception:
        msg = "Could not scan app %s due to unknown error: %s" % (app['id'], traceback.format_exc())
        return (None, msg)

def check_repotrunk(app, branch=None):

    try:
        if app['Repo Type'] == 'srclib':
            build_dir = os.path.join('build', 'srclib', app['Repo'])
            repotype = common.getsrclibvcs(app['Repo'])
        else:
            build_dir = os.path.join('build/', app['id'])
            repotype = app['Repo Type']

        if repotype not in ('svn', 'git-svn'):
            return (None, 'RepoTrunk update mode only makes sense in svn and git-svn repositories')

        # Set up vcs interface and make sure we have the latest code...
        vcs = common.getvcs(app['Repo Type'], app['Repo'], build_dir)

        vcs.gotorevision(None)

        ref = vcs.getref()
        return (ref, ref)
    except BuildException as be:
        msg = "Could not scan app %s due to BuildException: %s" % (app['id'], be)
        return (None, msg)
    except VCSException as vcse:
        msg = "VCS error while scanning app %s: %s" % (app['id'], vcse)
        return (None, msg)
    except Exception:
        msg = "Could not scan app %s due to unknown error: %s" % (app['id'], traceback.format_exc())
        return (None, msg)

# Check for a new version by looking at the Google Play Store.
# Returns (None, "a message") if this didn't work, or (version, None) for
# the details of the current version.
def check_gplay(app):
    time.sleep(15)
    url = 'https://play.google.com/store/apps/details?id=' + app['id']
    headers = {'User-Agent' : 'Mozilla/5.0 (X11; Linux i686; rv:18.0) Gecko/20100101 Firefox/18.0'}
    req = urllib2.Request(url, None, headers)
    try:
        resp = urllib2.urlopen(req, None, 20)
        page = resp.read()
    except urllib2.HTTPError, e:
        return (None, str(e.code))
    except Exception, e:
        return (None, 'Failed:' + str(e))

    version = None

    m = re.search('itemprop="softwareVersion">[ ]*([^<]+)[ ]*</div>', page)
    if m:
        html_parser = HTMLParser.HTMLParser()
        version = html_parser.unescape(m.group(1))

    if version == 'Varies with device':
        return (None, 'Device-variable version, cannot use this method')

    if not version:
        return (None, "Couldn't find version")
    return (version.strip(), None)


config = None
options = None

def main():

    global config, options

    # Parse command line...
    parser = OptionParser(usage="Usage: %prog [options] [APPID [APPID ...]]")
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("--auto", action="store_true", default=False,
                      help="Process auto-updates")
    parser.add_option("--autoonly", action="store_true", default=False,
                      help="Only process apps with auto-updates")
    parser.add_option("--commit", action="store_true", default=False,
                      help="Commit changes")
    parser.add_option("--gplay", action="store_true", default=False,
                      help="Only print differences with the Play Store")
    (options, args) = parser.parse_args()

    config = common.read_config(options)

    # Get all apps...
    allapps = metadata.read_metadata(options.verbose)

    apps = common.read_app_args(args, allapps, False)

    if options.gplay:
        for app in apps:
            version, reason = check_gplay(app)
            if version is None and options.verbose:
                if reason == '404':
                    print "%s is not in the Play Store" % common.getappname(app)
                else:
                    print "%s encountered a problem: %s" % (common.getappname(app), reason)
            if version is not None:
                stored = app['Current Version']
                if not stored:
                    if options.verbose:
                        print "%s has no Current Version but has version %s on the Play Store" % (
                                common.getappname(app), version)
                elif LooseVersion(stored) < LooseVersion(version):
                    print "%s has version %s on the Play Store, which is bigger than %s" % (
                            common.getappname(app), version, stored)
                elif options.verbose:
                    if stored != version:
                        print "%s has version %s on the Play Store, which differs from %s" % (
                                common.getappname(app), version, stored)
                    else:
                        print "%s has the same version %s on the Play Store" % (
                                common.getappname(app), version)
        return


    for app in apps:

        if options.autoonly and app['Auto Update Mode'] == 'None':
            if options.verbose:
                print "Nothing to do for %s..." % app['id']
            continue

        print "Processing " + app['id'] + '...'

        writeit = False
        logmsg = None

        tag = None
        msg = None
        vercode = None
        mode = app['Update Check Mode']
        if mode == 'Tags':
            (version, vercode, tag) = check_tags(app)
        elif mode == 'RepoManifest':
            (version, vercode) = check_repomanifest(app)
        elif mode.startswith('RepoManifest/'):
            tag = mode[13:]
            (version, vercode) = check_repomanifest(app, tag)
        elif mode == 'RepoTrunk':
            (version, vercode) = check_repotrunk(app)
        elif mode == 'HTTP':
            (version, vercode) = check_http(app)
        elif mode == 'Static':
            version = None
            msg = 'Checking disabled'
        elif mode == 'None':
            version = None
            msg = 'Checking disabled'
        else:
            version = None
            msg = 'Invalid update check method'

        if vercode and app['Vercode Operation']:
            op = app['Vercode Operation'].replace("%c", str(int(vercode)))
            vercode = str(eval(op))

        updating = False
        if not version:
            print "...%s" % msg
        elif vercode == app['Current Version Code']:
            print "...up to date"
        else:
            app['Current Version'] = version
            app['Current Version Code'] = str(int(vercode))
            updating = True
            writeit = True

        # Do the Auto Name thing as well as finding the CV real name
        if len(app["Repo Type"]) > 0:

            try:

                if app['Repo Type'] == 'srclib':
                    app_dir = os.path.join('build', 'srclib', app['Repo'])
                else:
                    app_dir = os.path.join('build/', app['id'])

                vcs = common.getvcs(app["Repo Type"], app["Repo"], app_dir)
                vcs.gotorevision(tag)

                flavour = None
                if len(app['builds']) > 0:
                    if 'subdir' in app['builds'][-1]:
                        app_dir = os.path.join(app_dir, app['builds'][-1]['subdir'])
                    if 'gradle' in app['builds'][-1]:
                        flavour = app['builds'][-1]['gradle']

                new_name = common.fetch_real_name(app_dir, flavour)
                if new_name != app['Auto Name']:
                    app['Auto Name'] = new_name

                if app['Current Version'].startswith('@string/'):
                    cv = common.version_name(app['Current Version'], app_dir, flavour)
                    if app['Current Version'] != cv:
                        app['Current Version'] = cv
                        writeit = True
            except Exception:
                print "ERROR: Auto Name or Current Version failed for %s due to exception: %s" % (app['id'], traceback.format_exc())

        if updating:
            name = common.getappname(app)
            ver = common.getcvname(app)
            print '...updating to version %s' % ver
            logmsg = 'Update CV of %s to %s' % (name, ver)

        if options.auto:
            mode = app['Auto Update Mode']
            if mode == 'None':
                pass
            elif mode.startswith('Version '):
                pattern = mode[8:]
                if pattern.startswith('+'):
                    try:
                        suffix, pattern = pattern.split(' ', 1)
                    except ValueError:
                        raise MetaDataException("Invalid AUM: " + mode)
                else:
                    suffix = ''
                gotcur = False
                latest = None
                for build in app['builds']:
                    if build['vercode'] == app['Current Version Code']:
                        gotcur = True
                    if not latest or int(build['vercode']) > int(latest['vercode']):
                        latest = build
                if not gotcur:
                    newbuild = latest.copy()
                    if 'origlines' in newbuild:
                        del newbuild['origlines']
                    newbuild['vercode'] = app['Current Version Code']
                    newbuild['version'] = app['Current Version'] + suffix
                    print "...auto-generating build for " + newbuild['version']
                    commit = pattern.replace('%v', newbuild['version'])
                    commit = commit.replace('%c', newbuild['vercode'])
                    newbuild['commit'] = commit
                    app['builds'].append(newbuild)
                    writeit = True
                    name = common.getappname(app)
                    ver = common.getcvname(app)
                    logmsg = "Update %s to %s" % (name, ver)
            else:
                print 'Invalid auto update mode "' + mode + '"'

        if writeit:
            metafile = os.path.join('metadata', app['id'] + '.txt')
            metadata.write_metadata(metafile, app)
            if options.commit and logmsg:
                print "Commiting update for " + metafile
                gitcmd = ["git", "commit", "-m",
                    logmsg]
                if 'auto_author' in config:
                    gitcmd.extend(['--author', config['auto_author']])
                gitcmd.extend(["--", metafile])
                if subprocess.call(gitcmd) != 0:
                    print "Git commit failed"
                    sys.exit(1)

    print "Finished."

if __name__ == "__main__":
    main()

