#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# import.py - part of the FDroid server tools
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

import sys
import os
import shutil
import urllib
from optparse import OptionParser
from ConfigParser import ConfigParser
import logging
import common
import metadata


# Get the repo type and address from the given web page. The page is scanned
# in a rather naive manner for 'git clone xxxx', 'hg clone xxxx', etc, and
# when one of these is found it's assumed that's the information we want.
# Returns repotype, address, or None, reason
def getrepofrompage(url):

    req = urllib.urlopen(url)
    if req.getcode() != 200:
        return (None, 'Unable to get ' + url + ' - return code ' + str(req.getcode()))
    page = req.read()

    # Works for Google Code and BitBucket...
    index = page.find('hg clone')
    if index != -1:
        repotype = 'hg'
        repo = page[index + 9:]
        index = repo.find('<')
        if index == -1:
            return (None, "Error while getting repo address")
        repo = repo[:index]
        repo = repo.split('"')[0]
        return (repotype, repo)

    # Works for Google Code and BitBucket...
    index = page.find('git clone')
    if index != -1:
        repotype = 'git'
        repo = page[index + 10:]
        index = repo.find('<')
        if index == -1:
            return (None, "Error while getting repo address")
        repo = repo[:index]
        repo = repo.split('"')[0]
        return (repotype, repo)

    # Google Code only...
    index = page.find('svn checkout')
    if index != -1:
        repotype = 'git-svn'
        repo = page[index + 13:]
        prefix = '<strong><em>http</em></strong>'
        if not repo.startswith(prefix):
            return (None, "Unexpected checkout instructions format")
        repo = 'http' + repo[len(prefix):]
        index = repo.find('<')
        if index == -1:
            return (None, "Error while getting repo address - no end tag? '" + repo + "'")
        repo = repo[:index]
        index = repo.find(' ')
        if index == -1:
            return (None, "Error while getting repo address - no space? '" + repo + "'")
        repo = repo[:index]
        repo = repo.split('"')[0]
        return (repotype, repo)

    return (None, "No information found." + page)

config = None
options = None


def main():

    global config, options

    # Parse command line...
    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help="Restrict output to warnings and errors")
    parser.add_option("-u", "--url", default=None,
                      help="Project URL to import from.")
    parser.add_option("-s", "--subdir", default=None,
                      help="Path to main android project subdirectory, if not in root.")
    parser.add_option("-r", "--repo", default=None,
                      help="Allows a different repo to be specified for a multi-repo google code project")
    parser.add_option("--rev", default=None,
                      help="Allows a different revision (or git branch) to be specified for the initial import")
    (options, args) = parser.parse_args()

    config = common.read_config(options)

    if not options.url:
        logging.error("Specify project url.")
        sys.exit(1)
    url = options.url

    tmp_dir = 'tmp'
    if not os.path.isdir(tmp_dir):
        logging.info("Creating temporary directory")
        os.makedirs(tmp_dir)

    # Get all apps...
    apps = metadata.read_metadata()

    # Figure out what kind of project it is...
    projecttype = None
    issuetracker = None
    license = None
    website = url  # by default, we might override it
    if url.startswith('git://'):
        projecttype = 'git'
        repo = url
        repotype = 'git'
        sourcecode = ""
        website = ""
    elif url.startswith('https://github.com'):
        projecttype = 'github'
        repo = url
        repotype = 'git'
        sourcecode = url
        issuetracker = url + '/issues'
    elif url.startswith('https://gitlab.com/'):
        projecttype = 'gitlab'
        repo = url
        repotype = 'git'
        sourcecode = url
        issuetracker = url + '/issues'
    elif url.startswith('https://gitorious.org/'):
        projecttype = 'gitorious'
        repo = 'https://git.gitorious.org/' + url[22:] + '.git'
        repotype = 'git'
        sourcecode = url
    elif url.startswith('https://bitbucket.org/'):
        if url.endswith('/'):
            url = url[:-1]
        projecttype = 'bitbucket'
        sourcecode = url + '/src'
        issuetracker = url + '/issues'
        # Figure out the repo type and adddress...
        repotype, repo = getrepofrompage(sourcecode)
        if not repotype:
            logging.error("Unable to determine vcs type. " + repo)
            sys.exit(1)
    elif (url.startswith('http://code.google.com/p/') or
            url.startswith('https://code.google.com/p/')):
        if not url.endswith('/'):
            url += '/'
        projecttype = 'googlecode'
        sourcecode = url + 'source/checkout'
        if options.repo:
            sourcecode += "?repo=" + options.repo
        issuetracker = url + 'issues/list'

        # Figure out the repo type and adddress...
        repotype, repo = getrepofrompage(sourcecode)
        if not repotype:
            logging.error("Unable to determine vcs type. " + repo)
            sys.exit(1)

        # Figure out the license...
        req = urllib.urlopen(url)
        if req.getcode() != 200:
            logging.error('Unable to find project page at ' + sourcecode + ' - return code ' + str(req.getcode()))
            sys.exit(1)
        page = req.read()
        index = page.find('Code license')
        if index == -1:
            logging.error("Couldn't find license data")
            sys.exit(1)
        ltext = page[index:]
        lprefix = 'rel="nofollow">'
        index = ltext.find(lprefix)
        if index == -1:
            logging.error("Couldn't find license text")
            sys.exit(1)
        ltext = ltext[index + len(lprefix):]
        index = ltext.find('<')
        if index == -1:
            logging.error("License text not formatted as expected")
            sys.exit(1)
        ltext = ltext[:index]
        if ltext == 'GNU GPL v3':
            license = 'GPLv3'
        elif ltext == 'GNU GPL v2':
            license = 'GPLv2'
        elif ltext == 'Apache License 2.0':
            license = 'Apache2'
        elif ltext == 'MIT License':
            license = 'MIT'
        elif ltext == 'GNU Lesser GPL':
            license = 'LGPL'
        elif ltext == 'Mozilla Public License 1.1':
            license = 'MPL'
        elif ltext == 'New BSD License':
            license = 'NewBSD'
        else:
            logging.error("License " + ltext + " is not recognised")
            sys.exit(1)

    if not projecttype:
        logging.error("Unable to determine the project type.")
        logging.error("The URL you supplied was not in one of the supported formats. Please consult")
        logging.error("the manual for a list of supported formats, and supply one of those.")
        sys.exit(1)

    # Get a copy of the source so we can extract some info...
    logging.info('Getting source from ' + repotype + ' repo at ' + repo)
    src_dir = os.path.join(tmp_dir, 'importer')
    if os.path.exists(src_dir):
        shutil.rmtree(src_dir)
    vcs = common.getvcs(repotype, repo, src_dir)
    vcs.gotorevision(options.rev)
    if options.subdir:
        root_dir = os.path.join(src_dir, options.subdir)
    else:
        root_dir = src_dir

    # Extract some information...
    paths = common.manifest_paths(root_dir, None)
    if paths:

        version, vercode, package = common.parse_androidmanifests(paths)
        if not package:
            logging.error("Couldn't find package ID")
            sys.exit(1)
        if not version:
            logging.warn("Couldn't find latest version name")
        if not vercode:
            logging.warn("Couldn't find latest version code")
    else:
        spec = os.path.join(root_dir, 'buildozer.spec')
        if os.path.exists(spec):
            defaults = {'orientation': 'landscape', 'icon': '',
                        'permissions': '', 'android.api': "18"}
            bconfig = ConfigParser(defaults, allow_no_value=True)
            bconfig.read(spec)
            package = bconfig.get('app', 'package.domain') + '.' + bconfig.get('app', 'package.name')
            version = bconfig.get('app', 'version')
            vercode = None
        else:
            logging.error("No android or kivy project could be found. Specify --subdir?")
            sys.exit(1)

    # Make sure it's actually new...
    for app in apps:
        if app['id'] == package:
            logging.error("Package " + package + " already exists")
            sys.exit(1)

    # Construct the metadata...
    app = metadata.parse_metadata(None)
    app['id'] = package
    app['Web Site'] = website
    app['Source Code'] = sourcecode
    if issuetracker:
        app['Issue Tracker'] = issuetracker
    if license:
        app['License'] = license
    app['Repo Type'] = repotype
    app['Repo'] = repo
    app['Update Check Mode'] = "Tags"

    # Create a build line...
    build = {}
    build['version'] = version or '?'
    build['vercode'] = vercode or '?'
    build['commit'] = '?'
    build['disable'] = 'Generated by import.py - check/set version fields and commit id'
    if options.subdir:
        build['subdir'] = options.subdir
    if os.path.exists(os.path.join(root_dir, 'jni')):
        build['buildjni'] = ['yes']

    for flag, value in metadata.flag_defaults.iteritems():
        if flag in build:
            continue
        build[flag] = value

    app['builds'].append(build)

    # Keep the repo directory to save bandwidth...
    if not os.path.exists('build'):
        os.mkdir('build')
    shutil.move(src_dir, os.path.join('build', package))
    with open('build/.fdroidvcs-' + package, 'w') as f:
        f.write(repotype + ' ' + repo)

    metafile = os.path.join('metadata', package + '.txt')
    metadata.write_metadata(metafile, app)
    logging.info("Wrote " + metafile)


if __name__ == "__main__":
    main()
