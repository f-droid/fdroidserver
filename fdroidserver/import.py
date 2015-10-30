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
from argparse import ArgumentParser
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

    # Works for BitBucket
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

    # Works for BitBucket
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

    return (None, "No information found." + page)

config = None
options = None


def get_metadata_from_url(app, url):

    tmp_dir = 'tmp'
    if not os.path.isdir(tmp_dir):
        logging.info("Creating temporary directory")
        os.makedirs(tmp_dir)

    # Figure out what kind of project it is...
    projecttype = None
    app['Web Site'] = url  # by default, we might override it
    if url.startswith('git://'):
        projecttype = 'git'
        repo = url
        repotype = 'git'
        app['Source Code'] = ""
        app['Web Site'] = ""
    elif url.startswith('https://github.com'):
        projecttype = 'github'
        repo = url
        repotype = 'git'
        app['Source Code'] = url
        app['Issue Tracker'] = url + '/issues'
        app['Web Site'] = ""
    elif url.startswith('https://gitlab.com/'):
        projecttype = 'gitlab'
        # git can be fussy with gitlab URLs unless they end in .git
        if url.endswith('.git'):
            repo = url
        else:
            repo = url + '.git'
        repotype = 'git'
        app['Source Code'] = url + '/tree/HEAD'
        app['Issue Tracker'] = url + '/issues'
    elif url.startswith('https://bitbucket.org/'):
        if url.endswith('/'):
            url = url[:-1]
        projecttype = 'bitbucket'
        app['Source Code'] = url + '/src'
        app['Issue Tracker'] = url + '/issues'
        # Figure out the repo type and adddress...
        repotype, repo = getrepofrompage(app['Source Code'])
        if not repotype:
            logging.error("Unable to determine vcs type. " + repo)
            sys.exit(1)
    if not projecttype:
        logging.error("Unable to determine the project type.")
        logging.error("The URL you supplied was not in one of the supported formats. Please consult")
        logging.error("the manual for a list of supported formats, and supply one of those.")
        sys.exit(1)

    # Ensure we have a sensible-looking repo address at this point. If not, we
    # might have got a page format we weren't expecting. (Note that we
    # specifically don't want git@...)
    if ((repotype != 'bzr' and (not repo.startswith('http://') and
        not repo.startswith('https://') and
        not repo.startswith('git://'))) or
            ' ' in repo):
        logging.error("Repo address '{0}' does not seem to be valid".format(repo))
        sys.exit(1)

    # Get a copy of the source so we can extract some info...
    logging.info('Getting source from ' + repotype + ' repo at ' + repo)
    build_dir = os.path.join(tmp_dir, 'importer')
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir)
    vcs = common.getvcs(repotype, repo, build_dir)
    vcs.gotorevision(options.rev)
    root_dir = get_subdir(build_dir)

    app['Repo Type'] = repotype
    app['Repo'] = repo

    return root_dir, build_dir


config = None
options = None


def get_subdir(build_dir):
    if options.subdir:
        return os.path.join(build_dir, options.subdir)

    return build_dir


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument("-u", "--url", default=None,
                        help="Project URL to import from.")
    parser.add_argument("-s", "--subdir", default=None,
                        help="Path to main android project subdirectory, if not in root.")
    parser.add_argument("--rev", default=None,
                        help="Allows a different revision (or git branch) to be specified for the initial import")
    options = parser.parse_args()

    config = common.read_config(options)

    apps = metadata.read_metadata()
    package, app = metadata.get_default_app_info_list(apps)
    app['Update Check Mode'] = "Tags"

    root_dir = None
    build_dir = None

    if options.url:
        root_dir, build_dir = get_metadata_from_url(app, options.url)
    elif os.path.isdir('.git'):
        if options.url:
            app['Web Site'] = options.url
        root_dir = get_subdir(os.getcwd())
    else:
        logging.error("Specify project url.")
        sys.exit(1)

    # Extract some information...
    paths = common.manifest_paths(root_dir, [])
    if paths:

        version, vercode, package = common.parse_androidmanifests(paths, app)
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
    if package in apps:
        logging.error("Package " + package + " already exists")
        sys.exit(1)

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
    if build_dir is not None:
        shutil.move(build_dir, os.path.join('build', package))
    with open('build/.fdroidvcs-' + package, 'w') as f:
        f.write(app['Repo Type'] + ' ' + app['Repo'])

    metadatapath = os.path.join('metadata', package + '.txt')
    with open(metadatapath, 'w') as f:
        metadata.write_metadata('txt', f, app)
    logging.info("Wrote " + metadatapath)


if __name__ == "__main__":
    main()
