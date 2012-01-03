#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# scanner.py - part of the FDroid server tools
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

import sys
import os
import shutil
import re
import urllib
import time
import subprocess
from optparse import OptionParser
import HTMLParser
import common

#Read configuration...
execfile('config.py')


# Parse command line...
parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true", default=False,
                  help="Spew out even more information than normal")
(options, args) = parser.parse_args()

# Get all apps...
apps = common.read_metadata(options.verbose)

html_parser = HTMLParser.HTMLParser()

problems = []

for app in apps:

    if app['disabled']:
        print "Skipping %s: disabled" % app['id']
    elif not app['builds']:
        print "Skipping %s: no builds specified" % app['id']

    if (app['disabled'] is None and app['repo'] != '' 
            and app['repotype'] != '' and len(app['builds']) > 0):

        print "Processing " + app['id']

        build_dir = 'build/' + app['id']

        # Set up vcs interface and make sure we have the latest code...
        vcs = common.getvcs(app['repotype'], app['repo'], build_dir)

        refreshed_source = False


        for thisbuild in app['builds']:

            if thisbuild['commit'].startswith('!'):
                print ("..skipping version " + thisbuild['version'] + " - " +
                        thisbuild['commit'][1:])
            else:
                print "..scanning version " + thisbuild['version']

                if not refreshed_source:
                    vcs.refreshlocal()
                    refreshed_source = True

                # Optionally, the actual app source can be in a subdirectory...
                if thisbuild.has_key('subdir'):
                    root_dir = os.path.join(build_dir, thisbuild['subdir'])
                else:
                    root_dir = build_dir

                # Get a working copy of the right revision...
                if options.verbose:
                    print "Resetting repository to " + thisbuild['commit']
                vcs.reset(thisbuild['commit'])

                # Initialise submodules if requred...
                if thisbuild.get('submodules', 'no')  == 'yes':
                    vcs.initsubmodules()

                # Generate (or update) the ant build file, build.xml...
                if (thisbuild.get('update', 'yes') == 'yes' and
                       not thisbuild.has_key('maven')):
                    parms = [os.path.join(sdk_path, 'tools', 'android'),
                             'update', 'project', '-p', '.']
                    parms.append('--subprojects')
                    if thisbuild.has_key('target'):
                        parms.append('-t')
                        parms.append(thisbuild['target'])
                    if subprocess.call(parms, cwd=root_dir) != 0:
                        print "Failed to update project"
                        sys.exit(1)

                # Delete unwanted file...
                if thisbuild.has_key('rm'):
                    os.remove(os.path.join(build_dir, thisbuild['rm']))

                # Run a pre-build command if one is required...
                if thisbuild.has_key('prebuild'):
                    if subprocess.call(thisbuild['prebuild'],
                            cwd=root_dir, shell=True) != 0:
                        print "Error running pre-build command"
                        sys.exit(1)

                # Apply patches if any
                if 'patch' in thisbuild:
                    for patch in thisbuild['patch'].split(';'):
                        print "Applying " + patch
                        patch_path = os.path.join('metadata', app['id'], patch)
                        if subprocess.call(['patch', '-p1',
                                        '-i', os.path.abspath(patch_path)], cwd=build_dir) != 0:
                            print "Failed to apply patch %s" % patch_path
                            sys.exit(1)

                # Scan for common known non-free blobs:
                usual_suspects = ['flurryagent.jar', 'paypal_mpl.jar']
                for r,d,f in os.walk(build_dir):
                    for curfile in f:
                        if curfile.lower() in usual_suspects:
                            msg = 'Found probable non-free blob ' + os.path.join(r,file)
                            msg += ' in ' + app['id'] + ' ' + thisbuild['version']
                            problems.append(msg)

print "Finished:"
for problem in problems:
    print problem
print str(len(problems)) + ' problems.'

