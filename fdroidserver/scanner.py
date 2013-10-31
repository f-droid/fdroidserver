#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# scanner.py - part of the FDroid server tools
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

import sys
import os
import traceback
from optparse import OptionParser
import HTMLParser
import common
from common import BuildException
from common import VCSException

config = {}

def main():

    # Read configuration...
    common.read_config(config)


    # Parse command line...
    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-p", "--package", default=None,
                      help="Scan only the specified package")
    parser.add_option("--nosvn", action="store_true", default=False,
                      help="Skip svn repositories - for test purposes, because they are too slow.")
    (options, args) = parser.parse_args()

    # Get all apps...
    apps = common.read_metadata(options.verbose)

    # Filter apps according to command-line options
    if options.package:
        apps = [app for app in apps if app['id'] == options.package]
        if len(apps) == 0:
            print "No such package"
            sys.exit(1)

    html_parser = HTMLParser.HTMLParser()

    problems = []

    build_dir = 'build'
    if not os.path.isdir(build_dir):
        print "Creating build directory"
        os.makedirs(build_dir)
    srclib_dir = os.path.join(build_dir, 'srclib')
    extlib_dir = os.path.join(build_dir, 'extlib')

    for app in apps:

        skip = False
        if app['Disabled']:
            print "Skipping %s: disabled" % app['id']
            skip = True
        elif not app['builds']:
            print "Skipping %s: no builds specified" % app['id']
            skip = True
        elif options.nosvn and app['Repo Type'] == 'svn':
            skip = True

        if not skip:

            print "Processing " + app['id']

            try:

                build_dir = 'build/' + app['id']

                # Set up vcs interface and make sure we have the latest code...
                vcs = common.getvcs(app['Repo Type'], app['Repo'], build_dir,
                        config['sdk_path'])

                for thisbuild in app['builds']:

                    if 'disable' in thisbuild:
                        print ("..skipping version " + thisbuild['version'] + " - " +
                                thisbuild.get('disable', thisbuild['commit'][1:]))
                    else:
                        print "..scanning version " + thisbuild['version']

                        # Prepare the source code...
                        root_dir, _ = common.prepare_source(vcs, app, thisbuild,
                                build_dir, srclib_dir, extlib_dir,
                                config['sdk_path'], config['ndk_path'],
                                config['javacc_path'], config['mvn3'],
                                options.verbose, False)

                        # Do the scan...
                        buildprobs = common.scan_source(build_dir, root_dir, thisbuild)
                        for problem in buildprobs:
                            problems.append(problem + 
                                ' in ' + app['id'] + ' ' + thisbuild['version'])

            except BuildException as be:
                msg = "Could not scan app %s due to BuildException: %s" % (app['id'], be)
                problems.append(msg)
            except VCSException as vcse:
                msg = "VCS error while scanning app %s: %s" % (app['id'], vcse)
                problems.append(msg)
            except Exception:
                msg = "Could not scan app %s due to unknown error: %s" % (app['id'], traceback.format_exc())
                problems.append(msg)

    print "Finished:"
    for problem in problems:
        print problem
    print str(len(problems)) + ' problems.'

if __name__ == "__main__":
    main()

