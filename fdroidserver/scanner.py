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

import os
import traceback
from optparse import OptionParser
import logging

import common
import metadata
from common import BuildException, VCSException

config = None
options = None


def main():

    global config, options

    # Parse command line...
    parser = OptionParser(usage="Usage: %prog [options] [APPID[:VERCODE] [APPID[:VERCODE] ...]]")
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help="Restrict output to warnings and errors")
    (options, args) = parser.parse_args()

    config = common.read_config(options)

    # Read all app and srclib metadata
    allapps = metadata.read_metadata()
    apps = common.read_app_args(args, allapps, True)

    problems = []

    build_dir = 'build'
    if not os.path.isdir(build_dir):
        logging.info("Creating build directory")
        os.makedirs(build_dir)
    srclib_dir = os.path.join(build_dir, 'srclib')
    extlib_dir = os.path.join(build_dir, 'extlib')

    for app in apps:

        if app['Disabled']:
            logging.info("Skipping %s: disabled" % app['id'])
            continue
        if not app['builds']:
            logging.info("Skipping %s: no builds specified" % app['id'])
            continue

        logging.info("Processing " + app['id'])

        try:

            build_dir = 'build/' + app['id']

            # Set up vcs interface and make sure we have the latest code...
            vcs = common.getvcs(app['Repo Type'], app['Repo'], build_dir)

            for thisbuild in app['builds']:

                if thisbuild['disable']:
                    logging.info("...skipping version %s - %s" % (
                        thisbuild['version'], thisbuild.get('disable', thisbuild['commit'][1:])))
                else:
                    logging.info("...scanning version " + thisbuild['version'])

                    # Prepare the source code...
                    root_dir, _ = common.prepare_source(vcs, app, thisbuild,
                                                        build_dir, srclib_dir,
                                                        extlib_dir, False)

                    # Do the scan...
                    buildprobs = common.scan_source(build_dir, root_dir, thisbuild)
                    for problem in buildprobs:
                        problems.append(problem + ' in ' + app['id']
                                        + ' ' + thisbuild['version'])

        except BuildException as be:
            msg = "Could not scan app %s due to BuildException: %s" % (app['id'], be)
            problems.append(msg)
        except VCSException as vcse:
            msg = "VCS error while scanning app %s: %s" % (app['id'], vcse)
            problems.append(msg)
        except Exception:
            msg = "Could not scan app %s due to unknown error: %s" % (app['id'], traceback.format_exc())
            problems.append(msg)

    logging.info("Finished:")
    for problem in problems:
        print problem
    print str(len(problems)) + ' problems.'

if __name__ == "__main__":
    main()
