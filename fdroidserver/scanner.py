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

    probcount = 0

    build_dir = 'build'
    if not os.path.isdir(build_dir):
        logging.info("Creating build directory")
        os.makedirs(build_dir)
    srclib_dir = os.path.join(build_dir, 'srclib')
    extlib_dir = os.path.join(build_dir, 'extlib')

    for appid, app in apps.iteritems():

        if app['Disabled']:
            logging.info("Skipping %s: disabled" % appid)
            continue
        if not app['builds']:
            logging.info("Skipping %s: no builds specified" % appid)
            continue

        logging.info("Processing " + appid)

        try:

            build_dir = 'build/' + appid

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
                    count = common.scan_source(build_dir, root_dir, thisbuild)
                    if count > 0:
                        logging.warn('Scanner found %d problems in %s (%s)' % (
                            count, appid, thisbuild['vercode']))
                        probcount += count

        except BuildException as be:
            logging.warn("Could not scan app %s due to BuildException: %s" % (
                appid, be))
            probcount += 1
        except VCSException as vcse:
            logging.warn("VCS error while scanning app %s: %s" % (appid, vcse))
            probcount += 1
        except Exception:
            logging.warn("Could not scan app %s due to unknown error: %s" % (
                appid, traceback.format_exc()))
            probcount += 1

    logging.info("Finished:")
    print "%d app(s) with problems" % probcount

if __name__ == "__main__":
    main()
