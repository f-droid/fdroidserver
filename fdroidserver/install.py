#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# verify.py - part of the FDroid server tools
# Copyright (C) 2013, Ciaran Gultnieks, ciaran@ciarang.com
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
from optparse import OptionParser

import common
from common import FDroidPopen
import metadata

options = None
config = None

def devices():
    p = FDroidPopen(["adb", "devices"])
    if p.returncode != 0:
        raise Exception("An error occured when finding devices: %s" % p.stderr)
    devs = []
    return [l.split()[0] for l in p.stdout.splitlines()[1:-1]]


def main():

    global options, config

    # Parse command line...
    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    (options, args) = parser.parse_args()

    config = common.read_config(options)

    output_dir = 'repo'
    if not os.path.isdir(output_dir):
        print "No signed output directory - nothing to do"
        sys.exit(1)

    # Get all apps...
    allapps = metadata.read_metadata()

    apps = common.read_app_args(args, options, allapps)

    for app in apps:
        last = None
        for build in app['builds']:
            apk = os.path.join(output_dir, common.getapkname(app, build))
            if os.path.exists(apk):
                last = build
        if last is None:
            raise Exception("No available signed apks for %s" % app['id'])

    for app in apps:
        build = app['builds'][0]
        apk = os.path.join(output_dir, common.getapkname(app, build))
        if not os.path.exists(apk):
            raise Exception("No such signed apk: %s" % apk)
            continue
        # Get device list each time to avoid device not found errors
        devs = devices()
        if not devs:
            raise Exception("No attached devices found")
        print "Installing %s..." % apk
        for dev in devs:
            print "Installing %s on %s..." % (apk, dev)
            p = FDroidPopen(["adb", "-s", dev, "install", apk ])
            fail= ""
            for line in p.stdout.splitlines():
                if line.startswith("Failure"):
                    fail = line[9:-1]
            if fail:
                raise Exception("Failed to install %s on %s: %s" % (
                    apk, dev, fail))

    print "\nFinished"

if __name__ == "__main__":
    main()

