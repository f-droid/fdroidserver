#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# install.py - part of the FDroid server tools
# Copyright (C) 2013, Ciaran Gultnieks, ciaran@ciarang.com
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
import glob
from optparse import OptionParser, OptionError
import logging

import common
from common import FDroidPopen, FDroidException

options = None
config = None


def devices():
    p = FDroidPopen([config['adb'], "devices"])
    if p.returncode != 0:
        raise FDroidException("An error occured when finding devices: %s" % p.output)
    lines = p.output.splitlines()
    if lines[0].startswith('* daemon not running'):
        lines = lines[2:]
    if len(lines) < 3:
        return []
    lines = lines[1:-1]
    return [l.split()[0] for l in lines]


def main():

    global options, config

    # Parse command line...
    parser = OptionParser(usage="Usage: %prog [options] [APPID[:VERCODE] [APPID[:VERCODE] ...]]")
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help="Restrict output to warnings and errors")
    parser.add_option("-a", "--all", action="store_true", default=False,
                      help="Install all signed applications available")
    (options, args) = parser.parse_args()

    if not args and not options.all:
        raise OptionError("If you really want to install all the signed apps, use --all", "all")

    config = common.read_config(options)

    output_dir = 'repo'
    if not os.path.isdir(output_dir):
        logging.info("No signed output directory - nothing to do")
        sys.exit(0)

    if args:

        vercodes = common.read_pkg_args(args, True)
        apks = {appid: None for appid in vercodes}

        # Get the signed apk with the highest vercode
        for apkfile in sorted(glob.glob(os.path.join(output_dir, '*.apk'))):

            appid, vercode = common.apknameinfo(apkfile)
            if appid not in apks:
                continue
            if vercodes[appid] and vercode not in vercodes[appid]:
                continue
            apks[appid] = apkfile

        for appid, apk in apks.iteritems():
            if not apk:
                raise FDroidException("No signed apk available for %s" % appid)

    else:

        apks = {common.apknameinfo(apkfile)[0]: apkfile for apkfile in
                sorted(glob.glob(os.path.join(output_dir, '*.apk')))}

    for appid, apk in apks.iteritems():
        # Get device list each time to avoid device not found errors
        devs = devices()
        if not devs:
            raise FDroidException("No attached devices found")
        logging.info("Installing %s..." % apk)
        for dev in devs:
            logging.info("Installing %s on %s..." % (apk, dev))
            p = FDroidPopen([config['adb'], "-s", dev, "install", apk])
            fail = ""
            for line in p.output.splitlines():
                if line.startswith("Failure"):
                    fail = line[9:-1]
            if not fail:
                continue

            if fail == "INSTALL_FAILED_ALREADY_EXISTS":
                logging.warn("%s is already installed on %s." % (apk, dev))
            else:
                raise FDroidException("Failed to install %s on %s: %s" % (
                    apk, dev, fail))

    logging.info("\nFinished")

if __name__ == "__main__":
    main()
