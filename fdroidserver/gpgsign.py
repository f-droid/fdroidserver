#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# publish.py - part of the FDroid server tools
# Copyright (C) 2010-2014, Ciaran Gultnieks, ciaran@ciarang.com
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
import md5
import glob
from optparse import OptionParser
import logging

import common
import metadata
from common import FDroidPopen, BuildException

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

    output_dir = 'repo'
    if not os.path.isdir(output_dir):
        logging.error("Missing output directory")
        sys.exit(1)

    # Process any apks that are waiting to be signed...
    for apkfile in sorted(glob.glob(os.path.join(output_dir, '*.apk'))):

        apkfilename = os.path.basename(apkfile)
        sigfilename = apkfilename + ".txt"
        sigpath = os.path.join(output_dir, sigfilename)

        if not os.path.exists(sigpath):
            p = FDroidPopen(['gpg', '-a',
                             '--output', sigpath,
                             '--detach-sig',
                             os.path.join(output_dir, apkfilename)])
            if p.returncode != 0:
                logging.error("Signing failed.")
                sys.exit(1)

            logging.info('Signed ' + apkfilename)


if __name__ == "__main__":
    main()
