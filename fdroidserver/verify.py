#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# publish.py - part of the FDroid server tools
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
import shutil
import subprocess
import glob
from optparse import OptionParser

from common import BuildException

def main():

    #Read configuration...
    execfile('config.py', globals())

    # Parse command line...
    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-p", "--package", default=None,
                      help="Verify only the specified package")
    (options, args) = parser.parse_args()

    tmp_dir = 'tmp'
    if not os.path.isdir(tmp_dir):
        print "Creating temporary directory"
        os.makedirs(tmp_dir)

    unsigned_dir = 'unsigned'
    if not os.path.isdir(unsigned_dir):
        print "No unsigned directory - nothing to do"
        sys.exit(0)

    for apkfile in sorted(glob.glob(os.path.join(unsigned_dir, '*.apk'))):

        apkfilename = os.path.basename(apkfile)
        i = apkfilename.rfind('_')
        if i == -1:
            raise BuildException("Invalid apk name")
        appid = apkfilename[:i]
        print "Processing " + apkfilename

        if not options.package or options.package == appid:

            remoteapk = os.path.join(tmp_dir, apkfilename)
            if os.path.exists(remoteapk):
                os.remove(remoteapk)
            if subprocess.call(['wget',
                'https://f-droid.org/repo/' + apkfilename],
                cwd=tmp_dir) != 0:
                print "Failed to get " + apkfilename
                sys.exit(1)

            thisdir = os.path.join(tmp_dir, 'this_apk')
            thatdir = os.path.join(tmp_dir, 'that_apk')
            for d in [thisdir, thatdir]:
                if os.path.exists(d):
                    shutil.rmtree(d)
                os.mkdir(d)

            if subprocess.call(['jar', 'xf',
                os.path.join(unsigned_dir, apkfilename)],
                cwd=thisdir) != 0:
                print "Failed to unpack local build of " + apkfilename
                sys.exit(1)
            if subprocess.call(['jar', 'xf', remoteapk],
                cwd=thisdir) != 0:
                print "Failed to unpack remote build of " + apkfilename
                sys.exit(1)

            p = subprocess.Popen(['diff', '-r', 'this_apk', 'that_apk'],
                cwd=tmp_dir, stdout=subprocess.PIPE)
            out = p.communicate()[0]
            lines = out.splitlines()
            if len(lines) != 1 or lines[0].find('META-INF') == -1:
                print "Unexpected diff output"
                print out
                sys.exit(1)

            print "...successfully verified"

if __name__ == "__main__":
    main()


