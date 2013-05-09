#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# server.py - part of the FDroid server tools
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
import subprocess
from optparse import OptionParser

def main():

    #Read configuration...
    global archive_older
    archive_older = 0
    execfile('config.py', globals())

    # Parse command line...
    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    (options, args) = parser.parse_args()

    if len(args) != 1:
        print "Specify a single command"
        sys.exit(1)

    if args[0] != 'update':
        print "The only command currently supported is 'update'"
        sys.exit(1)

    repodirs = ['repo']
    if archive_older != 0:
        repodirs.append('archive')

    for repodir in repodirs:
        index = os.path.join(repodir, 'index.xml')
        indexjar = os.path.join(repodir, 'index.jar')
        if subprocess.call(['rsync', '-u', '-v', '-r', '--delete',
                '--exclude', index, '--exclude', indexjar, repodir, serverwebroot]) != 0:
            sys.exit(1)
        if subprocess.call(['rsync', '-u', '-v', '-r', '--delete',
                index, serverwebroot + '/' + repodir]) != 0:
            sys.exit(1)
        if subprocess.call(['rsync', '-u', '-v', '-r', '--delete',
                indexjar, serverwebroot + '/' + repodir]) != 0:
            sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()


