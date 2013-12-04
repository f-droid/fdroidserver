#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# server.py - part of the FDroid server tools
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
import subprocess
from optparse import OptionParser
import common

config = None
options = None


def main():

    global config, options

    # Parse command line...
    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    (options, args) = parser.parse_args()

    config = common.read_config(options)

    if len(args) != 1:
        print "Specify a single command"
        sys.exit(1)

    if args[0] != 'init' and args[0] != 'update':
        print "The only commands currently supported are 'init' and 'update'"
        sys.exit(1)

    serverwebroot = config['serverwebroot'].rstrip('/').replace('//', '/')
    host, fdroiddir = serverwebroot.split(':')
    serverrepobase = os.path.basename(fdroiddir)
    if 'nonstandardwebroot' in config and config['nonstandardwebroot'] == True:
        standardwebroot = False
    else:
        standardwebroot = True
    if serverrepobase != 'fdroid' and standardwebroot:
        print('ERROR: serverwebroot does not end with "fdroid", '
              + 'perhaps you meant one of these:\n\t'
              + serverwebroot.rstrip('/') + '/fdroid\n\t'
              + serverwebroot.rstrip('/').rstrip(serverrepobase) + 'fdroid')
        sys.exit(1)

    repodirs = ['repo']
    if config['archive_older'] != 0:
        repodirs.append('archive')

    for repodir in repodirs:
        if args[0] == 'init':
            if subprocess.call(['ssh', '-v', host,
                                'mkdir -p', fdroiddir + '/' + repodir]) != 0:
                sys.exit(1)
        elif args[0] == 'update':
            index = os.path.join(repodir, 'index.xml')
            indexjar = os.path.join(repodir, 'index.jar')
            if subprocess.call(['rsync', '-u', '-v', '-r', '--delete',
                                '--exclude', index, '--exclude', indexjar,
                                repodir, config['serverwebroot']]) != 0:
                sys.exit(1)
            if subprocess.call(['rsync', '-u', '-v', '-r', '--delete',
                                index,
                                config['serverwebroot'] + '/' + repodir]) != 0:
                sys.exit(1)
            if subprocess.call(['rsync', '-u', '-v', '-r', '--delete',
                                indexjar,
                                config['serverwebroot'] + '/' + repodir]) != 0:
                sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
