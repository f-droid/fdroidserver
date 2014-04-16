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
import logging
import common

config = None
options = None


def update_serverwebroot(repo_section):
    rsyncargs = ['rsync', '-u', '-r', '--delete']
    if options.verbose:
        rsyncargs += ['--verbose']
    if options.quiet:
        rsyncargs += ['--quiet']
    index = os.path.join(repo_section, 'index.xml')
    indexjar = os.path.join(repo_section, 'index.jar')
    # serverwebroot is guaranteed to have a trailing slash in common.py
    if subprocess.call(rsyncargs +
                       ['--exclude', index, '--exclude', indexjar,
                        repo_section, config['serverwebroot']]) != 0:
        sys.exit(1)
    if subprocess.call(rsyncargs +
                       [index, config['serverwebroot'] + repo_section]) != 0:
        sys.exit(1)
    if subprocess.call(rsyncargs +
                       [indexjar, config['serverwebroot'] + repo_section]) != 0:
        sys.exit(1)

def main():
    global config, options

    # Parse command line...
    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help="Restrict output to warnings and errors")
    (options, args) = parser.parse_args()

    config = common.read_config(options)

    if len(args) != 1:
        logging.critical("Specify a single command")
        sys.exit(1)

    if args[0] != 'init' and args[0] != 'update':
        logging.critical("The only commands currently supported are 'init' and 'update'")
        sys.exit(1)

    if 'nonstandardwebroot' in config and config['nonstandardwebroot'] == True:
        standardwebroot = False
    else:
        standardwebroot = True

    if 'serverwebroot' in config:
        serverwebroot = config['serverwebroot']
        host, fdroiddir = serverwebroot.rstrip('/').split(':')
        serverrepobase = os.path.basename(fdroiddir)
        if serverrepobase != 'fdroid' and standardwebroot:
            logging.error('serverwebroot does not end with "fdroid", '
                          + 'perhaps you meant one of these:\n\t'
                          + serverwebroot.rstrip('/') + '/fdroid\n\t'
                          + serverwebroot.rstrip('/').rstrip(serverrepobase) + 'fdroid')
            sys.exit(1)
    else:
        serverwebroot = None

    if serverwebroot == None:
        logging.warn('No serverwebroot set! Edit your config.py to set one.')
        sys.exit(1)

    repo_sections = ['repo']
    if config['archive_older'] != 0:
        repo_sections.append('archive')

    if args[0] == 'init':
        if serverwebroot != None:
            sshargs = ['ssh']
            if options.quiet:
                sshargs += ['-q']
            for repo_section in repo_sections:
                cmd = sshargs + [host, 'mkdir -p', fdroiddir + '/' + repo_section]
                if options.verbose:
                    # ssh -v produces different output than rsync -v, so this
                    # simulates rsync -v
                    logging.info(' '.join(cmd))
                if subprocess.call(cmd) != 0:
                    sys.exit(1)
    elif args[0] == 'update':
        for repo_section in repo_sections:
            if serverwebroot != None:
                update_serverwebroot(repo_section)

    sys.exit(0)

if __name__ == "__main__":
    main()
