#!/usr/bin/env python3
#
# gpgsign.py - part of the FDroid server tools
# Copyright (C) 2014, Ciaran Gultnieks, ciaran@ciarang.com
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
import glob
from argparse import ArgumentParser
import logging

from . import _
from . import common
from .common import FDroidPopen
from .exception import FDroidException

config = None
options = None


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser(usage="%(prog)s [options]")
    common.setup_global_opts(parser)
    options = parser.parse_args()

    config = common.read_config(options)

    repodirs = ['repo']
    if config['archive_older'] != 0:
        repodirs.append('archive')

    for output_dir in repodirs:
        if not os.path.isdir(output_dir):
            raise FDroidException(_("Missing output directory") + " '" + output_dir + "'")

        # Process any apks that are waiting to be signed...
        for f in sorted(glob.glob(os.path.join(output_dir, '*.*'))):
            if common.get_file_extension(f) == 'asc':
                continue
            if not common.is_repo_file(f):
                continue
            filename = os.path.basename(f)
            sigfilename = filename + ".asc"
            sigpath = os.path.join(output_dir, sigfilename)

            if not os.path.exists(sigpath):
                gpgargs = ['gpg', '-a',
                           '--output', sigpath,
                           '--detach-sig']
                if 'gpghome' in config:
                    gpgargs.extend(['--homedir', config['gpghome']])
                if 'gpgkey' in config:
                    gpgargs.extend(['--local-user', config['gpgkey']])
                gpgargs.append(os.path.join(output_dir, filename))
                p = FDroidPopen(gpgargs)
                if p.returncode != 0:
                    raise FDroidException("Signing failed.")

                logging.info('Signed ' + filename)


if __name__ == "__main__":
    main()
