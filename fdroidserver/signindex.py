#!/usr/bin/env python3
#
# gpgsign.py - part of the FDroid server tools
# Copyright (C) 2015, Ciaran Gultnieks, ciaran@ciarang.com
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
from argparse import ArgumentParser
import logging

from . import common

config = None
options = None


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser(usage="%(prog)s [options]")
    common.setup_global_opts(parser)
    options = parser.parse_args()

    config = common.read_config(options)

    if 'jarsigner' not in config:
        logging.critical('Java jarsigner not found! Install in standard location or set java_paths!')
        sys.exit(1)

    repodirs = ['repo']
    if config['archive_older'] != 0:
        repodirs.append('archive')

    signed = 0
    for output_dir in repodirs:
        if not os.path.isdir(output_dir):
            logging.error("Missing output directory '" + output_dir + "'")
            sys.exit(1)

        unsigned = os.path.join(output_dir, 'index_unsigned.jar')
        if os.path.exists(unsigned):

            common.signjar(unsigned)
            os.rename(unsigned, os.path.join(output_dir, 'index.jar'))
            logging.info('Signed index in ' + output_dir)
            signed += 1

    if signed == 0:
        logging.info("Nothing to do")


if __name__ == "__main__":
    main()
