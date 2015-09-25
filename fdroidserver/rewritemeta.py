#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# rewritemeta.py - part of the FDroid server tools
# This cleans up the original .txt metadata file format.
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

from argparse import ArgumentParser
import logging
import common
import metadata

config = None
options = None


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser(usage="%(prog)s [options] [APPID [APPID ...]]")
    common.setup_global_opts(parser)
    parser.add_argument("appid", nargs='*', help="app-id in the form APPID")
    options = parser.parse_args()

    config = common.read_config(options)

    # Get all apps...
    allapps = metadata.read_metadata(xref=True)
    apps = common.read_app_args(options.appid, allapps, False)

    for appid, app in apps.iteritems():
        metadatapath = app['metadatapath']
        ext = common.get_extension(metadatapath)
        if ext not in ['txt']:
            logging.info("Ignoring %s file at '%s'"
                         % (ext.upper(), metadatapath))
            continue
        logging.debug("Rewriting " + metadatapath)
        with open(metadatapath, 'w') as f:
            metadata.write_metadata(f, app)

    logging.debug("Finished.")

if __name__ == "__main__":
    main()
