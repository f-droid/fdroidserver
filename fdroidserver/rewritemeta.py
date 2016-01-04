#!/usr/bin/env python3
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
import os
import logging
import io

import common
import metadata

config = None
options = None


def proper_format(app):
    s = io.StringIO()
    # TODO: currently reading entire file again, should reuse first
    # read in metadata.py
    with open(app.metadatapath, 'r') as f:
        cur_content = f.read()
    metadata.write_txt_metadata(s, app)
    content = s.getvalue()
    s.close()
    return content == cur_content


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser(usage="%(prog)s [options] [APPID [APPID ...]]")
    common.setup_global_opts(parser)
    parser.add_argument("-l", "--list", action="store_true", default=False,
                        help="List files that would be reformatted")
    parser.add_argument("-t", "--to", default=None,
                        help="Rewrite to a specific format")
    parser.add_argument("appid", nargs='*', help="app-id in the form APPID")
    options = parser.parse_args()

    config = common.read_config(options)

    # Get all apps...
    allapps = metadata.read_metadata(xref=True)
    apps = common.read_app_args(options.appid, allapps, False)

    if options.list and options.to is not None:
        parser.error("Cannot use --list and --to at the same time")

    supported = ['txt', 'yaml']

    if options.to is not None and options.to not in supported:
        parser.error("Must give a valid format to --to")

    for appid, app in apps.iteritems():
        base, ext = common.get_extension(app.metadatapath)
        if not options.to and ext not in supported:
            logging.info("Ignoring %s file at '%s'" % (ext, app.metadatapath))
            continue

        to_ext = ext
        if options.to is not None:
            to_ext = options.to

        if options.list:
            if not proper_format(app):
                print app.metadatapath
            continue

        with open(base + '.' + to_ext, 'w') as f:
            metadata.write_metadata(to_ext, f, app)

        if ext != to_ext:
            os.remove(app.metadatapath)

    logging.debug("Finished.")

if __name__ == "__main__":
    main()
