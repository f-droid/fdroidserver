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

from . import _
from . import common
from . import metadata

config = None
options = None


def proper_format(app):
    s = io.StringIO()
    # TODO: currently reading entire file again, should reuse first
    # read in metadata.py
    with open(app.metadatapath, 'r', encoding='utf8') as f:
        cur_content = f.read()
    _ignored, extension = common.get_extension(app.metadatapath)
    if extension == 'yml':
        metadata.write_yaml(s, app)
    elif extension == 'txt':
        metadata.write_txt(s, app)
    content = s.getvalue()
    s.close()
    return content == cur_content


def main():

    global config, options

    supported = ['txt', 'yml']

    # Parse command line...
    parser = ArgumentParser(usage="%(prog)s [options] [APPID [APPID ...]]")
    common.setup_global_opts(parser)
    parser.add_argument("-l", "--list", action="store_true", default=False,
                        help=_("List files that would be reformatted"))
    parser.add_argument("-t", "--to", default=None,
                        help=_("Rewrite to a specific format: ") + ', '.join(supported))
    parser.add_argument("appid", nargs='*', help=_("applicationId in the form APPID"))
    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    metadata.warnings_action = options.W

    config = common.read_config(options)

    # Get all apps...
    allapps = metadata.read_metadata(xref=True)
    apps = common.read_app_args(options.appid, allapps, False)

    if options.list and options.to is not None:
        parser.error(_("Cannot use --list and --to at the same time"))

    if options.to is not None and options.to not in supported:
        parser.error(_("Unsupported metadata format, use: --to [{supported}]")
                     .format(supported=' '.join(supported)))

    for appid, app in apps.items():
        path = app.metadatapath
        base, ext = common.get_extension(path)
        if not options.to and ext not in supported:
            logging.info(_("Ignoring {ext} file at '{path}'").format(ext=ext, path=path))
            continue
        elif options.to is not None:
            logging.info(_("Rewriting '{appid}' to '{path}'").format(appid=appid, path=options.to))
        else:
            logging.info(_("Rewriting '{appid}'").format(appid=appid))

        to_ext = ext
        if options.to is not None:
            to_ext = options.to

        if options.list:
            if not proper_format(app):
                print(path)
            continue

        newbuilds = []
        for build in app.builds:
            new = metadata.Build()
            for k in metadata.build_flags:
                v = build[k]
                if v is None or v is False or v == [] or v == '':
                    continue
                new[k] = v
            newbuilds.append(new)
        app.builds = newbuilds

        metadata.write_metadata(base + '.' + to_ext, app)

        if ext != to_ext:
            os.remove(path)

    logging.debug(_("Finished"))


if __name__ == "__main__":
    main()
