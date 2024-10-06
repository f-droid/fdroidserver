#!/usr/bin/env python3
#
# rewritemeta.py - part of the FDroid server tools
# This cleans up the original .yml metadata file format.
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
import io
import tempfile
import shutil
from pathlib import Path

from . import _
from . import common
from . import metadata

config = None


def proper_format(app):
    s = io.StringIO()
    # TODO: currently reading entire file again, should reuse first
    # read in metadata.py
    cur_content = Path(app.metadatapath).read_text(encoding='utf-8')
    if Path(app.metadatapath).suffix == '.yml':
        metadata.write_yaml(s, app)
    content = s.getvalue()
    s.close()
    return content == cur_content


def remove_blank_flags_from_builds(builds):
    """Remove unset entries from Builds so they are not written out."""
    if not builds:
        return list()
    newbuilds = list()
    for build in builds:
        new = dict()
        for k in metadata.build_flags:
            v = build.get(k)
            # 0 is valid value, it should not be stripped
            if v is None or v is False or v == '' or v == dict() or v == list():
                continue
            new[k] = v
        newbuilds.append(new)
    return newbuilds


def main():
    global config

    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        default=False,
        help=_("List files that would be reformatted (dry run)"),
    )
    parser.add_argument(
        "appid", nargs='*', help=_("application ID of file to operate on")
    )
    metadata.add_metadata_arguments(parser)
    options = common.parse_args(parser)
    metadata.warnings_action = options.W

    config = common.read_config()

    apps = common.read_app_args(options.appid)

    for appid, app in apps.items():
        path = Path(app.metadatapath)
        if path.suffix == '.yml':
            logging.info(_("Rewriting '{appid}'").format(appid=appid))
        else:
            logging.warning(_('Cannot rewrite "{path}"').format(path=path))
            continue

        if options.list:
            if not proper_format(app):
                print(path)
            continue

        # TODO these should be moved to metadata.write_yaml()
        builds = remove_blank_flags_from_builds(app.get('Builds'))
        if builds:
            app['Builds'] = builds

        # rewrite to temporary file before overwriting existing
        # file in case there's a bug in write_metadata
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir) / path.name
            metadata.write_metadata(tmp_path, app)
            shutil.move(tmp_path, path)

    logging.debug(_("Finished"))


if __name__ == "__main__":
    main()
