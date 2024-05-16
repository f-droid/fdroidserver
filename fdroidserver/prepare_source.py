#!/usr/bin/env python3
#
# prepare_source.py - part of the F-Droid server tools
# Copyright (C) 2024-2025 Michael Pöhn <michael@poehn.at>
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

"""Prepare the source code directory for a particular build."""

import argparse
import pathlib

from fdroidserver import common, metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    common.setup_global_opts(parser)
    parser.add_argument(
        "APPID:VERCODE",
        help="Application ID with Version Code in the form APPID:VERCODE",
    )
    options = common.parse_args(parser)
    common.get_config()
    appid, versionCode = common.split_pkg_arg(options.__dict__['APPID:VERCODE'])
    app, build = metadata.get_single_build(appid, versionCode)

    # prepare folders for git/vcs checkout
    vcs, build_dir = common.setup_vcs(app)
    srclib_dir = pathlib.Path('./build/srclib')
    extlib_dir = pathlib.Path('./build/extlib')
    log_dir = pathlib.Path('./logs')
    output_dir = pathlib.Path('./unsigned')
    for d in (srclib_dir, extlib_dir, log_dir, output_dir):
        d.mkdir(exist_ok=True, parents=True)

    # do git/vcs checkout
    common.prepare_source(
        vcs,
        app,
        build,
        build_dir,
        str(srclib_dir),
        str(extlib_dir),
        refresh=False,
        onserver=True,
    )


if __name__ == "__main__":
    main()
