#!/usr/bin/env python3
#
# fetch_srclibs.py - part of the F-Droid server tools
# Copyright (C) 2024-2025, Michael Pöhn <michael@poehn.at>
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

"""Subcommand for setting up source code from srclibs:."""

import argparse
import logging
import os
import sys
import traceback

from fdroidserver import common, metadata


def fetch_srclibs_wrapper(build):
    srclib_dir = os.path.join('build', 'srclib')
    os.makedirs(srclib_dir, exist_ok=True)

    for lib in build.srclibs:
        common.getsrclib(lib, srclib_dir, prepare=False, build=build)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    common.setup_global_opts(parser)
    parser.add_argument(
        "APPID:VERCODE",
        help="Application ID with Version Code in the form APPID:VERCODE",
    )
    options = common.parse_args(parser)
    common.set_console_logging(options.verbose)

    try:
        appid, vercode = common.split_pkg_arg(options.__dict__['APPID:VERCODE'])
        _ignored, build = metadata.get_single_build(appid, vercode)
        fetch_srclibs_wrapper(build)
    except Exception as e:
        if options.verbose:
            logging.error(traceback.format_exc())
        else:
            logging.error(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
