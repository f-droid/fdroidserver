#!/usr/bin/env python3
#
# pull_verify.py - part of the F-Droid server tools
# Copyright (C) 2024-2025, Hans-Christoph Steiner <hans@eds.org>
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

"""Pull file to verify from the buildserver container/box."""

import logging
import os
import sys
import traceback
from argparse import ArgumentParser

from . import common, metadata, pull


def make_file_list(appid, vercode):
    app, build = metadata.get_single_build(appid, vercode)
    ext = common.get_output_extension(build)
    return [
        os.path.join('tmp', common.get_release_filename(app, build, ext)),
    ]


def main():
    parser = ArgumentParser(description=__doc__)
    common.setup_global_opts(parser)
    common.setup_virt_container_type_opts(parser)
    parser.add_argument(
        "APPID:VERCODE",
        help="Application ID with Version Code in the form APPID:VERCODE",
    )
    options = common.parse_args(parser)
    common.set_console_logging(options.verbose)

    try:
        appid, vercode = common.split_pkg_arg(options.__dict__['APPID:VERCODE'])
        pull.make_file_list = make_file_list
        pull.pull_wrapper(appid, vercode, common.get_virt_container_type(options))
    except Exception as e:
        if options.verbose:
            logging.error(traceback.format_exc())
        else:
            logging.error(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
