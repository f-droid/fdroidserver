#!/usr/bin/env python3
#
# exec.py - part of the FDroid server tools
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

"""Run an fdroidserver subcommand inside of the VM for the build.

Since this is an internal command, the strings are not localized.

"""

import sys
import logging
import traceback
from argparse import ArgumentParser

from . import common


def main():
    parser = ArgumentParser(
        description="Run a subcommand in the buildserver container/box."
    )
    parser.add_argument(
        '--as-root',
        default=False,
        action='store_true',
        help="run command inside of container/VM as root user",
    )
    common.setup_global_opts(parser)
    common.setup_virt_container_type_opts(parser)
    parser.add_argument(
        "APPID:VERCODE",
        help="Application ID with Version Code in the form APPID:VERCODE",
    )
    parser.add_argument(
        "COMMAND", nargs="*", help="Command to run inside the container/box."
    )
    options = common.parse_args(parser)
    common.set_console_logging(options.verbose)

    try:
        appid, vercode = common.split_pkg_arg(options.__dict__['APPID:VERCODE'])
        common.inside_exec(
            appid,
            vercode,
            options.COMMAND,
            common.get_virt_container_type(options),
            options.as_root,
        )
    except Exception as e:
        if options.verbose:
            logging.error(traceback.format_exc())
        else:
            logging.error(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
