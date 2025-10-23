#!/usr/bin/env python3
#
# destroy.py - part of the FDroid server tools
# Copyright (C) 2024, Hans-Christoph Steiner <hans@eds.org>
# Copyright (C) 2024, Michael Pöhn <michael@poehn.at>
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

"""Destroy any existing per-build container/VM structures.

After this runs, there should be no trace of the given
ApplicationID:versionCode left in the container/VM system.

Since this is an internal command, the strings are not localized.

"""

import logging
import sys
import traceback
from argparse import ArgumentParser

from . import common

# TODO should this track whether it actually removed something?
# What do `podman rm` and `vagrant destroy` do?


def podman_rm(appid, vercode):
    """Remove a Podman pod and all its containers."""
    pod_name = common.get_pod_name(appid, vercode)
    for p in common.get_podman_client().pods.list():
        if p.name == pod_name:
            logging.debug(f'Removing {pod_name}.')
            p.remove(force=True)


def destroy_wrapper(appid, vercode, virt_container_type):
    if virt_container_type == 'vagrant':
        common.vagrant_destroy(appid, vercode)
    elif virt_container_type == 'podman':
        podman_rm(appid, vercode)


def main():
    parser = ArgumentParser(
        description="Push files into the buildserver container/box."
    )
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
        destroy_wrapper(
            appid,
            vercode,
            common.get_virt_container_type(options),
        )
    except Exception as e:
        if options.verbose:
            logging.error(traceback.format_exc())
        else:
            logging.error(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
