#!/usr/bin/env python3
#
# install_ndk.py - part of the F-Droid server tools
# Copyright (C) 2024-2025 Michael Pöhn <michael@poehn.at>
# Copyright (C) 2025 Hans-Christoph Steiner <hans@eds.org>
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

"""Read the "ndk:" field from the build metadata and install the right NDK packages.

For more info, see:
https://f-droid.org/docs/Build_Metadata_Reference/#build_ndk

"""

import argparse
import logging
import os

from fdroidserver import common, exception, metadata


def install_ndk_wrapper(build, ndk_paths=dict()):
    """Make sure the requested NDK version is or gets installed.

    Parameters
    ----------
    build
        metadata.Build instance entry that may contain the
        requested NDK version
    ndk_paths
        dictionary holding the currently installed NDKs
    """
    ndk_path = build.ndk_path()
    if build.ndk or (build.buildjni and build.buildjni != ['no']):
        if not ndk_path:
            for k, v in ndk_paths.items():
                if k.endswith("_orig"):
                    continue
            common.auto_install_ndk(build)
        ndk_path = build.ndk_path()
        if not os.path.isdir(ndk_path):
            logging.critical("Android NDK '%s' is not installed!" % ndk_path)
            raise exception.FDroidException()
    return ndk_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    common.setup_global_opts(parser)
    parser.add_argument(
        "APPID:VERCODE",
        help="Application ID with Version Code in the form APPID:VERCODE",
    )

    options = common.parse_args(parser)
    config = common.get_config()
    appid, versionCode = common.split_pkg_arg(options.__dict__['APPID:VERCODE'])
    app, build = metadata.get_single_build(appid, versionCode)
    install_ndk_wrapper(build, config.get('ndk_paths', dict()))


if __name__ == "__main__":
    main()
