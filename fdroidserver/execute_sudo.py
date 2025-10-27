#!/usr/bin/env python3
#
# execute_sudo.py - part of the F-Droid server tools
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

"""Read the "sudo:" field from the build metadata then remove sudo.

This assumes that the source code has not yet been pushed into the VM,
since the sudo: script should not be able to touch the source code.
Then after the sudo: script is run, sudo is removed and the root
account is locked so the build job can no longer run anything as
sudo/root.

For more info, see:
https://f-droid.org/docs/Build_Metadata_Reference/#build_sudo

"""

import argparse
import logging

from fdroidserver import common, metadata


def sudo_run(appid, vercode, virt_container_type, build):
    if build.sudo:
        try:
            common.inside_exec(
                appid,
                vercode,
                [
                    'DEBIAN_FRONTEND=noninteractive',
                    'bash',
                    '-e',
                    '-u',
                    '-o',
                    'pipefail',
                    '-x',
                    '-c',
                    '; '.join(build.sudo),
                ],
                virt_container_type,
                as_root=True,
            )
        except Exception as e:
            raise Exception(
                f"error running metadata sudo commands in '{appid}:{vercode}' container/VM"
            ) from e


def sudo_lock_root(appid, vercode, virt_container_type):
    try:
        common.inside_exec(
            appid,
            vercode,
            ['passwd', '--lock', 'root'],
            virt_container_type,
            as_root=True,
        )
        logging.info("locked root user login in build container/VM")
    except Exception as e:
        raise Exception(
            f"Error locking root account in {appid}:{vercode} container/VM"
        ) from e


def sudo_uninstall(appid, vercode, virt_container_type):
    try:
        common.inside_exec(
            appid,
            vercode,
            ['SUDO_FORCE_REMOVE=yes', 'dpkg', '--purge', 'sudo'],
            virt_container_type,
            as_root=True,
        )
        logging.info("uninstalled sudo in build container/VM")
    except Exception as e:
        raise Exception(f"Error removing sudo in {appid}:{vercode} VM") from e


def execute_sudo_wrapper(appid, vercode, virt_container_type, build):
    sudo_run(appid, vercode, virt_container_type, build)
    sudo_lock_root(appid, vercode, virt_container_type)
    sudo_uninstall(appid, vercode, virt_container_type)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    common.setup_global_opts(parser)
    common.setup_virt_container_type_opts(parser)
    parser.add_argument(
        "APPID:VERCODE",
        help="Application ID with Version Code in the form APPID:VERCODE",
    )
    options = common.parse_args(parser)
    common.set_console_logging(options.verbose)

    appid, vercode = common.split_pkg_arg(options.__dict__['APPID:VERCODE'])

    _ignored, build = metadata.get_single_build(appid, vercode)
    virt_container_type = common.get_virt_container_type(options)

    execute_sudo_wrapper(
        appid,
        vercode,
        virt_container_type,
        build,
    )


if __name__ == "__main__":
    main()
