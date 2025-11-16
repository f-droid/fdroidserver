#!/usr/bin/env python3
#
# send_buildcycle.py - part of the FDroid server tools
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


"""Sub-command for sending build requests to a F-Droid BuildBot instance."""


import sys
import json
import uuid
import shlex
import shutil
import logging
import argparse
import traceback
import subprocess

from pathlib import Path

from fdroidserver import _, common, schedule_buildcycle


def send_to_buildbot(
    package_name,
    version_code,
    cycle_item=None,
    cycle_count=None,
    cycle_uuid=None,
    timeout=None,
):
    """Use `buildbot sendchange` to submit builds to the queue.

    This requires the automatically generated password to authenticate
    to the buildbot instance, which is created at a static path by the
    buildbot master:
    https://gitlab.com/fdroid/buildbot/-/merge_requests/1

    """
    bb_bin = shutil.which("buildbot")
    if not bb_bin:
        raise Exception("'buildbot' not found, make sure it's installed correctly")

    passwd_path = Path('/tmp/fdroid-buildbot-sendchange/passwd')
    if not passwd_path.is_file():
        raise FileNotFoundError(
            f"'{passwd_path}' not found (file is managed by fdroid buildbot master)"
        )
    passwd = passwd_path.read_text().strip()

    git_revision = str(
        subprocess.check_output(["git", "-C", ".", "describe", "--always"]),
        encoding="utf=8",
    ).strip()
    cmd = [
        bb_bin,
        "sendchange",
        "--master={}".format("127.0.0.1:9999"),
        "--auth=fdroid:{}".format(passwd),
        "--branch=master",
        "--repository='https://gitlab.com/fdroid/fdroiddata'",
        "--revision={}".format(git_revision),
        "--category=build",
        "--who={}:{}".format(package_name, version_code),
        "--project={}".format(package_name),
        "--property=versionCode:{}".format(version_code),
        "--property=packageName:{}".format(package_name),
        "--property=timeout:{}".format(
            timeout or schedule_buildcycle.DEFAULT_BUILD_TIMEOUT
        ),
    ]
    if cycle_item:
        cmd.append("--property=buildCycleItem:{}".format(cycle_item))
    if cycle_count:
        cmd.append("--property=buildCycleSize:{}".format(cycle_count))
    if cycle_uuid:
        cmd.append("--property=buildCycleUuid:{}".format(cycle_uuid))
    cmd.append("metadata/{}.yml".format(package_name))

    logging.info(f"sending buildbot build request for {package_name}:{version_code}")
    logging.debug(shlex.join(cmd))
    r = subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if r.returncode > 0:
        raise Exception(
            f"sending build request for '{package_name}:{version_code}' failed."
            f"\nstdout: {r.stdout}\nstderr: {r.stderr}"
        )


def send_buildcycle_wrapper(
    build_list=[], read_stdin=False, timeout=schedule_buildcycle.DEFAULT_BUILD_TIMEOUT
):
    if not read_stdin and len(build_list) <= 0:
        raise Exception(
            "you can not specify both APPID:VERCODE and -i at "
            "the sametime (see -h for help)"
        )

    # generate a random unique indentifier for this build cycle
    cycle_uuid = uuid.uuid4().hex

    if read_stdin:
        json_input = json.loads(sys.stdin.read())
        count = len(json_input)
        for i, appver in enumerate(json_input):
            send_to_buildbot(
                appver["applicationId"],
                appver["versionCode"],
                cycle_item=i + 1,
                cycle_count=count,
                cycle_uuid=cycle_uuid,
                timeout=appver["timeout"],
            )
    else:
        count = len(build_list)
        for i, (appid, vercode) in enumerate(build_list):
            # appid, vercode = appver
            send_to_buildbot(
                appid,
                vercode,
                cycle_item=i + 1,
                cycle_count=count,
                cycle_uuid=cycle_uuid,
                timeout=timeout,
            )


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description=_(
            "send change notifications to buildbot for kicking off app builds"
        ),
    )
    common.setup_global_opts(parser)
    parser.add_argument(
        '--stdin',
        "-i",
        default=False,
        action="store_true",
        help="read JSON schedule data from stdin. "
        "(typically created by `fdroid schedule_build`)",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=int,
        default=schedule_buildcycle.DEFAULT_BUILD_TIMEOUT,
        help="builds will get aborted when this time interval expires "
        "(in seconds, defaults to 2 hours; will be ignored when --stdin is specified)",
    )
    parser.add_argument(
        "APPID:VERCODE",
        nargs="*",
        help=_("app id and version code tuple 'APPID:VERCODE'"),
    )
    options = common.parse_args(parser)

    try:
        build_list = [
            common.split_pkg_arg(x) for x in options.__dict__['APPID:VERCODE']
        ]
        send_buildcycle_wrapper(
            build_list=build_list, read_stdin=options.stdin, timeout=options.timeout
        )
    except Exception as e:
        if options.verbose:
            logging.error(traceback.format_exc())
        else:
            logging.error(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
