#!/usr/bin/env python3
#
# schedule_buildcycle.py - part of the FDroid server tools
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


import os
import sys
import json
import time
import urllib
import logging
import argparse
import traceback

from fdroidserver import _, common, metadata

start_timestamp = time.gmtime()


# by default fdroid builds time out after 2 hours
# see: https://f-droid.org/en/docs/Build_Metadata_Reference/#build_timeout
DEFAULT_BUILD_TIMEOUT = 7200


def get_web_index(index_v2_url="https://f-droid.org/repo/index-v2.json"):
    with urllib.request.urlopen(index_v2_url) as response:
        raw = response.read().decode('utf-8')
        return json.loads(raw)


def published_apps(index_v2={}):
    return index_v2.get("packages", {}).keys()


def is_binary_artifact_present(appid, build):
    """Check if a build artifact/result form a previous run exists.

    Parameters
    ----------
    appid
        app id you're looking for (e.g. 'org.fdroid.fdroid')
    build
        metadata build object you're checking

    Returns
    -------
    True if a build artifact exists, otherwise False.
    """
    bin_dirs = ["archive", "repo", "unsigned"]
    ext = common.get_output_extension(build)

    for bin_dir in bin_dirs:
        if os.path.exists(f"./{bin_dir}/{appid}_{build.versionCode}.{ext}"):
            return True

    return False


def collect_schedule_entries(apps):
    """Get list of schedule entries for next build run.

    This function matches which builds in metadata are not built yet.

    Parameters
    ----------
    apps
        list of all metadata app objects of current repo

    Returns
    -------
    list of schedule entries
    """
    schedule = []
    for appid, app in apps.items():
        enabled = not app.get("Disabled")
        archived = app.get('ArchivePolicy') == 0
        if enabled and not archived:
            for build in app.get("Builds", {}):
                if not build.get("disable"):
                    if app.get("CurrentVersionCode") == build.get("versionCode"):
                        if not is_binary_artifact_present(appid, build):
                            schedule.append(
                                {
                                    "applicationId": appid,
                                    "versionCode": build.get("versionCode"),
                                    "timeout": int(
                                        build.get("timeout") or DEFAULT_BUILD_TIMEOUT
                                    ),
                                }
                            )
    return schedule


def schedule_buildcycle_wrapper(limit=None, offset=None, published_only=False):
    apps = metadata.read_metadata()

    if published_only:
        pub_apps = published_apps(index_v2=get_web_index())
        appids = [x for x in apps.keys()]
        for appid in appids:
            if appid not in pub_apps:
                del apps[appid]

    schedule = collect_schedule_entries(apps)

    if offset:
        schedule = schedule[offset:]
    if limit:
        schedule = schedule[:limit]

    return schedule


def main():
    parser = argparse.ArgumentParser(
        description=_("""print not yet built apps in JSON fromat to STDOUT"""),
    )
    parser.add_argument(
        "--pretty",
        '-p',
        action="store_true",
        default=False,
        help="pretty output formatting",
    )
    parser.add_argument(
        "--limit",
        "-l",
        type=int,
        help="limit the number of apps in output (e.g. if you wan to set "
        "a batch size)",
        default=None,
    )
    parser.add_argument(
        "--offset",
        "-o",
        type=int,
        help="offset the generated schedule (e.g. if you want to skip "
        "building the first couple of apps for a batch)",
        default=None,
    )
    parser.add_argument(
        "--published-only",
        action="store_true",
        default=False,
    )

    # fdroid args/opts boilerplate
    common.setup_global_opts(parser)
    options = common.parse_args(parser)
    common.get_config()  # set up for common functions
    status_output = common.setup_status_output(start_timestamp)
    common.write_running_status_json(status_output)

    error = False
    try:
        schedule = schedule_buildcycle_wrapper(
            limit=options.limit,
            offset=options.offset,
            published_only=options.published_only,
        )
        indent = 2 if options.pretty else None
        print(json.dumps(schedule, indent=indent))
    except Exception as e:
        if options.verbose:
            logging.error(traceback.format_exc())
        else:
            logging.error(e)
        error = True
        status_output['errors'] = [traceback.format_exc()]

    common.write_status_json(status_output)
    sys.exit(error)


if __name__ == "__main__":
    main()
