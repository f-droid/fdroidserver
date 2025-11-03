#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# schedule_verify.py - part of the FDroid server tools
# Copyright (C) 2024-2025, Hans-Christoph Steiner <hans@eds.org>
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

"""Schedule packages to build and verify.

This creates a list of Application ID/Version Code that need the
verify process to be run.

Since this is an internal command, the strings are not localized.

"""

import collections
import json
import logging
import os
import sys
import subprocess
from argparse import ArgumentParser
from pathlib import Path

from . import common, index, metadata


def get_versions(
    repo='https://f-droid.org/repo?fingerprint=43238D512C1E5EB2D6569F4A3AFBF5523418B82E0A3ED1552770ABB9A9C9CCAB',
):
    """Get the list of versions that need to be built, newest first.

    Newest are built first because older versions that are still not
    built are most likely to be failing builds.  Repeating failed
    builds mostly results in another failure.

    If there are versions with the same versionCode but different
    signers, there will still only be a single entry returned.  If the
    rebuild matches one signature, that is enough.

    """
    data, _ignored = index.download_repo_index_v2(repo)
    to_schedule = collections.defaultdict(list)
    for appid, package in data['packages'].items():
        for version in package['versions'].values():
            versionCode = version['manifest']['versionCode']
            ext = common.get_file_extension(version['file']['name'])
            jsonf = f'unsigned/{appid}_{versionCode}.{ext}.json'
            if not os.path.exists(jsonf):
                to_schedule[version['added']].append(
                    {'applicationId': appid, 'versionCode': versionCode}
                )

    ret = list()
    for added in sorted(to_schedule, reverse=True):
        for i in to_schedule[added]:
            if i not in ret:
                ret.append(i)
    return ret


def get_scheduled(versions):
    """Get versions that need to be built and there is local build metadata for it."""
    apps = metadata.read_metadata(sort_by_time=True, enabled_only=True)
    schedule = []
    for version in versions:
        app = apps.get(version['applicationId'])
        if app:
            for build in app.get("Builds", []):
                versionCode = build['versionCode']
                if versionCode == version['versionCode'] and not build.get("disable"):
                    schedule.append(
                        {
                            "applicationId": app.id,
                            "versionCode": versionCode,
                        }
                    )
    return schedule


def sendchange(scheduled, verbose=False):
    """Use `buildbot sendchange` to submit builds to the queue.

    This requires the automatically generated password to authenticate
    to the buildbot instance, which is created at a static path by the
    buildbot master:
    https://gitlab.com/fdroid/buildbot/-/merge_requests/1

    The passwd file's path is hardcoded in the server setup, which is
    defined outside of fdroidserver.  Think of the path as a variable
    name for accessing a value from the filesystem.

    """
    git_revision = common.get_head_commit_id('.')
    passwd = Path('/tmp/fdroid-buildbot-sendchange/passwd').read_text().strip()  # nosec
    for d in scheduled:
        command = [
            'buildbot',
            'sendchange',
            '--master=127.0.0.1:9999',
            f'--auth=fdroid:{passwd}',
            '--branch=master',
            '--repository=https://gitlab.com/fdroid/fdroiddata',
            f'--revision={git_revision}',
            '--category=verify',
            f"--who={d['applicationId']}",
            f"--project={d['applicationId']}",
            f"--property=versionCode:{d['versionCode']}",
            f"--property=packageName:{d['applicationId']}",
            f"metadata/{d['applicationId']}.yml",
        ]
        if verbose:
            logging.info(' '.join(command))
        subprocess.run(command, check=True)


def main():
    parser = ArgumentParser(description="Schedule packages to build and verify.")
    common.setup_global_opts(parser)
    parser.add_argument(
        "url",
        default='https://f-droid.org/repo?fingerprint=43238D512C1E5EB2D6569F4A3AFBF5523418B82E0A3ED1552770ABB9A9C9CCAB',
        nargs='?',
        help='Base URL to mirror, can include the index signing key using the query string: ?fingerprint=',
    )
    parser.add_argument(
        '--sendchange',
        action="store_true",
        help='Call buildbot sendchange with the results instead of printing to stdout.',
    )
    options = common.parse_args(parser)
    common.get_config()
    common.set_console_logging(options.verbose)

    # TODO support priority list, and ignore list (see buildbot-sendchange-build)
    if not os.path.exists('metadata'):
        logging.error("'metadata/' directory does not exist!")
        sys.exit(1)

    versions = get_versions(options.url)
    scheduled = get_scheduled(versions)

    if options.sendchange:
        sendchange(scheduled, options.verbose)
    else:
        print(json.dumps(scheduled))


if __name__ == "__main__":
    main()
