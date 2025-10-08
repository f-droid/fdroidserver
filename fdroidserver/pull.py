#!/usr/bin/env python3
#
# pull.py - part of the FDroid server tools
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

"""Pull a single file from the build setup for a given ApplicationID:versionCode.

This is a carefully constructed method to copy files from inside the
buildserver VM/container to the host filesystem for further processing
and publishing.  The source path is forced to the within the app's
build dir, and the destination is forced to the repo's unsigned/ dir.
This is not meant as a generic method for getting files, that is already
provided by each VM/container system (e.g. `podman cp`).

Since this is an internal command, the strings are not localized.

"""

import os
import sys
import logging
import subprocess
import tarfile
import tempfile
import traceback
from argparse import ArgumentParser

from . import common, metadata


def podman_pull(appid, vercode, path):
    """Implement `fdroid pull` for Podman (e.g. not `podman pull`)."""
    path_in_container = os.path.join(common.BUILD_HOME, path)
    container = common.get_podman_container(appid, vercode)
    stream, stat = container.get_archive(path_in_container)
    if not stat['linkTarget'].endswith(path) or stat['name'] != os.path.basename(path):
        logging.warning(f'{path} not found!')
        return
    with tempfile.NamedTemporaryFile(prefix=".fdroidserver_pull_", suffix=".tar") as tf:
        for i in stream:
            tf.write(i)
        tf.seek(0)
        with tarfile.TarFile(fileobj=tf, mode='r') as tar:
            tar.extract(stat['name'], 'unsigned', set_attrs=False)


def vagrant_pull(appid, vercode, path):
    """Pull the path from the Vagrant VM."""
    vagrantfile = common.get_vagrantfile_path(appid, vercode)
    path_in_vm = os.path.join(common.BUILD_HOME, path)

    vagrantbin = common.get_vagrant_bin_path()
    rsyncbin = common.get_rsync_bin_path()

    with common.TmpVagrantSshConf(vagrantbin, vagrantfile.parent) as ssh_config_file:
        cmd = [
            rsyncbin,
            '-av',
            '-e',
            f'ssh -F {ssh_config_file}',
            f'default:{path_in_vm}',
            './unsigned',
        ]
        subprocess.check_call(cmd)


def make_file_list(appid, vercode):
    app, build = metadata.get_single_build(appid, vercode)
    ext = common.get_output_extension(build)
    return [
        os.path.join('unsigned', common.get_release_filename(app, build, ext)),
        os.path.join(
            'unsigned', common.get_src_tarball_name(app.id, build.versionCode)
        ),
    ]


def pull_wrapper(appid, vercode, virt_container_type):
    os.makedirs('unsigned', exist_ok=True)
    files = make_file_list(appid, vercode)
    for f in files:
        logging.info(f"""Pulling {f} from {appid}:{vercode}""")
        if virt_container_type == 'vagrant':
            vagrant_pull(appid, vercode, f)
        elif virt_container_type == 'podman':
            podman_pull(appid, vercode, f)


def main():
    parser = ArgumentParser(
        description="Pull build products from the buildserver container/box."
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
        pull_wrapper(
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
