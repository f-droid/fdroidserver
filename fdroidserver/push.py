#!/usr/bin/env python3
#
# push.py - part of the FDroid server tools
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

"""Push files into the build setup for a given ApplicationID:versionCode.

This is a carefully constructed method to copy files from the host
filesystem to inside the buildserver VM/container to run the build.  The
source paths are generated based on the build metadata, and the
destination is forced to build home.  This is not meant as a generic
method for copying files, that is already provided by each VM/container
system (e.g. `podman cp`).

Since this is an internal command, the strings are not localized.

"""

import logging
import os
import subprocess
import sys
import tarfile
import tempfile
import traceback
from argparse import ArgumentParser
from pathlib import Path

from . import common, metadata
from .exception import BuildException


def podman_push(paths, appid, vercode, as_root=False):
    """Push relative paths into the podman container using the tar method.

    This builds up a tar file from the supplied paths to send into
    container via put_archive(). This assumes it is running in the
    base of fdroiddata and it will push into common.BUILD_HOME in the
    container.

    This is a version of podman.api.create_tar() that builds up via
    adding paths rather than giving a base dir and an exclude list.

    """

    def _tar_perms_filter(tarinfo):
        """Force perms to something safe."""
        if '__pycache__' in tarinfo.name:
            return

        if as_root:
            tarinfo.uid = tarinfo.gid = 0
            tarinfo.uname = tarinfo.gname = 'root'
        else:
            tarinfo.uid = tarinfo.gid = 1000
            tarinfo.uname = tarinfo.gname = common.BUILD_USER

        if tarinfo.isdir():
            tarinfo.mode = 0o0755
        elif tarinfo.isfile():
            if tarinfo.mode & 0o111:
                tarinfo.mode = 0o0755
            else:
                tarinfo.mode = 0o0644
        elif not tarinfo.issym():  # symlinks shouldn't need perms set
            raise BuildException(f'{tarinfo.name} is not a file or directory!')
        return tarinfo

    if isinstance(paths, Path):
        paths = [str(paths)]
    if isinstance(paths, str):
        paths = [paths]

    container = common.get_podman_container(appid, vercode)
    with tempfile.TemporaryFile() as tf:
        with tarfile.TarFile(fileobj=tf, mode='w') as tar:
            for f in paths:
                if Path(f).is_absolute():
                    raise BuildException(f'{f} must be relative to {Path.cwd()}')
                # throw ValueError on bad path
                f = (Path.cwd() / f).resolve().relative_to(Path.cwd())
                tar.add(f, filter=_tar_perms_filter)
        tf.seek(0)
        container.put_archive(common.BUILD_HOME, tf.read())


def vagrant_push(paths, appid, vercode):
    """Push files into a build specific vagrant VM."""
    vagrantbin = common.get_vagrant_bin_path()
    rsyncbin = common.get_rsync_bin_path()

    vagrantfile = common.get_vagrantfile_path(appid, vercode)
    with common.TmpVagrantSshConf(vagrantbin, vagrantfile.parent) as ssh_config_file:
        for path in paths:
            cmd = [
                rsyncbin,
                '-av',
                '--relative',
                '-e',
                f'ssh -F {ssh_config_file}',
                path,
                'default:{}'.format(common.BUILD_HOME),
            ]
            subprocess.check_call(
                cmd,
            )


# TODO split out shared code into _podman.py, _vagrant.py, etc


def push_wrapper(paths, appid, vercode, virt_container_type):
    """Push standard set of files into VM/container."""
    if virt_container_type == 'vagrant':
        vagrant_push(paths, appid, vercode)
    elif virt_container_type == 'podman':
        podman_push(paths, appid, vercode)


def make_file_list(appid, vercode):
    """Assemble list of files/folders that go into this specific build."""
    files = [f'build/{appid}', f'metadata/{appid}.yml']
    app_dir = f'metadata/{appid}'
    if Path(app_dir).exists():
        files.append(app_dir)
    app, build = metadata.get_single_build(appid, vercode)

    for lib in build.srclibs:
        srclib = common.getsrclib(lib, 'build/srclib', basepath=True, prepare=False)
        if srclib:
            # srclib metadata file
            files.append(f"srclibs/{srclib[0]}.yml")
            # srclib sourcecode
            files.append(srclib[2])

    extlib_paths = [f"build/extlib/{lib}" for lib in build.extlibs]
    missing_extlibs = [p for p in extlib_paths if not os.path.exists(p)]
    if any(missing_extlibs):
        raise Exception(
            "error: requested missing extlibs: {}".format(" ".join(missing_extlibs))
        )
    files.extend(extlib_paths)

    return files


def create_build_dirs(appid, vercode, virt_container_type):
    """Create directories required for running builds."""
    dirs = ('build', 'build/extlib', 'build/srclib', 'metadata', 'fdroidserver')
    for dir_name in dirs:
        cmd = ['mkdir', '--parents', f'{common.BUILD_HOME}/{dir_name}']
        common.inside_exec(
            appid,
            vercode,
            cmd,
            virt_container_type,
        )


def full_push_sequence(appid, vercode, virt_container_type):
    """Push all files into vm required for specified build."""
    create_build_dirs(appid, vercode, virt_container_type)
    push_wrapper(make_file_list(appid, vercode), appid, vercode, virt_container_type)

    # fdroidserver is pushed in every build
    cwd = Path('.').absolute()
    try:
        os.chdir(Path(__file__).parent.parent.parent)
        push_wrapper(
            [
                'fdroidserver/fdroidserver',
                'fdroidserver/fdroid',
            ],
            appid,
            vercode,
            virt_container_type,
        )
    finally:
        os.chdir(cwd)


def main():
    """CLI main method for this subcommand."""
    parser = ArgumentParser(
        description="Push full build setup into the buildserver container/box."
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
        full_push_sequence(
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
