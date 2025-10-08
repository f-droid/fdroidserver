#!/usr/bin/env python3
#
# up.py - part of the FDroid server tools
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


"""Create dedicated VM/container to run single build, destroying any existing ones.

The ApplicationID:versionCode argument from the command line should be
used as the unique identifier.  This is necessary so that the other
related processes (push, pull, destroy) can find the dedicated
container/VM without there being any other database or file lookup.

Since this is an internal command, the strings are not localized.

"""

import logging
import sys
import textwrap
import traceback
from argparse import ArgumentParser

from . import common
from .exception import BuildException


def run_podman(appid, vercode):
    """Create a Podman container env isolated for a single app build.

    This creates a Podman "pod", which is like an isolated box to
    create containers in.  Then it creates a container in that pod to
    run the actual processes.  Using the "pod" seems to be a
    requirement of Podman.  It also further isolates each app build,
    so seems fine to use.  It is confusing because these containers
    won't show up by default when listing containers using defaults.

    The container is set up with an interactive bash process to keep
    the container running.

    """
    container_name = common.get_container_name(appid, vercode)
    pod_name = common.get_pod_name(appid, vercode)
    client = common.get_podman_client()

    logging.debug(f'Pulling {common.PODMAN_BUILDSERVER_IMAGE}...')
    image = client.images.pull(common.PODMAN_BUILDSERVER_IMAGE)

    for c in client.containers.list():
        if c.name == container_name:
            logging.warning(f'Container {container_name} exists, removing!')
            c.remove(force=True)

    for p in client.pods.list():
        if p.name == pod_name:
            logging.warning(f'Pod {pod_name} exists, removing!')
            p.remove(force=True)

    pod = client.pods.create(pod_name)
    container = client.containers.create(
        image,
        command=['/bin/bash', '-e', '-i', '-l'],
        pod=pod,
        name=container_name,
        detach=True,
        remove=True,
        stdin_open=True,
    )
    pod.start()
    pod.reload()
    if container.status != 'created':
        raise BuildException(
            f'Container {container_name} failed to start ({container.status})!'
        )


def run_vagrant(appid, vercode, cpus, memory):
    import vagrant

    if cpus is None or not isinstance(cpus, int) or not cpus > 0:
        raise BuildException(
            f"vagrant cpu setting required, '{cpus}' not a valid value!"
        )
    if memory is None or not isinstance(memory, int) or not memory > 0:
        raise BuildException(
            f"vagrant memory setting required, '{memory}' not a valid value!"
        )

    vagrantfile = common.get_vagrantfile_path(appid, vercode)

    # cleanup potentially still existsing vagrant VMs/dirs
    common.vagrant_destroy(appid, vercode)

    # start new dedicated buildserver vagrant vm from scratch
    vagrantfile.parent.mkdir(exist_ok=True, parents=True)
    vagrantfile.write_text(
        textwrap.dedent(
            f"""# generated file, do not change.

                Vagrant.configure("2") do |config|
                  config.vm.box = "buildserver"
                  config.vm.synced_folder ".", "/vagrant", disabled: true

                  config.vm.provider :libvirt do |libvirt|
                    libvirt.cpus = {cpus}
                    libvirt.memory = {memory}
                  end
                end
            """
        )
    )

    v = vagrant.Vagrant(vagrantfile.parent)

    if not any((b for b in v.box_list() if b.name == 'buildserver')):
        raise BuildException("'buildserver' box not added to vagrant")

    v.up()


def up_wrapper(appid, vercode, virt_container_type, cpus=None, memory=None):
    if virt_container_type == 'vagrant':
        run_vagrant(appid, vercode, cpus, memory)
    elif virt_container_type == 'podman':
        run_podman(appid, vercode)


def main():
    parser = ArgumentParser(
        description="Create dedicated VM/container to run single build."
    )
    common.setup_global_opts(parser)
    common.setup_virt_container_type_opts(parser)
    parser.add_argument(
        "APPID:VERCODE",
        help="Application ID with Version Code in the form APPID:VERCODE",
    )
    parser.add_argument(
        "--cpus",
        default=None,
        type=int,
        help="How many CPUs the Vagrant VM should be allocated.",
    )
    parser.add_argument(
        "--memory",
        default=None,
        type=int,
        help="How many MB of RAM the Vagrant VM should be allocated.",
    )
    options = common.parse_args(parser)
    common.set_console_logging(options.verbose)

    try:
        appid, vercode = common.split_pkg_arg(options.__dict__['APPID:VERCODE'])
        up_wrapper(
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
