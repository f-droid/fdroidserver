#!/usr/bin/env python3
#
# This script is some of the only documentation of certain processes
# that run in the buildserver setup.  It is not really maintained, but
# is still here as a kind of reference.

import os
import sys
import logging
import textwrap
import tempfile
import inspect
from argparse import ArgumentParser

localmodule = os.path.realpath(
    os.path.join(os.path.dirname(inspect.getfile(inspect.currentframe())), '..', '..'))
print('localmodule: ' + localmodule)
if localmodule not in sys.path:
    sys.path.insert(0, localmodule)

from fdroidserver.vmtools import get_build_vm


# pylint: disable=no-member
def main(args):

    if args.provider != None:
        if args.provider not in ('libvirt', 'virtualbox'):
            logging.critical('provider: %s not supported.', args.provider)
            sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdir:

        # define a simple vagrant vm 'x'
        x_dir = os.path.join(tmpdir, 'x')
        os.makedirs(x_dir)
        with open(os.path.join(x_dir, 'Vagrantfile'), 'w') as f:
            f.write(textwrap.dedent("""\
                Vagrant.configure("2") do |config|
                    config.vm.box = "debian/jessie64"
                    config.vm.synced_folder ".", "/vagrant", disabled: true
                    config.ssh.insert_key = false
                end
                """))
        # define another simple vagrant vm 'y' which uses 'x' as a base box
        y_dir = os.path.join(tmpdir, 'y')
        os.makedirs(y_dir)
        with open(os.path.join(y_dir, 'Vagrantfile'), 'w') as f:
            f.write(textwrap.dedent("""\
                Vagrant.configure("2") do |config|
                    config.vm.box = "x"
                    config.vm.synced_folder ".", "/vagrant", disabled: true
                end
                """))

        # vagrant file for packaging 'x' box
        vgrntf=textwrap.dedent("""\
            Vagrant.configure("2") do |config|

                config.vm.synced_folder ".", "/vagrant", type: "nfs", nfs_version: "4", nfs_udp: false

                config.vm.provider :libvirt do |libvirt|
                    libvirt.driver = "kvm"
                    libvirt.connect_via_ssh = false
                    libvirt.username = "root"
                    libvirt.storage_pool_name = "default"
                end
            end
            """)

        # create a box: x
        if not args.skip_create_x:
            x = get_build_vm(x_dir, provider=args.provider)
            x.destroy()
            x.up(provision=True)
            x.halt()
            x.package(output='x.box', vagrantfile=vgrntf, keep_box_file=False)
            x.box_remove('x')
            x.box_add('x', 'x.box')

        # use previously created box to spin up a new vm
        if not args.skip_create_y:
            y = get_build_vm(y_dir, provider=args.provider)
            y.destroy()
            y.up()

        # create and restore a snapshot
        if not args.skip_snapshot_y:
            y = get_build_vm(y_dir, provider=args.provider)

            if y.snapshot_exists('clean'):
                y.destroy()
                y.up()

            y.suspend()
            y.snapshot_create('clean')
            y.up()

            logging.info('snapshot \'clean\' exsists: %r', y.snapshot_exists('clean'))

            # test if snapshot exists
            se = y.snapshot_exists('clean')
            logging.info('snapshot \'clean\' available: %r', se)

            # revert snapshot
            y.suspend()
            logging.info('asdf %s', y.snapshot_revert('clean'))
            y.resume()

        # cleanup
        if not args.skip_clean:
            x = get_build_vm(x_dir, provider=args.provider)
            y = get_build_vm(y_dir, provider=args.provider)
            y.destroy()
            x.destroy()
            x.box_remove('x')

if __name__ == '__main__':
    logging.basicConfig(format='%(message)s', level=logging.DEBUG)

    parser = ArgumentParser(description="""\
This is intended for manually testing vmtools.py

NOTE: Should this test-run fail it might leave traces of vagrant VMs or boxes
      on your system. Those vagrant VMs are named 'x' and 'y'.
    """)
    parser.add_argument('--provider', help="Force this script use supplied "
                        "provider instead using our auto provider lookup. "
                        "Supported values: 'libvirt', 'virtualbox'")
    parser.add_argument('--skip-create-x', action="store_true", default=False,
                        help="Skips: Creating 'x' vm, packaging it into a "
                        "a box and adding it to vagrant.")
    parser.add_argument('--skip-create-y', action="store_true", default=False,
                        help="Skips: Creating 'y' vm. Depends on having "
                        "box 'x' added to vagrant.")
    parser.add_argument('--skip-snapshot-y', action="store_true", default=False,
                        help="Skips: Taking a snapshot and restoring a "
                        "a snapshot of 'y' vm. Requires 'y' mv to be "
                        "present.")
    parser.add_argument('--skip-clean', action="store_true", default=False,
                        help="Skips: Cleaning up mv images and vagrant "
                        "metadata on the system.")
    args = parser.parse_args()

    main(args)
