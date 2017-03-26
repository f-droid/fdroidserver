#!/usr/bin/env python3
#
# vmtools.py - part of the FDroid server tools
# Copyright (C) 2017 Michael Poehn <michael.poehn@fsfe.org>
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

from os.path import isdir, isfile, join as joinpath, basename, abspath
import time
import shutil
import vagrant
import subprocess
from .common import FDroidException
from logging import getLogger

logger = getLogger('fdroidserver-vmtools')


def get_build_vm(srvdir, provider=None):
    """Factory function for getting FDroidBuildVm instances.

    This function tries to figure out what hypervisor should be used
    and creates an object for controlling a build VM.

    :param srvdir: path to a directory which contains a Vagrantfile
    :param provider: optionally this parameter allows specifiying an
        spesific vagrant provider.
    :returns: FDroidBuildVm instance.
    """
    abssrvdir = abspath(srvdir)
    if provider:
        if provider == 'libvirt':
            logger.debug('build vm provider \'libvirt\' selected')
            return LibvirtBuildVm(abssrvdir)
        elif provider == 'virtualbox':
            logger.debug('build vm provider \'virtualbox\' selected')
            return VirtualboxBuildVm(abssrvdir)
        else:
            logger.warn('build vm provider not supported: \'%s\'', provider)
    has_libvirt_machine = isdir(joinpath(abssrvdir, '.vagrant',
                                         'machines', 'default', 'libvirt'))
    has_vbox_machine = isdir(joinpath(abssrvdir, '.vagrant',
                                      'machines', 'default', 'libvirt'))
    if has_libvirt_machine and has_vbox_machine:
        logger.info('build vm provider lookup found virtualbox and libvirt, defaulting to \'virtualbox\'')
        return VirtualboxBuildVm(abssrvdir)
    elif has_libvirt_machine:
        logger.debug('build vm provider lookup found \'libvirt\'')
        return LibvirtBuildVm(abssrvdir)
    elif has_vbox_machine:
        logger.debug('build vm provider lookup found \'virtualbox\'')
        return VirtualboxBuildVm(abssrvdir)

    logger.info('build vm provider lookup could not determine provider, defaulting to \'virtualbox\'')
    return VirtualboxBuildVm(abssrvdir)


class FDroidBuildVmException(FDroidException):
    pass


class FDroidBuildVm():
    """Abstract base class for working with FDroids build-servers.

    Use the factory method `fdroidserver.vmtools.get_build_vm()` for
    getting correct instances of this class.

    This is intended to be a hypervisor independant, fault tolerant
    wrapper around the vagrant functions we use.
    """

    def __init__(self, srvdir):
        """Create new server class.
        """
        self.srvdir = srvdir
        self.srvname = basename(srvdir) + '_default'
        self.vgrntfile = joinpath(srvdir, 'Vagrantfile')
        if not isdir(srvdir):
            raise FDroidBuildVmException("Can not init vagrant, directory %s not present" % (srvdir))
        if not isfile(self.vgrntfile):
            raise FDroidBuildVmException("Can not init vagrant, '%s' not present" % (self.vgrntfile))
        self.vgrnt = vagrant.Vagrant(root=srvdir, out_cm=vagrant.stdout_cm, err_cm=vagrant.stdout_cm)

    def isUpAndRunning(self):
        raise NotImplementedError('TODO implement this')

    def up(self, provision=True):
        try:
            self.vgrnt.up(provision=provision)
        except subprocess.CalledProcessError as e:
            logger.info('could not bring vm up: %s', e)

    def destroy(self):
        """Remove every trace of this VM from the system.

        This includes deleting:
        * hypervisor specific definitions
        * vagrant state informations (eg. `.vagrant` folder)
        * images related to this vm
        """
        try:
            self.vgrnt.destroy()
            logger.debug('vagrant destroy completed')
        except subprocess.CalledProcessError as e:
            logger.debug('vagrant destroy failed: %s', e)
        vgrntdir = joinpath(self.srvdir, '.vagrant')
        try:
            shutil.rmtree(vgrntdir)
            logger.debug('deleted vagrant dir: %s', vgrntdir)
        except Exception as e:
            logger.debug("could not delete vagrant dir: %s, %s", vgrntdir, e)
        try:
            subprocess.check_call(['vagrant', 'global-status', '--prune'])
        except subprocess.CalledProcessError as e:
            logger.debug('pruning global vagrant status failed: %s', e)


class LibvirtBuildVm(FDroidBuildVm):
    def __init__(self, srvdir):
        super().__init__(srvdir)
        import libvirt

        try:
            self.conn = libvirt.open('qemu:///system')
        except libvirt.libvirtError as e:
            logger.critical('could not connect to libvirtd: %s', e)

    def destroy(self):

        super().destroy()

        # resorting to virsh instead of libvirt python bindings, because
        # this is way more easy and therefore fault tolerant.
        # (eg. lookupByName only works on running VMs)
        try:
            logger.debug('virsh -c qemu:///system destroy', self.srvname)
            subprocess.check_call(('virsh', '-c', 'qemu:///system', 'destroy'))
            logger.info("...waiting a sec...")
            time.sleep(10)
        except subprocess.CalledProcessError as e:
            logger.info("could not force libvirt domain '%s' off: %s", self.srvname, e)
        try:
            # libvirt python bindings do not support all flags required
            # for undefining domains correctly.
            logger.debug('virsh -c qemu:///system undefine %s --nvram --managed-save --remove-all-storage --snapshots-metadata', self.srvname)
            subprocess.check_call(('virsh', '-c', 'qemu:///system', 'undefine', self.srvname, '--nvram', '--managed-save', '--remove-all-storage', '--snapshots-metadata'))
            logger.info("...waiting a sec...")
            time.sleep(10)
        except subprocess.CalledProcessError as e:
            logger.info("could not undefine libvirt domain '%s': %s", self.srvname, e)


class VirtualboxBuildVm(FDroidBuildVm):
    pass
