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

from os.path import isdir, isfile, basename, abspath, expanduser
import os
import json
import shutil
import subprocess
import textwrap
import logging
from .common import FDroidException

import threading

lock = threading.Lock()


def get_clean_builder(serverdir):
    if not os.path.isdir(serverdir):
        if os.path.islink(serverdir):
            os.unlink(serverdir)
        logging.info("buildserver path does not exists, creating %s", serverdir)
        os.makedirs(serverdir)
    vagrantfile = os.path.join(serverdir, 'Vagrantfile')
    if not os.path.isfile(vagrantfile):
        with open(vagrantfile, 'w') as f:
            f.write(
                textwrap.dedent(
                    """\
                # generated file, do not change.

                Vagrant.configure("2") do |config|
                    config.vm.box = "buildserver"
                    config.vm.synced_folder ".", "/vagrant", disabled: true
                end
                """
                )
            )
    vm = get_build_vm(serverdir)
    logging.info('destroying buildserver before build')
    vm.destroy()
    logging.info('starting buildserver')
    vm.up()

    try:
        sshinfo = vm.sshinfo()
    except FDroidBuildVmException:
        # workaround because libvirt sometimes likes to forget
        # about ssh connection info even thou the vm is running
        vm.halt()
        vm.up()
        sshinfo = vm.sshinfo()

    return sshinfo


def _check_call(cmd, cwd=None):
    logging.debug(' '.join(cmd))
    return subprocess.check_call(cmd, shell=False, cwd=cwd)


def _check_output(cmd, cwd=None):
    logging.debug(' '.join(cmd))
    return subprocess.check_output(cmd, shell=False, cwd=cwd)


def get_build_vm(srvdir, provider=None):
    """No summary.

    Factory function for getting FDroidBuildVm instances.

    This function tries to figure out what hypervisor should be used
    and creates an object for controlling a build VM.

    Parameters
    ----------
    srvdir
      path to a directory which contains a Vagrantfile
    provider
      optionally this parameter allows specifiying an
      specific vagrant provider.

    Returns
    -------
    FDroidBuildVm instance.
    """
    abssrvdir = abspath(srvdir)

    # use supplied provider
    if provider:
        if provider == 'libvirt':
            logging.debug('build vm provider \'libvirt\' selected')
            return LibvirtBuildVm(abssrvdir)
        elif provider == 'virtualbox':
            logging.debug('build vm provider \'virtualbox\' selected')
            return VirtualboxBuildVm(abssrvdir)
        else:
            logging.warning('build vm provider not supported: \'%s\'', provider)

    # try guessing provider from installed software
    kvm_installed = shutil.which('kvm') is not None
    kvm_installed |= shutil.which('qemu') is not None
    kvm_installed |= shutil.which('qemu-kvm') is not None
    vbox_installed = shutil.which('VBoxHeadless') is not None
    if kvm_installed and vbox_installed:
        logging.debug('both kvm and vbox are installed.')
    elif kvm_installed:
        logging.debug(
            'libvirt is the sole installed and supported vagrant provider, selecting \'libvirt\''
        )
        return LibvirtBuildVm(abssrvdir)
    elif vbox_installed:
        logging.debug(
            'virtualbox is the sole installed and supported vagrant provider, selecting \'virtualbox\''
        )
        return VirtualboxBuildVm(abssrvdir)
    else:
        logging.debug(
            'could not confirm that either virtualbox or kvm/libvirt are installed'
        )

    # try guessing provider from .../srvdir/.vagrant internals
    vagrant_libvirt_path = os.path.join(
        abssrvdir, '.vagrant', 'machines', 'default', 'libvirt'
    )
    has_libvirt_machine = (
        isdir(vagrant_libvirt_path) and len(os.listdir(vagrant_libvirt_path)) > 0
    )
    vagrant_virtualbox_path = os.path.join(
        abssrvdir, '.vagrant', 'machines', 'default', 'virtualbox'
    )
    has_vbox_machine = (
        isdir(vagrant_virtualbox_path) and len(os.listdir(vagrant_virtualbox_path)) > 0
    )
    if has_libvirt_machine and has_vbox_machine:
        logging.info(
            'build vm provider lookup found virtualbox and libvirt, defaulting to \'virtualbox\''
        )
        return VirtualboxBuildVm(abssrvdir)
    elif has_libvirt_machine:
        logging.debug('build vm provider lookup found \'libvirt\'')
        return LibvirtBuildVm(abssrvdir)
    elif has_vbox_machine:
        logging.debug('build vm provider lookup found \'virtualbox\'')
        return VirtualboxBuildVm(abssrvdir)

    # try guessing provider from available buildserver boxes
    available_boxes = []
    import vagrant

    boxes = vagrant.Vagrant().box_list()
    for box in boxes:
        if box.name == "buildserver":
            available_boxes.append(box.provider)
    if "libvirt" in available_boxes and "virtualbox" in available_boxes:
        logging.info(
            'basebox lookup found virtualbox and libvirt boxes, defaulting to \'virtualbox\''
        )
        return VirtualboxBuildVm(abssrvdir)
    elif "libvirt" in available_boxes:
        logging.info('\'libvirt\' buildserver box available, using that')
        return LibvirtBuildVm(abssrvdir)
    elif "virtualbox" in available_boxes:
        logging.info('\'virtualbox\' buildserver box available, using that')
        return VirtualboxBuildVm(abssrvdir)
    else:
        logging.error('No available \'buildserver\' box. Cannot proceed')
        os._exit(1)


class FDroidBuildVmException(FDroidException):
    pass


class FDroidBuildVm:
    """Abstract base class for working with FDroids build-servers.

    Use the factory method `fdroidserver.vmtools.get_build_vm()` for
    getting correct instances of this class.

    This is intended to be a hypervisor independent, fault tolerant
    wrapper around the vagrant functions we use.
    """

    def __init__(self, srvdir, provider=None):
        """Create new server class."""
        self.provider = provider
        self.srvdir = srvdir
        self.srvname = basename(srvdir) + '_default'
        self.vgrntfile = os.path.join(srvdir, 'Vagrantfile')
        self.srvuuid = self._vagrant_fetch_uuid()
        if not isdir(srvdir):
            raise FDroidBuildVmException(
                "Can not init vagrant, directory %s not present" % (srvdir)
            )
        if not isfile(self.vgrntfile):
            raise FDroidBuildVmException(
                "Can not init vagrant, '%s' not present" % (self.vgrntfile)
            )
        import vagrant

        self.vgrnt = vagrant.Vagrant(
            root=srvdir, out_cm=vagrant.stdout_cm, err_cm=vagrant.stdout_cm
        )

    def up(self, provision=True):
        global lock
        with lock:
            try:
                self.vgrnt.up(provision=provision, provider=self.provider)
                self.srvuuid = self._vagrant_fetch_uuid()
            except subprocess.CalledProcessError as e:
                statusline = ""
                try:
                    # try to get some additional info about the vagrant vm
                    status = self.vgrnt.status()
                    if len(status) > 0:
                        statusline = "VM status: name={n}, state={s}, provider={p}"\
                            .format(n=status[0].name,
                                    s=status[0].state,
                                    p=status[0].provider)
                except subprocess.CalledProcessError:
                    pass
                raise FDroidBuildVmException(value="could not bring up vm '{vmname}'"
                                                   .format(vmname=self.srvname),
                                             detail="{err}\n{statline}"
                                                    .format(err=str(e), statline=statusline)
                                             ) from e

    def suspend(self):
        global lock
        with lock:
            logging.info('suspending buildserver')
            try:
                self.vgrnt.suspend()
            except subprocess.CalledProcessError as e:
                raise FDroidBuildVmException("could not suspend vm '%s'" % self.srvname) from e

    def halt(self):
        global lock
        with lock:
            self.vgrnt.halt(force=True)

    def destroy(self):
        """Remove every trace of this VM from the system.

        This includes deleting:
        * hypervisor specific definitions
        * vagrant state informations (eg. `.vagrant` folder)
        * images related to this vm
        """
        logging.info("destroying vm '%s'", self.srvname)
        try:
            self.vgrnt.destroy()
            logging.debug('vagrant destroy completed')
        except subprocess.CalledProcessError as e:
            logging.exception('vagrant destroy failed: %s', e)
        vgrntdir = os.path.join(self.srvdir, '.vagrant')
        try:
            shutil.rmtree(vgrntdir)
            logging.debug('deleted vagrant dir: %s', vgrntdir)
        except Exception as e:
            logging.debug("could not delete vagrant dir: %s, %s", vgrntdir, e)
        try:
            _check_call(['vagrant', 'global-status', '--prune'])
        except subprocess.CalledProcessError as e:
            logging.debug('pruning global vagrant status failed: %s', e)

    def vagrant_uuid_okay(self):
        """Having an uuid means that vagrant up has run successfully."""
        if self.srvuuid is None:
            return False
        return True

    def _vagrant_file_name(self, name):
        return name.replace('/', '-VAGRANTSLASH-')

    def _vagrant_fetch_uuid(self):
        if isfile(os.path.join(self.srvdir, '.vagrant')):
            # Vagrant 1.0 - it's a json file...
            with open(os.path.join(self.srvdir, '.vagrant')) as f:
                id = json.load(f)['active']['default']
                logging.debug('vm uuid: %s', id)
            return id
        elif isfile(os.path.join(self.srvdir, '.vagrant', 'machines',
                                 'default', self.provider, 'id')):
            # Vagrant 1.2 (and maybe 1.1?) it's a directory tree...
            with open(os.path.join(self.srvdir, '.vagrant', 'machines',
                                   'default', self.provider, 'id')) as f:
                id = f.read()
                logging.debug('vm uuid: %s', id)
            return id
        else:
            logging.debug('vm uuid is None')
            return None

    def box_add(self, boxname, boxfile, force=True):
        """Add vagrant box to vagrant.

        Parameters
        ----------
        boxname
          name assigned to local deployment of box
        boxfile
          path to box file
        force
          overwrite existing box image (default: True)
        """
        boxfile = abspath(boxfile)
        if not isfile(boxfile):
            raise FDroidBuildVmException(
                'supplied boxfile \'%s\' does not exist' % boxfile
            )
        self.vgrnt.box_add(boxname, abspath(boxfile), force=force)

    def box_remove(self, boxname):
        try:
            _check_call(['vagrant', 'box', 'remove', '--all', '--force', boxname])
        except subprocess.CalledProcessError as e:
            logging.debug('tried removing box %s, but is did not exist: %s', boxname, e)
        boxpath = os.path.join(
            expanduser('~'), '.vagrant', self._vagrant_file_name(boxname)
        )
        if isdir(boxpath):
            logging.info(
                "attempting to remove box '%s' by deleting: %s", boxname, boxpath
            )
            shutil.rmtree(boxpath)

    def sshinfo(self):
        """Get ssh connection info for a vagrant VM.

        Returns
        -------
        A dictionary containing 'hostname', 'port', 'user' and 'idfile'
        """
        import paramiko

        try:
            sshconfig_path = os.path.join(self.srvdir, 'sshconfig')
            with open(sshconfig_path, 'wb') as fp:
                fp.write(_check_output(['vagrant', 'ssh-config'], cwd=self.srvdir))
            vagranthost = 'default'  # Host in ssh config file
            sshconfig = paramiko.SSHConfig()
            with open(sshconfig_path, 'r') as f:
                sshconfig.parse(f)
            sshconfig = sshconfig.lookup(vagranthost)
            idfile = sshconfig['identityfile']
            if isinstance(idfile, list):
                idfile = idfile[0]
            elif idfile.startswith('"') and idfile.endswith('"'):
                idfile = idfile[1:-1]
            return {
                'hostname': sshconfig['hostname'],
                'port': int(sshconfig['port']),
                'user': sshconfig['user'],
                'idfile': idfile,
            }
        except subprocess.CalledProcessError as e:
            raise FDroidBuildVmException("Error getting ssh config") from e


class LibvirtBuildVm(FDroidBuildVm):
    def __init__(self, srvdir):
        super().__init__(srvdir, 'libvirt')
        import libvirt

        try:
            self.conn = libvirt.open('qemu:///system')
        except libvirt.libvirtError as e:
            raise FDroidBuildVmException('could not connect to libvirtd: %s' % (e)) from e

    def destroy(self):

        super().destroy()

        # resorting to virsh instead of libvirt python bindings, because
        # this is way more easy and therefore fault tolerant.
        # (eg. lookupByName only works on running VMs)
        try:
            _check_call(('virsh', '-c', 'qemu:///system', 'destroy', self.srvname))
        except subprocess.CalledProcessError as e:
            logging.info("could not force libvirt domain '%s' off: %s", self.srvname, e)
        try:
            # libvirt python bindings do not support all flags required
            # for undefining domains correctly.
            _check_call(('virsh', '-c', 'qemu:///system', 'undefine', self.srvname, '--nvram', '--managed-save', '--remove-all-storage', '--snapshots-metadata'))
        except subprocess.CalledProcessError as e:
            logging.info("could not undefine libvirt domain '%s': %s", self.srvname, e)

    def box_add(self, boxname, boxfile, force=True):
        boximg = '%s_vagrant_box_image_0.img' % (boxname)
        if force:
            try:
                _check_call(['virsh', '-c', 'qemu:///system', 'vol-delete', '--pool', 'default', boximg])
                logging.debug("removed old box image '%s'"
                              "from libvirt storeage pool", boximg)
            except subprocess.CalledProcessError as e:
                logging.debug("tried removing old box image '%s',"
                              "file was not present in first place",
                              boximg, exc_info=e)
        super().box_add(boxname, boxfile, force)

    def box_remove(self, boxname):
        super().box_remove(boxname)
        try:
            _check_call(['virsh', '-c', 'qemu:///system', 'vol-delete', '--pool', 'default', '%s_vagrant_box_image_0.img' % (boxname)])
        except subprocess.CalledProcessError as e:
            logging.debug("tried removing '%s', file was not present in first place", boxname, exc_info=e)


class VirtualboxBuildVm(FDroidBuildVm):

    def __init__(self, srvdir):
        super().__init__(srvdir, 'virtualbox')
