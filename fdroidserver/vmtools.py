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

from os import remove as rmfile
from os.path import isdir, isfile, join as joinpath, basename, abspath, expanduser
import os
import math
import json
import tarfile
import time
import shutil
import subprocess
import textwrap
from .common import FDroidException
from logging import getLogger

logger = getLogger('fdroidserver-vmtools')


def get_clean_builder(serverdir, reset=False):
    if not os.path.isdir(serverdir):
        if os.path.islink(serverdir):
            os.unlink(serverdir)
        logger.info("buildserver path does not exists, creating %s", serverdir)
        os.makedirs(serverdir)
    vagrantfile = os.path.join(serverdir, 'Vagrantfile')
    if not os.path.isfile(vagrantfile):
        with open(os.path.join('builder', 'Vagrantfile'), 'w') as f:
            f.write(textwrap.dedent("""\
                # generated file, do not change.

                Vagrant.configure("2") do |config|
                    config.vm.box = "buildserver"
                    config.vm.synced_folder ".", "/vagrant", disabled: true
                end
                """))
    vm = get_build_vm(serverdir)
    if reset:
        logger.info('resetting buildserver by request')
    elif not vm.vagrant_uuid_okay():
        logger.info('resetting buildserver, bceause vagrant vm is not okay.')
        reset = True
    elif not vm.snapshot_exists('fdroidclean'):
        logger.info("resetting buildserver, because snapshot 'fdroidclean' is not present.")
        reset = True

    if reset:
        vm.destroy()
    vm.up()
    vm.suspend()

    if reset:
        logger.info('buildserver recreated: taking a clean snapshot')
        vm.snapshot_create('fdroidclean')
    else:
        logger.info('builserver ok: reverting to clean snapshot')
        vm.snapshot_revert('fdroidclean')
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


def _check_call(cmd, shell=False, cwd=None):
    logger.debug(' '.join(cmd))
    return subprocess.check_call(cmd, shell=shell, cwd=cwd)


def _check_output(cmd, shell=False, cwd=None):
    logger.debug(' '.join(cmd))
    return subprocess.check_output(cmd, shell=shell, cwd=cwd)


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

    # use supplied provider
    if provider:
        if provider == 'libvirt':
            logger.debug('build vm provider \'libvirt\' selected')
            return LibvirtBuildVm(abssrvdir)
        elif provider == 'virtualbox':
            logger.debug('build vm provider \'virtualbox\' selected')
            return VirtualboxBuildVm(abssrvdir)
        else:
            logger.warn('build vm provider not supported: \'%s\'', provider)

    # try guessing provider from installed software
    try:
        kvm_installed = 0 == _check_call(['which', 'kvm'])
    except subprocess.CalledProcessError:
        kvm_installed = False
        try:
            kvm_installed |= 0 == _check_call(['which', 'qemu'])
        except subprocess.CalledProcessError:
            pass
    try:
        vbox_installed = 0 == _check_call(['which', 'VBoxHeadless'])
    except subprocess.CalledProcessError:
        vbox_installed = False
    if kvm_installed and vbox_installed:
        logger.debug('both kvm and vbox are installed.')
    elif kvm_installed:
        logger.debug('libvirt is the sole installed and supported vagrant provider, selecting \'libvirt\'')
        return LibvirtBuildVm(abssrvdir)
    elif vbox_installed:
        logger.debug('virtualbox is the sole installed and supported vagrant provider, selecting \'virtualbox\'')
        return VirtualboxBuildVm(abssrvdir)
    else:
        logger.debug('could not confirm that either virtualbox or kvm/libvirt are installed')

    # try guessing provider from .../srvdir/.vagrant internals
    has_libvirt_machine = isdir(joinpath(abssrvdir, '.vagrant',
                                         'machines', 'default', 'libvirt'))
    has_vbox_machine = isdir(joinpath(abssrvdir, '.vagrant',
                                      'machines', 'default', 'virtualbox'))
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
        self.srvuuid = self._vagrant_fetch_uuid()
        if not isdir(srvdir):
            raise FDroidBuildVmException("Can not init vagrant, directory %s not present" % (srvdir))
        if not isfile(self.vgrntfile):
            raise FDroidBuildVmException("Can not init vagrant, '%s' not present" % (self.vgrntfile))
        import vagrant
        self.vgrnt = vagrant.Vagrant(root=srvdir, out_cm=vagrant.stdout_cm, err_cm=vagrant.stdout_cm)

    def up(self, provision=True):
        try:
            self.vgrnt.up(provision=provision)
            logger.info('...waiting a sec...')
            time.sleep(10)
            self.srvuuid = self._vagrant_fetch_uuid()
        except subprocess.CalledProcessError as e:
            raise FDroidBuildVmException("could not bring up vm '%s'" % self.srvname) from e

    def suspend(self):
        logger.info('suspending buildserver')
        try:
            self.vgrnt.suspend()
            logger.info('...waiting a sec...')
            time.sleep(10)
        except subprocess.CalledProcessError as e:
            raise FDroidBuildVmException("could not suspend vm '%s'" % self.srvname) from e

    def halt(self):
        self.vgrnt.halt(force=True)

    def destroy(self):
        """Remove every trace of this VM from the system.

        This includes deleting:
        * hypervisor specific definitions
        * vagrant state informations (eg. `.vagrant` folder)
        * images related to this vm
        """
        logger.info("destroying vm '%s'", self.srvname)
        try:
            self.vgrnt.destroy()
            logger.debug('vagrant destroy completed')
        except subprocess.CalledProcessError as e:
            logger.exception('vagrant destroy failed: %s', e)
        vgrntdir = joinpath(self.srvdir, '.vagrant')
        try:
            shutil.rmtree(vgrntdir)
            logger.debug('deleted vagrant dir: %s', vgrntdir)
        except Exception as e:
            logger.debug("could not delete vagrant dir: %s, %s", vgrntdir, e)
        try:
            _check_call(['vagrant', 'global-status', '--prune'])
        except subprocess.CalledProcessError as e:
            logger.debug('pruning global vagrant status failed: %s', e)

    def package(self, output=None):
        self.vgrnt.package(output=output)

    def vagrant_uuid_okay(self):
        '''Having an uuid means that vagrant up has run successfully.'''
        if self.srvuuid is None:
            return False
        return True

    def _vagrant_file_name(self, name):
        return name.replace('/', '-VAGRANTSLASH-')

    def _vagrant_fetch_uuid(self):
        if isfile(joinpath(self.srvdir, '.vagrant')):
            # Vagrant 1.0 - it's a json file...
            with open(joinpath(self.srvdir, '.vagrant')) as f:
                id = json.load(f)['active']['default']
                logger.debug('vm uuid: %s', id)
            return id
        elif isfile(joinpath(self.srvdir, '.vagrant', 'machines',
                             'default', self.provider, 'id')):
            # Vagrant 1.2 (and maybe 1.1?) it's a directory tree...
            with open(joinpath(self.srvdir, '.vagrant', 'machines',
                               'default', self.provider, 'id')) as f:
                id = f.read()
                logger.debug('vm uuid: %s', id)
            return id
        else:
            logger.debug('vm uuid is None')
            return None

    def box_add(self, boxname, boxfile, force=True):
        """Add vagrant box to vagrant.

        :param boxname: name assigned to local deployment of box
        :param boxfile: path to box file
        :param force: overwrite existing box image (default: True)
        """
        boxfile = abspath(boxfile)
        if not isfile(boxfile):
            raise FDroidBuildVmException('supplied boxfile \'%s\' does not exist', boxfile)
        self.vgrnt.box_add(boxname, abspath(boxfile), force=force)

    def box_remove(self, boxname):
        try:
            _check_call(['vagrant', 'box', 'remove', '--all', '--force', boxname])
        except subprocess.CalledProcessError as e:
            logger.debug('tried removing box %s, but is did not exist: %s', boxname, e)
        boxpath = joinpath(expanduser('~'), '.vagrant',
                           self._vagrant_file_name(boxname))
        if isdir(boxpath):
            logger.info("attempting to remove box '%s' by deleting: %s",
                        boxname, boxpath)
            shutil.rmtree(boxpath)

    def sshinfo(self):
        """Get ssh connection info for a vagrant VM

        :returns: A dictionary containing 'hostname', 'port', 'user'
            and 'idfile'
        """
        import paramiko
        try:
            _check_call(['vagrant ssh-config > sshconfig'],
                        cwd=self.srvdir, shell=True)
            vagranthost = 'default'  # Host in ssh config file
            sshconfig = paramiko.SSHConfig()
            with open(joinpath(self.srvdir, 'sshconfig'), 'r') as f:
                sshconfig.parse(f)
            sshconfig = sshconfig.lookup(vagranthost)
            idfile = sshconfig['identityfile']
            if isinstance(idfile, list):
                idfile = idfile[0]
            elif idfile.startswith('"') and idfile.endswith('"'):
                idfile = idfile[1:-1]
            return {'hostname': sshconfig['hostname'],
                    'port': int(sshconfig['port']),
                    'user': sshconfig['user'],
                    'idfile': idfile}
        except subprocess.CalledProcessError as e:
            raise FDroidBuildVmException("Error getting ssh config") from e

    def snapshot_create(self, snapshot_name):
        raise NotImplementedError('not implemented, please use a sub-type instance')

    def snapshot_list(self):
        raise NotImplementedError('not implemented, please use a sub-type instance')

    def snapshot_exists(self, snapshot_name):
        raise NotImplementedError('not implemented, please use a sub-type instance')

    def snapshot_revert(self, snapshot_name):
        raise NotImplementedError('not implemented, please use a sub-type instance')


class LibvirtBuildVm(FDroidBuildVm):
    def __init__(self, srvdir):
        self.provider = 'libvirt'
        super().__init__(srvdir)
        import libvirt

        try:
            self.conn = libvirt.open('qemu:///system')
        except libvirt.libvirtError as e:
            raise FDroidBuildVmException('could not connect to libvirtd: %s' % (e))

    def destroy(self):

        super().destroy()

        # resorting to virsh instead of libvirt python bindings, because
        # this is way more easy and therefore fault tolerant.
        # (eg. lookupByName only works on running VMs)
        try:
            _check_call(('virsh', '-c', 'qemu:///system', 'destroy', self.srvname))
            logger.info("...waiting a sec...")
            time.sleep(10)
        except subprocess.CalledProcessError as e:
            logger.info("could not force libvirt domain '%s' off: %s", self.srvname, e)
        try:
            # libvirt python bindings do not support all flags required
            # for undefining domains correctly.
            _check_call(('virsh', '-c', 'qemu:///system', 'undefine', self.srvname, '--nvram', '--managed-save', '--remove-all-storage', '--snapshots-metadata'))
            logger.info("...waiting a sec...")
            time.sleep(10)
        except subprocess.CalledProcessError as e:
            logger.info("could not undefine libvirt domain '%s': %s", self.srvname, e)

    def package(self, output=None, keep_box_file=False):
        if not output:
            output = "buildserver.box"
            logger.debug('no output name set for packaging \'%s\',' +
                         'defaulting to %s', self.srvname, output)
        storagePool = self.conn.storagePoolLookupByName('default')
        domainInfo = self.conn.lookupByName(self.srvname).info()
        if storagePool:

            if isfile('metadata.json'):
                rmfile('metadata.json')
            if isfile('Vagrantfile'):
                rmfile('Vagrantfile')
            if isfile('box.img'):
                rmfile('box.img')

            logger.debug('preparing box.img for box %s', output)
            vol = storagePool.storageVolLookupByName(self.srvname + '.img')
            imagepath = vol.path()
            # TODO use a libvirt storage pool to ensure the img file is readable
            _check_call(['sudo', '/bin/chmod', '-R', 'a+rX', '/var/lib/libvirt/images'])
            shutil.copy2(imagepath, 'box.img')
            _check_call(['qemu-img', 'rebase', '-p', '-b', '', 'box.img'])
            img_info_raw = _check_output(['qemu-img', 'info', '--output=json', 'box.img'])
            img_info = json.loads(img_info_raw.decode('utf-8'))
            metadata = {"provider": "libvirt",
                        "format": img_info['format'],
                        "virtual_size": math.ceil(img_info['virtual-size'] / (1024. ** 3)),
                        }

            logger.debug('preparing metadata.json for box %s', output)
            with open('metadata.json', 'w') as fp:
                fp.write(json.dumps(metadata))
            logger.debug('preparing Vagrantfile for box %s', output)
            vagrantfile = textwrap.dedent("""\
                  Vagrant.configure("2") do |config|
                    config.ssh.username = "vagrant"
                    config.ssh.password = "vagrant"

                    config.vm.provider :libvirt do |libvirt|

                      libvirt.driver = "kvm"
                      libvirt.host = ""
                      libvirt.connect_via_ssh = false
                      libvirt.storage_pool_name = "default"
                      libvirt.cpus = {cpus}
                      libvirt.memory = {memory}

                    end
                  end""".format_map({'memory': str(int(domainInfo[1] / 1024)), 'cpus': str(domainInfo[3])}))
            with open('Vagrantfile', 'w') as fp:
                fp.write(vagrantfile)
            with tarfile.open(output, 'w:gz') as tar:
                logger.debug('adding metadata.json to box %s ...', output)
                tar.add('metadata.json')
                logger.debug('adding Vagrantfile to box %s ...', output)
                tar.add('Vagrantfile')
                logger.debug('adding box.img to box %s ...', output)
                tar.add('box.img')

            if not keep_box_file:
                logger.debug('box packaging complete, removing temporary files.')
                rmfile('metadata.json')
                rmfile('Vagrantfile')
                rmfile('box.img')

        else:
            logger.warn('could not connect to storage-pool \'default\',' +
                        'skipping packaging buildserver box')

    def box_add(self, boxname, boxfile, force=True):
        boximg = '%s_vagrant_box_image_0.img' % (boxname)
        if force:
            try:
                _check_call(['virsh', '-c', 'qemu:///system', 'vol-delete', '--pool', 'default', boximg])
                logger.debug("removed old box image '%s' from libvirt storeage pool", boximg)
            except subprocess.CalledProcessError as e:
                logger.debug("tired removing old box image '%s', file was not present in first place", boximg, exc_info=e)
        super().box_add(boxname, boxfile, force)

    def box_remove(self, boxname):
        super().box_remove(boxname)
        try:
            _check_call(['virsh', '-c', 'qemu:///system', 'vol-delete', '--pool', 'default', '%s_vagrant_box_image_0.img' % (boxname)])
        except subprocess.CalledProcessError as e:
            logger.debug("tired removing '%s', file was not present in first place", boxname, exc_info=e)

    def snapshot_create(self, snapshot_name):
        logger.info("creating snapshot '%s' for vm '%s'", snapshot_name, self.srvname)
        try:
            _check_call(['virsh', '-c', 'qemu:///system', 'snapshot-create-as', self.srvname, snapshot_name])
            logger.info('...waiting a sec...')
            time.sleep(10)
        except subprocess.CalledProcessError as e:
            raise FDroidBuildVmException("could not cerate snapshot '%s' "
                                         "of libvirt vm '%s'"
                                         % (snapshot_name, self.srvname)) from e

    def snapshot_list(self):
        import libvirt
        try:
            dom = self.conn.lookupByName(self.srvname)
            return dom.listAllSnapshots()
        except libvirt.libvirtError as e:
            raise FDroidBuildVmException('could not list snapshots for domain \'%s\'' % self.srvname) from e

    def snapshot_exists(self, snapshot_name):
        import libvirt
        try:
            dom = self.conn.lookupByName(self.srvname)
            return dom.snapshotLookupByName(snapshot_name) is not None
        except libvirt.libvirtError:
            return False

    def snapshot_revert(self, snapshot_name):
        logger.info("reverting vm '%s' to snapshot '%s'", self.srvname, snapshot_name)
        import libvirt
        try:
            dom = self.conn.lookupByName(self.srvname)
            snap = dom.snapshotLookupByName(snapshot_name)
            dom.revertToSnapshot(snap)
            logger.info('...waiting a sec...')
            time.sleep(10)
        except libvirt.libvirtError as e:
            raise FDroidBuildVmException('could not revert domain \'%s\' to snapshot \'%s\''
                                         % (self.srvname, snapshot_name)) from e


class VirtualboxBuildVm(FDroidBuildVm):

    def __init__(self, srvdir):
        self.provider = 'virtualbox'
        super().__init__(srvdir)

    def snapshot_create(self, snapshot_name):
        logger.info("creating snapshot '%s' for vm '%s'", snapshot_name, self.srvname)
        try:
            _check_call(['VBoxManage', 'snapshot', self.srvuuid, 'take', 'fdroidclean'], cwd=self.srvdir)
            logger.info('...waiting a sec...')
            time.sleep(10)
        except subprocess.CalledProcessError as e:
            raise FDroidBuildVmException('could not cerate snapshot '
                                         'of virtualbox vm %s'
                                         % self.srvname) from e

    def snapshot_list(self):
        try:
            o = _check_output(['VBoxManage', 'snapshot',
                               self.srvuuid, 'list',
                               '--details'], cwd=self.srvdir)
            return o
        except subprocess.CalledProcessError as e:
            raise FDroidBuildVmException("could not list snapshots "
                                         "of virtualbox vm '%s'"
                                         % (self.srvname)) from e

    def snapshot_exists(self, snapshot_name):
        try:
            return str(snapshot_name) in str(self.snapshot_list())
        except FDroidBuildVmException:
            return False

    def snapshot_revert(self, snapshot_name):
        logger.info("reverting vm '%s' to snapshot '%s'",
                    self.srvname, snapshot_name)
        try:
            _check_call(['VBoxManage', 'snapshot', self.srvuuid,
                         'restore', 'fdroidclean'], cwd=self.srvdir)
        except subprocess.CalledProcessError as e:
            raise FDroidBuildVmException("could not load snapshot "
                                         "'fdroidclean' for vm '%s'"
                                         % (self.srvname)) from e
