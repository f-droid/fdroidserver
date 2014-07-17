#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# build.py - part of the FDroid server tools
# Copyright (C) 2010-2014, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
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

import sys
import os
import shutil
import glob
import subprocess
import re
import tarfile
import traceback
import time
import json
from ConfigParser import ConfigParser
from optparse import OptionParser, OptionError
from distutils.version import LooseVersion
import logging

import common
import metadata
from common import FDroidException, BuildException, VCSException, FDroidPopen, SilentPopen

try:
    import paramiko
except ImportError:
    pass


def get_builder_vm_id():
    vd = os.path.join('builder', '.vagrant')
    if os.path.isdir(vd):
        # Vagrant 1.2 (and maybe 1.1?) it's a directory tree...
        with open(os.path.join(vd, 'machines', 'default',
                  'virtualbox', 'id')) as vf:
            id = vf.read()
        return id
    else:
        # Vagrant 1.0 - it's a json file...
        with open(os.path.join('builder', '.vagrant')) as vf:
            v = json.load(vf)
        return v['active']['default']


def got_valid_builder_vm():
    """Returns True if we have a valid-looking builder vm
    """
    if not os.path.exists(os.path.join('builder', 'Vagrantfile')):
        return False
    vd = os.path.join('builder', '.vagrant')
    if not os.path.exists(vd):
        return False
    if not os.path.isdir(vd):
        # Vagrant 1.0 - if the directory is there, it's valid...
        return True
    # Vagrant 1.2 - the directory can exist, but the id can be missing...
    if not os.path.exists(os.path.join(vd, 'machines', 'default',
                          'virtualbox', 'id')):
        return False
    return True


def vagrant(params, cwd=None, printout=False):
    """Run a vagrant command.

    :param: list of parameters to pass to vagrant
    :cwd: directory to run in, or None for current directory
    :returns: (ret, out) where ret is the return code, and out
               is the stdout (and stderr) from vagrant
    """
    p = FDroidPopen(['vagrant'] + params, cwd=cwd)
    return (p.returncode, p.output)


def get_vagrant_sshinfo():
    """Get ssh connection info for a vagrant VM

    :returns: A dictionary containing 'hostname', 'port', 'user'
        and 'idfile'
    """
    if subprocess.call('vagrant ssh-config >sshconfig',
                       cwd='builder', shell=True) != 0:
        raise BuildException("Error getting ssh config")
    vagranthost = 'default'  # Host in ssh config file
    sshconfig = paramiko.SSHConfig()
    sshf = open('builder/sshconfig', 'r')
    sshconfig.parse(sshf)
    sshf.close()
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


def get_clean_vm(reset=False):
    """Get a clean VM ready to do a buildserver build.

    This might involve creating and starting a new virtual machine from
    scratch, or it might be as simple (unless overridden by the reset
    parameter) as re-using a snapshot created previously.

    A BuildException will be raised if anything goes wrong.

    :reset: True to force creating from scratch.
    :returns: A dictionary containing 'hostname', 'port', 'user'
        and 'idfile'
    """
    # Reset existing builder machine to a clean state if possible.
    vm_ok = False
    if not reset:
        logging.info("Checking for valid existing build server")

        if got_valid_builder_vm():
            logging.info("...VM is present")
            p = FDroidPopen(['VBoxManage', 'snapshot',
                             get_builder_vm_id(), 'list',
                             '--details'], cwd='builder')
            if 'fdroidclean' in p.output:
                logging.info("...snapshot exists - resetting build server to "
                             "clean state")
                retcode, output = vagrant(['status'], cwd='builder')

                if 'running' in output:
                    logging.info("...suspending")
                    vagrant(['suspend'], cwd='builder')
                    logging.info("...waiting a sec...")
                    time.sleep(10)
                p = FDroidPopen(['VBoxManage', 'snapshot', get_builder_vm_id(),
                                 'restore', 'fdroidclean'],
                                cwd='builder')

                if p.returncode == 0:
                    logging.info("...reset to snapshot - server is valid")
                    retcode, output = vagrant(['up'], cwd='builder')
                    if retcode != 0:
                        raise BuildException("Failed to start build server")
                    logging.info("...waiting a sec...")
                    time.sleep(10)
                    sshinfo = get_vagrant_sshinfo()
                    vm_ok = True
                else:
                    logging.info("...failed to reset to snapshot")
            else:
                logging.info("...snapshot doesn't exist - "
                             "VBoxManage snapshot list:\n" + p.output)

    # If we can't use the existing machine for any reason, make a
    # new one from scratch.
    if not vm_ok:
        if os.path.exists('builder'):
            logging.info("Removing broken/incomplete/unwanted build server")
            vagrant(['destroy', '-f'], cwd='builder')
            shutil.rmtree('builder')
        os.mkdir('builder')

        p = subprocess.Popen('vagrant --version', shell=True,
                             stdout=subprocess.PIPE)
        vver = p.communicate()[0]
        if vver.startswith('Vagrant version 1.2'):
            with open('builder/Vagrantfile', 'w') as vf:
                vf.write('Vagrant.configure("2") do |config|\n')
                vf.write('config.vm.box = "buildserver"\n')
                vf.write('end\n')
        else:
            with open('builder/Vagrantfile', 'w') as vf:
                vf.write('Vagrant::Config.run do |config|\n')
                vf.write('config.vm.box = "buildserver"\n')
                vf.write('end\n')

        logging.info("Starting new build server")
        retcode, _ = vagrant(['up'], cwd='builder')
        if retcode != 0:
            raise BuildException("Failed to start build server")

        # Open SSH connection to make sure it's working and ready...
        logging.info("Connecting to virtual machine...")
        sshinfo = get_vagrant_sshinfo()
        sshs = paramiko.SSHClient()
        sshs.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sshs.connect(sshinfo['hostname'], username=sshinfo['user'],
                     port=sshinfo['port'], timeout=300,
                     look_for_keys=False,
                     key_filename=sshinfo['idfile'])
        sshs.close()

        logging.info("Saving clean state of new build server")
        retcode, _ = vagrant(['suspend'], cwd='builder')
        if retcode != 0:
            raise BuildException("Failed to suspend build server")
        logging.info("...waiting a sec...")
        time.sleep(10)
        p = FDroidPopen(['VBoxManage', 'snapshot', get_builder_vm_id(),
                         'take', 'fdroidclean'],
                        cwd='builder')
        if p.returncode != 0:
            raise BuildException("Failed to take snapshot")
        logging.info("...waiting a sec...")
        time.sleep(10)
        logging.info("Restarting new build server")
        retcode, _ = vagrant(['up'], cwd='builder')
        if retcode != 0:
            raise BuildException("Failed to start build server")
        logging.info("...waiting a sec...")
        time.sleep(10)
        # Make sure it worked...
        p = FDroidPopen(['VBoxManage', 'snapshot', get_builder_vm_id(),
                         'list', '--details'],
                        cwd='builder')
        if 'fdroidclean' not in p.output:
            raise BuildException("Failed to take snapshot.")

    return sshinfo


def release_vm():
    """Release the VM previously started with get_clean_vm().

    This should always be called.
    """
    logging.info("Suspending build server")
    subprocess.call(['vagrant', 'suspend'], cwd='builder')


# Note that 'force' here also implies test mode.
def build_server(app, thisbuild, vcs, build_dir, output_dir, force):
    """Do a build on the build server."""

    try:
        paramiko
    except NameError:
        raise BuildException("Paramiko is required to use the buildserver")
    if options.verbose:
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARN)

    sshinfo = get_clean_vm()

    try:

        # Open SSH connection...
        logging.info("Connecting to virtual machine...")
        sshs = paramiko.SSHClient()
        sshs.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        sshs.connect(sshinfo['hostname'], username=sshinfo['user'],
                     port=sshinfo['port'], timeout=300,
                     look_for_keys=False, key_filename=sshinfo['idfile'])

        homedir = '/home/' + sshinfo['user']

        # Get an SFTP connection...
        ftp = sshs.open_sftp()
        ftp.get_channel().settimeout(15)

        # Put all the necessary files in place...
        ftp.chdir(homedir)

        # Helper to copy the contents of a directory to the server...
        def send_dir(path):
            root = os.path.dirname(path)
            main = os.path.basename(path)
            ftp.mkdir(main)
            for r, d, f in os.walk(path):
                rr = os.path.relpath(r, root)
                ftp.chdir(rr)
                for dd in d:
                    ftp.mkdir(dd)
                for ff in f:
                    lfile = os.path.join(root, rr, ff)
                    if not os.path.islink(lfile):
                        ftp.put(lfile, ff)
                        ftp.chmod(ff, os.stat(lfile).st_mode)
                for i in range(len(rr.split('/'))):
                    ftp.chdir('..')
            ftp.chdir('..')

        logging.info("Preparing server for build...")
        serverpath = os.path.abspath(os.path.dirname(__file__))
        ftp.put(os.path.join(serverpath, 'build.py'), 'build.py')
        ftp.put(os.path.join(serverpath, 'common.py'), 'common.py')
        ftp.put(os.path.join(serverpath, 'metadata.py'), 'metadata.py')
        ftp.put(os.path.join(serverpath, '..', 'buildserver',
                'config.buildserver.py'), 'config.py')
        ftp.chmod('config.py', 0o600)

        # Copy over the ID (head commit hash) of the fdroidserver in use...
        subprocess.call('git rev-parse HEAD >' +
                        os.path.join(os.getcwd(), 'tmp', 'fdroidserverid'),
                        shell=True, cwd=serverpath)
        ftp.put('tmp/fdroidserverid', 'fdroidserverid')

        # Copy the metadata - just the file for this app...
        ftp.mkdir('metadata')
        ftp.mkdir('srclibs')
        ftp.chdir('metadata')
        ftp.put(os.path.join('metadata', app['id'] + '.txt'),
                app['id'] + '.txt')
        # And patches if there are any...
        if os.path.exists(os.path.join('metadata', app['id'])):
            send_dir(os.path.join('metadata', app['id']))

        ftp.chdir(homedir)
        # Create the build directory...
        ftp.mkdir('build')
        ftp.chdir('build')
        ftp.mkdir('extlib')
        ftp.mkdir('srclib')
        # Copy any extlibs that are required...
        if thisbuild['extlibs']:
            ftp.chdir(homedir + '/build/extlib')
            for lib in thisbuild['extlibs']:
                lib = lib.strip()
                libsrc = os.path.join('build/extlib', lib)
                if not os.path.exists(libsrc):
                    raise BuildException("Missing extlib {0}".format(libsrc))
                lp = lib.split('/')
                for d in lp[:-1]:
                    if d not in ftp.listdir():
                        ftp.mkdir(d)
                    ftp.chdir(d)
                ftp.put(libsrc, lp[-1])
                for _ in lp[:-1]:
                    ftp.chdir('..')
        # Copy any srclibs that are required...
        srclibpaths = []
        if thisbuild['srclibs']:
            for lib in thisbuild['srclibs']:
                srclibpaths.append(
                    common.getsrclib(lib, 'build/srclib', srclibpaths,
                                     basepath=True, prepare=False))

        # If one was used for the main source, add that too.
        basesrclib = vcs.getsrclib()
        if basesrclib:
            srclibpaths.append(basesrclib)
        for name, number, lib in srclibpaths:
            logging.info("Sending srclib '%s'" % lib)
            ftp.chdir(homedir + '/build/srclib')
            if not os.path.exists(lib):
                raise BuildException("Missing srclib directory '" + lib + "'")
            fv = '.fdroidvcs-' + name
            ftp.put(os.path.join('build/srclib', fv), fv)
            send_dir(lib)
            # Copy the metadata file too...
            ftp.chdir(homedir + '/srclibs')
            ftp.put(os.path.join('srclibs', name + '.txt'),
                    name + '.txt')
        # Copy the main app source code
        # (no need if it's a srclib)
        if (not basesrclib) and os.path.exists(build_dir):
            ftp.chdir(homedir + '/build')
            fv = '.fdroidvcs-' + app['id']
            ftp.put(os.path.join('build', fv), fv)
            send_dir(build_dir)

        # Execute the build script...
        logging.info("Starting build...")
        chan = sshs.get_transport().open_session()
        chan.get_pty()
        cmdline = 'python build.py --on-server'
        if force:
            cmdline += ' --force --test'
        if options.verbose:
            cmdline += ' --verbose'
        cmdline += " %s:%s" % (app['id'], thisbuild['vercode'])
        chan.exec_command('bash -c ". ~/.bsenv && ' + cmdline + '"')
        output = ''
        while not chan.exit_status_ready():
            while chan.recv_ready():
                output += chan.recv(1024)
            time.sleep(0.1)
        logging.info("...getting exit status")
        returncode = chan.recv_exit_status()
        while True:
            get = chan.recv(1024)
            if len(get) == 0:
                break
            output += get
        if returncode != 0:
            raise BuildException(
                "Build.py failed on server for {0}:{1}".format(
                    app['id'], thisbuild['version']), output)

        # Retrieve the built files...
        logging.info("Retrieving build output...")
        if force:
            ftp.chdir(homedir + '/tmp')
        else:
            ftp.chdir(homedir + '/unsigned')
        apkfile = common.getapkname(app, thisbuild)
        tarball = common.getsrcname(app, thisbuild)
        try:
            ftp.get(apkfile, os.path.join(output_dir, apkfile))
            if not options.notarball:
                ftp.get(tarball, os.path.join(output_dir, tarball))
        except:
            raise BuildException(
                "Build failed for %s:%s - missing output files".format(
                    app['id'], thisbuild['version']), output)
        ftp.close()

    finally:

        # Suspend the build server.
        release_vm()


def adapt_gradle(build_dir):
    for root, dirs, files in os.walk(build_dir):
        if 'build.gradle' in files:
            path = os.path.join(root, 'build.gradle')
            logging.debug("Adapting build.gradle at %s" % path)

            FDroidPopen(['sed', '-i',
                         r's@buildToolsVersion\([ =]*\)["\'][0-9\.]*["\']@buildToolsVersion\1"'
                         + config['build_tools'] + '"@g', path])


def build_local(app, thisbuild, vcs, build_dir, output_dir, srclib_dir, extlib_dir, tmp_dir, force, onserver):
    """Do a build locally."""

    if thisbuild['buildjni'] and thisbuild['buildjni'] != ['no']:
        if not config['ndk_path']:
            logging.critical("$ANDROID_NDK is not set!")
            sys.exit(3)
        elif not os.path.isdir(config['sdk_path']):
            logging.critical("$ANDROID_NDK points to a non-existing directory!")
            sys.exit(3)

    # Prepare the source code...
    root_dir, srclibpaths = common.prepare_source(vcs, app, thisbuild,
                                                  build_dir, srclib_dir,
                                                  extlib_dir, onserver)

    # We need to clean via the build tool in case the binary dirs are
    # different from the default ones
    p = None
    if thisbuild['type'] == 'maven':
        logging.info("Cleaning Maven project...")
        cmd = [config['mvn3'], 'clean', '-Dandroid.sdk.path=' + config['sdk_path']]

        if '@' in thisbuild['maven']:
            maven_dir = os.path.join(root_dir, thisbuild['maven'].split('@', 1)[1])
            maven_dir = os.path.normpath(maven_dir)
        else:
            maven_dir = root_dir

        p = FDroidPopen(cmd, cwd=maven_dir)

    elif thisbuild['type'] == 'gradle':

        logging.info("Cleaning Gradle project...")
        cmd = [config['gradle'], 'clean']

        adapt_gradle(build_dir)
        for name, number, libpath in srclibpaths:
            adapt_gradle(libpath)

        p = FDroidPopen(cmd, cwd=root_dir)

    elif thisbuild['type'] == 'kivy':
        pass

    elif thisbuild['type'] == 'ant':
        logging.info("Cleaning Ant project...")
        p = FDroidPopen(['ant', 'clean'], cwd=root_dir)

    if p is not None and p.returncode != 0:
        raise BuildException("Error cleaning %s:%s" %
                             (app['id'], thisbuild['version']), p.output)

    for root, dirs, files in os.walk(build_dir):
        # Don't remove possibly necessary 'gradle' dirs if 'gradlew' is not there
        if 'gradlew' in files:
            logging.debug("Getting rid of Gradle wrapper stuff in %s" % root)
            os.remove(os.path.join(root, 'gradlew'))
            if 'gradlew.bat' in files:
                os.remove(os.path.join(root, 'gradlew.bat'))
            if 'gradle' in dirs:
                shutil.rmtree(os.path.join(root, 'gradle'))

    if not options.skipscan:
        # Scan before building...
        logging.info("Scanning source for common problems...")
        count = common.scan_source(build_dir, root_dir, thisbuild)
        if count > 0:
            if force:
                logging.warn('Scanner found %d problems:' % count)
            else:
                raise BuildException("Can't build due to %d errors while scanning" % count)

    if not options.notarball:
        # Build the source tarball right before we build the release...
        logging.info("Creating source tarball...")
        tarname = common.getsrcname(app, thisbuild)
        tarball = tarfile.open(os.path.join(tmp_dir, tarname), "w:gz")

        def tarexc(f):
            return any(f.endswith(s) for s in ['.svn', '.git', '.hg', '.bzr'])
        tarball.add(build_dir, tarname, exclude=tarexc)
        tarball.close()

    if onserver:
        manifest = os.path.join(root_dir, 'AndroidManifest.xml')
        if os.path.exists(manifest):
            homedir = os.path.expanduser('~')
            with open(os.path.join(homedir, 'buildserverid'), 'r') as f:
                buildserverid = f.read()
            with open(os.path.join(homedir, 'fdroidserverid'), 'r') as f:
                fdroidserverid = f.read()
            with open(manifest, 'r') as f:
                manifestcontent = f.read()
            manifestcontent = manifestcontent.replace('</manifest>',
                                                      '<fdroid buildserverid="'
                                                      + buildserverid + '"'
                                                      + ' fdroidserverid="'
                                                      + fdroidserverid + '"'
                                                      + '/></manifest>')
            with open(manifest, 'w') as f:
                f.write(manifestcontent)

    # Run a build command if one is required...
    if thisbuild['build']:
        logging.info("Running 'build' commands in %s" % root_dir)
        cmd = common.replace_config_vars(thisbuild['build'])

        # Substitute source library paths into commands...
        for name, number, libpath in srclibpaths:
            libpath = os.path.relpath(libpath, root_dir)
            cmd = cmd.replace('$$' + name + '$$', libpath)

        p = FDroidPopen(['bash', '-x', '-c', cmd], cwd=root_dir)

        if p.returncode != 0:
            raise BuildException("Error running build command for %s:%s" %
                                 (app['id'], thisbuild['version']), p.output)

    # Build native stuff if required...
    if thisbuild['buildjni'] and thisbuild['buildjni'] != ['no']:
        logging.info("Building the native code")
        jni_components = thisbuild['buildjni']

        if jni_components == ['yes']:
            jni_components = ['']
        cmd = [os.path.join(config['ndk_path'], "ndk-build"), "-j1"]
        for d in jni_components:
            if d:
                logging.info("Building native code in '%s'" % d)
            else:
                logging.info("Building native code in the main project")
            manifest = root_dir + '/' + d + '/AndroidManifest.xml'
            if os.path.exists(manifest):
                # Read and write the whole AM.xml to fix newlines and avoid
                # the ndk r8c or later 'wordlist' errors. The outcome of this
                # under gnu/linux is the same as when using tools like
                # dos2unix, but the native python way is faster and will
                # work in non-unix systems.
                manifest_text = open(manifest, 'U').read()
                open(manifest, 'w').write(manifest_text)
                # In case the AM.xml read was big, free the memory
                del manifest_text
            p = FDroidPopen(cmd, cwd=os.path.join(root_dir, d))
            if p.returncode != 0:
                raise BuildException("NDK build failed for %s:%s" % (app['id'], thisbuild['version']), p.output)

    p = None
    # Build the release...
    if thisbuild['type'] == 'maven':
        logging.info("Building Maven project...")

        if '@' in thisbuild['maven']:
            maven_dir = os.path.join(root_dir, thisbuild['maven'].split('@', 1)[1])
        else:
            maven_dir = root_dir

        mvncmd = [config['mvn3'], '-Dandroid.sdk.path=' + config['sdk_path'],
                  '-Dmaven.jar.sign.skip=true', '-Dmaven.test.skip=true',
                  '-Dandroid.sign.debug=false', '-Dandroid.release=true',
                  'package']
        if thisbuild['target']:
            target = thisbuild["target"].split('-')[1]
            FDroidPopen(['sed', '-i',
                         's@<platform>[0-9]*</platform>@<platform>'
                         + target + '</platform>@g',
                         'pom.xml'],
                        cwd=root_dir)
            if '@' in thisbuild['maven']:
                FDroidPopen(['sed', '-i',
                             's@<platform>[0-9]*</platform>@<platform>'
                             + target + '</platform>@g',
                             'pom.xml'],
                            cwd=maven_dir)

        p = FDroidPopen(mvncmd, cwd=maven_dir)

        bindir = os.path.join(root_dir, 'target')

    elif thisbuild['type'] == 'kivy':
        logging.info("Building Kivy project...")

        spec = os.path.join(root_dir, 'buildozer.spec')
        if not os.path.exists(spec):
            raise BuildException("Expected to find buildozer-compatible spec at {0}"
                                 .format(spec))

        defaults = {'orientation': 'landscape', 'icon': '',
                    'permissions': '', 'android.api': "18"}
        bconfig = ConfigParser(defaults, allow_no_value=True)
        bconfig.read(spec)

        distdir = 'python-for-android/dist/fdroid'
        if os.path.exists(distdir):
            shutil.rmtree(distdir)

        modules = bconfig.get('app', 'requirements').split(',')

        cmd = 'ANDROIDSDK=' + config['sdk_path']
        cmd += ' ANDROIDNDK=' + config['ndk_path']
        cmd += ' ANDROIDNDKVER=r9'
        cmd += ' ANDROIDAPI=' + str(bconfig.get('app', 'android.api'))
        cmd += ' VIRTUALENV=virtualenv'
        cmd += ' ./distribute.sh'
        cmd += ' -m ' + "'" + ' '.join(modules) + "'"
        cmd += ' -d fdroid'
        p = FDroidPopen(cmd, cwd='python-for-android', shell=True)
        if p.returncode != 0:
            raise BuildException("Distribute build failed")

        cid = bconfig.get('app', 'package.domain') + '.' + bconfig.get('app', 'package.name')
        if cid != app['id']:
            raise BuildException("Package ID mismatch between metadata and spec")

        orientation = bconfig.get('app', 'orientation', 'landscape')
        if orientation == 'all':
            orientation = 'sensor'

        cmd = ['./build.py'
               '--dir', root_dir,
               '--name', bconfig.get('app', 'title'),
               '--package', app['id'],
               '--version', bconfig.get('app', 'version'),
               '--orientation', orientation
               ]

        perms = bconfig.get('app', 'permissions')
        for perm in perms.split(','):
            cmd.extend(['--permission', perm])

        if config.get('app', 'fullscreen') == 0:
            cmd.append('--window')

        icon = bconfig.get('app', 'icon.filename')
        if icon:
            cmd.extend(['--icon', os.path.join(root_dir, icon)])

        cmd.append('release')
        p = FDroidPopen(cmd, cwd=distdir)

    elif thisbuild['type'] == 'gradle':
        logging.info("Building Gradle project...")
        flavours = thisbuild['gradle'].split(',')

        if len(flavours) == 1 and flavours[0] in ['main', 'yes', '']:
            flavours[0] = ''

        commands = [config['gradle']]
        if thisbuild['preassemble']:
            commands += thisbuild['preassemble'].split()

        flavours_cmd = ''.join(flavours)
        if flavours_cmd:
            flavours_cmd = flavours_cmd[0].upper() + flavours_cmd[1:]

        commands += ['assemble' + flavours_cmd + 'Release']

        # Avoid having to use lintOptions.abortOnError false
        if thisbuild['gradlepluginver'] >= LooseVersion('0.7'):
            with open(os.path.join(root_dir, 'build.gradle'), "a") as f:
                f.write("\nandroid { lintOptions { checkReleaseBuilds false } }\n")

        p = FDroidPopen(commands, cwd=root_dir)

    elif thisbuild['type'] == 'ant':
        logging.info("Building Ant project...")
        cmd = ['ant']
        if thisbuild['antcommand']:
            cmd += [thisbuild['antcommand']]
        else:
            cmd += ['release']
        p = FDroidPopen(cmd, cwd=root_dir)

        bindir = os.path.join(root_dir, 'bin')

    if p is not None and p.returncode != 0:
        raise BuildException("Build failed for %s:%s" % (app['id'], thisbuild['version']), p.output)
    logging.info("Successfully built version " + thisbuild['version'] + ' of ' + app['id'])

    if thisbuild['type'] == 'maven':
        stdout_apk = '\n'.join([
            line for line in p.output.splitlines() if any(a in line for a in ('.apk', '.ap_'))])
        m = re.match(r".*^\[INFO\] .*apkbuilder.*/([^/]*)\.apk",
                     stdout_apk, re.S | re.M)
        if not m:
            m = re.match(r".*^\[INFO\] Creating additional unsigned apk file .*/([^/]+)\.apk[^l]",
                         stdout_apk, re.S | re.M)
        if not m:
            m = re.match(r'.*^\[INFO\] [^$]*aapt \[package,[^$]*' + bindir + r'/([^/]+)\.ap[_k][,\]]',
                         stdout_apk, re.S | re.M)
        if not m:
            raise BuildException('Failed to find output')
        src = m.group(1)
        src = os.path.join(bindir, src) + '.apk'
    elif thisbuild['type'] == 'kivy':
        src = 'python-for-android/dist/default/bin/{0}-{1}-release.apk'.format(
            bconfig.get('app', 'title'), bconfig.get('app', 'version'))
    elif thisbuild['type'] == 'gradle':

        if thisbuild['gradlepluginver'] >= LooseVersion('0.11'):
            apks_dir = os.path.join(root_dir, 'build', 'outputs', 'apk')
        else:
            apks_dir = os.path.join(root_dir, 'build', 'apk')

        apks = glob.glob(os.path.join(apks_dir, '*-release-unsigned.apk'))
        if len(apks) > 1:
            raise BuildException('More than one resulting apks found in %s' % apks_dir,
                                 '\n'.join(apks))
        if len(apks) < 1:
            raise BuildException('Failed to find gradle output in %s' % apks_dir)
        src = apks[0]
    elif thisbuild['type'] == 'ant':
        stdout_apk = '\n'.join([
            line for line in p.output.splitlines() if '.apk' in line])
        src = re.match(r".*^.*Creating (.+) for release.*$.*", stdout_apk,
                       re.S | re.M).group(1)
        src = os.path.join(bindir, src)
    elif thisbuild['type'] == 'raw':
        src = os.path.join(root_dir, thisbuild['output'])
        src = os.path.normpath(src)

    # Make sure it's not debuggable...
    if common.isApkDebuggable(src, config):
        raise BuildException("APK is debuggable")

    # By way of a sanity check, make sure the version and version
    # code in our new apk match what we expect...
    logging.debug("Checking " + src)
    if not os.path.exists(src):
        raise BuildException("Unsigned apk is not at expected location of " + src)

    p = SilentPopen([config['aapt'], 'dump', 'badging', src])

    vercode = None
    version = None
    foundid = None
    nativecode = None
    for line in p.output.splitlines():
        if line.startswith("package:"):
            pat = re.compile(".*name='([a-zA-Z0-9._]*)'.*")
            m = pat.match(line)
            if m:
                foundid = m.group(1)
            pat = re.compile(".*versionCode='([0-9]*)'.*")
            m = pat.match(line)
            if m:
                vercode = m.group(1)
            pat = re.compile(".*versionName='([^']*)'.*")
            m = pat.match(line)
            if m:
                version = m.group(1)
        elif line.startswith("native-code:"):
            nativecode = line[12:]

    # Ignore empty strings or any kind of space/newline chars that we don't
    # care about
    if nativecode is not None:
        nativecode = nativecode.strip()
        nativecode = None if not nativecode else nativecode

    if thisbuild['buildjni'] and thisbuild['buildjni'] != ['no']:
        if nativecode is None:
            raise BuildException("Native code should have been built but none was packaged")
    if thisbuild['novcheck']:
        vercode = thisbuild['vercode']
        version = thisbuild['version']
    if not version or not vercode:
        raise BuildException("Could not find version information in build in output")
    if not foundid:
        raise BuildException("Could not find package ID in output")
    if foundid != app['id']:
        raise BuildException("Wrong package ID - build " + foundid + " but expected " + app['id'])

    # Some apps (e.g. Timeriffic) have had the bonkers idea of
    # including the entire changelog in the version number. Remove
    # it so we can compare. (TODO: might be better to remove it
    # before we compile, in fact)
    index = version.find(" //")
    if index != -1:
        version = version[:index]

    if (version != thisbuild['version'] or
            vercode != thisbuild['vercode']):
        raise BuildException(("Unexpected version/version code in output;"
                              " APK: '%s' / '%s', "
                              " Expected: '%s' / '%s'")
                             % (version, str(vercode), thisbuild['version'],
                                str(thisbuild['vercode']))
                             )

    # Copy the unsigned apk to our destination directory for further
    # processing (by publish.py)...
    dest = os.path.join(output_dir, common.getapkname(app, thisbuild))
    shutil.copyfile(src, dest)

    # Move the source tarball into the output directory...
    if output_dir != tmp_dir and not options.notarball:
        shutil.move(os.path.join(tmp_dir, tarname),
                    os.path.join(output_dir, tarname))


def trybuild(app, thisbuild, build_dir, output_dir, also_check_dir, srclib_dir, extlib_dir,
             tmp_dir, repo_dir, vcs, test, server, force, onserver):
    """
    Build a particular version of an application, if it needs building.

    :param output_dir: The directory where the build output will go. Usually
       this is the 'unsigned' directory.
    :param repo_dir: The repo directory - used for checking if the build is
       necessary.
    :paaram also_check_dir: An additional location for checking if the build
       is necessary (usually the archive repo)
    :param test: True if building in test mode, in which case the build will
       always happen, even if the output already exists. In test mode, the
       output directory should be a temporary location, not any of the real
       ones.

    :returns: True if the build was done, False if it wasn't necessary.
    """

    dest_apk = common.getapkname(app, thisbuild)

    dest = os.path.join(output_dir, dest_apk)
    dest_repo = os.path.join(repo_dir, dest_apk)

    if not test:
        if os.path.exists(dest) or os.path.exists(dest_repo):
            return False

        if also_check_dir:
            dest_also = os.path.join(also_check_dir, dest_apk)
            if os.path.exists(dest_also):
                return False

    if thisbuild['disable']:
        return False

    logging.info("Building version %s (%s) of %s" % (
        thisbuild['version'], thisbuild['vercode'], app['id']))

    if server:
        # When using server mode, still keep a local cache of the repo, by
        # grabbing the source now.
        vcs.gotorevision(thisbuild['commit'])

        build_server(app, thisbuild, vcs, build_dir, output_dir, force)
    else:
        build_local(app, thisbuild, vcs, build_dir, output_dir, srclib_dir, extlib_dir, tmp_dir, force, onserver)
    return True


def parse_commandline():
    """Parse the command line. Returns options, args."""

    parser = OptionParser(usage="Usage: %prog [options] [APPID[:VERCODE] [APPID[:VERCODE] ...]]")
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help="Restrict output to warnings and errors")
    parser.add_option("-l", "--latest", action="store_true", default=False,
                      help="Build only the latest version of each package")
    parser.add_option("-s", "--stop", action="store_true", default=False,
                      help="Make the build stop on exceptions")
    parser.add_option("-t", "--test", action="store_true", default=False,
                      help="Test mode - put output in the tmp directory only, and always build, even if the output already exists.")
    parser.add_option("--server", action="store_true", default=False,
                      help="Use build server")
    parser.add_option("--resetserver", action="store_true", default=False,
                      help="Reset and create a brand new build server, even if the existing one appears to be ok.")
    parser.add_option("--on-server", dest="onserver", action="store_true", default=False,
                      help="Specify that we're running on the build server")
    parser.add_option("--skip-scan", dest="skipscan", action="store_true", default=False,
                      help="Skip scanning the source code for binaries and other problems")
    parser.add_option("--no-tarball", dest="notarball", action="store_true", default=False,
                      help="Don't create a source tarball, useful when testing a build")
    parser.add_option("-f", "--force", action="store_true", default=False,
                      help="Force build of disabled apps, and carries on regardless of scan problems. Only allowed in test mode.")
    parser.add_option("-a", "--all", action="store_true", default=False,
                      help="Build all applications available")
    parser.add_option("-w", "--wiki", default=False, action="store_true",
                      help="Update the wiki")
    options, args = parser.parse_args()

    # Force --stop with --on-server to get correct exit code
    if options.onserver:
        options.stop = True

    if options.force and not options.test:
        raise OptionError("Force is only allowed in test mode", "force")

    return options, args

options = None
config = None


def main():

    global options, config

    options, args = parse_commandline()
    if not args and not options.all:
        raise OptionError("If you really want to build all the apps, use --all", "all")

    config = common.read_config(options)

    if config['build_server_always']:
        options.server = True
    if options.resetserver and not options.server:
        raise OptionError("Using --resetserver without --server makes no sense", "resetserver")

    log_dir = 'logs'
    if not os.path.isdir(log_dir):
        logging.info("Creating log directory")
        os.makedirs(log_dir)

    tmp_dir = 'tmp'
    if not os.path.isdir(tmp_dir):
        logging.info("Creating temporary directory")
        os.makedirs(tmp_dir)

    if options.test:
        output_dir = tmp_dir
    else:
        output_dir = 'unsigned'
        if not os.path.isdir(output_dir):
            logging.info("Creating output directory")
            os.makedirs(output_dir)

    if config['archive_older'] != 0:
        also_check_dir = 'archive'
    else:
        also_check_dir = None

    repo_dir = 'repo'

    build_dir = 'build'
    if not os.path.isdir(build_dir):
        logging.info("Creating build directory")
        os.makedirs(build_dir)
    srclib_dir = os.path.join(build_dir, 'srclib')
    extlib_dir = os.path.join(build_dir, 'extlib')

    # Read all app and srclib metadata
    allapps = metadata.read_metadata(xref=not options.onserver)

    apps = common.read_app_args(args, allapps, True)
    apps = [app for app in apps if (options.force or not app['Disabled']) and
            len(app['Repo Type']) > 0 and len(app['builds']) > 0]

    if len(apps) == 0:
        raise FDroidException("No apps to process.")

    if options.latest:
        for app in apps:
            for build in reversed(app['builds']):
                if build['disable']:
                    continue
                app['builds'] = [build]
                break

    if options.wiki:
        import mwclient
        site = mwclient.Site((config['wiki_protocol'], config['wiki_server']),
                             path=config['wiki_path'])
        site.login(config['wiki_user'], config['wiki_password'])

    # Build applications...
    failed_apps = {}
    build_succeeded = []
    for app in apps:

        first = True

        for thisbuild in app['builds']:
            wikilog = None
            try:

                # For the first build of a particular app, we need to set up
                # the source repo. We can reuse it on subsequent builds, if
                # there are any.
                if first:
                    if app['Repo Type'] == 'srclib':
                        build_dir = os.path.join('build', 'srclib', app['Repo'])
                    else:
                        build_dir = os.path.join('build', app['id'])

                    # Set up vcs interface and make sure we have the latest code...
                    logging.debug("Getting {0} vcs interface for {1}"
                                  .format(app['Repo Type'], app['Repo']))
                    vcs = common.getvcs(app['Repo Type'], app['Repo'], build_dir)

                    first = False

                logging.debug("Checking " + thisbuild['version'])
                if trybuild(app, thisbuild, build_dir, output_dir,
                            also_check_dir, srclib_dir, extlib_dir,
                            tmp_dir, repo_dir, vcs, options.test,
                            options.server, options.force,
                            options.onserver):
                    build_succeeded.append(app)
                    wikilog = "Build succeeded"
            except BuildException as be:
                logfile = open(os.path.join(log_dir, app['id'] + '.log'), 'a+')
                logfile.write(str(be))
                logfile.close()
                print("Could not build app %s due to BuildException: %s" % (app['id'], be))
                if options.stop:
                    sys.exit(1)
                failed_apps[app['id']] = be
                wikilog = be.get_wikitext()
            except VCSException as vcse:
                reason = str(vcse).split('\n', 1)[0] if options.verbose else str(vcse)
                logging.error("VCS error while building app %s: %s" % (
                    app['id'], reason))
                if options.stop:
                    sys.exit(1)
                failed_apps[app['id']] = vcse
                wikilog = str(vcse)
            except Exception as e:
                logging.error("Could not build app %s due to unknown error: %s" % (
                    app['id'], traceback.format_exc()))
                if options.stop:
                    sys.exit(1)
                failed_apps[app['id']] = e
                wikilog = str(e)

            if options.wiki and wikilog:
                try:
                    # Write a page with the last build log for this version code
                    lastbuildpage = app['id'] + '/lastbuild_' + thisbuild['vercode']
                    newpage = site.Pages[lastbuildpage]
                    txt = "Build completed at " + time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()) + "\n\n" + wikilog
                    newpage.save(txt, summary='Build log')
                    # Redirect from /lastbuild to the most recent build log
                    newpage = site.Pages[app['id'] + '/lastbuild']
                    newpage.save('#REDIRECT [[' + lastbuildpage + ']]', summary='Update redirect')
                except:
                    logging.error("Error while attempting to publish build log")

    for app in build_succeeded:
        logging.info("success: %s" % (app['id']))

    if not options.verbose:
        for fa in failed_apps:
            logging.info("Build for app %s failed:\n%s" % (fa, failed_apps[fa]))

    logging.info("Finished.")
    if len(build_succeeded) > 0:
        logging.info(str(len(build_succeeded)) + ' builds succeeded')
    if len(failed_apps) > 0:
        logging.info(str(len(failed_apps)) + ' builds failed')

    sys.exit(0)

if __name__ == "__main__":
    main()
