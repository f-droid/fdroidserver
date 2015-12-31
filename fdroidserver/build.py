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
from argparse import ArgumentParser
import logging

import common
import net
import metadata
import scanner
from common import FDroidException, BuildException, VCSException, FDroidPopen, SdkToolsPopen

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
    sshf = open(os.path.join('builder', 'sshconfig'), 'r')
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

        p = subprocess.Popen(['vagrant', '--version'],
                             stdout=subprocess.PIPE)
        vver = p.communicate()[0]
        with open(os.path.join('builder', 'Vagrantfile'), 'w') as vf:
            if vver.startswith('Vagrant version 1.2'):
                vf.write('Vagrant.configure("2") do |config|\n')
                vf.write('config.vm.box = "buildserver"\n')
                vf.write('end\n')
            else:
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
def build_server(app, build, vcs, build_dir, output_dir, force):
    """Do a build on the build server."""

    try:
        paramiko
    except NameError:
        raise BuildException("Paramiko is required to use the buildserver")
    if options.verbose:
        logging.getLogger("paramiko").setLevel(logging.INFO)
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
        ftp.mkdir('fdroidserver')
        ftp.chdir('fdroidserver')
        ftp.put(os.path.join(serverpath, '..', 'fdroid'), 'fdroid')
        ftp.chmod('fdroid', 0o755)
        send_dir(os.path.join(serverpath))
        ftp.chdir(homedir)

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
        ftp.put(os.path.join('metadata', app.id + '.txt'),
                app.id + '.txt')
        # And patches if there are any...
        if os.path.exists(os.path.join('metadata', app.id)):
            send_dir(os.path.join('metadata', app.id))

        ftp.chdir(homedir)
        # Create the build directory...
        ftp.mkdir('build')
        ftp.chdir('build')
        ftp.mkdir('extlib')
        ftp.mkdir('srclib')
        # Copy any extlibs that are required...
        if build.extlibs:
            ftp.chdir(homedir + '/build/extlib')
            for lib in build.extlibs:
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
        if build.srclibs:
            for lib in build.srclibs:
                srclibpaths.append(
                    common.getsrclib(lib, 'build/srclib', basepath=True, prepare=False))

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
            fv = '.fdroidvcs-' + app.id
            ftp.put(os.path.join('build', fv), fv)
            send_dir(build_dir)

        # Execute the build script...
        logging.info("Starting build...")
        chan = sshs.get_transport().open_session()
        chan.get_pty()
        cmdline = os.path.join(homedir, 'fdroidserver', 'fdroid')
        cmdline += ' build --on-server'
        if force:
            cmdline += ' --force --test'
        if options.verbose:
            cmdline += ' --verbose'
        cmdline += " %s:%s" % (app.id, build.vercode)
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
                    app.id, build.version), output)

        # Retrieve the built files...
        logging.info("Retrieving build output...")
        if force:
            ftp.chdir(homedir + '/tmp')
        else:
            ftp.chdir(homedir + '/unsigned')
        apkfile = common.getapkname(app, build)
        tarball = common.getsrcname(app, build)
        try:
            ftp.get(apkfile, os.path.join(output_dir, apkfile))
            if not options.notarball:
                ftp.get(tarball, os.path.join(output_dir, tarball))
        except:
            raise BuildException(
                "Build failed for %s:%s - missing output files".format(
                    app.id, build.version), output)
        ftp.close()

    finally:

        # Suspend the build server.
        release_vm()


def adapt_gradle(build_dir):
    filename = 'build.gradle'
    for root, dirs, files in os.walk(build_dir):
        for filename in files:
            if not filename.endswith('.gradle'):
                continue
            path = os.path.join(root, filename)
            if not os.path.isfile(path):
                continue
            logging.debug("Adapting %s at %s" % (filename, path))
            common.regsub_file(r"""(\s*)buildToolsVersion([\s=]+).*""",
                               r"""\1buildToolsVersion\2'%s'""" % config['build_tools'],
                               path)


def capitalize_intact(string):
    """Like str.capitalize(), but leave the rest of the string intact without
    switching it to lowercase."""
    if len(string) == 0:
        return string
    if len(string) == 1:
        return string.upper()
    return string[0].upper() + string[1:]


def build_local(app, build, vcs, build_dir, output_dir, srclib_dir, extlib_dir, tmp_dir, force, onserver, refresh):
    """Do a build locally."""

    ndk_path = build.ndk_path()
    if build.buildjni and build.buildjni != ['no']:
        if not ndk_path:
            logging.critical("Android NDK version '%s' could not be found!" % build.ndk or 'r10e')
            logging.critical("Configured versions:")
            for k, v in config['ndk_paths'].iteritems():
                if k.endswith("_orig"):
                    continue
                logging.critical("  %s: %s" % (k, v))
            sys.exit(3)
        elif not os.path.isdir(ndk_path):
            logging.critical("Android NDK '%s' is not a directory!" % ndk_path)
            sys.exit(3)

    # Set up environment vars that depend on each build
    for n in ['ANDROID_NDK', 'NDK', 'ANDROID_NDK_HOME']:
        common.env[n] = ndk_path

    common.reset_env_path()
    # Set up the current NDK to the PATH
    common.add_to_env_path(ndk_path)

    # Prepare the source code...
    root_dir, srclibpaths = common.prepare_source(vcs, app, build,
                                                  build_dir, srclib_dir,
                                                  extlib_dir, onserver, refresh)

    # We need to clean via the build tool in case the binary dirs are
    # different from the default ones
    p = None
    gradletasks = []
    method = build.method()
    if method == 'maven':
        logging.info("Cleaning Maven project...")
        cmd = [config['mvn3'], 'clean', '-Dandroid.sdk.path=' + config['sdk_path']]

        if '@' in build.maven:
            maven_dir = os.path.join(root_dir, build.maven.split('@', 1)[1])
            maven_dir = os.path.normpath(maven_dir)
        else:
            maven_dir = root_dir

        p = FDroidPopen(cmd, cwd=maven_dir)

    elif method == 'gradle':

        logging.info("Cleaning Gradle project...")

        if build.preassemble:
            gradletasks += build.preassemble

        flavours = build.gradle
        if flavours == ['yes']:
            flavours = []

        flavours_cmd = ''.join([capitalize_intact(f) for f in flavours])

        gradletasks += ['assemble' + flavours_cmd + 'Release']

        adapt_gradle(build_dir)
        for name, number, libpath in srclibpaths:
            adapt_gradle(libpath)

        cmd = [config['gradle']]
        if build.gradleprops:
            cmd += ['-P'+kv for kv in build.gradleprops]

        for task in gradletasks:
            parts = task.split(':')
            parts[-1] = 'clean' + capitalize_intact(parts[-1])
            cmd += [':'.join(parts)]

        cmd += ['clean']

        p = FDroidPopen(cmd, cwd=root_dir)

    elif method == 'kivy':
        pass

    elif method == 'ant':
        logging.info("Cleaning Ant project...")
        p = FDroidPopen(['ant', 'clean'], cwd=root_dir)

    if p is not None and p.returncode != 0:
        raise BuildException("Error cleaning %s:%s" %
                             (app.id, build.version), p.output)

    for root, dirs, files in os.walk(build_dir):

        def del_dirs(dl):
            for d in dl:
                if d in dirs:
                    shutil.rmtree(os.path.join(root, d))

        def del_files(fl):
            for f in fl:
                if f in files:
                    os.remove(os.path.join(root, f))

        if 'build.gradle' in files:
            # Even when running clean, gradle stores task/artifact caches in
            # .gradle/ as binary files. To avoid overcomplicating the scanner,
            # manually delete them, just like `gradle clean` should have removed
            # the build/ dirs.
            del_dirs(['build', '.gradle', 'gradle'])
            del_files(['gradlew', 'gradlew.bat'])

        if 'pom.xml' in files:
            del_dirs(['target'])

        if any(f in files for f in ['ant.properties', 'project.properties', 'build.xml']):
            del_dirs(['bin', 'gen'])

        if 'jni' in dirs:
            del_dirs(['obj'])

    if options.skipscan:
        if build.scandelete:
            raise BuildException("Refusing to skip source scan since scandelete is present")
    else:
        # Scan before building...
        logging.info("Scanning source for common problems...")
        count = scanner.scan_source(build_dir, root_dir, build)
        if count > 0:
            if force:
                logging.warn('Scanner found %d problems' % count)
            else:
                raise BuildException("Can't build due to %d errors while scanning" % count)

    if not options.notarball:
        # Build the source tarball right before we build the release...
        logging.info("Creating source tarball...")
        tarname = common.getsrcname(app, build)
        tarball = tarfile.open(os.path.join(tmp_dir, tarname), "w:gz")

        def tarexc(f):
            return any(f.endswith(s) for s in ['.svn', '.git', '.hg', '.bzr'])
        tarball.add(build_dir, tarname, exclude=tarexc)
        tarball.close()

    # Run a build command if one is required...
    if build.build:
        logging.info("Running 'build' commands in %s" % root_dir)
        cmd = common.replace_config_vars(build.build, build)

        # Substitute source library paths into commands...
        for name, number, libpath in srclibpaths:
            libpath = os.path.relpath(libpath, root_dir)
            cmd = cmd.replace('$$' + name + '$$', libpath)

        p = FDroidPopen(['bash', '-x', '-c', cmd], cwd=root_dir)

        if p.returncode != 0:
            raise BuildException("Error running build command for %s:%s" %
                                 (app.id, build.version), p.output)

    # Build native stuff if required...
    if build.buildjni and build.buildjni != ['no']:
        logging.info("Building the native code")
        jni_components = build.buildjni

        if jni_components == ['yes']:
            jni_components = ['']
        cmd = [os.path.join(ndk_path, "ndk-build"), "-j1"]
        for d in jni_components:
            if d:
                logging.info("Building native code in '%s'" % d)
            else:
                logging.info("Building native code in the main project")
            manifest = os.path.join(root_dir, d, 'AndroidManifest.xml')
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
                raise BuildException("NDK build failed for %s:%s" % (app.id, build.version), p.output)

    p = None
    # Build the release...
    if method == 'maven':
        logging.info("Building Maven project...")

        if '@' in build.maven:
            maven_dir = os.path.join(root_dir, build.maven.split('@', 1)[1])
        else:
            maven_dir = root_dir

        mvncmd = [config['mvn3'], '-Dandroid.sdk.path=' + config['sdk_path'],
                  '-Dmaven.jar.sign.skip=true', '-Dmaven.test.skip=true',
                  '-Dandroid.sign.debug=false', '-Dandroid.release=true',
                  'package']
        if build.target:
            target = build.target.split('-')[1]
            common.regsub_file(r'<platform>[0-9]*</platform>',
                               r'<platform>%s</platform>' % target,
                               os.path.join(root_dir, 'pom.xml'))
            if '@' in build.maven:
                common.regsub_file(r'<platform>[0-9]*</platform>',
                                   r'<platform>%s</platform>' % target,
                                   os.path.join(maven_dir, 'pom.xml'))

        p = FDroidPopen(mvncmd, cwd=maven_dir)

        bindir = os.path.join(root_dir, 'target')

    elif method == 'kivy':
        logging.info("Building Kivy project...")

        spec = os.path.join(root_dir, 'buildozer.spec')
        if not os.path.exists(spec):
            raise BuildException("Expected to find buildozer-compatible spec at {0}"
                                 .format(spec))

        defaults = {'orientation': 'landscape', 'icon': '',
                    'permissions': '', 'android.api': "18"}
        bconfig = ConfigParser(defaults, allow_no_value=True)
        bconfig.read(spec)

        distdir = os.path.join('python-for-android', 'dist', 'fdroid')
        if os.path.exists(distdir):
            shutil.rmtree(distdir)

        modules = bconfig.get('app', 'requirements').split(',')

        cmd = 'ANDROIDSDK=' + config['sdk_path']
        cmd += ' ANDROIDNDK=' + ndk_path
        cmd += ' ANDROIDNDKVER=' + build.ndk
        cmd += ' ANDROIDAPI=' + str(bconfig.get('app', 'android.api'))
        cmd += ' VIRTUALENV=virtualenv'
        cmd += ' ./distribute.sh'
        cmd += ' -m ' + "'" + ' '.join(modules) + "'"
        cmd += ' -d fdroid'
        p = subprocess.Popen(cmd, cwd='python-for-android', shell=True)
        if p.returncode != 0:
            raise BuildException("Distribute build failed")

        cid = bconfig.get('app', 'package.domain') + '.' + bconfig.get('app', 'package.name')
        if cid != app.id:
            raise BuildException("Package ID mismatch between metadata and spec")

        orientation = bconfig.get('app', 'orientation', 'landscape')
        if orientation == 'all':
            orientation = 'sensor'

        cmd = ['./build.py'
               '--dir', root_dir,
               '--name', bconfig.get('app', 'title'),
               '--package', app.id,
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

    elif method == 'gradle':
        logging.info("Building Gradle project...")

        cmd = [config['gradle']]
        if build.gradleprops:
            cmd += ['-P'+kv for kv in build.gradleprops]

        cmd += gradletasks

        p = FDroidPopen(cmd, cwd=root_dir)

    elif method == 'ant':
        logging.info("Building Ant project...")
        cmd = ['ant']
        if build.antcommands:
            cmd += build.antcommands
        else:
            cmd += ['release']
        p = FDroidPopen(cmd, cwd=root_dir)

        bindir = os.path.join(root_dir, 'bin')

    if p is not None and p.returncode != 0:
        raise BuildException("Build failed for %s:%s" % (app.id, build.version), p.output)
    logging.info("Successfully built version " + build.version + ' of ' + app.id)

    if method == 'maven':
        stdout_apk = '\n'.join([
            line for line in p.output.splitlines() if any(
                a in line for a in ('.apk', '.ap_', '.jar'))])
        m = re.match(r".*^\[INFO\] .*apkbuilder.*/([^/]*)\.apk",
                     stdout_apk, re.S | re.M)
        if not m:
            m = re.match(r".*^\[INFO\] Creating additional unsigned apk file .*/([^/]+)\.apk[^l]",
                         stdout_apk, re.S | re.M)
        if not m:
            m = re.match(r'.*^\[INFO\] [^$]*aapt \[package,[^$]*' + bindir + r'/([^/]+)\.ap[_k][,\]]',
                         stdout_apk, re.S | re.M)

        if not m:
            m = re.match(r".*^\[INFO\] Building jar: .*/" + bindir + r"/(.+)\.jar",
                         stdout_apk, re.S | re.M)
        if not m:
            raise BuildException('Failed to find output')
        src = m.group(1)
        src = os.path.join(bindir, src) + '.apk'
    elif method == 'kivy':
        src = os.path.join('python-for-android', 'dist', 'default', 'bin',
                           '{0}-{1}-release.apk'.format(
                               bconfig.get('app', 'title'),
                               bconfig.get('app', 'version')))
    elif method == 'gradle':
        src = None
        for apks_dir in [
                os.path.join(root_dir, 'build', 'outputs', 'apk'),
                os.path.join(root_dir, 'build', 'apk'),
                ]:
            for apkglob in ['*-release-unsigned.apk', '*-unsigned.apk', '*.apk']:
                apks = glob.glob(os.path.join(apks_dir, apkglob))

                if len(apks) > 1:
                    raise BuildException('More than one resulting apks found in %s' % apks_dir,
                                         '\n'.join(apks))
                if len(apks) == 1:
                    src = apks[0]
                    break
            if src is not None:
                break

        if src is None:
            raise BuildException('Failed to find any output apks')

    elif method == 'ant':
        stdout_apk = '\n'.join([
            line for line in p.output.splitlines() if '.apk' in line])
        src = re.match(r".*^.*Creating (.+) for release.*$.*", stdout_apk,
                       re.S | re.M).group(1)
        src = os.path.join(bindir, src)
    elif method == 'raw':
        src = os.path.join(root_dir, build.output)
        src = os.path.normpath(src)

    # Make sure it's not debuggable...
    if common.isApkDebuggable(src, config):
        raise BuildException("APK is debuggable")

    # By way of a sanity check, make sure the version and version
    # code in our new apk match what we expect...
    logging.debug("Checking " + src)
    if not os.path.exists(src):
        raise BuildException("Unsigned apk is not at expected location of " + src)

    p = SdkToolsPopen(['aapt', 'dump', 'badging', src], output=False)

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

    if build.buildjni and build.buildjni != ['no']:
        if nativecode is None:
            raise BuildException("Native code should have been built but none was packaged")
    if build.novcheck:
        vercode = build.vercode
        version = build.version
    if not version or not vercode:
        raise BuildException("Could not find version information in build in output")
    if not foundid:
        raise BuildException("Could not find package ID in output")
    if foundid != app.id:
        raise BuildException("Wrong package ID - build " + foundid + " but expected " + app.id)

    # Some apps (e.g. Timeriffic) have had the bonkers idea of
    # including the entire changelog in the version number. Remove
    # it so we can compare. (TODO: might be better to remove it
    # before we compile, in fact)
    index = version.find(" //")
    if index != -1:
        version = version[:index]

    if (version != build.version or
            vercode != build.vercode):
        raise BuildException(("Unexpected version/version code in output;"
                              " APK: '%s' / '%s', "
                              " Expected: '%s' / '%s'")
                             % (version, str(vercode), build.version,
                                str(build.vercode))
                             )

    # Add information for 'fdroid verify' to be able to reproduce the build
    # environment.
    if onserver:
        metadir = os.path.join(tmp_dir, 'META-INF')
        if not os.path.exists(metadir):
            os.mkdir(metadir)
        homedir = os.path.expanduser('~')
        for fn in ['buildserverid', 'fdroidserverid']:
            shutil.copyfile(os.path.join(homedir, fn),
                            os.path.join(metadir, fn))
            subprocess.call(['jar', 'uf', os.path.abspath(src),
                             'META-INF/' + fn], cwd=tmp_dir)

    # Copy the unsigned apk to our destination directory for further
    # processing (by publish.py)...
    dest = os.path.join(output_dir, common.getapkname(app, build))
    shutil.copyfile(src, dest)

    # Move the source tarball into the output directory...
    if output_dir != tmp_dir and not options.notarball:
        shutil.move(os.path.join(tmp_dir, tarname),
                    os.path.join(output_dir, tarname))


def trybuild(app, build, build_dir, output_dir, also_check_dir, srclib_dir, extlib_dir,
             tmp_dir, repo_dir, vcs, test, server, force, onserver, refresh):
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

    dest_apk = common.getapkname(app, build)

    dest = os.path.join(output_dir, dest_apk)
    dest_repo = os.path.join(repo_dir, dest_apk)

    if not test:
        if os.path.exists(dest) or os.path.exists(dest_repo):
            return False

        if also_check_dir:
            dest_also = os.path.join(also_check_dir, dest_apk)
            if os.path.exists(dest_also):
                return False

    if build.disable and not options.force:
        return False

    logging.info("Building version %s (%s) of %s" % (
        build.version, build.vercode, app.id))

    if server:
        # When using server mode, still keep a local cache of the repo, by
        # grabbing the source now.
        vcs.gotorevision(build.commit)

        build_server(app, build, vcs, build_dir, output_dir, force)
    else:
        build_local(app, build, vcs, build_dir, output_dir, srclib_dir, extlib_dir, tmp_dir, force, onserver, refresh)
    return True


def parse_commandline():
    """Parse the command line. Returns options, parser."""

    parser = ArgumentParser(usage="%(prog)s [options] [APPID[:VERCODE] [APPID[:VERCODE] ...]]")
    common.setup_global_opts(parser)
    parser.add_argument("appid", nargs='*', help="app-id with optional versioncode in the form APPID[:VERCODE]")
    parser.add_argument("-l", "--latest", action="store_true", default=False,
                        help="Build only the latest version of each package")
    parser.add_argument("-s", "--stop", action="store_true", default=False,
                        help="Make the build stop on exceptions")
    parser.add_argument("-t", "--test", action="store_true", default=False,
                        help="Test mode - put output in the tmp directory only, and always build, even if the output already exists.")
    parser.add_argument("--server", action="store_true", default=False,
                        help="Use build server")
    parser.add_argument("--resetserver", action="store_true", default=False,
                        help="Reset and create a brand new build server, even if the existing one appears to be ok.")
    parser.add_argument("--on-server", dest="onserver", action="store_true", default=False,
                        help="Specify that we're running on the build server")
    parser.add_argument("--skip-scan", dest="skipscan", action="store_true", default=False,
                        help="Skip scanning the source code for binaries and other problems")
    parser.add_argument("--no-tarball", dest="notarball", action="store_true", default=False,
                        help="Don't create a source tarball, useful when testing a build")
    parser.add_argument("--no-refresh", dest="refresh", action="store_false", default=True,
                        help="Don't refresh the repository, useful when testing a build with no internet connection")
    parser.add_argument("-f", "--force", action="store_true", default=False,
                        help="Force build of disabled apps, and carries on regardless of scan problems. Only allowed in test mode.")
    parser.add_argument("-a", "--all", action="store_true", default=False,
                        help="Build all applications available")
    parser.add_argument("-w", "--wiki", default=False, action="store_true",
                        help="Update the wiki")
    options = parser.parse_args()

    # Force --stop with --on-server to get correct exit code
    if options.onserver:
        options.stop = True

    if options.force and not options.test:
        parser.error("option %s: Force is only allowed in test mode" % "force")

    return options, parser

options = None
config = None


def main():

    global options, config

    options, parser = parse_commandline()
    if not options.appid and not options.all:
        parser.error("option %s: If you really want to build all the apps, use --all" % "all")

    config = common.read_config(options)

    if config['build_server_always']:
        options.server = True
    if options.resetserver and not options.server:
        parser.error("option %s: Using --resetserver without --server makes no sense" % "resetserver")

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

    apps = common.read_app_args(options.appid, allapps, True)
    for appid, app in apps.items():
        if (app.Disabled and not options.force) or not app.RepoType or not app.builds:
            del apps[appid]

    if not apps:
        raise FDroidException("No apps to process.")

    if options.latest:
        for app in apps.itervalues():
            for build in reversed(app.builds):
                if build.disable and not options.force:
                    continue
                app.builds = [build]
                break

    if options.wiki:
        import mwclient
        site = mwclient.Site((config['wiki_protocol'], config['wiki_server']),
                             path=config['wiki_path'])
        site.login(config['wiki_user'], config['wiki_password'])

    # Build applications...
    failed_apps = {}
    build_succeeded = []
    for appid, app in apps.iteritems():

        first = True

        for build in app.builds:
            wikilog = None
            try:

                # For the first build of a particular app, we need to set up
                # the source repo. We can reuse it on subsequent builds, if
                # there are any.
                if first:
                    if app.RepoType == 'srclib':
                        build_dir = os.path.join('build', 'srclib', app.Repo)
                    else:
                        build_dir = os.path.join('build', appid)

                    # Set up vcs interface and make sure we have the latest code...
                    logging.debug("Getting {0} vcs interface for {1}"
                                  .format(app.RepoType, app.Repo))
                    vcs = common.getvcs(app.RepoType, app.Repo, build_dir)

                    first = False

                logging.debug("Checking " + build.version)
                if trybuild(app, build, build_dir, output_dir,
                            also_check_dir, srclib_dir, extlib_dir,
                            tmp_dir, repo_dir, vcs, options.test,
                            options.server, options.force,
                            options.onserver, options.refresh):

                    if app.Binaries is not None:
                        # This is an app where we build from source, and
                        # verify the apk contents against a developer's
                        # binary. We get that binary now, and save it
                        # alongside our built one in the 'unsigend'
                        # directory.
                        url = app.Binaries
                        url = url.replace('%v', build.version)
                        url = url.replace('%c', str(build.vercode))
                        logging.info("...retrieving " + url)
                        of = "{0}_{1}.apk.binary".format(app.id, build.vercode)
                        of = os.path.join(output_dir, of)
                        net.download_file(url, local_filename=of)

                    build_succeeded.append(app)
                    wikilog = "Build succeeded"
            except VCSException as vcse:
                reason = str(vcse).split('\n', 1)[0] if options.verbose else str(vcse)
                logging.error("VCS error while building app %s: %s" % (
                    appid, reason))
                if options.stop:
                    sys.exit(1)
                failed_apps[appid] = vcse
                wikilog = str(vcse)
            except FDroidException as e:
                with open(os.path.join(log_dir, appid + '.log'), 'a+') as f:
                    f.write(str(e))
                logging.error("Could not build app %s: %s" % (appid, e))
                if options.stop:
                    sys.exit(1)
                failed_apps[appid] = e
                wikilog = e.get_wikitext()
            except Exception as e:
                logging.error("Could not build app %s due to unknown error: %s" % (
                    appid, traceback.format_exc()))
                if options.stop:
                    sys.exit(1)
                failed_apps[appid] = e
                wikilog = str(e)

            if options.wiki and wikilog:
                try:
                    # Write a page with the last build log for this version code
                    lastbuildpage = appid + '/lastbuild_' + build.vercode
                    newpage = site.Pages[lastbuildpage]
                    txt = "Build completed at " + time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()) + "\n\n" + wikilog
                    newpage.save(txt, summary='Build log')
                    # Redirect from /lastbuild to the most recent build log
                    newpage = site.Pages[appid + '/lastbuild']
                    newpage.save('#REDIRECT [[' + lastbuildpage + ']]', summary='Update redirect')
                except:
                    logging.error("Error while attempting to publish build log")

    for app in build_succeeded:
        logging.info("success: %s" % (app.id))

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
