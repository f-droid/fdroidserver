#!/usr/bin/env python3
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

import os
import shutil
import glob
import subprocess
import re
import resource
import sys
import tarfile
import threading
import traceback
import time
import requests
import tempfile
from configparser import ConfigParser
from argparse import ArgumentParser
import logging
from gettext import ngettext

from . import _
from . import common
from . import net
from . import metadata
from . import scanner
from . import vmtools
from .common import FDroidPopen, SdkToolsPopen
from .exception import FDroidException, BuildException, VCSException

try:
    import paramiko
except ImportError:
    pass


# Note that 'force' here also implies test mode.
def build_server(app, build, vcs, build_dir, output_dir, log_dir, force):
    """Do a build on the builder vm.

    :param app: app metadata dict
    :param build:
    :param vcs: version control system controller object
    :param build_dir: local source-code checkout of app
    :param output_dir: target folder for the build result
    :param force:
    """

    global buildserverid

    try:
        paramiko
    except NameError:
        raise BuildException("Paramiko is required to use the buildserver")
    if options.verbose:
        logging.getLogger("paramiko").setLevel(logging.INFO)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARN)

    sshinfo = vmtools.get_clean_builder('builder', options.reset_server)

    try:
        if not buildserverid:
            buildserverid = subprocess.check_output(['vagrant', 'ssh', '-c',
                                                     'cat /home/vagrant/buildserverid'],
                                                    cwd='builder').strip().decode()
            logging.debug(_('Fetched buildserverid from VM: {buildserverid}')
                          .format(buildserverid=buildserverid))

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
        ftp.get_channel().settimeout(60)

        # Put all the necessary files in place...
        ftp.chdir(homedir)

        # Helper to copy the contents of a directory to the server...
        def send_dir(path):
            logging.debug("rsyncing " + path + " to " + ftp.getcwd())
            # TODO this should move to `vagrant rsync` from >= v1.5
            try:
                subprocess.check_output(['rsync', '--recursive', '--perms', '--links', '--quiet', '--rsh=' +
                                         'ssh -o StrictHostKeyChecking=no' +
                                         ' -o UserKnownHostsFile=/dev/null' +
                                         ' -o LogLevel=FATAL' +
                                         ' -o IdentitiesOnly=yes' +
                                         ' -o PasswordAuthentication=no' +
                                         ' -p ' + str(sshinfo['port']) +
                                         ' -i ' + sshinfo['idfile'],
                                         path,
                                         sshinfo['user'] + "@" + sshinfo['hostname'] + ":" + ftp.getcwd()],
                                        stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                raise FDroidException(str(e), e.output.decode())

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
        with open(os.path.join(os.getcwd(), 'tmp', 'fdroidserverid'), 'wb') as fp:
            fp.write(subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                             cwd=serverpath))
        ftp.put('tmp/fdroidserverid', 'fdroidserverid')

        # Copy the metadata - just the file for this app...
        ftp.mkdir('metadata')
        ftp.mkdir('srclibs')
        ftp.chdir('metadata')
        ftp.put(app.metadatapath, os.path.basename(app.metadatapath))

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
                for _ignored in lp[:-1]:
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
        if options.skipscan:
            cmdline += ' --skip-scan'
        cmdline += " %s:%s" % (app.id, build.versionCode)
        chan.exec_command('bash --login -c "' + cmdline + '"')

        # Fetch build process output ...
        try:
            cmd_stdout = chan.makefile('rb', 1024)
            output = bytes()
            output += common.get_android_tools_version_log(build.ndk_path()).encode()
            while not chan.exit_status_ready():
                line = cmd_stdout.readline()
                if line:
                    if options.verbose:
                        logging.debug("buildserver > " + str(line, 'utf-8').rstrip())
                    output += line
                else:
                    time.sleep(0.05)
            for line in cmd_stdout.readlines():
                if options.verbose:
                    logging.debug("buildserver > " + str(line, 'utf-8').rstrip())
                output += line
        finally:
            cmd_stdout.close()

        # Check build process exit status ...
        logging.info("...getting exit status")
        returncode = chan.recv_exit_status()
        if returncode != 0:
            if timeout_event.is_set():
                message = "Timeout exceeded! Build VM force-stopped for {0}:{1}"
            else:
                message = "Build.py failed on server for {0}:{1}"
            raise BuildException(message.format(app.id, build.versionName),
                                 None if options.verbose else str(output, 'utf-8'))

        # Retreive logs...
        toolsversion_log = common.get_toolsversion_logname(app, build)
        try:
            ftp.chdir(os.path.join(homedir, log_dir))
            ftp.get(toolsversion_log, os.path.join(log_dir, toolsversion_log))
            logging.debug('retrieved %s', toolsversion_log)
        except Exception as e:
            logging.warn('could not get %s from builder vm: %s' % (toolsversion_log, e))

        # Retrieve the built files...
        logging.info("Retrieving build output...")
        if force:
            ftp.chdir(homedir + '/tmp')
        else:
            ftp.chdir(homedir + '/unsigned')
        apkfile = common.get_release_filename(app, build)
        tarball = common.getsrcname(app, build)
        try:
            ftp.get(apkfile, os.path.join(output_dir, apkfile))
            if not options.notarball:
                ftp.get(tarball, os.path.join(output_dir, tarball))
        except Exception:
            raise BuildException(
                "Build failed for {0}:{1} - missing output files".format(
                    app.id, build.versionName), None if options.verbose else str(output, 'utf-8'))
        ftp.close()

    finally:
        # Suspend the build server.
        vm = vmtools.get_build_vm('builder')
        vm.suspend()


def force_gradle_build_tools(build_dir, build_tools):
    for root, dirs, files in os.walk(build_dir):
        for filename in files:
            if not filename.endswith('.gradle'):
                continue
            path = os.path.join(root, filename)
            if not os.path.isfile(path):
                continue
            logging.debug("Forcing build-tools %s in %s" % (build_tools, path))
            common.regsub_file(r"""(\s*)buildToolsVersion([\s=]+).*""",
                               r"""\1buildToolsVersion\2'%s'""" % build_tools,
                               path)


def transform_first_char(string, method):
    """Uses method() on the first character of string."""
    if len(string) == 0:
        return string
    if len(string) == 1:
        return method(string)
    return method(string[0]) + string[1:]


def has_native_code(apkobj):
    """aapt checks if there are architecture folders under the lib/ folder
    so we are simulating the same behaviour"""
    arch_re = re.compile("^lib/(.*)/.*$")
    arch = [file for file in apkobj.get_files() if arch_re.match(file)]
    return False if not arch else True


def get_apk_metadata_aapt(apkfile):
    """aapt function to extract versionCode, versionName, packageName and nativecode"""
    vercode = None
    version = None
    foundid = None
    nativecode = None

    p = SdkToolsPopen(['aapt', 'dump', 'badging', apkfile], output=False)

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

    return vercode, version, foundid, nativecode


def get_apk_metadata_androguard(apkfile):
    """androguard function to extract versionCode, versionName, packageName and nativecode"""
    try:
        from androguard.core.bytecodes.apk import APK
        apkobject = APK(apkfile)
    except ImportError:
        raise BuildException("androguard library is not installed and aapt binary not found")
    except FileNotFoundError:
        raise BuildException("Could not open apk file for metadata analysis")

    if not apkobject.is_valid_APK():
        raise BuildException("Invalid APK provided")

    foundid = apkobject.get_package()
    vercode = apkobject.get_androidversion_code()
    version = apkobject.get_androidversion_name()
    nativecode = has_native_code(apkobject)

    return vercode, version, foundid, nativecode


def get_metadata_from_apk(app, build, apkfile):
    """get the required metadata from the built APK"""

    if common.SdkToolsPopen(['aapt', 'version'], output=False):
        vercode, version, foundid, nativecode = get_apk_metadata_aapt(apkfile)
    else:
        vercode, version, foundid, nativecode = get_apk_metadata_androguard(apkfile)

    # Ignore empty strings or any kind of space/newline chars that we don't
    # care about
    if nativecode is not None:
        nativecode = nativecode.strip()
        nativecode = None if not nativecode else nativecode

    if build.buildjni and build.buildjni != ['no']:
        if nativecode is None:
            raise BuildException("Native code should have been built but none was packaged")
    if build.novcheck:
        vercode = build.versionCode
        version = build.versionName
    if not version or not vercode:
        raise BuildException("Could not find version information in build in output")
    if not foundid:
        raise BuildException("Could not find package ID in output")
    if foundid != app.id:
        raise BuildException("Wrong package ID - build " + foundid + " but expected " + app.id)

    return vercode, version


def build_local(app, build, vcs, build_dir, output_dir, log_dir, srclib_dir, extlib_dir, tmp_dir, force, onserver, refresh):
    """Do a build locally."""
    ndk_path = build.ndk_path()
    if build.ndk or (build.buildjni and build.buildjni != ['no']):
        if not ndk_path:
            logging.critical("Android NDK version '%s' could not be found!" % build.ndk or 'r12b')
            logging.critical("Configured versions:")
            for k, v in config['ndk_paths'].items():
                if k.endswith("_orig"):
                    continue
                logging.critical("  %s: %s" % (k, v))
            raise FDroidException()
        elif not os.path.isdir(ndk_path):
            logging.critical("Android NDK '%s' is not a directory!" % ndk_path)
            raise FDroidException()

    common.set_FDroidPopen_env(build)

    # create ..._toolsversion.log when running in builder vm
    if onserver:
        # before doing anything, run the sudo commands to setup the VM
        if build.sudo:
            logging.info("Running 'sudo' commands in %s" % os.getcwd())

            p = FDroidPopen(['sudo', 'bash', '-x', '-c', build.sudo])
            if p.returncode != 0:
                raise BuildException("Error running sudo command for %s:%s" %
                                     (app.id, build.versionName), p.output)

        p = FDroidPopen(['sudo', 'passwd', '--lock', 'root'])
        if p.returncode != 0:
            raise BuildException("Error locking root account for %s:%s" %
                                 (app.id, build.versionName), p.output)

        p = FDroidPopen(['sudo', 'SUDO_FORCE_REMOVE=yes', 'dpkg', '--purge', 'sudo'])
        if p.returncode != 0:
            raise BuildException("Error removing sudo for %s:%s" %
                                 (app.id, build.versionName), p.output)

        log_path = os.path.join(log_dir,
                                common.get_toolsversion_logname(app, build))
        with open(log_path, 'w') as f:
            f.write(common.get_android_tools_version_log(build.ndk_path()))
    else:
        if build.sudo:
            logging.warning('%s:%s runs this on the buildserver with sudo:\n\t%s'
                            % (app.id, build.versionName, build.sudo))

    # Prepare the source code...
    root_dir, srclibpaths = common.prepare_source(vcs, app, build,
                                                  build_dir, srclib_dir,
                                                  extlib_dir, onserver, refresh)

    # We need to clean via the build tool in case the binary dirs are
    # different from the default ones
    p = None
    gradletasks = []
    bmethod = build.build_method()
    if bmethod == 'maven':
        logging.info("Cleaning Maven project...")
        cmd = [config['mvn3'], 'clean', '-Dandroid.sdk.path=' + config['sdk_path']]

        if '@' in build.maven:
            maven_dir = os.path.join(root_dir, build.maven.split('@', 1)[1])
            maven_dir = os.path.normpath(maven_dir)
        else:
            maven_dir = root_dir

        p = FDroidPopen(cmd, cwd=maven_dir)

    elif bmethod == 'gradle':

        logging.info("Cleaning Gradle project...")

        if build.preassemble:
            gradletasks += build.preassemble

        flavours = build.gradle
        if flavours == ['yes']:
            flavours = []

        flavours_cmd = ''.join([transform_first_char(flav, str.upper) for flav in flavours])

        gradletasks += ['assemble' + flavours_cmd + 'Release']

        if config['force_build_tools']:
            force_gradle_build_tools(build_dir, config['build_tools'])
            for name, number, libpath in srclibpaths:
                force_gradle_build_tools(libpath, config['build_tools'])

        cmd = [config['gradle']]
        if build.gradleprops:
            cmd += ['-P' + kv for kv in build.gradleprops]

        cmd += ['clean']

        p = FDroidPopen(cmd, cwd=root_dir)

    elif bmethod == 'buildozer':
        pass

    elif bmethod == 'ant':
        logging.info("Cleaning Ant project...")
        p = FDroidPopen(['ant', 'clean'], cwd=root_dir)

    if p is not None and p.returncode != 0:
        raise BuildException("Error cleaning %s:%s" %
                             (app.id, build.versionName), p.output)

    for root, dirs, files in os.walk(build_dir):

        def del_dirs(dl):
            for d in dl:
                if d in dirs:
                    shutil.rmtree(os.path.join(root, d))

        def del_files(fl):
            for f in fl:
                if f in files:
                    os.remove(os.path.join(root, f))

        if any(f in files for f in ['build.gradle', 'settings.gradle']):
            # Even when running clean, gradle stores task/artifact caches in
            # .gradle/ as binary files. To avoid overcomplicating the scanner,
            # manually delete them, just like `gradle clean` should have removed
            # the build/* dirs.
            del_dirs([os.path.join('build', 'android-profile'),
                      os.path.join('build', 'generated'),
                      os.path.join('build', 'intermediates'),
                      os.path.join('build', 'outputs'),
                      os.path.join('build', 'reports'),
                      os.path.join('build', 'tmp'),
                      '.gradle'])
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
        count = scanner.scan_source(build_dir, build)
        if count > 0:
            if force:
                logging.warning(ngettext('Scanner found {} problem',
                                         'Scanner found {} problems', count).format(count))
            else:
                raise BuildException(ngettext(
                    "Can't build due to {} error while scanning",
                    "Can't build due to {} errors while scanning", count).format(count))

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
                                 (app.id, build.versionName), p.output)

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
                raise BuildException("NDK build failed for %s:%s" % (app.id, build.versionName), p.output)

    p = None
    # Build the release...
    if bmethod == 'maven':
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

    elif bmethod == 'buildozer':
        logging.info("Building Kivy project using buildozer...")

        # parse buildozer.spez
        spec = os.path.join(root_dir, 'buildozer.spec')
        if not os.path.exists(spec):
            raise BuildException("Expected to find buildozer-compatible spec at {0}"
                                 .format(spec))
        defaults = {'orientation': 'landscape', 'icon': '',
                    'permissions': '', 'android.api': "19"}
        bconfig = ConfigParser(defaults, allow_no_value=True)
        bconfig.read(spec)

        # update spec with sdk and ndk locations to prevent buildozer from
        # downloading.
        loc_ndk = common.env['ANDROID_NDK']
        loc_sdk = common.env['ANDROID_SDK']
        if loc_ndk == '$ANDROID_NDK':
            loc_ndk = loc_sdk + '/ndk-bundle'

        bc_ndk = None
        bc_sdk = None
        try:
            bc_ndk = bconfig.get('app', 'android.sdk_path')
        except Exception:
            pass
        try:
            bc_sdk = bconfig.get('app', 'android.ndk_path')
        except Exception:
            pass

        if bc_sdk is None:
            bconfig.set('app', 'android.sdk_path', loc_sdk)
        if bc_ndk is None:
            bconfig.set('app', 'android.ndk_path', loc_ndk)

        fspec = open(spec, 'w')
        bconfig.write(fspec)
        fspec.close()

        logging.info("sdk_path = %s" % loc_sdk)
        logging.info("ndk_path = %s" % loc_ndk)

        p = None
        # execute buildozer
        cmd = ['buildozer', 'android', 'release']
        try:
            p = FDroidPopen(cmd, cwd=root_dir)
        except Exception:
            pass

        # buidozer not installed ? clone repo and run
        if (p is None or p.returncode != 0):
            cmd = ['git', 'clone', 'https://github.com/kivy/buildozer.git']
            p = subprocess.Popen(cmd, cwd=root_dir, shell=False)
            p.wait()
            if p.returncode != 0:
                raise BuildException("Distribute build failed")

            cmd = ['python', 'buildozer/buildozer/scripts/client.py', 'android', 'release']
            p = FDroidPopen(cmd, cwd=root_dir)

        # expected to fail.
        # Signing will fail if not set by environnment vars (cf. p4a docs).
        # But the unsigned apk will be ok.
        p.returncode = 0

    elif bmethod == 'gradle':
        logging.info("Building Gradle project...")

        cmd = [config['gradle']]
        if build.gradleprops:
            cmd += ['-P' + kv for kv in build.gradleprops]

        cmd += gradletasks

        p = FDroidPopen(cmd, cwd=root_dir)

    elif bmethod == 'ant':
        logging.info("Building Ant project...")
        cmd = ['ant']
        if build.antcommands:
            cmd += build.antcommands
        else:
            cmd += ['release']
        p = FDroidPopen(cmd, cwd=root_dir)

        bindir = os.path.join(root_dir, 'bin')

    if p is not None and p.returncode != 0:
        raise BuildException("Build failed for %s:%s" % (app.id, build.versionName), p.output)
    logging.info("Successfully built version " + build.versionName + ' of ' + app.id)

    omethod = build.output_method()
    if omethod == 'maven':
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

    elif omethod == 'buildozer':
        src = None
        for apks_dir in [
                os.path.join(root_dir, '.buildozer', 'android', 'platform', 'build', 'dists', bconfig.get('app', 'title'), 'bin'),
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

    elif omethod == 'gradle':
        src = None
        apk_dirs = [
            # gradle plugin >= 3.0
            os.path.join(root_dir, 'build', 'outputs', 'apk', 'release'),
            # gradle plugin < 3.0 and >= 0.11
            os.path.join(root_dir, 'build', 'outputs', 'apk'),
            # really old path
            os.path.join(root_dir, 'build', 'apk'),
            ]
        # If we build with gradle flavours with gradle plugin >= 3.0 the apk will be in
        # a subdirectory corresponding to the flavour command used, but with different
        # capitalization.
        if flavours_cmd:
            apk_dirs.append(os.path.join(root_dir, 'build', 'outputs', 'apk', transform_first_char(flavours_cmd, str.lower), 'release'))
        for apks_dir in apk_dirs:
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

    elif omethod == 'ant':
        stdout_apk = '\n'.join([
            line for line in p.output.splitlines() if '.apk' in line])
        src = re.match(r".*^.*Creating (.+) for release.*$.*", stdout_apk,
                       re.S | re.M).group(1)
        src = os.path.join(bindir, src)
    elif omethod == 'raw':
        output_path = common.replace_build_vars(build.output, build)
        globpath = os.path.join(root_dir, output_path)
        apks = glob.glob(globpath)
        if len(apks) > 1:
            raise BuildException('Multiple apks match %s' % globpath, '\n'.join(apks))
        if len(apks) < 1:
            raise BuildException('No apks match %s' % globpath)
        src = os.path.normpath(apks[0])

    # Make sure it's not debuggable...
    if common.is_apk_and_debuggable(src):
        raise BuildException("APK is debuggable")

    # By way of a sanity check, make sure the version and version
    # code in our new apk match what we expect...
    logging.debug("Checking " + src)
    if not os.path.exists(src):
        raise BuildException("Unsigned apk is not at expected location of " + src)

    if common.get_file_extension(src) == 'apk':
        vercode, version = get_metadata_from_apk(app, build, src)
        if version != build.versionName or vercode != build.versionCode:
            raise BuildException(("Unexpected version/version code in output;"
                                  " APK: '%s' / '%s', "
                                  " Expected: '%s' / '%s'")
                                 % (version, str(vercode), build.versionName,
                                    str(build.versionCode)))

    # Copy the unsigned apk to our destination directory for further
    # processing (by publish.py)...
    dest = os.path.join(output_dir, common.get_release_filename(app, build))
    shutil.copyfile(src, dest)

    # Move the source tarball into the output directory...
    if output_dir != tmp_dir and not options.notarball:
        shutil.move(os.path.join(tmp_dir, tarname),
                    os.path.join(output_dir, tarname))


def trybuild(app, build, build_dir, output_dir, log_dir, also_check_dir,
             srclib_dir, extlib_dir, tmp_dir, repo_dir, vcs, test,
             server, force, onserver, refresh):
    """
    Build a particular version of an application, if it needs building.

    :param output_dir: The directory where the build output will go. Usually
       this is the 'unsigned' directory.
    :param repo_dir: The repo directory - used for checking if the build is
       necessary.
    :param also_check_dir: An additional location for checking if the build
       is necessary (usually the archive repo)
    :param test: True if building in test mode, in which case the build will
       always happen, even if the output already exists. In test mode, the
       output directory should be a temporary location, not any of the real
       ones.

    :returns: True if the build was done, False if it wasn't necessary.
    """

    dest_file = common.get_release_filename(app, build)

    dest = os.path.join(output_dir, dest_file)
    dest_repo = os.path.join(repo_dir, dest_file)

    if not test:
        if os.path.exists(dest) or os.path.exists(dest_repo):
            return False

        if also_check_dir:
            dest_also = os.path.join(also_check_dir, dest_file)
            if os.path.exists(dest_also):
                return False

    if build.disable and not options.force:
        return False

    logging.info("Building version %s (%s) of %s" % (
        build.versionName, build.versionCode, app.id))

    if server:
        # When using server mode, still keep a local cache of the repo, by
        # grabbing the source now.
        vcs.gotorevision(build.commit, refresh)

        build_server(app, build, vcs, build_dir, output_dir, log_dir, force)
    else:
        build_local(app, build, vcs, build_dir, output_dir, log_dir, srclib_dir, extlib_dir, tmp_dir, force, onserver, refresh)
    return True


def force_halt_build(timeout):
    """Halt the currently running Vagrant VM, to be called from a Timer"""
    logging.error(_('Force halting build after {0} sec timeout!').format(timeout))
    timeout_event.set()
    vm = vmtools.get_build_vm('builder')
    vm.halt()


def parse_commandline():
    """Parse the command line. Returns options, parser."""

    parser = ArgumentParser(usage="%(prog)s [options] [APPID[:VERCODE] [APPID[:VERCODE] ...]]")
    common.setup_global_opts(parser)
    parser.add_argument("appid", nargs='*', help=_("applicationId with optional versionCode in the form APPID[:VERCODE]"))
    parser.add_argument("-l", "--latest", action="store_true", default=False,
                        help=_("Build only the latest version of each package"))
    parser.add_argument("-s", "--stop", action="store_true", default=False,
                        help=_("Make the build stop on exceptions"))
    parser.add_argument("-t", "--test", action="store_true", default=False,
                        help=_("Test mode - put output in the tmp directory only, and always build, even if the output already exists."))
    parser.add_argument("--server", action="store_true", default=False,
                        help=_("Use build server"))
    parser.add_argument("--reset-server", action="store_true", default=False,
                        help=_("Reset and create a brand new build server, even if the existing one appears to be ok."))
    parser.add_argument("--on-server", dest="onserver", action="store_true", default=False,
                        help=_("Specify that we're running on the build server"))
    parser.add_argument("--skip-scan", dest="skipscan", action="store_true", default=False,
                        help=_("Skip scanning the source code for binaries and other problems"))
    parser.add_argument("--dscanner", action="store_true", default=False,
                        help=_("Setup an emulator, install the APK on it and perform a Drozer scan"))
    parser.add_argument("--no-tarball", dest="notarball", action="store_true", default=False,
                        help=_("Don't create a source tarball, useful when testing a build"))
    parser.add_argument("--no-refresh", dest="refresh", action="store_false", default=True,
                        help=_("Don't refresh the repository, useful when testing a build with no internet connection"))
    parser.add_argument("-f", "--force", action="store_true", default=False,
                        help=_("Force build of disabled apps, and carries on regardless of scan problems. Only allowed in test mode."))
    parser.add_argument("-a", "--all", action="store_true", default=False,
                        help=_("Build all applications available"))
    parser.add_argument("-w", "--wiki", default=False, action="store_true",
                        help=_("Update the wiki"))
    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    metadata.warnings_action = options.W

    # Force --stop with --on-server to get correct exit code
    if options.onserver:
        options.stop = True

    if options.force and not options.test:
        parser.error("option %s: Force is only allowed in test mode" % "force")

    return options, parser


options = None
config = None
buildserverid = None
fdroidserverid = None
start_timestamp = time.gmtime()
timeout_event = threading.Event()


def main():

    global options, config, buildserverid, fdroidserverid

    options, parser = parse_commandline()

    # The defaults for .fdroid.* metadata that is included in a git repo are
    # different than for the standard metadata/ layout because expectations
    # are different.  In this case, the most common user will be the app
    # developer working on the latest update of the app on their own machine.
    local_metadata_files = common.get_local_metadata_files()
    if len(local_metadata_files) == 1:  # there is local metadata in an app's source
        config = dict(common.default_config)
        # `fdroid build` should build only the latest version by default since
        # most of the time the user will be building the most recent update
        if not options.all:
            options.latest = True
    elif len(local_metadata_files) > 1:
        raise FDroidException("Only one local metadata file allowed! Found: "
                              + " ".join(local_metadata_files))
    else:
        if not os.path.isdir('metadata') and len(local_metadata_files) == 0:
            raise FDroidException("No app metadata found, nothing to process!")
        if not options.appid and not options.all:
            parser.error("option %s: If you really want to build all the apps, use --all" % "all")

    config = common.read_config(options)

    if config['build_server_always']:
        options.server = True
    if options.reset_server and not options.server:
        parser.error("option %s: Using --reset-server without --server makes no sense" % "reset-server")

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
    pkgs = common.read_pkg_args(options.appid, True)
    allapps = metadata.read_metadata(not options.onserver, pkgs, options.refresh, sort_by_time=True)
    apps = common.read_app_args(options.appid, allapps, True)

    for appid, app in list(apps.items()):
        if (app.Disabled and not options.force) or not app.RepoType or not app.builds:
            del apps[appid]

    if not apps:
        raise FDroidException("No apps to process.")

    # make sure enough open files are allowed to process everything
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if len(apps) > soft:
        try:
            soft = len(apps) * 2
            if soft > hard:
                soft = hard
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
            logging.debug(_('Set open file limit to {integer}')
                          .format(integer=soft))
        except (OSError, ValueError) as e:
            logging.warning(_('Setting open file limit failed: ') + str(e))

    if options.latest:
        for app in apps.values():
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
    # Only build for 36 hours, then stop gracefully.
    endtime = time.time() + 36 * 60 * 60
    max_build_time_reached = False
    for appid, app in apps.items():

        first = True

        for build in app.builds:
            if time.time() > endtime:
                max_build_time_reached = True
                break

            # Enable watchdog timer (2 hours by default).
            if build.timeout is None:
                timeout = 7200
            else:
                timeout = int(build.timeout)
            if options.server and timeout > 0:
                logging.debug(_('Setting {0} sec timeout for this build').format(timeout))
                timer = threading.Timer(timeout, force_halt_build, [timeout])
                timeout_event.clear()
                timer.start()
            else:
                timer = None

            wikilog = None
            build_starttime = common.get_wiki_timestamp()
            tools_version_log = ''
            if not options.onserver:
                tools_version_log = common.get_android_tools_version_log(build.ndk_path())
            try:

                # For the first build of a particular app, we need to set up
                # the source repo. We can reuse it on subsequent builds, if
                # there are any.
                if first:
                    vcs, build_dir = common.setup_vcs(app)
                    first = False

                logging.info("Using %s" % vcs.clientversion())
                logging.debug("Checking " + build.versionName)
                if trybuild(app, build, build_dir, output_dir, log_dir,
                            also_check_dir, srclib_dir, extlib_dir,
                            tmp_dir, repo_dir, vcs, options.test,
                            options.server, options.force,
                            options.onserver, options.refresh):
                    toolslog = os.path.join(log_dir,
                                            common.get_toolsversion_logname(app, build))
                    if not options.onserver and os.path.exists(toolslog):
                        with open(toolslog, 'r') as f:
                            tools_version_log = ''.join(f.readlines())
                        os.remove(toolslog)

                    if app.Binaries is not None:
                        # This is an app where we build from source, and
                        # verify the apk contents against a developer's
                        # binary. We get that binary now, and save it
                        # alongside our built one in the 'unsigend'
                        # directory.
                        url = app.Binaries
                        url = url.replace('%v', build.versionName)
                        url = url.replace('%c', str(build.versionCode))
                        logging.info("...retrieving " + url)
                        of = re.sub(r'.apk$', '.binary.apk', common.get_release_filename(app, build))
                        of = os.path.join(output_dir, of)
                        try:
                            net.download_file(url, local_filename=of)
                        except requests.exceptions.HTTPError as e:
                            raise FDroidException(
                                'Downloading Binaries from %s failed. %s' % (url, e))

                        # Now we check weather the build can be verified to
                        # match the supplied binary or not. Should the
                        # comparison fail, we mark this build as a failure
                        # and remove everything from the unsigend folder.
                        with tempfile.TemporaryDirectory() as tmpdir:
                            unsigned_apk = \
                                common.get_release_filename(app, build)
                            unsigned_apk = \
                                os.path.join(output_dir, unsigned_apk)
                            compare_result = \
                                common.verify_apks(of, unsigned_apk, tmpdir)
                            if compare_result:
                                logging.debug('removing %s', unsigned_apk)
                                os.remove(unsigned_apk)
                                logging.debug('removing %s', of)
                                os.remove(of)
                                compare_result = compare_result.split('\n')
                                line_count = len(compare_result)
                                compare_result = compare_result[:299]
                                if line_count > len(compare_result):
                                    line_difference = \
                                        line_count - len(compare_result)
                                    compare_result.append('%d more lines ...' %
                                                          line_difference)
                                compare_result = '\n'.join(compare_result)
                                raise FDroidException('compared built binary '
                                                      'to supplied reference '
                                                      'binary but failed',
                                                      compare_result)
                            else:
                                logging.info('compared built binary to '
                                             'supplied reference binary '
                                             'successfully')

                    build_succeeded.append(app)
                    wikilog = "Build succeeded"

            except VCSException as vcse:
                reason = str(vcse).split('\n', 1)[0] if options.verbose else str(vcse)
                logging.error("VCS error while building app %s: %s" % (
                    appid, reason))
                if options.stop:
                    logging.debug("Error encoutered, stopping by user request.")
                    sys.exit(1)
                failed_apps[appid] = vcse
                wikilog = str(vcse)
            except FDroidException as e:
                with open(os.path.join(log_dir, appid + '.log'), 'a+') as f:
                    f.write('\n\n============================================================\n')
                    f.write('versionCode: %s\nversionName: %s\ncommit: %s\n' %
                            (build.versionCode, build.versionName, build.commit))
                    f.write('Build completed at '
                            + common.get_wiki_timestamp() + '\n')
                    f.write('\n' + tools_version_log + '\n')
                    f.write(str(e))
                logging.error("Could not build app %s: %s" % (appid, e))
                if options.stop:
                    logging.debug("Error encoutered, stopping by user request.")
                    sys.exit(1)
                failed_apps[appid] = e
                wikilog = e.get_wikitext()
            except Exception as e:
                logging.error("Could not build app %s due to unknown error: %s" % (
                    appid, traceback.format_exc()))
                if options.stop:
                    logging.debug("Error encoutered, stopping by user request.")
                    sys.exit(1)
                failed_apps[appid] = e
                wikilog = str(e)

            if options.wiki and wikilog:
                try:
                    # Write a page with the last build log for this version code
                    lastbuildpage = appid + '/lastbuild_' + build.versionCode
                    newpage = site.Pages[lastbuildpage]
                    with open(os.path.join('tmp', 'fdroidserverid')) as fp:
                        fdroidserverid = fp.read().rstrip()
                    txt = "* build session started at " + common.get_wiki_timestamp(start_timestamp) + '\n' \
                          + "* this build started at " + build_starttime + '\n' \
                          + "* this build completed at " + common.get_wiki_timestamp() + '\n' \
                          + common.get_git_describe_link() \
                          + '* fdroidserverid: [https://gitlab.com/fdroid/fdroidserver/commit/' \
                          + fdroidserverid + ' ' + fdroidserverid + ']\n\n'
                    if buildserverid:
                        txt += '* buildserverid: [https://gitlab.com/fdroid/fdroidserver/commit/' \
                               + buildserverid + ' ' + buildserverid + ']\n\n'
                    txt += tools_version_log + '\n\n'
                    txt += '== Build Log ==\n\n' + wikilog
                    newpage.save(txt, summary='Build log')
                    # Redirect from /lastbuild to the most recent build log
                    newpage = site.Pages[appid + '/lastbuild']
                    newpage.save('#REDIRECT [[' + lastbuildpage + ']]', summary='Update redirect')
                except Exception as e:
                    logging.error("Error while attempting to publish build log: %s" % e)

            if timer:
                timer.cancel()  # kill the watchdog timer

        if max_build_time_reached:
            logging.info("Stopping after global build timeout...")
            break

    for app in build_succeeded:
        logging.info("success: %s" % (app.id))

    if not options.verbose:
        for fa in failed_apps:
            logging.info("Build for app %s failed:\n%s" % (fa, failed_apps[fa]))

    # perform a drozer scan of all successful builds
    if options.dscanner and build_succeeded:
        from .dscanner import DockerDriver

        docker = DockerDriver()

        try:
            for app in build_succeeded:

                logging.info("Need to sign the app before we can install it.")
                subprocess.call("fdroid publish {0}".format(app.id))

                apk_path = None

                for f in os.listdir(repo_dir):
                    if f.endswith('.apk') and f.startswith(app.id):
                        apk_path = os.path.join(repo_dir, f)
                        break

                if not apk_path:
                    raise Exception("No signed APK found at path: {path}".format(path=apk_path))

                if not os.path.isdir(repo_dir):
                    logging.critical("directory does not exists '{path}'".format(path=repo_dir))
                    sys.exit(1)

                logging.info("Performing Drozer scan on {0}.".format(app))
                docker.perform_drozer_scan(apk_path, app.id, repo_dir)
        except Exception as e:
            logging.error(str(e))
            logging.error("An exception happened. Making sure to clean up")
        else:
            logging.info("Scan succeeded.")

        logging.info("Cleaning up after ourselves.")
        docker.clean()

    logging.info(_("Finished"))
    if len(build_succeeded) > 0:
        logging.info(ngettext("{} build succeeded",
                              "{} builds succeeded", len(build_succeeded)).format(len(build_succeeded)))
    if len(failed_apps) > 0:
        logging.info(ngettext("{} build failed",
                              "{} builds failed", len(failed_apps)).format(len(failed_apps)))

    if options.wiki:
        wiki_page_path = 'build_' + time.strftime('%s', start_timestamp)
        newpage = site.Pages[wiki_page_path]
        txt = ''
        txt += "* command line: <code>%s</code>\n" % ' '.join(sys.argv)
        txt += "* started at %s\n" % common.get_wiki_timestamp(start_timestamp)
        txt += "* completed at %s\n" % common.get_wiki_timestamp()
        if buildserverid:
            txt += ('* buildserverid: [https://gitlab.com/fdroid/fdroidserver/commit/{id} {id}]\n'
                    .format(id=buildserverid))
        if fdroidserverid:
            txt += ('* fdroidserverid: [https://gitlab.com/fdroid/fdroidserver/commit/{id} {id}]\n'
                    .format(id=fdroidserverid))
        if os.cpu_count():
            txt += "* host processors: %d\n" % os.cpu_count()
        if os.path.isfile('/proc/meminfo') and os.access('/proc/meminfo', os.R_OK):
            with open('/proc/meminfo') as fp:
                for line in fp:
                    m = re.search(r'MemTotal:\s*([0-9].*)', line)
                    if m:
                        txt += "* host RAM: %s\n" % m.group(1)
                        break
        txt += "* successful builds: %d\n" % len(build_succeeded)
        txt += "* failed builds: %d\n" % len(failed_apps)
        txt += "\n\n"
        newpage.save(txt, summary='Run log')
        newpage = site.Pages['build']
        newpage.save('#REDIRECT [[' + wiki_page_path + ']]', summary='Update redirect')

    # hack to ensure this exits, even is some threads are still running
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
