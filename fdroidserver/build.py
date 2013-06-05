#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# build.py - part of the FDroid server tools
# Copyright (C) 2010-12, Ciaran Gultnieks, ciaran@ciarang.com
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
import subprocess
import re
import tarfile
import traceback
import time
import json
from optparse import OptionParser

import common
from common import BuildException
from common import VCSException


def get_builder_vm_id():
    with open(os.path.join('builder', '.vagrant')) as vf:
        v = json.load(vf)
    return v['active']['default']


# Note that 'force' here also implies test mode.
def build_server(app, thisbuild, vcs, build_dir, output_dir, sdk_path, force):
    """Do a build on the build server."""

    import ssh

    # Reset existing builder machine to a clean state if possible.
    vm_ok = False
    if not options.resetserver:
        print "Checking for valid existing build server"
        if (os.path.exists(os.path.join('builder', 'Vagrantfile')) and 
                os.path.exists(os.path.join('builder', '.vagrant'))):
            print "...VM is present"
            p = subprocess.Popen(['VBoxManage', 'snapshot', get_builder_vm_id(), 'list', '--details'],
                cwd='builder', stdout=subprocess.PIPE)
            output = p.communicate()[0]
            if output.find('fdroidclean') != -1:
                print "...snapshot exists - resetting build server to clean state"
                p = subprocess.Popen(['vagrant', 'status'],
                    cwd='builder', stdout=subprocess.PIPE)
                output = p.communicate()[0]
                if output.find('running') != -1:
                    print "...suspending"
                    subprocess.call(['vagrant', 'suspend'], cwd='builder')
                if subprocess.call(['VBoxManage', 'snapshot', get_builder_vm_id(), 'restore', 'fdroidclean'],
                    cwd='builder') == 0:
                    print "...reset to snapshot - server is valid"
                    if subprocess.call(['vagrant', 'up'], cwd='builder') != 0:
                        raise BuildException("Failed to start build server")
                    vm_ok = True
                else:
                    print "...failed to reset to snapshot"
            else:
                print "...snapshot doesn't exist - vagrant snap said:\n" + output

    # If we can't use the existing machine for any reason, make a
    # new one from scratch.
    if not vm_ok:
        if os.path.exists('builder'):
            print "Removing broken/incomplete/unwanted build server"
            subprocess.call(['vagrant', 'destroy', '-f'], cwd='builder')
            shutil.rmtree('builder')
        os.mkdir('builder')
        with open('builder/Vagrantfile', 'w') as vf:
            vf.write('Vagrant::Config.run do |config|\n')
            vf.write('config.vm.box = "buildserver"\n')
            vf.write('config.vm.customize ["modifyvm", :id, "--memory", "768"]\n')
            vf.write('end\n')

        print "Starting new build server"
        if subprocess.call(['vagrant', 'up'], cwd='builder') != 0:
            raise BuildException("Failed to start build server")

        # Open SSH connection to make sure it's working and ready...
        print "Connecting to virtual machine..."
        if subprocess.call('vagrant ssh-config >sshconfig',
                cwd='builder', shell=True) != 0:
            raise BuildException("Error getting ssh config")
        vagranthost = 'default' # Host in ssh config file
        sshconfig = ssh.SSHConfig()
        sshf = open('builder/sshconfig', 'r')
        sshconfig.parse(sshf)
        sshf.close()
        sshconfig = sshconfig.lookup(vagranthost)
        sshs = ssh.SSHClient()
        sshs.set_missing_host_key_policy(ssh.AutoAddPolicy())
        idfile = sshconfig['identityfile']
        if idfile.startswith('"') and idfile.endswith('"'):
            idfile = idfile[1:-1]
        sshs.connect(sshconfig['hostname'], username=sshconfig['user'],
            port=int(sshconfig['port']), timeout=300, look_for_keys=False,
            key_filename=idfile)
        sshs.close()

        print "Saving clean state of new build server"
        subprocess.call(['vagrant', 'suspend'], cwd='builder')
        if subprocess.call(['VBoxManage', 'snapshot', get_builder_vm_id(), 'take', 'fdroidclean'],
                cwd='builder') != 0:
            raise BuildException("Failed to take snapshot")
        print "Restarting new build server"
        if subprocess.call(['vagrant', 'up'], cwd='builder') != 0:
            raise BuildException("Failed to start build server")
        # Make sure it worked...
        p = subprocess.Popen(['VBoxManage', 'snapshot', get_builder_vm_id(), 'list', '--details'],
            cwd='builder', stdout=subprocess.PIPE)
        output = p.communicate()[0]
        if output.find('fdroidclean') == -1:
            raise BuildException("Failed to take snapshot.")

    try:

        # Get SSH configuration settings for us to connect...
        print "Getting ssh configuration..."
        subprocess.call('vagrant ssh-config >sshconfig',
                cwd='builder', shell=True)
        vagranthost = 'default' # Host in ssh config file

        # Load and parse the SSH config...
        sshconfig = ssh.SSHConfig()
        sshf = open('builder/sshconfig', 'r')
        sshconfig.parse(sshf)
        sshf.close()
        sshconfig = sshconfig.lookup(vagranthost)

        # Open SSH connection...
        print "Connecting to virtual machine..."
        sshs = ssh.SSHClient()
        sshs.set_missing_host_key_policy(ssh.AutoAddPolicy())
        idfile = sshconfig['identityfile']
        if idfile.startswith('"') and idfile.endswith('"'):
            idfile = idfile[1:-1]
        sshs.connect(sshconfig['hostname'], username=sshconfig['user'],
            port=int(sshconfig['port']), timeout=300, look_for_keys=False,
            key_filename=idfile)

        # Get an SFTP connection...
        ftp = sshs.open_sftp()
        ftp.get_channel().settimeout(15)

        # Put all the necessary files in place...
        ftp.chdir('/home/vagrant')

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
                    if not os.path.islink(os.path.join(root, rr, ff)):
                        ftp.put(os.path.join(root, rr, ff), ff)
                for i in range(len(rr.split('/'))):
                    ftp.chdir('..')
            ftp.chdir('..')

        print "Preparing server for build..."
        serverpath = os.path.abspath(os.path.dirname(__file__))
        ftp.put(os.path.join(serverpath, 'build.py'), 'build.py')
        ftp.put(os.path.join(serverpath, 'common.py'), 'common.py')
        ftp.put(os.path.join(serverpath, '..', 'config.buildserver.py'), 'config.py')

        # Copy the metadata - just the file for this app...
        ftp.mkdir('metadata')
        ftp.mkdir('srclibs')
        ftp.chdir('metadata')
        ftp.put(os.path.join('metadata', app['id'] + '.txt'),
                app['id'] + '.txt')
        # And patches if there are any...
        if os.path.exists(os.path.join('metadata', app['id'])):
            send_dir(os.path.join('metadata', app['id']))

        ftp.chdir('/home/vagrant')
        # Create the build directory...
        ftp.mkdir('build')
        ftp.chdir('build')
        ftp.mkdir('extlib')
        ftp.mkdir('srclib')
        # Copy the main app source code
        if os.path.exists(build_dir):
            send_dir(build_dir)
        # Copy any extlibs that are required...
        if 'extlibs' in thisbuild:
            ftp.chdir('/home/vagrant/build/extlib')
            for lib in thisbuild['extlibs'].split(';'):
                lp = lib.split('/')
                for d in lp[:-1]:
                    if d not in ftp.listdir():
                        ftp.mkdir(d)
                    ftp.chdir(d)
                ftp.put(os.path.join('build/extlib', lib), lp[-1])
                for _ in lp[:-1]:
                    ftp.chdir('..')
        # Copy any srclibs that are required...
        srclibpaths = []
        if 'srclibs' in thisbuild:
            for lib in thisbuild['srclibs'].split(';'):
                name, _ = lib.split('@')
                if options.verbose:
                    print "Processing srclib '" + name + "'"
                srclibpaths.append((name, common.getsrclib(lib, 'build/srclib', sdk_path, basepath=True, prepare=False)))
        # If one was used for the main source, add that too.
        basesrclib = vcs.getsrclib()
        if basesrclib:
            srclibpaths.append(basesrclib)
        for name, lib in srclibpaths:
            print "Sending srclib '" + lib + "'"
            ftp.chdir('/home/vagrant/build/srclib')
            if not os.path.exists(lib):
                raise BuildException("Missing srclib directory '" + lib + "'")
            send_dir(lib)
            # Copy the metadata file too...
            ftp.chdir('/home/vagrant/srclibs')
            ftp.put(os.path.join('srclibs', name + '.txt'),
                    name + '.txt')


        # Execute the build script...
        print "Starting build..."
        chan = sshs.get_transport().open_session()
        cmdline = 'python build.py --on-server'
        if force:
            cmdline += ' --force --test'
        cmdline += ' -p ' + app['id'] + ' --vercode ' + thisbuild['vercode']
        chan.exec_command(cmdline)
        output = ''
        error = ''
        while not chan.exit_status_ready():
            while chan.recv_ready():
                output += chan.recv(1024)
            while chan.recv_stderr_ready():
                error += chan.recv_stderr(1024)
        print "...getting exit status"
        returncode = chan.recv_exit_status()
        while chan.recv_ready():
            output += chan.recv(1024)
        while chan.recv_stderr_ready():
            error += chan.recv_stderr(1024)
        if returncode != 0:
            raise BuildException("Build.py failed on server for %s:%s" % (app['id'], thisbuild['version']), output.strip(), error.strip())

        # Retrieve the built files...
        print "Retrieving build output..."
        if force:
            ftp.chdir('/home/vagrant/tmp')
        else:
            ftp.chdir('/home/vagrant/unsigned')
        apkfile = app['id'] + '_' + thisbuild['vercode'] + '.apk'
        tarball = app['id'] + '_' + thisbuild['vercode'] + '_src' + '.tar.gz'
        try:
            ftp.get(apkfile, os.path.join(output_dir, apkfile))
            ftp.get(tarball, os.path.join(output_dir, tarball))
        except:
            raise BuildException("Build failed for %s:%s" % (app['id'], thisbuild['version']), output.strip(), error.strip())
        ftp.close()

    finally:

        # Suspend the build server.
        print "Suspending build server"
        subprocess.call(['vagrant', 'suspend'], cwd='builder')


def build_local(app, thisbuild, vcs, build_dir, output_dir, srclib_dir, extlib_dir, tmp_dir, install, force, verbose, onserver):
    """Do a build locally."""

    # Prepare the source code...
    root_dir, srclibpaths = common.prepare_source(vcs, app, thisbuild,
            build_dir, srclib_dir, extlib_dir, sdk_path, ndk_path,
            javacc_path, mvn3, verbose, onserver)

    # Scan before building...
    buildprobs = common.scan_source(build_dir, root_dir, thisbuild)
    if len(buildprobs) > 0:
        print 'Scanner found ' + str(len(buildprobs)) + ' problems:'
        for problem in buildprobs:
            print '...' + problem
        if not force:
            raise BuildException("Can't build due to " +
                str(len(buildprobs)) + " scanned problems")

    # Build the source tarball right before we build the release...
    tarname = app['id'] + '_' + thisbuild['vercode'] + '_src'
    tarball = tarfile.open(os.path.join(tmp_dir,
        tarname + '.tar.gz'), "w:gz")
    def tarexc(f):
        for vcs_dir in ['.svn', '.git', '.hg', '.bzr']:
            if f.endswith(vcs_dir):
                return True
        return False
    tarball.add(build_dir, tarname, exclude=tarexc)
    tarball.close()

    # Run a build command if one is required...
    if 'build' in thisbuild:
        prebuild = thisbuild['build']
        # Substitute source library paths into prebuild commands...
        for name, libpath in srclibpaths:
            libpath = os.path.relpath(libpath, root_dir)
            prebuild = prebuild.replace('$$' + name + '$$', libpath)
        prebuild = prebuild.replace('$$SDK$$', sdk_path)
        prebuild = prebuild.replace('$$NDK$$', ndk_path)
        prebuild = prebuild.replace('$$MVN3$$', mvn3)
        p = subprocess.Popen(prebuild, cwd=root_dir, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if p.returncode != 0:
            raise BuildException("Error running build command", out, err)

    # Build native stuff if required...
    if thisbuild.get('buildjni') not in (None, 'no'):
        jni_components = thisbuild.get('buildjni')
        if jni_components == 'yes':
            jni_components = ['']
        else:
            jni_components = jni_components.split(';')
        ndkbuild = os.path.join(ndk_path, "ndk-build")
        for d in jni_components:
            if options.verbose:
                print "Running ndk-build in " + root_dir + '/' + d
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
            p = subprocess.Popen([ndkbuild], cwd=root_dir + '/' + d,
                    stdout=subprocess.PIPE)
        output = p.communicate()[0]
        if p.returncode != 0:
            print output
            raise BuildException("NDK build failed for %s:%s" % (app['id'], thisbuild['version']))

    # Build the release...
    if 'maven' in thisbuild:
        mvncmd = [mvn3, 'clean', 'package', '-Dandroid.sdk.path=' + sdk_path]
        if install:
            mvncmd += ['-Dandroid.sign.debug=true']
        else:
            mvncmd += ['-Dandroid.sign.debug=false', '-Dandroid.release=true']
        if 'mvnflags' in thisbuild:
            mvncmd += thisbuild['mvnflags']
        p = subprocess.Popen(mvncmd, cwd=root_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        if install:
            antcommands = ['debug','install']
        elif 'antcommand' in thisbuild:
            antcommands = [thisbuild['antcommand']]
        else:
            antcommands = ['release']
        p = subprocess.Popen(['ant'] + antcommands, cwd=root_dir, 
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = p.communicate()
    if p.returncode != 0:
        raise BuildException("Build failed for %s:%s" % (app['id'], thisbuild['version']), output.strip(), error.strip())
    if verbose:
        print output
    if install:
        if 'maven' in thisbuild:
            p = subprocess.Popen([mvn3, 'android:deploy', '-Dandroid.sdk.path=' + sdk_path],
                    cwd=root_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = p.communicate()
            if p.returncode != 0:
                raise BuildException("Warning: Could not deploy %s:%s" % (app['id'], thisbuild['version']), output.strip(), error.strip())
        return
    print "Build successful"

    # Find the apk name in the output...
    if 'bindir' in thisbuild:
        bindir = os.path.join(build_dir, thisbuild['bindir'])
    else:
        bindir = os.path.join(root_dir, 'bin')
    if thisbuild.get('initfun', 'no')  == "yes":
        # Special case (again!) for funambol...
        src = ("funambol-android-sync-client-" +
                thisbuild['version'] + "-unsigned.apk")
        src = os.path.join(bindir, src)
    elif 'maven' in thisbuild:
        m = re.match(r".*^\[INFO\] .*apkbuilder.*/([^/]*)\.apk",
                output, re.S|re.M)
        if not m:
            m = re.match(r".*^\[INFO\] Creating additional unsigned apk file .*/([^/]+)\.apk",
                    output, re.S|re.M)
        if not m:
            # This format is found in com.github.mobile, com.yubico.yubitotp and com.botbrew.basil for example...
            m = re.match(r".*^\[INFO\] [^$]*aapt \[package,[^$]*" + app['id'] + "/" + thisbuild['bindir'] + "/([^/]+)\.ap[_k][,\]]",
                    output, re.S|re.M)
        if not m:
            print output
            raise BuildException('Failed to find output')
        src = m.group(1)
        src = os.path.join(bindir, src) + '.apk'
    else:
        src = re.match(r".*^.*Creating (.+) for release.*$.*", output,
            re.S|re.M).group(1)
        src = os.path.join(bindir, src)

    # Make sure it's not debuggable...
    if not install and common.isApkDebuggable(src, sdk_path):
        raise BuildException("APK is debuggable")

    # By way of a sanity check, make sure the version and version
    # code in our new apk match what we expect...
    print "Checking " + src
    if not os.path.exists(src):
        raise BuildException("Unsigned apk is not at expected location of " + src)
    p = subprocess.Popen([os.path.join(sdk_path, 'platform-tools',
                                    'aapt'),
                        'dump', 'badging', src],
                        stdout=subprocess.PIPE)
    output = p.communicate()[0]
    if thisbuild.get('novcheck', 'no') == "yes":
        vercode = thisbuild['vercode']
        version = thisbuild['version']
    else:
        vercode = None
        version = None
        foundid = None
        for line in output.splitlines():
            if line.startswith("package:"):
                pat = re.compile(".*name='([a-zA-Z0-9._]*)'.*")
                foundid = re.match(pat, line).group(1)
                pat = re.compile(".*versionCode='([0-9]*)'.*")
                vercode = re.match(pat, line).group(1)
                pat = re.compile(".*versionName='([^']*)'.*")
                version = re.match(pat, line).group(1)
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
                             % (version, str(vercode), thisbuild['version'], str(thisbuild['vercode']))
                            )

    # Copy the unsigned apk to our destination directory for further
    # processing (by publish.py)...
    dest = os.path.join(output_dir, app['id'] + '_' +
            thisbuild['vercode'] + '.apk')
    shutil.copyfile(src, dest)

    # Move the source tarball into the output directory...
    if output_dir != tmp_dir:
        tarfilename = tarname + '.tar.gz'
        shutil.move(os.path.join(tmp_dir, tarfilename),
            os.path.join(output_dir, tarfilename))


def trybuild(app, thisbuild, build_dir, output_dir, also_check_dir, srclib_dir, extlib_dir,
        tmp_dir, repo_dir, vcs, test, server, install, force, verbose, onserver):
    """
    Build a particular version of an application, if it needs building.

    Returns True if the build was done, False if it wasn't necessary.
    """

    dest = os.path.join(output_dir, app['id'] + '_' +
            thisbuild['vercode'] + '.apk')
    dest_repo = os.path.join(repo_dir, app['id'] + '_' +
            thisbuild['vercode'] + '.apk')

    if os.path.exists(dest) or (not test and os.path.exists(dest_repo)):
        return False

    if also_check_dir and not test:
        dest_also = os.path.join(also_check_dir, app['id'] + '_' +
                thisbuild['vercode'] + '.apk')
        if os.path.exists(dest_also):
            return False

    if thisbuild['commit'].startswith('!'):
        return False

    print "Building version " + thisbuild['version'] + ' of ' + app['id']

    if server:
        # When using server mode, still keep a local cache of the repo, by
        # grabbing the source now.
        vcs.gotorevision(thisbuild['commit'])

        build_server(app, thisbuild, vcs, build_dir, output_dir, sdk_path, force)
    else:
        build_local(app, thisbuild, vcs, build_dir, output_dir, srclib_dir, extlib_dir, tmp_dir, install, force, verbose, onserver)
    return True


def parse_commandline():
    """Parse the command line. Returns options, args."""

    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-p", "--package", default=None,
                      help="Build only the specified package")
    parser.add_option("-c", "--vercode", default=None,
                      help="Build only the specified version code")
    parser.add_option("-l", "--latest", action="store_true", default=False,
                      help="Build only the latest version code available")
    parser.add_option("-s", "--stop", action="store_true", default=False,
                      help="Make the build stop on exceptions")
    parser.add_option("-t", "--test", action="store_true", default=False,
                      help="Test mode - put output in the tmp directory only.")
    parser.add_option("--server", action="store_true", default=False,
                      help="Use build server")
    parser.add_option("--resetserver", action="store_true", default=False,
                      help="Reset and create a brand new build server, even if the existing one appears to be ok.")
    parser.add_option("--on-server", dest="onserver", action="store_true", default=False,
                      help="Specify that we're running on the build server")
    parser.add_option("-f", "--force", action="store_true", default=False,
                      help="Force build of disabled apps, and carries on regardless of scan problems. Only allowed in test mode.")
    parser.add_option("--install", action="store_true", default=False,
                      help="Use 'ant debug install' to build and install a " +
                      "debug version on your device or emulator. " +
                      "Implies --force and --test")
    parser.add_option("--all", action="store_true", default=False,
                      help="Use with --install, when not using --package"
                      " to confirm you really want to build and install everything.")
    parser.add_option("-w", "--wiki", default=False, action="store_true",
                      help="Update the wiki")
    options, args = parser.parse_args()

    # The --install option implies --test and --force...
    if options.install:
        if options.server:
            print "Can't install when building on a build server."
            sys.exit(1)
        if not options.package and not options.all:
            print "This would build and install everything in the repo to the device."
            print "You probably want to use --package and maybe also --vercode."
            print "If you really want to install everything, use --all."
            sys.exit(1)
        options.force = True
        options.test = True

    if options.force and not options.test:
        print "Force is only allowed in test mode"
        sys.exit(1)

    return options, args

options = None

def main():

    global options

    # Read configuration...
    globals()['build_server_always'] = False
    globals()['mvn3'] = "mvn3"
    globals()['archive_older'] = 0
    execfile('config.py', globals())

    options, args = parse_commandline()
    if build_server_always:
        options.server = True
    if options.resetserver and not options.server:
        print "Using --resetserver without --server makes no sense"
        sys.exit(1)

    # Get all apps...
    apps = common.read_metadata(options.verbose, xref=not options.onserver)

    log_dir = 'logs'
    if not os.path.isdir(log_dir):
        print "Creating log directory"
        os.makedirs(log_dir)

    tmp_dir = 'tmp'
    if not os.path.isdir(tmp_dir):
        print "Creating temporary directory"
        os.makedirs(tmp_dir)

    if options.test:
        output_dir = tmp_dir
    else:
        output_dir = 'unsigned'
        if not os.path.isdir(output_dir):
            print "Creating output directory"
            os.makedirs(output_dir)

    if archive_older != 0:
        also_check_dir = 'archive'
    else:
        also_check_dir = None

    repo_dir = 'repo'

    build_dir = 'build'
    if not os.path.isdir(build_dir):
        print "Creating build directory"
        os.makedirs(build_dir)
    srclib_dir = os.path.join(build_dir, 'srclib')
    extlib_dir = os.path.join(build_dir, 'extlib')

    # Filter apps and build versions according to command-line options, etc...
    if options.package:
        apps = [app for app in apps if app['id'] == options.package]
        if len(apps) == 0:
            print "No such package"
            sys.exit(1)
    apps = [app for app in apps if (options.force or not app['Disabled']) and
            app['builds'] and len(app['Repo Type']) > 0 and len(app['builds']) > 0]
    if len(apps) == 0:
        print "Nothing to do - all apps are disabled or have no builds defined."
        sys.exit(1)
    if options.vercode:
        for app in apps:
            app['builds'] = [b for b in app['builds']
                    if str(b['vercode']) == options.vercode]
    elif options.latest:
        for app in apps:
            m = max([i['vercode'] for i in app['builds']], key=int)
            app['builds'] = [b for b in app['builds'] if b['vercode'] == m]

    if options.wiki:
        import mwclient
        site = mwclient.Site(wiki_server, path=wiki_path)
        site.login(wiki_user, wiki_password)

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
                    if options.verbose:
                        print "Getting {0} vcs interface for {1}".format(
                                app['Repo Type'], app['Repo'])
                    vcs = common.getvcs(app['Repo Type'], app['Repo'], build_dir, sdk_path)

                    first = False

                if options.verbose:
                    print "Checking " + thisbuild['version']
                if trybuild(app, thisbuild, build_dir, output_dir, also_check_dir,
                        srclib_dir, extlib_dir, tmp_dir, repo_dir, vcs, options.test,
                        options.server, options.install, options.force,
                        options.verbose, options.onserver):
                    build_succeeded.append(app)
                    wikilog = "Build succeeded"
            except BuildException as be:
                logfile = open(os.path.join(log_dir, app['id'] + '.log'), 'a+')
                logfile.write(str(be))
                logfile.close()
                print "Could not build app %s due to BuildException: %s" % (app['id'], be)
                if options.stop:
                    sys.exit(1)
                failed_apps[app['id']] = be
                wikilog = be.get_wikitext()
            except VCSException as vcse:
                print "VCS error while building app %s: %s" % (app['id'], vcse)
                if options.stop:
                    sys.exit(1)
                failed_apps[app['id']] = vcse
                wikilog = str(vcse)
            except Exception as e:
                print "Could not build app %s due to unknown error: %s" % (app['id'], traceback.format_exc())
                if options.stop:
                    sys.exit(1)
                failed_apps[app['id']] = e
                wikilog = str(e)

            if options.wiki and wikilog:
                try:
                    newpage = site.Pages[app['id'] + '/lastbuild']
                    txt = wikilog
                    if len(txt) > 8192:
                        txt = txt[-8192:]
                    txt = "Build completed at " + time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()) + "\n\n" + txt
                    newpage.save(wikilog, summary='Build log')
                except:
                    print "Error while attempting to publish build log"

    for app in build_succeeded:
        print "success: %s" % (app['id'])

    for fa in failed_apps:
        print "Build for app %s failed:\n%s" % (fa, failed_apps[fa])

    print "Finished."
    if len(build_succeeded) > 0:
        print str(len(build_succeeded)) + ' builds succeeded'
    if len(failed_apps) > 0:
        print str(len(failed_apps)) + ' builds failed'

    sys.exit(0)

if __name__ == "__main__":
    main()

