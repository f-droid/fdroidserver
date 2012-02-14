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
import zipfile
import tarfile
import traceback
from xml.dom.minidom import Document
from optparse import OptionParser

import common
from common import BuildException
from common import VCSException

#Read configuration...
execfile('config.py')

# Parse command line...
parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true", default=False,
                  help="Spew out even more information than normal")
parser.add_option("-p", "--package", default=None,
                  help="Build only the specified package")
parser.add_option("-s", "--stop", action="store_true", default=False,
                  help="Make the build stop on exceptions")
parser.add_option("-t", "--test", action="store_true", default=False,
                  help="Test mode - put output in the tmp directory only.")
parser.add_option("--server", action="store_true", default=False,
                  help="Use build server")
parser.add_option("--on-server", action="store_true", default=False,
                  help="Specify that we're running on the build server")
parser.add_option("-f", "--force", action="store_true", default=False,
                  help="Force build of disabled app. Only allowed in test mode.")
(options, args) = parser.parse_args()

if options.force and not options.test:
    print "Force is only allowed in test mode"
    sys.exit(1)

# Get all apps...
apps = common.read_metadata(options.verbose)

failed_apps = {}
build_succeeded = []

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

repo_dir = 'repo'

build_dir = 'build'
if not os.path.isdir(build_dir):
    print "Creating build directory"
    os.makedirs(build_dir)
extlib_dir = os.path.join(build_dir, 'extlib')

# Build applications...
for app in apps:

    if options.package and options.package != app['id']:
        # Silent skip...
        pass
    elif app['Disabled'] and not options.force:
        if options.verbose:
            print "Skipping %s: disabled" % app['id']
    elif (not app['builds']) or app['Repo Type'] =='' or len(app['builds']) == 0:
        if options.verbose:
            print "Skipping %s: no builds specified" % app['id']
    else:

        build_dir = 'build/' + app['id']

        # Set up vcs interface and make sure we have the latest code...
        vcs = common.getvcs(app['Repo Type'], app['Repo'], build_dir)

        refreshed_source = False


        for thisbuild in app['builds']:
            try:
                dest = os.path.join(output_dir, app['id'] + '_' +
                        thisbuild['vercode'] + '.apk')
                dest_repo = os.path.join(repo_dir, app['id'] + '_' +
                        thisbuild['vercode'] + '.apk')

                if os.path.exists(dest) or (not options.test and os.path.exists(dest_repo)):
                    if options.verbose:
                        print "..version " + thisbuild['version'] + " already exists"
                elif thisbuild['commit'].startswith('!'):
                    if options.verbose:
                        print ("..skipping version " + thisbuild['version'] + " - " +
                            thisbuild['commit'][1:])
                else:
                    if options.verbose:
                        mstart = '.. building version '
                    else:
                        mstart = 'Building version '
                    print mstart + thisbuild['version'] + ' of ' + app['id']

                    if options.server:

                        import paramiko

                        # Start up the virtual maachine...
                        if subprocess.call(['vagrant', 'up'], cwd='builder') != 0:
                            # Not a very helpful message yet!
                            raise BuildException("Failed to set up build server")
                        # Get SSH configuration settings for us to connect...
                        subprocess.call('vagrant ssh-config >sshconfig',
                                cwd='builder', shell=True)
                        vagranthost = 'default' # Host in ssh config file

                        # Load and parse the SSH config...
                        sshconfig = paramiko.SSHConfig()
                        sshconfig.parse('builder/sshconfig')
                        sshconfig = sshconfig.lookup(vagranthost)

                        # Open SSH connection...
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AcceptPolicy)
                        ssh.connect(sshconfig['HostName'], username=sshconfig['Username'],
                            port=sshconfig['Port'], timeout=10, look_for_keys=False,
                            key_filename=sshconfig['IdentityFile'])

                        # Get an SFTP connection...
                        ftp = ssh.open_sftp()
                        ftp.get_channel().settimeout(15)

                        # Put all the necessary files in place...
                        ftp.chdir('/home/vagrant')
                        ftp.put('build.py', 'build.py')
                        ftp.put('common.py', 'common.py')
                        ftp.put('config.buildserver.py', 'config.py')
                        ftp.mkdir('build')
                        ftp.chdir('build')
                        ftp.mkdir('extlib')
                        def send_dir(path):
                            lastdir = path
                            for r, d, f in os.walk(base):
                                while lastdir != os.path.commonprefix([lastdir, root]):
                                    ftp.chdir('..')
                                    lastdir = os.path.split(lastdir)[0]
                                lastdir = r
                                for ff in f:
                                    ftp.put(os.path.join(r, ff), ff)
                        ftp.send_dir(app['id'])
                        # TODO: send relevant extlib directories too
                        ftp.chdir('/home/vagrant')

                        # Execute the build script...
                        ssh.exec_command('python build.py --on-server -p ' +
                                app['id'])

                        # Retrieve the built files...
                        apkfile = app['id'] + '_' + thisbuild['vercode'] + '.apk'
                        tarball = app['id'] + '_' + thisbuild['vercode'] + '_src' + '.tar.gz'
                        ftp.chdir('unsigned')
                        ftp.get(apkfile, os.path.join(output_dir, apkfile))
                        ftp.get(tarball, os.path.join(output_dir, tarball))

                        # Get rid of the virtual machine...
                        if subprocess.call(['vagrant', 'destroy'], cwd='builder') != 0:
                            # Not a very helpful message yet!
                            raise BuildException("Failed to destroy")

                    else:

                        # Prepare the source code...
                        root_dir = common.prepare_source(vcs, app, thisbuild,
                                build_dir, extlib_dir, sdk_path, ndk_path,
                                javacc_path, not refreshed_source)
                        refreshed_source = True

                        # Scan before building...
                        buildprobs = common.scan_source(build_dir, root_dir, thisbuild)
                        if len(buildprobs) > 0:
                            print 'Scanner found ' + str(len(buildprobs)) + ' problems:'
                            for problem in buildprobs:
                                print '...' + problem
                            raise BuildException("Can't build due to " +
                                    str(len(buildprobs)) + " scanned problems")

                        # Build the source tarball right before we build the release...
                        tarname = app['id'] + '_' + thisbuild['vercode'] + '_src'
                        tarball = tarfile.open(os.path.join(tmp_dir,
                            tarname + '.tar.gz'), "w:gz")
                        def tarexc(f):
                            if f in ['.svn', '.git', '.hg', '.bzr']:
                                return True
                            return False
                        tarball.add(build_dir, tarname, exclude=tarexc)
                        tarball.close()

                        # Build native stuff if required...
                        if thisbuild.get('buildjni', 'no') == 'yes':
                            ndkbuild = os.path.join(ndk_path, "ndk-build")
                            p = subprocess.Popen([ndkbuild], cwd=root_dir,
                                    stdout=subprocess.PIPE)
                            output = p.communicate()[0]
                            if p.returncode != 0:
                                print output
                                raise BuildException("NDK build failed for %s:%s" % (app['id'], thisbuild['version']))
                            elif options.verbose:
                                print output

                        # Build the release...
                        if thisbuild.has_key('maven'):
                            p = subprocess.Popen(['mvn', 'clean', 'install',
                                '-Dandroid.sdk.path=' + sdk_path],
                                cwd=root_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        else:
                            if thisbuild.has_key('antcommand'):
                                antcommand = thisbuild['antcommand']
                            else:
                                antcommand = 'release'
                            p = subprocess.Popen(['ant', antcommand], cwd=root_dir, 
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        output, error = p.communicate()
                        if p.returncode != 0:
                            raise BuildException("Build failed for %s:%s" % (app['id'], thisbuild['version']), output.strip(), error.strip())
                        elif options.verbose:
                            print output
                        print "Build successful"

                        # Find the apk name in the output...
                        if thisbuild.has_key('bindir'):
                            bindir = os.path.join(build_dir, thisbuild['bindir'])
                        else:
                            bindir = os.path.join(root_dir, 'bin')
                        if thisbuild.get('initfun', 'no')  == "yes":
                            # Special case (again!) for funambol...
                            src = ("funambol-android-sync-client-" +
                                    thisbuild['version'] + "-unsigned.apk")
                            src = os.path.join(bindir, src)
                        elif thisbuild.has_key('maven'):
                            src = re.match(r".*^\[INFO\] Installing /.*/([^/]*)\.apk",
                                    output, re.S|re.M).group(1)
                            src = os.path.join(bindir, src) + '.apk'
#[INFO] Installing /home/ciaran/fdroidserver/tmp/mainline/application/target/callerid-1.0-SNAPSHOT.apk
                        else:
                            src = re.match(r".*^.*Creating (\S+) for release.*$.*", output,
                                re.S|re.M).group(1)
                            src = os.path.join(bindir, src)

                        # By way of a sanity check, make sure the version and version
                        # code in our new apk match what we expect...
                        print "Checking " + src
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
                            for line in output.splitlines():
                                if line.startswith("package:"):
                                    pat = re.compile(".*versionCode='([0-9]*)'.*")
                                    vercode = re.match(pat, line).group(1)
                                    pat = re.compile(".*versionName='([^']*)'.*")
                                    version = re.match(pat, line).group(1)
                            if version == None or vercode == None:
                                raise BuildException("Could not find version information in build in output")

                        # Some apps (e.g. Timeriffic) have had the bonkers idea of
                        # including the entire changelog in the version number. Remove
                        # it so we can compare. (TODO: might be better to remove it
                        # before we compile, in fact)
                        index = version.find(" //")
                        if index != -1:
                            version = version[:index]

                        if (version != thisbuild['version'] or
                                vercode != thisbuild['vercode']):
                            raise BuildException(("Unexpected version/version code in output"
                                                 "APK: %s / %s"
                                                 "Expected: %s / %s")
                                                 % (version, str(vercode), thisbuild['version'], str(thisbuild['vercode']))
                                                )

                        # Copy the unsigned apk to our destination directory for further
                        # processing (by publish.py)...
                        shutil.copyfile(src, dest)

                        # Move the source tarball into the output directory...
                        if output_dir != tmp_dir:
                            tarfilename = tarname + '.tar.gz'
                            shutil.move(os.path.join(tmp_dir, tarfilename),
                                os.path.join(output_dir, tarfilename))

                    build_succeeded.append(app)
            except BuildException as be:
                if options.stop:
                    raise
                print "Could not build app %s due to BuildException: %s" % (app['id'], be)
                logfile = open(os.path.join(log_dir, app['id'] + '.log'), 'a+')
                logfile.write(str(be))
                logfile.close
                failed_apps[app['id']] = be
            except VCSException as vcse:
                if options.stop:
                    raise
                print "VCS error while building app %s: %s" % (app['id'], vcse)
                failed_apps[app['id']] = vcse
            except Exception as e:
                if options.stop:
                    raise
                print "Could not build app %s due to unknown error: %s" % (app['id'], traceback.format_exc())
                failed_apps[app['id']] = e

for app in build_succeeded:
    print "success: %s" % (app['id'])

for fa in failed_apps:
    print "Build for app %s failed:\n%s" % (fa, failed_apps[fa])

print "Finished."
if len(build_succeeded) > 0:
    print str(len(build_succeeded)) + ' builds succeeded'
if len(failed_apps) > 0:
    print str(len(failed_apps)) + ' builds failed'

