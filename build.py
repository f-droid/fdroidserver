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
import md5
import shlex
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
(options, args) = parser.parse_args()

# Get all apps...
apps = common.read_metadata(options.verbose)

failed_apps = {}
build_succeeded = []

output_dir = 'repo'
if not os.path.isdir(output_dir):
    print "Creating output directory"
    os.makedirs(output_dir)

tmp_dir = 'tmp'
if not os.path.isdir(tmp_dir):
    print "Creating temporary directory"
    os.makedirs(tmp_dir)

build_dir = 'build'
if not os.path.isdir(build_dir):
    print "Creating build directory"
    os.makedirs(build_dir)

for app in apps:

    if app['disabled']:
        print "Skipping %s: disabled" % app['id']
    elif not app['builds']:
        print "Skipping %s: no builds specified" % app['id']

    if (app['disabled'] is None and app['repo'] != '' 
            and app['repotype'] != '' and (options.package is None or
            options.package == app['id']) and len(app['builds']) > 0):

        print "Processing " + app['id']

        build_dir = 'build/' + app['id']

        # Set up vcs interface and make sure we have the latest code...
        vcs = common.getvcs(app['repotype'], app['repo'], build_dir)

        refreshed_source = False


        for thisbuild in app['builds']:
            try:
                dest = os.path.join(output_dir, app['id'] + '_' +
                        thisbuild['vercode'] + '.apk')
                dest_unsigned = os.path.join(tmp_dir, app['id'] + '_' +
                        thisbuild['vercode'] + '_unsigned.apk')

                if os.path.exists(dest):
                    print "..version " + thisbuild['version'] + " already exists"
                elif thisbuild['commit'].startswith('!'):
                    print ("..skipping version " + thisbuild['version'] + " - " +
                            thisbuild['commit'][1:])
                else:
                    print "..building version " + thisbuild['version']

                    # Prepare the source code...
                    root_dir = common.prepare_source(vcs, app, thisbuild,
                            build_dir, sdk_path, ndk_path, javacc_path,
                            not refreshed_source)
                    refreshed_source = True

                    # Build the source tarball right before we build the release...
                    tarname = app['id'] + '_' + thisbuild['vercode'] + '_src'
                    tarball = tarfile.open(os.path.join(output_dir,
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
                            cwd=root_dir, stdout=subprocess.PIPE)
                    else:
                        if thisbuild.has_key('antcommand'):
                            antcommand = thisbuild['antcommand']
                        else:
                            antcommand = 'release'
                        p = subprocess.Popen(['ant', antcommand], cwd=root_dir, 
                                stdout=subprocess.PIPE)
                    output = p.communicate()[0]
                    if p.returncode != 0:
                        raise BuildException("Build failed for %s:%s (%s)" % (app['id'], thisbuild['version'], output.strip()))
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

                    # Copy the unsigned apk to our temp directory for further
                    # processing...
                    shutil.copyfile(src, dest_unsigned)

                    # Figure out the key alias name we'll use. Only the first 8
                    # characters are significant, so we'll use the first 8 from
                    # the MD5 of the app's ID and hope there are no collisions.
                    # If a collision does occur later, we're going to have to
                    # come up with a new alogrithm, AND rename all existing keys
                    # in the keystore!
                    if keyaliases.has_key(app['id']):
                        # For this particular app, the key alias is overridden...
                        keyalias = keyaliases[app['id']]
                    else:
                        m = md5.new()
                        m.update(app['id'])
                        keyalias = m.hexdigest()[:8]
                    print "Key alias: " + keyalias

                    # See if we already have a key for this application, and
                    # if not generate one...
                    p = subprocess.Popen(['keytool', '-list',
                        '-alias', keyalias, '-keystore', keystore,
                        '-storepass', keystorepass], stdout=subprocess.PIPE)
                    output = p.communicate()[0]
                    if p.returncode !=0:
                        print "Key does not exist - generating..."
                        p = subprocess.Popen(['keytool', '-genkey',
                            '-keystore', keystore, '-alias', keyalias,
                            '-keyalg', 'RSA', '-keysize', '2048',
                            '-validity', '10000',
                            '-storepass', keystorepass, '-keypass', keypass,
                            '-dname', keydname], stdout=subprocess.PIPE)
                        output = p.communicate()[0]
                        print output
                        if p.returncode != 0:
                            raise BuildException("Failed to generate key")

                    # Sign the application...
                    p = subprocess.Popen(['jarsigner', '-keystore', keystore,
                        '-storepass', keystorepass, '-keypass', keypass,
                            dest_unsigned, keyalias], stdout=subprocess.PIPE)
                    output = p.communicate()[0]
                    print output
                    if p.returncode != 0:
                        raise BuildException("Failed to sign application")

                    # Zipalign it...
                    p = subprocess.Popen([os.path.join(sdk_path,'tools','zipalign'),
                                        '-v', '4', dest_unsigned, dest],
                                        stdout=subprocess.PIPE)
                    output = p.communicate()[0]
                    print output
                    if p.returncode != 0:
                        raise BuildException("Failed to align application")
                    os.remove(dest_unsigned)
                    build_succeeded.append(app)
            except BuildException as be:
                print "Could not build app %s due to BuildException: %s" % (app['id'], be)
                failed_apps[app['id']] = be
            except VCSException as vcse:
                print "VCS error while building app %s: %s" % (app['id'], vcse)
                failed_apps[app['id']] = vcse
            except Exception as e:
                print "Could not build app %s due to unknown error: %s" % (app['id'], e)
                failed_apps[app['id']] = e

for app in build_succeeded:
    print "success: %s" % (app['id'])

for fa in failed_apps:
    print "Build for app %s failed: %s" % (fa, failed_apps[fa])

print "Finished."
if len(failed_apps) > 0:
    print str(len(failed_apps)) + ' builds failed'

