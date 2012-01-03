#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# build.py - part of the FDroid server tools
# Copyright (C) 2010-11, Ciaran Gultnieks, ciaran@ciarang.com
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

                    if not refreshed_source:
                        vcs.refreshlocal()
                        refreshed_source = True

                    # Optionally, the actual app source can be in a subdirectory...
                    if thisbuild.has_key('subdir'):
                        root_dir = os.path.join(build_dir, thisbuild['subdir'])
                    else:
                        root_dir = build_dir

                    # Get a working copy of the right revision...
                    if options.verbose:
                        print "Resetting repository to " + thisbuild['commit']
                    vcs.reset(thisbuild['commit'])

                    # Initialise submodules if requred...
                    if thisbuild.get('submodules', 'no')  == 'yes':
                        vcs.initsubmodules()

                    # Generate (or update) the ant build file, build.xml...
                    if (thisbuild.get('update', 'yes') == 'yes' and
                        not thisbuild.has_key('maven')):
                        parms = [os.path.join(sdk_path, 'tools', 'android'),
                                'update', 'project', '-p', '.']
                        parms.append('--subprojects')
                        if thisbuild.has_key('target'):
                            parms.append('-t')
                            parms.append(thisbuild['target'])
                        if subprocess.call(parms, cwd=root_dir) != 0:
                            raise BuildException("Failed to update project")

                    # If the app has ant set up to sign the release, we need to switch
                    # that off, because we want the unsigned apk...
                    for propfile in ('build.properties', 'default.properties'):
                        if os.path.exists(os.path.join(root_dir, propfile)):
                            if subprocess.call(['sed','-i','s/^key.store/#/',
                                                propfile], cwd=root_dir) !=0:
                                raise BuildException("Failed to amend %s" % propfile)

                    # Update the local.properties file...
                    locprops = os.path.join(root_dir, 'local.properties')
                    if os.path.exists(locprops):
                        f = open(locprops, 'r')
                        props = f.read()
                        f.close()
                        # Fix old-fashioned 'sdk-location' by copying
                        # from sdk.dir, if necessary...
                        if thisbuild.get('oldsdkloc', 'no') == "yes":
                            sdkloc = re.match(r".*^sdk.dir=(\S+)$.*", props,
                                re.S|re.M).group(1)
                            props += "\nsdk-location=" + sdkloc + "\n"
                        # Add ndk location...
                        props+= "\nndk.dir=" + ndk_path + "\n"
                        # Add java.encoding if necessary...
                        if thisbuild.has_key('encoding'):
                            props += "\njava.encoding=" + thisbuild['encoding'] + "\n"
                        f = open(locprops, 'w')
                        f.write(props)
                        f.close()

                    # Insert version code and number into the manifest if necessary...
                    if thisbuild.has_key('insertversion'):
                        if subprocess.call(['sed','-i','s/' + thisbuild['insertversion'] +
                            '/' + thisbuild['version'] +'/g',
                            'AndroidManifest.xml'], cwd=root_dir) !=0:
                            raise BuildException("Failed to amend manifest")
                    if thisbuild.has_key('insertvercode'):
                        if subprocess.call(['sed','-i','s/' + thisbuild['insertvercode'] +
                            '/' + thisbuild['vercode'] +'/g',
                            'AndroidManifest.xml'], cwd=root_dir) !=0:
                            raise BuildException("Failed to amend manifest")

                    # Delete unwanted file...
                    if thisbuild.has_key('rm'):
                        os.remove(os.path.join(build_dir, thisbuild['rm']))

                    # Fix apostrophes translation files if necessary...
                    if thisbuild.get('fixapos', 'no') == 'yes':
                        for root, dirs, files in os.walk(os.path.join(root_dir,'res')):
                            for filename in files:
                                if filename.endswith('.xml'):
                                    if subprocess.call(['sed','-i','s@' +
                                        r"\([^\\]\)'@\1\\'" +
                                        '@g',
                                        os.path.join(root, filename)]) != 0:
                                        raise BuildException("Failed to amend " + filename)

                    # Fix translation files if necessary...
                    if thisbuild.get('fixtrans', 'no') == 'yes':
                        for root, dirs, files in os.walk(os.path.join(root_dir,'res')):
                            for filename in files:
                                if filename.endswith('.xml'):
                                    f = open(os.path.join(root, filename))
                                    changed = False
                                    outlines = []
                                    for line in f:
                                        num = 1
                                        index = 0
                                        oldline = line
                                        while True:
                                            index = line.find("%", index)
                                            if index == -1:
                                                break
                                            next = line[index+1:index+2]
                                            if next == "s" or next == "d":
                                                line = (line[:index+1] +
                                                        str(num) + "$" +
                                                        line[index+1:])
                                                num += 1
                                                index += 3
                                            else:
                                                index += 1
                                        # We only want to insert the positional arguments
                                        # when there is more than one argument...
                                        if oldline != line:
                                            if num > 2:
                                                changed = True
                                            else:
                                                line = oldline
                                        outlines.append(line)
                                    f.close()
                                    if changed:
                                        f = open(os.path.join(root, filename), 'w')
                                        f.writelines(outlines)
                                        f.close()

                    # Run a pre-build command if one is required...
                    if thisbuild.has_key('prebuild'):
                        if subprocess.call(thisbuild['prebuild'],
                                cwd=root_dir, shell=True) != 0:
                            raise BuildException("Error running pre-build command")

                    # Apply patches if any
                    if 'patch' in thisbuild:
                        for patch in thisbuild['patch'].split(';'):
                            print "Applying " + patch
                            patch_path = os.path.join('metadata', app['id'], patch)
                            if subprocess.call(['patch', '-p1',
                                            '-i', os.path.abspath(patch_path)], cwd=build_dir) != 0:
                                raise BuildException("Failed to apply patch %s" % patch_path)

                    # Special case init functions for funambol...
                    if thisbuild.get('initfun', 'no')  == "yes":

                        if subprocess.call(['sed','-i','s@' +
                            '<taskdef resource="net/sf/antcontrib/antcontrib.properties" />' +
                            '@' +
                            '<taskdef resource="net/sf/antcontrib/antcontrib.properties">' +
                            '<classpath>' +
                            '<pathelement location="/usr/share/java/ant-contrib.jar"/>' +
                            '</classpath>' +
                            '</taskdef>' +
                            '@g',
                            'build.xml'], cwd=root_dir) !=0:
                            raise BuildException("Failed to amend build.xml")

                        if subprocess.call(['sed','-i','s@' +
                            '\${user.home}/funambol/build/android/build.properties' +
                            '@' +
                            'build.properties' +
                            '@g',
                            'build.xml'], cwd=root_dir) !=0:
                            raise BuildException("Failed to amend build.xml")

                        buildxml = os.path.join(root_dir, 'build.xml')
                        f = open(buildxml, 'r')
                        xml = f.read()
                        f.close()
                        xmlout = ""
                        mode = 0
                        for line in xml.splitlines():
                            if mode == 0:
                                if line.find("jarsigner") != -1:
                                    mode = 1
                                else:
                                    xmlout += line + "\n"
                            else:
                                if line.find("/exec") != -1:
                                    mode += 1
                                    if mode == 3:
                                        mode =0
                        f = open(buildxml, 'w')
                        f.write(xmlout)
                        f.close()

                        if subprocess.call(['sed','-i','s@' +
                            'platforms/android-2.0' +
                            '@' +
                            'platforms/android-8' +
                            '@g',
                            'build.xml'], cwd=root_dir) !=0:
                            raise BuildException("Failed to amend build.xml")

                        shutil.copyfile(
                                os.path.join(root_dir, "build.properties.example"),
                                os.path.join(root_dir, "build.properties"))

                        if subprocess.call(['sed','-i','s@' +
                            'javacchome=.*'+
                            '@' +
                            'javacchome=' + javacc_path +
                            '@g',
                            'build.properties'], cwd=root_dir) !=0:
                            raise BuildException("Failed to amend build.properties")

                        if subprocess.call(['sed','-i','s@' +
                            'sdk-folder=.*'+
                            '@' +
                            'sdk-folder=' + sdk_path +
                            '@g',
                            'build.properties'], cwd=root_dir) !=0:
                            raise BuildException("Failed to amend build.properties")

                        if subprocess.call(['sed','-i','s@' +
                            'android.sdk.version.*'+
                            '@' +
                            'android.sdk.version=2.0' +
                            '@g',
                            'build.properties'], cwd=root_dir) !=0:
                            raise BuildException("Failed to amend build.properties")


                    # Build the source tarball right before we build the release...
                    tarname = app['id'] + '_' + thisbuild['vercode'] + '_src'
                    tarball = tarfile.open(os.path.join(output_dir,
                        tarname + '.tar.gz'), "w:gz")
                    tarball.add(build_dir, tarname)
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
                        print output
                        raise BuildException("Build failed for %s:%s" % (app['id'], thisbuild['version']))
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
                                            ) % (version, str(vercode), thisbuild['version'], str(thisbuild['vercode']))

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
            except BuildException as be:
                print "Could not build app %s due to BuildException: %s" % (app['id'], be)
                failed_apps[app['id']] = be
            except VCSException as vcse:
                print "VCS error while building app %s: %s" % (app['id'], vcse)
                failed_apps[app['id']] = vcse
            except Exception as e:
                print "Could not build app %s due to unknown error: %s" % (app['id'], e)
                failed_apps[app['id']] = e
            build_succeeded.append(app)

for app in build_succeeded:
    print "success: %s" % (app['id'])

for fa in failed_apps:
    print "Build for app %s failed: %s" % (fa, failed_apps[fa])

print "Finished."
if len(failed_apps) > 0:
    print str(len(failed_apps)) + 'builds failed'

