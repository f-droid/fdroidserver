#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# build.py - part of the FDroid server tools
# Copyright (C) 2010, Ciaran Gultnieks, ciaran@ciarang.com
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

#Read configuration...
execfile('config.py')


# Parse command line...
parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true", default=False,
                  help="Spew out even more information than normal")
parser.add_option("-p", "--package", default=None,
                  help="Build only the specified package")
parser.add_option("-c", "--clean", action="store_true", default=False,
                  help="Clean mode - build everything from scratch")
(options, args) = parser.parse_args()

# Get all apps...
apps = common.read_metadata(options.verbose)

#Clear and/or create the 'built' directory, depending on mode:
built_dir = 'built'
if options.clean:
    if os.path.exists(built_dir):
        shutil.rmtree(built_dir)
if not os.path.exists(built_dir):
    os.mkdir(built_dir)

for app in apps:

    if (app['disabled'] is None and app['repo'] != '' 
            and app['repotype'] != '' and (options.package is None or
            options.package == app['id']) and len(app['builds']) > 0):

        print "Processing " + app['id']

        build_dir = 'build_' + app['id']

        got_source = False


        for thisbuild in app['builds']:

            dest = os.path.join(built_dir, app['id'] + '_' +
                    thisbuild['vercode'] + '.apk')
            dest_unsigned = dest + "_unsigned"

            if os.path.exists(dest):
                print "..version " + thisbuild['version'] + " already exists"
            elif thisbuild['commit'].startswith('!'):
                print ("..skipping version " + thisbuild['version'] + " - " +
                        thisbuild['commit'][1:])
            else:
                print "..building version " + thisbuild['version']

                if not got_source:

                    got_source = True

                    # Remove the build directory if it already exists...
                    if os.path.exists(build_dir):
                        shutil.rmtree(build_dir)

                    # Strip username/password out of repo address if specified (relevant
                    # only for SVN) and store for use later.
                    repo = app['repo']
                    index = repo.find('@')
                    if index != -1:
                        username = repo[:index]
                        repo = repo[index+1:]
                        index = username.find(':')
                        if index == -1:
                            print "Password required with username"
                            sys.exit(1)
                        password = username[index+1:]
                        username = username[:index]
                        repouserargs = ['--username', username, 
                                '--password', password, '--non-interactive']
                    else:
                        repouserargs = []

                    # Get the source code...
                    if app['repotype'] == 'git':
                        if subprocess.call(['git', 'clone', repo, build_dir]) != 0:
                            print "Git clone failed"
                            sys.exit(1)
                    elif app['repotype'] == 'svn':
                        if not repo.endswith("*"):
                            if subprocess.call(['svn', 'checkout', repo, build_dir] +
                                    repouserargs) != 0:
                                print "Svn checkout failed"
                                sys.exit(1)
                    elif app['repotype'] == 'hg':
                        if subprocess.call(['hg', 'clone', repo, build_dir]) !=0:
                            print "Hg clone failed"
                            sys.exit(1)
                    elif app['repotype'] == 'bzr':
                        if subprocess.call(['bzr', 'branch', repo, build_dir]) !=0:
                            print "Bzr branch failed"
                            sys.exit(1)
                    else:
                        print "Invalid repo type " + app['repotype'] + " in " + app['id']
                        sys.exit(1)

                # Optionally, the actual app source can be in a subdirectory...
                doupdate = True
                if thisbuild.has_key('subdir'):
                    if app['repotype'] == 'svn' and repo.endswith("*"):
                        root_dir = build_dir
                        # Remove the build directory if it already exists...
                        if os.path.exists(build_dir):
                            shutil.rmtree(build_dir)
                        if subprocess.call(['svn', 'checkout',
                                repo[:-1] + thisbuild['subdir'],
                                '-r', thisbuild['commit'],
                                build_dir] + repouserargs) != 0:
                            print "Svn checkout failed"
                            sys.exit(1)
                        # Because we're checking out for every version we build,
                        # we've already checked out the repo at the correct revision
                        # and don't need to update to it...
                        doupdate = False
                    else:
                        root_dir = os.path.join(build_dir, thisbuild['subdir'])
                else:
                    root_dir = build_dir

                if doupdate:
                    if app['repotype'] == 'git':
                        if subprocess.call(['git', 'reset', '--hard', thisbuild['commit']],
                                cwd=build_dir) != 0:
                            print "Git reset failed"
                            sys.exit(1)
                    elif app['repotype'] == 'svn':
                        for svncommand in (['svn', 'update', '--force',
                                            '-r', thisbuild['commit']],
                                           ['svn', 'revert', '-R', '.']):
                            if subprocess.call(svncommand, cwd=build_dir) != 0:
                                print "Svn update failed"
                                sys.exit(1)
                    elif app['repotype'] == 'hg':
                        if subprocess.call(['hg', 'checkout', thisbuild['commit']],
                                cwd=build_dir) != 0:
                            print "Hg checkout failed"
                            sys.exit(1)
                    elif app['repotype'] == 'bzr':
                        if subprocess.call(['bzr', 'revert', '-r', thisbuild['commit']],
                                cwd=build_dir) != 0:
                            print "Bzr revert failed"
                            sys.exit(1)
                    else:
                        print "Invalid repo type " + app['repotype']
                        sys.exit(1)

                # Initialise submodules if requred...
                if thisbuild.get('submodules', 'no')  == 'yes':
                        if subprocess.call(['git', 'submodule', 'init'],
                                cwd=build_dir) != 0:
                            print "Git submodule init failed"
                            sys.exit(1)
                        if subprocess.call(['git', 'submodule', 'update'],
                                cwd=build_dir) != 0:
                            print "Git submodule update failed"
                            sys.exit(1)

                # Generate (or update) the ant build file, build.xml...
                if thisbuild.get('update', 'yes') == 'yes':
                    parms = [os.path.join(sdk_path, 'tools', 'android'),
                             'update', 'project', '-p', '.']
                    parms.append('--subprojects')
                    if thisbuild.has_key('target'):
                        parms.append('-t')
                        parms.append(thisbuild['target'])
                    if subprocess.call(parms, cwd=root_dir) != 0:
                        print "Failed to update project"
                        sys.exit(1)

                # If the app has ant set up to sign the release, we need to switch
                # that off, because we want the unsigned apk...
                for propfile in ('build.properties', 'default.properties'):
                    if os.path.exists(os.path.join(root_dir, propfile)):
                        if subprocess.call(['sed','-i','s/^key.store/#/',
                                            propfile], cwd=root_dir) !=0:
                            print "Failed to amend %s" % propfile
                            sys.exit(1)

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
                        print "Failed to amend manifest"
                        sys.exit(1)
                if thisbuild.has_key('insertvercode'):
                    if subprocess.call(['sed','-i','s/' + thisbuild['insertvercode'] +
                        '/' + thisbuild['vercode'] +'/g',
                        'AndroidManifest.xml'], cwd=root_dir) !=0:
                        print "Failed to amend manifest"
                        sys.exit(1)

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
                                    print "Failed to amend " + filename
                                    sys.exit(1)

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
                        print "Error running pre-build command"
                        sys.exit(1)

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
                        print "Failed to amend build.xml"
                        sys.exit(1)

                    if subprocess.call(['sed','-i','s@' +
                        '\${user.home}/funambol/build/android/build.properties' +
                        '@' +
                        'build.properties' +
                        '@g',
                        'build.xml'], cwd=root_dir) !=0:
                        print "Failed to amend build.xml"
                        sys.exit(1)

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
                        print "Failed to amend build.xml"
                        sys.exit(1)

                    shutil.copyfile(
                            os.path.join(root_dir, "build.properties.example"),
                            os.path.join(root_dir, "build.properties"))

                    if subprocess.call(['sed','-i','s@' +
                        'javacchome=.*'+
                        '@' +
                        'javacchome=' + javacc_path +
                        '@g',
                        'build.properties'], cwd=root_dir) !=0:
                        print "Failed to amend build.properties"
                        sys.exit(1)

                    if subprocess.call(['sed','-i','s@' +
                        'sdk-folder=.*'+
                        '@' +
                        'sdk-folder=' + sdk_path +
                        '@g',
                        'build.properties'], cwd=root_dir) !=0:
                        print "Failed to amend build.properties"
                        sys.exit(1)

                    if subprocess.call(['sed','-i','s@' +
                        'android.sdk.version.*'+
                        '@' +
                        'android.sdk.version=2.0' +
                        '@g',
                        'build.properties'], cwd=root_dir) !=0:
                        print "Failed to amend build.properties"
                        sys.exit(1)


                # Build the source tarball right before we build the release...
                tarname = app['id'] + '_' + thisbuild['vercode'] + '_src'
                tarball = tarfile.open(os.path.join(built_dir,
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
                        print "NDK build failed"
                        sys.exit(1)
                    elif options.verbose:
                        print output

                # Build the release...
                if thisbuild.has_key('antcommand'):
                    antcommand = thisbuild['antcommand']
                else:
                    antcommand = 'release'
                p = subprocess.Popen(['ant', antcommand], cwd=root_dir, 
                        stdout=subprocess.PIPE)
                output = p.communicate()[0]
                if p.returncode != 0:
                    print output
                    print "Build failed"
                    sys.exit(1)
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
                else:
                    src = re.match(r".*^.*Creating (\S+) for release.*$.*", output,
                        re.S|re.M).group(1)
                src = os.path.join(bindir, src)

                # By way of a sanity check, make sure the version and version
                # code in our new apk match what we expect...
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
                        print "Could not find version information in build in output"
                        sys.exit(1)

                # Some apps (e.g. Timeriffic) have had the bonkers idea of
                # including the entire changelog in the version number. Remove
                # it so we can compare. (TODO: might be better to remove it
                # before we compile, in fact)
                index = version.find(" //")
                if index != -1:
                    version = version[:index]

                if (version != thisbuild['version'] or
                        vercode != thisbuild['vercode']):
                    print "Unexpected version/version code in output"
                    sys.exit(1)

                # Copy the unsigned apk to our 'built' directory for further
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
                        print "Failed to generate key"
                        sys.exit(1)

                # Sign the application...
                p = subprocess.Popen(['jarsigner', '-keystore', keystore,
                       '-storepass', keystorepass, '-keypass', keypass,
                        dest_unsigned, keyalias], stdout=subprocess.PIPE)
                output = p.communicate()[0]
                print output
                if p.returncode != 0:
                    print "Failed to sign application"
                    sys.exit(1)

                # Zipalign it...
                p = subprocess.Popen([os.path.join(sdk_path,'tools','zipalign'),
                                      '-v', '4', dest_unsigned, dest],
                                     stdout=subprocess.PIPE)
                output = p.communicate()[0]
                print output
                if p.returncode != 0:
                    print "Failed to align application"
                    sys.exit(1)
                os.remove(dest_unsigned)

print "Finished."

