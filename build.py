# -*- coding: UTF-8 -*-
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
import glob
import subprocess
import re
import zipfile
import tarfile
import md5
from xml.dom.minidom import Document
from optparse import OptionParser

#Read configuration...
execfile('config.py')

execfile('metadata.py')

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
apps = read_metadata()

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
                print "Version " + thisbuild['version'] + " already exists"
            else:
                print "Building version " + thisbuild['version']

                if not got_source:

                    got_source = True

                    # Remove the build directory if it already exists...
                    if os.path.exists(build_dir):
                        shutil.rmtree(build_dir)

                    # Get the source code...
                    if app['repotype'] == 'git':
                        if subprocess.call(['git', 'clone', app['repo'], build_dir]) != 0:
                            print "Git clone failed"
                            sys.exit(1)
                    elif app['repotype'] == 'svn':
                        if not app['repo'].endswith("*"):
                            if subprocess.call(['svn', 'checkout', app['repo'], build_dir]) != 0:
                                print "Svn checkout failed"
                                sys.exit(1)
                    elif app['repotype'] == 'hg':
                        if subprocess.call(['hg', 'clone', app['repo'], build_dir]) !=0:
                            print "Hg clone failed"
                            sys.exit(1)
                    else:
                        print "Invalid repo type " + app['repotype'] + " in " + app['id']
                        sys.exit(1)


                    # Optionally, the actual app source can be in a subdirectory...
                    if thisbuild.has_key('subdir'):
                        if app['repotype'] == 'svn' and app['repo'].endswith("*"):
                            root_dir = build_dir
                            if subprocess.call(['svn', 'checkout',
                                    app['repo'][:-1] + thisbuild['subdir'],
                                    build_dir]) != 0:
                                print "Svn checkout failed"
                                sys.exit(1)
                        else:
                            root_dir = os.path.join(build_dir, thisbuild['subdir'])
                    else:
                        root_dir = build_dir

                    if app['repotype'] == 'git':
                        if subprocess.call(['git', 'checkout', thisbuild['commit']],
                                cwd=build_dir) != 0:
                            print "Git checkout failed"
                            sys.exit(1)
                    elif app['repotype'] == 'svn':
                        if subprocess.call(['svn', 'update', '-r', thisbuild['commit']],
                                cwd=build_dir) != 0:
                            print "Svn update failed"
                            sys.exit(1)
                    elif app['repotype'] == 'hg':
                        if subprocess.call(['hg', 'checkout', thisbuild['commit']],
                                cwd=build_dir) != 0:
                            print "Hg checkout failed"
                            sys.exit(1)

                    else:
                        print "Invalid repo type " + app['repotype']
                        sys.exit(1)

                    # Generate (or update) the ant build file, build.xml...
                    parms = ['android','update','project','-p','.']
                    parms.append('--subprojects')
                    if thisbuild.has_key('target'):
                        parms.append('-t')
                        parms.append(thisbuild['target'])
                    if subprocess.call(parms, cwd=root_dir) != 0:
                        print "Failed to update project"
                        sys.exit(1)

                    # If the app has ant set up to sign the release, we need to switch
                    # that off, because we want the unsigned apk...
                    if os.path.exists(os.path.join(root_dir, 'build.properties')):
                        if subprocess.call(['sed','-i','s/^key.store/#/',
                            'build.properties'], cwd=root_dir) !=0:
                            print "Failed to amend build.properties"
                            sys.exit(1)

                    # Fix old-fashioned 'sdk-location' in local.properties by copying
                    # from sdk.dir, if necessary...
                    if (thisbuild.has_key('oldsdkloc') and
                            thisbuild['oldsdkloc'] == "yes"):
                        locprops = os.path.join(root_dir, 'local.properties')
                        f = open(locprops, 'r')
                        props = f.read()
                        f.close()
                        sdkloc = re.match(r".*^sdk.dir=(\S+)$.*", props,
                            re.S|re.M).group(1)
                        props += "\nsdk-location=" + sdkloc + "\n"
                        f = open(locprops, 'w')
                        f.write(props)
                        f.close()

                    #Delete unwanted file...
                    if thisbuild.has_key('rm'):
                        os.remove(os.path.join(build_dir, thisbuild['rm']))

                    #Build the source tarball right before we build the relase...
                    tarname = app['id'] + '_' + thisbuild['vercode'] + '_src'
                    tarball = tarfile.open(os.path.join(built_dir,
                        tarname + '.tar.gz'), "w:gz")
                    tarball.add(build_dir, tarname)
                    tarball.close()

                    # Build the release...
                    p = subprocess.Popen(['ant','release'], cwd=root_dir, 
                            stdout=subprocess.PIPE)
                    output = p.communicate()[0]
                    if p.returncode != 0:
                        print output
                        print "Build failed"
                        sys.exit(1)

                    # Find the apk name in the output...
                    if thisbuild.has_key('bindir'):
                        bindir = os.path.join(build_dir, thisbuild['bindir'])
                    else:
                        bindir = os.path.join(root_dir, 'bin')
                    src = re.match(r".*^.*Creating (\S+) for release.*$.*", output,
                            re.S|re.M).group(1)
                    src = os.path.join(bindir, src)

                    # By way of a sanity check, make sure the version and version
                    # code in our new apk match what we expect...
                    p = subprocess.Popen([aapt_path,'dump','badging',
                       src], stdout=subprocess.PIPE)
                    output = p.communicate()[0]
                    vercode = None
                    version = None
                    for line in output.splitlines():
                        if line.startswith("package:"):
                            pat = re.compile(".*versionCode='([0-9]*)'.*")
                            vercode = re.match(pat, line).group(1)
                            pat = re.compile(".*versionName='([^']*)'.*")
                            version = re.match(pat, line).group(1)

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
                    p = subprocess.Popen(['zipalign', '-v', '4',
                            dest_unsigned, dest], stdout=subprocess.PIPE)
                    output = p.communicate()[0]
                    print output
                    if p.returncode != 0:
                        print "Failed to align application"
                        sys.exit(1)
                    os.remove(dest_unsigned)

print "Finished."

