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
(options, args) = parser.parse_args()

# Get all apps...
apps = read_metadata()

unsigned_dir = 'unsigned'
if os.path.exists(unsigned_dir):
    shutil.rmtree(unsigned_dir)
os.mkdir(unsigned_dir)

for app in apps:

    if (app['disabled'] is None and app['repo'] != '' 
            and app['repotype'] != '' and (options.package is None or
            options.package == app['id'])):

        print "About to build " + app['id']

        build_dir = 'build_' + app['id']

        # Remove the build directory if it already exists...
        if os.path.exists(build_dir):
            shutil.rmtree(build_dir)

        # Get the source code...
        if app['repotype'] == 'git':
            if subprocess.call(['git', 'clone',app['repo'], build_dir]) != 0:
                print "Git clone failed"
                sys.exit(1)
        elif app['repotype'] == 'svn':
            if not app['repo'].endswith("*"):
                if subprocess.call(['svn', 'checkout', app['repo'], build_dir]) != 0:
                    print "Svn checkout failed"
                    sys.exit(1)
        else:
            print "Invalid repo type " + app['repotype'] + " in " + app['id']
            sys.exit(1)

        for thisbuild in app['builds']:

            print "Building version " + thisbuild['version']

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
                os.remove(os.path.join(root_dir, thisbuild['rm']))

            #Build the source tarball right before we build the relase...
            tarname = app['id'] + '_' + thisbuild['vercode'] + '_src'
            tarball = tarfile.open(os.path.join(unsigned_dir,
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
            src = re.match(r".*^.*Creating (\S+) for release.*$.*", output,
                    re.S|re.M).group(1)
            src = os.path.join(os.path.join(root_dir, 'bin'), src)

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

            # Copy the unsigned apk to our 'unsigned' directory to be
            # dealt with later...
            dest = os.path.join(unsigned_dir, app['id'] + '_' +
                    thisbuild['vercode'] + '.apk')
            shutil.copyfile(src, dest)

print "Finished."

