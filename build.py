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
import md5
from xml.dom.minidom import Document
from optparse import OptionParser

#Read configuration...
execfile('config.py')

# Parse command line...
parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true", default=False,
                  help="Spew out even more information than normal")
(options, args) = parser.parse_args()

# Get all apps...
apps = []

for metafile in glob.glob(os.path.join('metadata','*.txt')):

    thisinfo = {}

    # Get metadata...
    thisinfo['id'] = metafile[9:-4]
    print "Reading metadata for " + thisinfo['id']
    thisinfo['description'] = ''
    thisinfo['summary'] = ''
    thisinfo['license'] = 'Unknown'
    thisinfo['web'] = ''
    thisinfo['source'] = ''
    thisinfo['tracker'] = ''
    thisinfo['disabled'] = None
    thisinfo['marketversion'] = ''
    thisinfo['marketvercode'] = '0'
    thisinfo['repotype'] = ''
    thisinfo['repo'] = ''
    f = open(metafile, 'r')
    mode = 0
    for line in f.readlines():
        line = line.rstrip('\r\n')
        if len(line) == 0:
            pass
        elif mode == 0:
            index = line.find(':')
            if index == -1:
                print "Invalid metadata in " + metafile + " at:" + line
                sys.exit(1)
            field = line[:index]
            value = line[index+1:]
            if field == 'Description':
                mode = 1
            elif field == 'Summary':
                thisinfo['summary'] = value
            elif field == 'Source Code':
                thisinfo['source'] = value
            elif field == 'License':
                thisinfo['license'] = value
            elif field == 'Web Site':
                thisinfo['web'] = value
            elif field == 'Issue Tracker':
                thisinfo['tracker'] = value
            elif field == 'Disabled':
                thisinfo['disabled'] = value
            elif field == 'Market Version':
                thisinfo['marketversion'] = value
            elif field == 'Market Version Code':
                thisinfo['marketvercode'] = value
            elif field == 'Repo Type':
                thisinfo['repotype'] = value
            elif field == 'Repo':
                thisinfo['repo'] = value
            else:
                print "Unrecognised field " + field
                sys.exit(1)
        elif mode == 1:
            if line == '.':
                mode = 0
            else:
                if len(line) == 0:
                    thisinfo['description'] += '\n\n'
                else:
                    if (not thisinfo['description'].endswith('\n') and
                        len(thisinfo['description']) > 0):
                        thisinfo['description'] += ' '
                    thisinfo['description'] += line
    if len(thisinfo['description']) == 0:
        thisinfo['description'] = 'No description available'

    apps.append(thisinfo)

unsigned_dir = 'unsigned'
if os.path.exists(unsigned_dir):
    shutil.rmtree(unsigned_dir)
os.mkdir(unsigned_dir)

for app in apps:

    if app['disabled'] is None and app['repo'] != '' and app['repotype'] != '':

        print "About to build " + app['id']

        build_dir = 'build_' + app['id']

        # Remove the build directory if it already exists...
        if os.path.exists(build_dir):
            shutil.rmtree(build_dir)

        # Get the source code...
        if app['repotype'] == 'git':
            if subprocess.call(['git','clone',app['repo'],build_dir]) != 0:
                print "Git clone failed"
                sys.exit(1)
        else:
            print "Invalid repo type " + app['repotype'] + " in " + app['id']
            sys.exit(1)

        # Generate (or update) the ant build file, build.xml...
        if subprocess.call(['android','update','project','-p','.'],
                cwd=build_dir) != 0:
            print "Failed to update project"
            sys.exit(1)

        # If the app has ant set up to sign the release, we need to switch
        # that off, because we want the unsigned apk...
        if os.path.exists(os.path.join(build_dir, 'build.properties')):
            if subprocess.call(['sed','-i','s/^key.store/#/',
                'build.properties'], cwd=build_dir) !=0:
                print "Failed to amend build.properties"
                sys.exit(1)

        # Build the release...
        p = subprocess.Popen(['ant','release'], cwd=build_dir, 
                stdout=subprocess.PIPE)
        output = p.communicate()[0]
        print output
        if p.returncode != 0:
            print "Build failed"
            sys.exit(1)

        # Find the apk name in the output...
        src = re.match(r".*^.*Creating (\S+) for release.*$.*", output,
                re.S|re.M).group(1)
        dest = os.path.join(unsigned_dir, app['id'] + '.apk')
        shutil.copyfile(os.path.join( os.path.join(build_dir, 'bin'),
            src), dest)

print "Finished."

