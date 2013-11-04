#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# update.py - part of the FDroid server tools
# Copyright (C) 2010-2013, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013 Daniel Martí <mvdan@mvdan.cc>
# Copyright (C) 2013 Hans-Christoph Steiner <hans@eds.org>
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
import re
import shutil
import sys
from optparse import OptionParser

import common


config = {}
options = None

def write_to_config(key, value):
    '''write a key/value to the local config.py'''
    with open('config.py', 'r') as f:
        data = f.read()
    pattern = key + '\s*=.*'
    repl = key + ' = "' + value + '"'
    data = re.sub(pattern, repl, data)
    with open('config.py', 'w') as f:
        f.writelines(data)

def main():
    # Parse command line...
    global options
    parser = OptionParser()

    # find root install prefix
    tmp = os.path.dirname(sys.argv[0])
    if os.path.basename(tmp) == 'bin':
        prefix = os.path.dirname(tmp)
        examplesdir = prefix + '/share/doc/fdroidserver/examples'
    else:
        # we're running straight out of the git repo
        prefix = tmp
        examplesdir = prefix

    repodir = os.getcwd()

    if not os.path.exists('config.py') and not os.path.exists('repo'):
        # 'metadata' and 'tmp' are created in fdroid
        os.mkdir('repo')
        shutil.copy(os.path.join(examplesdir, 'fdroid-icon.png'), repodir)
        shutil.copyfile(os.path.join(examplesdir, 'config.sample.py'), 'config.py')
    else:
        print('Looks like this is already an F-Droid repo, cowardly refusing to overwrite it...')
        sys.exit()

    # now that we have a local config.py, read configuration...
    config = common.read_config(options)

    # track down where the Android SDK is
    if os.path.isdir(config['sdk_path']):
        print('Using "' + config['sdk_path'] + '" for the Android SDK')
        sdk_path = config['sdk_path']
    elif 'ANDROID_HOME' in os.environ.keys():
        sdk_path = os.environ['ANDROID_HOME']
    else:
        default_sdk_path = '/opt/android-sdk'
        while True:
            s = raw_input('Enter the path to the Android SDK (' + default_sdk_path + '): ')
            if re.match('^\s*$', s) != None:
                sdk_path = default_sdk_path
            else:
                sdk_path = s
            if os.path.isdir(os.path.join(sdk_path, 'build-tools')):
                break
            else:
                print('"' + s + '" does not contain the Android SDK! Try again...')
    if os.path.isdir(sdk_path):
        write_to_config('sdk_path', sdk_path)

    # try to find a working aapt, in all the recent possible paths
    build_tools = os.path.join(sdk_path, 'build-tools')
    aaptdirs = []
    aaptdirs.append(os.path.join(build_tools, config['build_tools']))
    aaptdirs.append(build_tools)
    for f in sorted(os.listdir(build_tools), reverse=True):
        if os.path.isdir(os.path.join(build_tools, f)):
            aaptdirs.append(os.path.join(build_tools, f))
    for d in aaptdirs:
        if os.path.isfile(os.path.join(d, 'aapt')):
            aapt = os.path.join(d, 'aapt')
            break
    if os.path.isfile(aapt):
        dirname = os.path.basename(os.path.dirname(aapt))
        if dirname == 'build-tools':
            # this is the old layout, before versioned build-tools
            write_to_config('build_tools', '')
        else:
            write_to_config('build_tools', dirname)

    # track down where the Android NDK is
    ndk_path = '/opt/android-ndk'
    if os.path.isdir(config['ndk_path']):
        ndk_path = config['ndk_path']
    elif 'ANDROID_NDK' in os.environ.keys():
        print('using ANDROID_NDK')
        ndk_path = os.environ['ANDROID_NDK']
    if os.path.isdir(ndk_path):
        write_to_config('ndk_path', ndk_path)
    # the NDK is optional so we don't prompt the user for it if its not found

    print('Built repo in "' + repodir + '" with this config:')
    print('  Android SDK:\t\t\t' + sdk_path)
    print('  Android SDK Build Tools:\t' + os.path.dirname(aapt))
    print('  Android NDK (optional):\t' + ndk_path)
    print('\nTo complete the setup, add your APKs to "' +
          os.path.join(repodir, 'repo') + '"' +
'''
then run "fdroid update -c; fdroid update".  You might also want to edit
"config.py" to set the URL, repo name, and more.  You should also set up
a signing key.

For more info: https://f-droid.org/manual/fdroid.html#Simple-Binary-Repository
''')
