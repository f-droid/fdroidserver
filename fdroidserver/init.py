#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# update.py - part of the FDroid server tools
# Copyright (C) 2010-2013, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
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

import glob
import hashlib
import os
import re
import shutil
import socket
import sys
from optparse import OptionParser
import logging

import common
from common import FDroidPopen, BuildException

config = {}
options = None


def write_to_config(key, value):
    '''write a key/value to the local config.py'''
    with open('config.py', 'r') as f:
        data = f.read()
    pattern = '\n[\s#]*' + key + '\s*=\s*"[^"]*"'
    repl = '\n' + key + ' = "' + value + '"'
    data = re.sub(pattern, repl, data)
    with open('config.py', 'w') as f:
        f.writelines(data)


def disable_in_config(key, value):
    '''write a key/value to the local config.py, then comment it out'''
    with open('config.py', 'r') as f:
        data = f.read()
    pattern = '\n[\s#]*' + key + '\s*=\s*"[^"]*"'
    repl = '\n#' + key + ' = "' + value + '"'
    data = re.sub(pattern, repl, data)
    with open('config.py', 'w') as f:
        f.writelines(data)


def genpassword():
    '''generate a random password for when generating keys'''
    h = hashlib.sha256()
    h.update(os.urandom(16))  # salt
    h.update(bytes(socket.getfqdn()))
    return h.digest().encode('base64').strip()


def genkey(keystore, repo_keyalias, password, keydname):
    '''generate a new keystore with a new key in it for signing repos'''
    logging.info('Generating a new key in "' + keystore + '"...')
    common.write_password_file("keystorepass", password)
    common.write_password_file("keypass", password)
    p = FDroidPopen(['keytool', '-genkey',
                     '-keystore', keystore, '-alias', repo_keyalias,
                     '-keyalg', 'RSA', '-keysize', '4096',
                     '-sigalg', 'SHA256withRSA',
                     '-validity', '10000',
                     '-storepass:file', config['keystorepassfile'],
                     '-keypass:file', config['keypassfile'],
                     '-dname', keydname])
    # TODO keypass should be sent via stdin
    if p.returncode != 0:
        raise BuildException("Failed to generate key", p.output)
    # now show the lovely key that was just generated
    p = FDroidPopen(['keytool', '-list', '-v',
                     '-keystore', keystore, '-alias', repo_keyalias,
                     '-storepass:file', config['keystorepassfile']])
    logging.info(p.output.strip() + '\n\n')


def main():

    global options, config

    # Parse command line...
    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help="Restrict output to warnings and errors")
    parser.add_option("-d", "--distinguished-name", default=None,
                      help="X.509 'Distiguished Name' used when generating keys")
    parser.add_option("--keystore", default=None,
                      help="Path to the keystore for the repo signing key")
    parser.add_option("--repo-keyalias", default=None,
                      help="Alias of the repo signing key in the keystore")
    parser.add_option("--android-home", default=None,
                      help="Path to the Android SDK (sometimes set in ANDROID_HOME)")
    parser.add_option("--no-prompt", action="store_true", default=False,
                      help="Do not prompt for Android SDK path, just fail")
    (options, args) = parser.parse_args()

    # find root install prefix
    tmp = os.path.dirname(sys.argv[0])
    if os.path.basename(tmp) == 'bin':
        prefix = os.path.dirname(tmp)
        examplesdir = prefix + '/share/doc/fdroidserver/examples'
    else:
        # we're running straight out of the git repo
        prefix = os.path.normpath(os.path.join(os.path.dirname(__file__), '..'))
        examplesdir = prefix + '/examples'

    fdroiddir = os.getcwd()
    test_config = common.get_default_config()

    # track down where the Android SDK is, the default is to use the path set
    # in ANDROID_HOME if that exists, otherwise None
    if options.android_home is not None:
        test_config['sdk_path'] = options.android_home
    elif not common.test_sdk_exists(test_config):
        # if neither --android-home nor the default sdk_path exist, prompt the user
        default_sdk_path = '/opt/android-sdk'
        while not options.no_prompt:
            try:
                s = raw_input('Enter the path to the Android SDK ('
                              + default_sdk_path + ') here:\n> ')
            except KeyboardInterrupt:
                print('')
                sys.exit(1)
            if re.match('^\s*$', s) is not None:
                test_config['sdk_path'] = default_sdk_path
            else:
                test_config['sdk_path'] = s
            if common.test_sdk_exists(test_config):
                break
    if not common.test_sdk_exists(test_config):
        sys.exit(3)

    if not os.path.exists('config.py'):
        # 'metadata' and 'tmp' are created in fdroid
        if not os.path.exists('repo'):
            os.mkdir('repo')
        shutil.copy(os.path.join(examplesdir, 'fdroid-icon.png'), fdroiddir)
        shutil.copyfile(os.path.join(examplesdir, 'config.py'), 'config.py')
        os.chmod('config.py', 0o0600)
        write_to_config('sdk_path', test_config['sdk_path'])
    else:
        logging.warn('Looks like this is already an F-Droid repo, cowardly refusing to overwrite it...')
        logging.info('Try running `fdroid init` in an empty directory.')
        sys.exit()

    # try to find a working aapt, in all the recent possible paths
    build_tools = os.path.join(test_config['sdk_path'], 'build-tools')
    aaptdirs = []
    aaptdirs.append(os.path.join(build_tools, test_config['build_tools']))
    aaptdirs.append(build_tools)
    for f in os.listdir(build_tools):
        if os.path.isdir(os.path.join(build_tools, f)):
            aaptdirs.append(os.path.join(build_tools, f))
    for d in sorted(aaptdirs, reverse=True):
        if os.path.isfile(os.path.join(d, 'aapt')):
            aapt = os.path.join(d, 'aapt')
            break
    if os.path.isfile(aapt):
        dirname = os.path.basename(os.path.dirname(aapt))
        if dirname == 'build-tools':
            # this is the old layout, before versioned build-tools
            test_config['build_tools'] = ''
        else:
            test_config['build_tools'] = dirname
        write_to_config('build_tools', test_config['build_tools'])
    if not common.test_build_tools_exists(test_config):
        sys.exit(3)

    # now that we have a local config.py, read configuration...
    config = common.read_config(options)

    # track down where the Android NDK is
    ndk_path = '/opt/android-ndk'
    if os.path.isdir(config['ndk_path']):
        ndk_path = config['ndk_path']
    elif 'ANDROID_NDK' in os.environ.keys():
        logging.info('using ANDROID_NDK')
        ndk_path = os.environ['ANDROID_NDK']
    if os.path.isdir(ndk_path):
        write_to_config('ndk_path', ndk_path)
    # the NDK is optional so we don't prompt the user for it if its not found

    # find or generate the keystore for the repo signing key. First try the
    # path written in the default config.py.  Then check if the user has
    # specified a path from the command line, which will trump all others.
    # Otherwise, create ~/.local/share/fdroidserver and stick it in there.  If
    # keystore is set to NONE, that means that Java will look for keys in a
    # Hardware Security Module aka Smartcard.
    keystore = config['keystore']
    if options.keystore:
        keystore = os.path.abspath(options.keystore)
        if options.keystore == 'NONE':
            keystore = options.keystore
        else:
            keystore = os.path.abspath(options.keystore)
            if not os.path.exists(keystore):
                logging.info('"' + keystore
                             + '" does not exist, creating a new keystore there.')
    write_to_config('keystore', keystore)
    repo_keyalias = None
    if options.repo_keyalias:
        repo_keyalias = options.repo_keyalias
        write_to_config('repo_keyalias', repo_keyalias)
    if options.distinguished_name:
        keydname = options.distinguished_name
        write_to_config('keydname', keydname)
    if keystore == 'NONE':  # we're using a smartcard
        write_to_config('repo_keyalias', '1')  # seems to be the default
        disable_in_config('keypass', 'never used with smartcard')
        write_to_config('smartcardoptions',
                        ('-storetype PKCS11 -providerName SunPKCS11-OpenSC '
                         + '-providerClass sun.security.pkcs11.SunPKCS11 '
                         + '-providerArg opensc-fdroid.cfg'))
        # find opensc-pkcs11.so
        if not os.path.exists('opensc-fdroid.cfg'):
            if os.path.exists('/usr/lib/opensc-pkcs11.so'):
                opensc_so = '/usr/lib/opensc-pkcs11.so'
            elif os.path.exists('/usr/lib64/opensc-pkcs11.so'):
                opensc_so = '/usr/lib64/opensc-pkcs11.so'
            else:
                files = glob.glob('/usr/lib/' + os.uname()[4] + '-*-gnu/opensc-pkcs11.so')
                if len(files) > 0:
                    opensc_so = files[0]
                else:
                    opensc_so = '/usr/lib/opensc-pkcs11.so'
                    logging.warn('No OpenSC PKCS#11 module found, ' +
                                 'install OpenSC then edit "opensc-fdroid.cfg"!')
            with open(os.path.join(examplesdir, 'opensc-fdroid.cfg'), 'r') as f:
                opensc_fdroid = f.read()
            opensc_fdroid = re.sub('^library.*', 'library = ' + opensc_so, opensc_fdroid,
                                   flags=re.MULTILINE)
            with open('opensc-fdroid.cfg', 'w') as f:
                f.write(opensc_fdroid)
    elif not os.path.exists(keystore):
        # no existing or specified keystore, generate the whole thing
        keystoredir = os.path.dirname(keystore)
        if not os.path.exists(keystoredir):
            os.makedirs(keystoredir, mode=0o700)
        password = genpassword()
        write_to_config('keystorepass', password)
        write_to_config('keypass', password)
        if options.repo_keyalias is None:
            repo_keyalias = socket.getfqdn()
            write_to_config('repo_keyalias', repo_keyalias)
        if not options.distinguished_name:
            keydname = 'CN=' + repo_keyalias + ', OU=F-Droid'
            write_to_config('keydname', keydname)
        genkey(keystore, repo_keyalias, password, keydname)

    logging.info('Built repo based in "' + fdroiddir + '"')
    logging.info('with this config:')
    logging.info('  Android SDK:\t\t\t' + config['sdk_path'])
    logging.info('  Android SDK Build Tools:\t' + os.path.dirname(aapt))
    logging.info('  Android NDK (optional):\t' + ndk_path)
    logging.info('  Keystore for signing key:\t' + keystore)
    if repo_keyalias is not None:
        logging.info('  Alias for key in store:\t' + repo_keyalias)
    logging.info('\nTo complete the setup, add your APKs to "' +
                 os.path.join(fdroiddir, 'repo') + '"' + '''
then run "fdroid update -c; fdroid update".  You might also want to edit
"config.py" to set the URL, repo name, and more.  You should also set up
a signing key (a temporary one might have been automatically generated).

For more info: https://f-droid.org/manual/fdroid.html#Simple-Binary-Repository
and https://f-droid.org/manual/fdroid.html#Signing
''')
