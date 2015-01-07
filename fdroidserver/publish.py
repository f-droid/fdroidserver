#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# publish.py - part of the FDroid server tools
# Copyright (C) 2010-13, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
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
import md5
import glob
from optparse import OptionParser
import logging

import common
import metadata
from common import FDroidPopen, SdkToolsPopen, BuildException

config = None
options = None


def main():

    global config, options

    # Parse command line...
    parser = OptionParser(usage="Usage: %prog [options] "
                          "[APPID[:VERCODE] [APPID[:VERCODE] ...]]")
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help="Restrict output to warnings and errors")
    (options, args) = parser.parse_args()

    config = common.read_config(options)

    log_dir = 'logs'
    if not os.path.isdir(log_dir):
        logging.info("Creating log directory")
        os.makedirs(log_dir)

    tmp_dir = 'tmp'
    if not os.path.isdir(tmp_dir):
        logging.info("Creating temporary directory")
        os.makedirs(tmp_dir)

    output_dir = 'repo'
    if not os.path.isdir(output_dir):
        logging.info("Creating output directory")
        os.makedirs(output_dir)

    unsigned_dir = 'unsigned'
    if not os.path.isdir(unsigned_dir):
        logging.warning("No unsigned directory - nothing to do")
        sys.exit(1)

    for f in [config['keystorepassfile'],
              config['keystore'],
              config['keypassfile']]:
        if not os.path.exists(f):
            logging.error("Config error - missing '{0}'".format(f))
            sys.exit(1)

    # It was suggested at
    #    https://dev.guardianproject.info/projects/bazaar/wiki/FDroid_Audit
    # that a package could be crafted, such that it would use the same signing
    # key as an existing app. While it may be theoretically possible for such a
    # colliding package ID to be generated, it seems virtually impossible that
    # the colliding ID would be something that would be a) a valid package ID,
    # and b) a sane-looking ID that would make its way into the repo.
    # Nonetheless, to be sure, before publishing we check that there are no
    # collisions, and refuse to do any publishing if that's the case...
    allapps = metadata.read_metadata()
    vercodes = common.read_pkg_args(args, True)
    allaliases = []
    for appid in allapps:
        m = md5.new()
        m.update(appid)
        keyalias = m.hexdigest()[:8]
        if keyalias in allaliases:
            logging.error("There is a keyalias collision - publishing halted")
            sys.exit(1)
        allaliases.append(keyalias)
    logging.info("{0} apps, {0} key aliases".format(len(allapps),
                                                    len(allaliases)))

    # Process any apks that are waiting to be signed...
    for apkfile in sorted(glob.glob(os.path.join(unsigned_dir, '*.apk'))):

        appid, vercode = common.apknameinfo(apkfile)
        apkfilename = os.path.basename(apkfile)
        if vercodes and appid not in vercodes:
            continue
        if appid in vercodes and vercodes[appid]:
            if vercode not in vercodes[appid]:
                continue
        logging.info("Processing " + apkfile)

        # There ought to be valid metadata for this app, otherwise why are we
        # trying to publish it?
        if appid not in allapps:
            logging.error("Unexpected {0} found in unsigned directory"
                          .format(apkfilename))
            sys.exit(1)
        app = allapps[appid]

        if app.get('Binaries', None):

            # It's an app where we build from source, and verify the apk
            # contents against a developer's binary, and then publish their
            # version if everything checks out.

            # Need the version name for the version code...
            versionname = None
            for build in app['builds']:
                if build['vercode'] == vercode:
                    versionname = build['version']
                    break
            if not versionname:
                logging.error("...no defined build for version code {0}"
                              .format(vercode))
                continue

            # Figure out where the developer's binary is supposed to come from...
            url = app['Binaries']
            url = url.replace('%v', versionname)
            url = url.replace('%c', str(vercode))

            # Grab the binary from where the developer publishes it...
            logging.info("...retrieving " + url)
            srcapk = os.path.join(tmp_dir, url.split('/')[-1])
            p = FDroidPopen(['wget', '-nv', '--continue', url], cwd=tmp_dir)
            if p.returncode != 0 or not os.path.exists(srcapk):
                logging.error("...failed to retrieve " + url +
                              " - publish skipped")
                continue

            # Compare our unsigned one with the downloaded one...
            compare_result = common.compare_apks(srcapk, apkfile, tmp_dir)
            if compare_result:
                logging.error("...verfication failed - publish skipped : "
                              + compare_result)
                continue

            # Success! So move the downloaded file to the repo...
            shutil.move(srcapk, os.path.join(output_dir, apkfilename))

        else:

            # It's a 'normal' app, i.e. we sign and publish it...

            # Figure out the key alias name we'll use. Only the first 8
            # characters are significant, so we'll use the first 8 from
            # the MD5 of the app's ID and hope there are no collisions.
            # If a collision does occur later, we're going to have to
            # come up with a new alogrithm, AND rename all existing keys
            # in the keystore!
            if appid in config['keyaliases']:
                # For this particular app, the key alias is overridden...
                keyalias = config['keyaliases'][appid]
                if keyalias.startswith('@'):
                    m = md5.new()
                    m.update(keyalias[1:])
                    keyalias = m.hexdigest()[:8]
            else:
                m = md5.new()
                m.update(appid)
                keyalias = m.hexdigest()[:8]
            logging.info("Key alias: " + keyalias)

            # See if we already have a key for this application, and
            # if not generate one...
            p = FDroidPopen(['keytool', '-list',
                             '-alias', keyalias, '-keystore', config['keystore'],
                             '-storepass:file', config['keystorepassfile']])
            if p.returncode != 0:
                logging.info("Key does not exist - generating...")
                p = FDroidPopen(['keytool', '-genkey',
                                 '-keystore', config['keystore'],
                                 '-alias', keyalias,
                                 '-keyalg', 'RSA', '-keysize', '2048',
                                 '-validity', '10000',
                                 '-storepass:file', config['keystorepassfile'],
                                 '-keypass:file', config['keypassfile'],
                                 '-dname', config['keydname']])
                # TODO keypass should be sent via stdin
                if p.returncode != 0:
                    raise BuildException("Failed to generate key")

            # Sign the application...
            p = FDroidPopen(['jarsigner', '-keystore', config['keystore'],
                             '-storepass:file', config['keystorepassfile'],
                             '-keypass:file', config['keypassfile'], '-sigalg',
                             'MD5withRSA', '-digestalg', 'SHA1',
                             apkfile, keyalias])
            # TODO keypass should be sent via stdin
            if p.returncode != 0:
                raise BuildException("Failed to sign application")

            # Zipalign it...
            p = SdkToolsPopen(['zipalign', '-v', '4', apkfile,
                               os.path.join(output_dir, apkfilename)])
            if p.returncode != 0:
                raise BuildException("Failed to align application")
            os.remove(apkfile)

        # Move the source tarball into the output directory...
        tarfilename = apkfilename[:-4] + '_src.tar.gz'
        tarfile = os.path.join(unsigned_dir, tarfilename)
        if os.path.exists(tarfile):
            shutil.move(tarfile, os.path.join(output_dir, tarfilename))

        logging.info('Published ' + apkfilename)


if __name__ == "__main__":
    main()
