#!/usr/bin/env python3
#
# publish.py - part of the FDroid server tools
# Copyright (C) 2010-13, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
# Copyright (C) 2021 Felix C. Stegerman <flx@obfusk.net>
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

"""Sign APKs using keys or via reproducible builds signature copying.

This command takes unsigned APKs and signs them.  It looks for
unsigned APKs in the unsigned/ directory and puts successfully signed
APKs into the repo/ directory.  The default is to run in a kind of
batch mode, where it will only quit on certain kinds of errors. It
mostly reports success by moving an APK from unsigned/ to repo/

"""

import sys
import os
import re
import shutil
import glob
import hashlib
from argparse import ArgumentParser
from collections import OrderedDict
import logging
from gettext import ngettext
import json
import time
import zipfile

from . import _
from . import common
from . import metadata
from .common import FDroidPopen
from .exception import BuildException, FDroidException

config = None
start_timestamp = time.gmtime()


def publish_source_tarball(apkfilename, unsigned_dir, output_dir):
    """Move the source tarball into the output directory..."""
    tarfilename = apkfilename[:-4] + '_src.tar.gz'
    tarfile = os.path.join(unsigned_dir, tarfilename)
    if os.path.exists(tarfile):
        shutil.move(tarfile, os.path.join(output_dir, tarfilename))
        logging.debug('...published %s', tarfilename)
    else:
        logging.debug('...no source tarball for %s', apkfilename)


def key_alias(appid):
    """No summary.

    Get the alias which F-Droid uses to indentify the singing key
    for this App in F-Droids keystore.
    """
    if config and 'keyaliases' in config and appid in config['keyaliases']:
        # For this particular app, the key alias is overridden...
        keyalias = config['keyaliases'][appid]
        if keyalias.startswith('@'):
            m = hashlib.md5()  # nosec just used to generate a keyalias
            m.update(keyalias[1:].encode('utf-8'))
            keyalias = m.hexdigest()[:8]
        return keyalias
    else:
        m = hashlib.md5()  # nosec just used to generate a keyalias
        m.update(appid.encode('utf-8'))
        return m.hexdigest()[:8]


def read_fingerprints_from_keystore():
    """Obtain a dictionary containing all singning-key fingerprints which are managed by F-Droid, grouped by appid."""
    env_vars = {'LC_ALL': 'C.UTF-8', 'FDROID_KEY_STORE_PASS': config['keystorepass']}
    cmd = [
        config['keytool'],
        '-list',
        '-v',
        '-keystore',
        config['keystore'],
        '-storepass:env',
        'FDROID_KEY_STORE_PASS',
    ]
    if config['keystore'] == 'NONE':
        cmd += config['smartcardoptions']
    p = FDroidPopen(cmd, envs=env_vars, output=False)
    if p.returncode != 0:
        raise FDroidException('could not read keystore {}'.format(config['keystore']))

    realias = re.compile('Alias name: (?P<alias>.+)' + os.linesep)
    resha256 = re.compile(r'\s+SHA256: (?P<sha256>[:0-9A-F]{95})' + os.linesep)
    fps = {}
    for block in p.output.split(('*' * 43) + os.linesep + '*' * 43):
        s_alias = realias.search(block)
        s_sha256 = resha256.search(block)
        if s_alias and s_sha256:
            sigfp = s_sha256.group('sha256').replace(':', '').lower()
            fps[s_alias.group('alias')] = sigfp
    return fps


def sign_sig_key_fingerprint_list(jar_file):
    """Sign the list of app-signing key fingerprints.

    This is used primaryily by fdroid update to determine which APKs
    where built and signed by F-Droid and which ones were
    manually added by users.
    """
    cmd = [config['jarsigner']]
    cmd += '-keystore', config['keystore']
    cmd += '-storepass:env', 'FDROID_KEY_STORE_PASS'
    cmd += '-digestalg', 'SHA1'
    cmd += '-sigalg', 'SHA1withRSA'
    cmd += jar_file, config['repo_keyalias']
    if config['keystore'] == 'NONE':
        cmd += config['smartcardoptions']
    else:  # smardcards never use -keypass
        cmd += '-keypass:env', 'FDROID_KEY_PASS'
    env_vars = {
        'FDROID_KEY_STORE_PASS': config['keystorepass'],
        'FDROID_KEY_PASS': config.get('keypass', ""),
    }
    p = common.FDroidPopen(cmd, envs=env_vars)
    if p.returncode != 0:
        raise FDroidException("Failed to sign '{}'!".format(jar_file))


def store_stats_fdroid_signing_key_fingerprints(appids, indent=None):
    """Store list of all signing-key fingerprints for given appids to HD.

    This list will later on be needed by fdroid update.
    """
    if not os.path.exists('stats'):
        os.makedirs('stats')
    data = OrderedDict()
    fps = read_fingerprints_from_keystore()
    for appid in sorted(appids):
        alias = key_alias(appid)
        if alias in fps:
            data[appid] = {'signer': fps[key_alias(appid)]}

    jar_file = os.path.join('stats', 'publishsigkeys.jar')
    with zipfile.ZipFile(jar_file, 'w', zipfile.ZIP_DEFLATED) as jar:
        jar.writestr('publishsigkeys.json', json.dumps(data, indent=indent))
    sign_sig_key_fingerprint_list(jar_file)


def status_update_json(generatedKeys, signedApks):
    """Output a JSON file with metadata about this run."""
    logging.debug(_('Outputting JSON'))
    output = common.setup_status_output(start_timestamp)
    output['apksigner'] = shutil.which(config.get('apksigner', ''))
    output['jarsigner'] = shutil.which(config.get('jarsigner', ''))
    output['keytool'] = shutil.which(config.get('keytool', ''))
    if generatedKeys:
        output['generatedKeys'] = generatedKeys
    if signedApks:
        output['signedApks'] = signedApks
    common.write_status_json(output)


def check_for_key_collisions(allapps):
    """Make sure there's no collision in keyaliases from apps.

    It was suggested at
    https://dev.guardianproject.info/projects/bazaar/wiki/FDroid_Audit
    that a package could be crafted, such that it would use the same signing
    key as an existing app. While it may be theoretically possible for such a
    colliding package ID to be generated, it seems virtually impossible that
    the colliding ID would be something that would be a) a valid package ID,
    and b) a sane-looking ID that would make its way into the repo.
    Nonetheless, to be sure, before publishing we check that there are no
    collisions, and refuse to do any publishing if that's the case.

    Parameters
    ----------
    allapps
      a dict of all apps to process

    Returns
    -------
    a list of all aliases corresponding to allapps
    """
    allaliases = []
    for appid in allapps:
        m = hashlib.md5()  # nosec just used to generate a keyalias
        m.update(appid.encode('utf-8'))
        keyalias = m.hexdigest()[:8]
        if keyalias in allaliases:
            logging.error(_("There is a keyalias collision - publishing halted"))
            sys.exit(1)
        allaliases.append(keyalias)
    return allaliases


def create_key_if_not_existing(keyalias):
    """Ensure a signing key with the given keyalias exists.

    Returns
    -------
    boolean
      True if a new key was created, False otherwise
    """
    # See if we already have a key for this application, and
    # if not generate one...
    env_vars = {
        'LC_ALL': 'C.UTF-8',
        'FDROID_KEY_STORE_PASS': config['keystorepass'],
        'FDROID_KEY_PASS': config.get('keypass', ""),
    }
    cmd = [
        config['keytool'],
        '-list',
        '-alias',
        keyalias,
        '-keystore',
        config['keystore'],
        '-storepass:env',
        'FDROID_KEY_STORE_PASS',
    ]
    if config['keystore'] == 'NONE':
        cmd += config['smartcardoptions']
    p = FDroidPopen(cmd, envs=env_vars)
    if p.returncode != 0:
        logging.info("Key does not exist - generating...")
        cmd = [
            config['keytool'],
            '-genkey',
            '-keystore',
            config['keystore'],
            '-alias',
            keyalias,
            '-keyalg',
            'RSA',
            '-keysize',
            '2048',
            '-validity',
            '10000',
            '-storepass:env',
            'FDROID_KEY_STORE_PASS',
            '-dname',
            config['keydname'],
        ]
        if config['keystore'] == 'NONE':
            cmd += config['smartcardoptions']
        else:
            cmd += '-keypass:env', 'FDROID_KEY_PASS'
        p = FDroidPopen(cmd, envs=env_vars)
        if p.returncode != 0:
            raise BuildException("Failed to generate key", p.output)
        return True
    else:
        return False


def main():
    global config

    # Parse command line...
    parser = ArgumentParser(
        usage="%(prog)s [options] " "[APPID[:VERCODE] [APPID[:VERCODE] ...]]"
    )
    common.setup_global_opts(parser)
    parser.add_argument(
        "-e",
        "--error-on-failed",
        action="store_true",
        default=False,
        help=_("When signing or verifying fails, exit with an error code."),
    )
    parser.add_argument(
        "appid",
        nargs='*',
        help=_("application ID with optional versionCode in the form APPID[:VERCODE]"),
    )
    metadata.add_metadata_arguments(parser)
    options = common.parse_args(parser)
    metadata.warnings_action = options.W

    config = common.read_config()

    if not ('jarsigner' in config and 'keytool' in config):
        logging.critical(
            _('Java JDK not found! Install in standard location or set java_paths!')
        )
        sys.exit(1)

    common.assert_config_keystore(config)

    log_dir = 'logs'
    if not os.path.isdir(log_dir):
        logging.info(_("Creating log directory"))
        os.makedirs(log_dir)

    tmp_dir = 'tmp'
    if not os.path.isdir(tmp_dir):
        logging.info(_("Creating temporary directory"))
        os.makedirs(tmp_dir)

    output_dir = 'repo'
    if not os.path.isdir(output_dir):
        logging.info(_("Creating output directory"))
        os.makedirs(output_dir)

    unsigned_dir = 'unsigned'
    if not os.path.isdir(unsigned_dir):
        logging.warning(_("No unsigned directory - nothing to do"))
        sys.exit(1)
    binaries_dir = os.path.join(unsigned_dir, 'binaries')

    if not config['keystore'] == "NONE" and not os.path.exists(config['keystore']):
        logging.error("Config error - missing '{0}'".format(config['keystore']))
        sys.exit(1)

    allapps = metadata.read_metadata()
    vercodes = common.read_pkg_args(options.appid, True)
    common.get_metadata_files(vercodes)  # only check appids
    signed_apks = dict()
    generated_keys = dict()
    allaliases = check_for_key_collisions(allapps)
    logging.info(
        ngettext(
            '{0} app, {1} key aliases', '{0} apps, {1} key aliases', len(allapps)
        ).format(len(allapps), len(allaliases))
    )

    failed = 0
    # Process any APKs or ZIPs that are waiting to be signed...
    for apkfile in sorted(
        glob.glob(os.path.join(unsigned_dir, '*.apk'))
        + glob.glob(os.path.join(unsigned_dir, '*.zip'))
    ):

        appid, vercode = common.publishednameinfo(apkfile)
        apkfilename = os.path.basename(apkfile)
        if vercodes and appid not in vercodes:
            continue
        if appid in vercodes and vercodes[appid]:
            if vercode not in vercodes[appid]:
                continue
        logging.info(_("Processing {apkfilename}").format(apkfilename=apkfile))

        # There ought to be valid metadata for this app, otherwise why are we
        # trying to publish it?
        if appid not in allapps:
            logging.error(
                "Unexpected {0} found in unsigned directory".format(apkfilename)
            )
            sys.exit(1)
        app = allapps[appid]

        build = None
        for b in app.get("Builds", ()):
            if b.get("versionCode") == vercode:
                build = b
        if app.Binaries or (build and build.binary):

            # It's an app where we build from source, and verify the apk
            # contents against a developer's binary, and then publish their
            # version if everything checks out.
            # The binary should already have been retrieved during the build
            # process.

            srcapk = re.sub(r'\.apk$', '.binary.apk', apkfile)
            srcapk = srcapk.replace(unsigned_dir, binaries_dir)

            if not os.path.isfile(srcapk):
                logging.error("...reference binary missing - publish skipped: "
                              "'{refpath}'".format(refpath=srcapk))
                failed += 1
            else:
                # Compare our unsigned one with the downloaded one...
                compare_result = common.verify_apks(srcapk, apkfile, tmp_dir)
                if compare_result:
                    logging.error("...verification failed - publish skipped : "
                                  "{result}".format(result=compare_result))
                    failed += 1
                else:
                    # Success! So move the downloaded file to the repo, and remove
                    # our built version.
                    shutil.move(srcapk, os.path.join(output_dir, apkfilename))
                    os.remove(apkfile)

                    publish_source_tarball(apkfilename, unsigned_dir, output_dir)
                    logging.info('Published ' + apkfilename)

        elif apkfile.endswith('.zip'):

            # OTA ZIPs built by fdroid do not need to be signed by jarsigner,
            # just to be moved into place in the repo
            shutil.move(apkfile, os.path.join(output_dir, apkfilename))
            publish_source_tarball(apkfilename, unsigned_dir, output_dir)
            logging.info('Published ' + apkfilename)

        else:

            # It's a 'normal' app, i.e. we sign and publish it...
            skipsigning = False

            # First we handle signatures for this app from local metadata
            signingfiles = common.metadata_find_developer_signing_files(appid, vercode)
            if signingfiles:
                # There's a signature of the app developer present in our
                # metadata. This means we're going to prepare both a locally
                # signed APK and a version signed with the developers key.

                signature_file, _ignored, manifest, v2_files = signingfiles

                with open(signature_file, 'rb') as f:
                    devfp = common.signer_fingerprint_short(
                        common.get_certificate(f.read())
                    )
                devsigned = '{}_{}_{}.apk'.format(appid, vercode, devfp)
                devsignedtmp = os.path.join(tmp_dir, devsigned)

                common.apk_implant_signatures(apkfile, devsignedtmp, manifest=manifest)
                if common.verify_apk_signature(devsignedtmp):
                    shutil.move(devsignedtmp, os.path.join(output_dir, devsigned))
                else:
                    os.remove(devsignedtmp)
                    logging.error('...verification failed - skipping: %s', devsigned)
                    skipsigning = True
                    failed += 1

            # Now we sign with the F-Droid key.
            if not skipsigning:
                keyalias = key_alias(appid)
                logging.info("Key alias: " + keyalias)

                if create_key_if_not_existing(keyalias):
                    generated_keys[appid] = keyalias

                signed_apk_path = os.path.join(output_dir, apkfilename)
                if os.path.exists(signed_apk_path):
                    raise BuildException("Refusing to sign '{0}' file exists in both "
                                         "{1} and {2} folder.".format(apkfilename,
                                                                      unsigned_dir,
                                                                      output_dir))

                # Sign the application...
                common.sign_apk(apkfile, signed_apk_path, keyalias)
                if appid not in signed_apks:
                    signed_apks[appid] = []
                signed_apks[appid].append({"keyalias": keyalias, "filename": apkfile})

                publish_source_tarball(apkfilename, unsigned_dir, output_dir)
                logging.info('Published ' + apkfilename)

    store_stats_fdroid_signing_key_fingerprints(allapps.keys())
    status_update_json(generated_keys, signed_apks)
    logging.info('published list signing-key fingerprints')

    if failed:
        logging.error(_('%d APKs failed to be signed or verified!') % failed)
        if options.error_on_failed:
            sys.exit(failed)


if __name__ == "__main__":
    main()
