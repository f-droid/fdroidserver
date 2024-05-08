#!/usr/bin/env python3
#
# gpgsign.py - part of the FDroid server tools
# Copyright (C) 2015, Ciaran Gultnieks, ciaran@ciarang.com
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

import json
import os
import time
import zipfile
from argparse import ArgumentParser
import logging

from . import _
from . import common
from . import metadata
from .exception import FDroidException

config = None
start_timestamp = time.gmtime()


def sign_jar(jar, use_old_algs=False):
    """Sign a JAR file with the best available algorithm.

    The current signing method uses apksigner to sign the JAR so that
    it will automatically select algorithms that are compatible with
    Android SDK 23, which added the most recent algorithms:
    https://developer.android.com/reference/java/security/Signature

    This signing method uses then inherits the default signing
    algothim settings, since Java and Android both maintain those.
    That helps avoid a repeat of being stuck on an old signing
    algorithm.  That means specifically that this call to apksigner
    does not specify any of the algorithms.

    The old indexes must be signed by SHA1withRSA otherwise they will
    no longer be compatible with old Androids.

    This method requires a properly initialized config object.

    """
    if use_old_algs:
        # This does use old hashing algorithms, i.e. SHA1, but that's not
        # broken yet for file verification.  This could be set to SHA256,
        # but then Android < 4.3 would not be able to verify it.
        # https://code.google.com/p/android/issues/detail?id=38321
        args = [
            config['jarsigner'],
            '-keystore',
            config['keystore'],
            '-storepass:env',
            'FDROID_KEY_STORE_PASS',
            '-digestalg',
            'SHA1',
            '-sigalg',
            'SHA1withRSA',
            jar,
            config['repo_keyalias'],
        ]
        if config['keystore'] == 'NONE':
            args += config['smartcardoptions']
        else:  # smardcards never use -keypass
            args += ['-keypass:env', 'FDROID_KEY_PASS']
    else:
        # https://developer.android.com/studio/command-line/apksigner
        args = [
            config['apksigner'],
            'sign',
            '--min-sdk-version',
            '23',  # enable all current algorithms
            '--max-sdk-version',
            '24',  # avoid future incompatible algorithms
            # disable all APK signature types, only use JAR sigs aka v1
            '--v1-signing-enabled',
            'true',
            '--v2-signing-enabled',
            'false',
            '--v3-signing-enabled',
            'false',
            '--v4-signing-enabled',
            'false',
            '--ks',
            config['keystore'],
            '--ks-pass',
            'env:FDROID_KEY_STORE_PASS',
            '--ks-key-alias',
            config['repo_keyalias'],
        ]
        if config['keystore'] == 'NONE':
            args += common.get_apksigner_smartcardoptions(config['smartcardoptions'])
        else:  # smardcards never use --key-pass
            args += ['--key-pass', 'env:FDROID_KEY_PASS']
        args += [jar]
    env_vars = {
        'FDROID_KEY_STORE_PASS': config['keystorepass'],
        'FDROID_KEY_PASS': config.get('keypass', ""),
    }
    p = common.FDroidPopen(args, envs=env_vars)
    if not use_old_algs and p.returncode != 0:
        # workaround for apksigner v30 on f-droid.org publish server
        v4 = args.index("--v4-signing-enabled")
        del args[v4 + 1]
        del args[v4]
        p = common.FDroidPopen(args, envs=env_vars)
        if p.returncode != 0:
            raise FDroidException("Failed to sign %s: %s" % (jar, p.output))


def sign_index(repodir, json_name):
    """Sign data file like entry.json to make a signed JAR like entry.jar.

    The data file like index-v1.json means that there is unsigned
    data.  That file is then stuck into a jar and signed by the
    signing process. This is a bit different than sign_jar, which is
    used for index.jar: that creates index.xml then puts that in a
    index_unsigned.jar, then that file is signed.

    This also checks to make sure that the JSON files are intact
    before signing them.  Broken JSON files should never be signed, so
    taking some extra time and failing hard is the preferred
    option. This signing process can happen on an entirely separate
    machine and file tree, so this ensures that nothing got broken
    during transfer.

    """
    json_file = os.path.join(repodir, json_name)
    with open(json_file, encoding="utf-8") as fp:
        data = json.load(fp)
        if json_name == 'entry.json':
            index_file = os.path.join(repodir, data['index']['name'].lstrip('/'))
            sha256 = common.sha256sum(index_file)
            if sha256 != data['index']['sha256']:
                raise FDroidException(
                    _('%s has bad SHA-256: %s') % (index_file, sha256)
                )
            with open(index_file) as fp:
                index = json.load(fp)
            if not isinstance(index, dict):
                raise FDroidException(_('%s did not produce a dict!') % index_file)
        elif json_name == 'index-v1.json':
            [metadata.App(app) for app in data["apps"]]

    name, ext = common.get_extension(json_name)
    jar_file = os.path.join(repodir, name + '.jar')
    with zipfile.ZipFile(jar_file, 'w', zipfile.ZIP_DEFLATED) as jar:
        jar.write(json_file, json_name)

    if json_name in ('index.xml', 'index-v1.json'):
        sign_jar(jar_file, use_old_algs=True)
    else:
        sign_jar(jar_file)


def status_update_json(signed):
    """Output a JSON file with metadata about this run."""
    logging.debug(_('Outputting JSON'))
    output = common.setup_status_output(start_timestamp)
    if signed:
        output['signed'] = signed
    common.write_status_json(output)


def main():
    global config

    parser = ArgumentParser()
    common.setup_global_opts(parser)
    common.parse_args(parser)

    config = common.read_config()

    if 'jarsigner' not in config:
        raise FDroidException(
            _(
                'Java jarsigner not found! Install in standard location or set java_paths!'
            )
        )

    repodirs = ['repo']
    if config['archive_older'] != 0:
        repodirs.append('archive')

    signed = []
    for output_dir in repodirs:
        if not os.path.isdir(output_dir):
            raise FDroidException("Missing output directory '" + output_dir + "'")

        unsigned = os.path.join(output_dir, 'index_unsigned.jar')
        if os.path.exists(unsigned):
            sign_jar(unsigned)
            index_jar = os.path.join(output_dir, 'index.jar')
            os.rename(unsigned, index_jar)
            logging.info('Signed index in ' + output_dir)
            signed.append(index_jar)

        json_name = 'index-v1.json'
        index_file = os.path.join(output_dir, json_name)
        if os.path.exists(index_file):
            sign_index(output_dir, json_name)
            logging.info('Signed ' + index_file)
            signed.append(index_file)

        json_name = 'entry.json'
        index_file = os.path.join(output_dir, json_name)
        if os.path.exists(index_file):
            sign_index(output_dir, json_name)
            logging.info('Signed ' + index_file)
            signed.append(index_file)

    if not signed:
        logging.info(_("Nothing to do"))
    status_update_json(signed)


if __name__ == "__main__":
    main()
