#!/usr/bin/env python3

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from fdroidserver import apksigcopier, common, exception, signindex, update
from pathlib import Path
from unittest.mock import patch


class Options:
    allow_disabled_algorithms = False
    clean = False
    delete_unknown = False
    nosign = False
    pretty = True
    rename_apks = False
    verbose = False


class SignindexTest(unittest.TestCase):
    basedir = Path(__file__).resolve().parent

    def setUp(self):
        signindex.config = None
        config = common.read_config()
        config['jarsigner'] = common.find_sdk_tools_cmd('jarsigner')
        config['verbose'] = True
        config['keystore'] = str(self.basedir / 'keystore.jks')
        config['repo_keyalias'] = 'sova'
        config['keystorepass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        config['keypass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        signindex.config = config

        self.tempdir = tempfile.TemporaryDirectory()
        os.chdir(self.tempdir.name)
        self.repodir = Path('repo')
        self.repodir.mkdir()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_sign_index(self):
        shutil.copy(str(self.basedir / 'repo/index-v1.json'), 'repo')
        signindex.sign_index(str(self.repodir), 'index-v1.json')
        self.assertTrue((self.repodir / 'index-v1.jar').exists())
        self.assertTrue((self.repodir / 'index-v1.json').exists())

    def test_sign_index_corrupt(self):
        with open('repo/index-v1.json', 'w') as fp:
            fp.write('corrupt JSON!')
        with self.assertRaises(json.decoder.JSONDecodeError, msg='error on bad JSON'):
            signindex.sign_index(str(self.repodir), 'index-v1.json')

    def test_sign_entry(self):
        entry = 'repo/entry.json'
        v2 = 'repo/index-v2.json'
        shutil.copy(self.basedir / entry, entry)
        shutil.copy(self.basedir / v2, v2)
        signindex.sign_index(self.repodir, 'entry.json')
        self.assertTrue((self.repodir / 'entry.jar').exists())

    def test_sign_entry_corrupt(self):
        """sign_index should exit with error if entry.json is bad JSON"""
        entry = 'repo/entry.json'
        with open(entry, 'w') as fp:
            fp.write('{')
        with self.assertRaises(json.decoder.JSONDecodeError, msg='error on bad JSON'):
            signindex.sign_index(self.repodir, 'entry.json')
        self.assertFalse((self.repodir / 'entry.jar').exists())

    def test_sign_entry_corrupt_leave_entry_jar(self):
        """sign_index should not touch existing entry.jar if entry.json is corrupt"""
        existing = 'repo/entry.jar'
        testvalue = "Don't touch!"
        with open(existing, 'w') as fp:
            fp.write(testvalue)
        with open('repo/entry.json', 'w') as fp:
            fp.write('{')
        with self.assertRaises(json.decoder.JSONDecodeError, msg='error on bad JSON'):
            signindex.sign_index(self.repodir, 'entry.json')
        with open(existing) as fp:
            self.assertEqual(testvalue, fp.read())

    def test_sign_corrupt_index_v2_json(self):
        """sign_index should exit with error if index-v2.json JSON is corrupt"""
        with open('repo/index-v2.json', 'w') as fp:
            fp.write('{"key": "not really an index"')
        good_entry = {
            "timestamp": 1676583021000,
            "version": 20002,
            "index": {
                "name": "/index-v2.json",
                "sha256": common.sha256sum('repo/index-v2.json'),
                "size": os.path.getsize('repo/index-v2.json'),
                "numPackages": 0,
            },
        }
        with open('repo/entry.json', 'w') as fp:
            json.dump(good_entry, fp)
        with self.assertRaises(json.decoder.JSONDecodeError, msg='error on bad JSON'):
            signindex.sign_index(self.repodir, 'entry.json')
        self.assertFalse((self.repodir / 'entry.jar').exists())

    def test_sign_index_v2_corrupt_sha256(self):
        """sign_index should exit with error if SHA-256 of file in entry is wrong"""
        entry = 'repo/entry.json'
        v2 = 'repo/index-v2.json'
        shutil.copy(self.basedir / entry, entry)
        shutil.copy(self.basedir / v2, v2)
        with open(v2, 'a') as fp:
            fp.write(' ')
        with self.assertRaises(exception.FDroidException, msg='error on bad SHA-256'):
            signindex.sign_index(self.repodir, 'entry.json')
        self.assertFalse((self.repodir / 'entry.jar').exists())

    def test_signindex(self):
        if common.find_apksigner({}) is None:  # TODO remove me for buildserver-bullseye
            self.skipTest('SKIPPING test_signindex, apksigner not installed!')
        os.mkdir('archive')
        metadata = Path('metadata')
        metadata.mkdir()
        with (metadata / 'info.guardianproject.urzip.yml').open('w') as fp:
            fp.write('# placeholder')
        shutil.copy(str(self.basedir / 'urzip.apk'), 'repo')
        index_files = []
        for f in (
            'entry.jar',
            'entry.json',
            'index-v1.jar',
            'index-v1.json',
            'index-v2.json',
            'index.jar',
            'index.xml',
        ):
            for section in (Path('repo'), Path('archive')):
                path = section / f
                self.assertFalse(path.exists(), '%s should not exist yet!' % path)
                index_files.append(path)
        common.options = Options
        with patch('sys.argv', ['fdroid update']):
            update.main()
        with patch('sys.argv', ['fdroid signindex', '--verbose']):
            signindex.main()
        for f in index_files:
            self.assertTrue(f.exists(), '%s should exist!' % f)
        self.assertFalse(os.path.exists('index-v2.jar'))  # no JAR version of this file

        # index.jar aka v0 must by signed by SHA1withRSA
        f = 'repo/index.jar'
        common.verify_deprecated_jar_signature(f)
        self.assertIsNone(apksigcopier.extract_v2_sig(f, expected=False))
        cp = subprocess.run(
            ['jarsigner', '-verify', '-verbose', f], stdout=subprocess.PIPE
        )
        self.assertTrue(b'SHA1withRSA' in cp.stdout)

        # index-v1.jar must by signed by SHA1withRSA
        f = 'repo/index-v1.jar'
        common.verify_deprecated_jar_signature(f)
        self.assertIsNone(apksigcopier.extract_v2_sig(f, expected=False))
        cp = subprocess.run(
            ['jarsigner', '-verify', '-verbose', f], stdout=subprocess.PIPE
        )
        self.assertTrue(b'SHA1withRSA' in cp.stdout)

        # entry.jar aka index v2 must by signed by a modern algorithm
        f = 'repo/entry.jar'
        common.verify_deprecated_jar_signature(f)
        self.assertIsNone(apksigcopier.extract_v2_sig(f, expected=False))
        cp = subprocess.run(
            ['jarsigner', '-verify', '-verbose', f], stdout=subprocess.PIPE
        )
        self.assertFalse(b'SHA1withRSA' in cp.stdout)
