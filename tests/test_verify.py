#!/usr/bin/env python3

import json
import os
import shutil
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

from fdroidserver import verify


TEST_APP_ENTRY = {
    "1539780240.3885746": {
        "local": {
            "file": "unsigned/com.politedroid_6.apk",
            "packageName": "com.politedroid",
            "sha256": "70c2f776a2bac38a58a7d521f96ee0414c6f0fb1de973c3ca8b10862a009247d",
            "timestamp": 1234567.8900000,
            "versionCode": "6",
            "versionName": "1.5",
        },
        "remote": {
            "file": "tmp/com.politedroid_6.apk",
            "packageName": "com.politedroid",
            "sha256": "70c2f776a2bac38a58a7d521f96ee0414c6f0fb1de973c3ca8b10862a009247d",
            "timestamp": 1234567.8900000,
            "versionCode": "6",
            "versionName": "1.5",
        },
        "url": "https://f-droid.org/repo/com.politedroid_6.apk",
        "verified": True,
    }
}

basedir = Path(__file__).parent


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.chdir(self.tempdir.name)
        self.repodir = Path('repo')
        self.repodir.mkdir()
        self.apk_reports_json = basedir / 'org.fdroid.fdroid_1019051.apk.json'

    def tearDown(self):
        self.tempdir.cleanup()

    def test_get_verified_json_creation(self):
        self.assertEqual({'packages': {}}, verify.get_verified_json('does-not-exist'))

    def test_get_verified_json_existing(self):
        f = 'verified.json'
        reports = {'packages': {'placeholder': {}}}
        with open(f, 'w') as fp:
            json.dump(reports, fp)
        self.assertEqual(reports, verify.get_verified_json(f))

    def test_get_verified_json_pull_in_one_report(self):
        shutil.copy(self.apk_reports_json, self.tempdir.name)
        with open(self.apk_reports_json) as fp:
            reports = json.load(fp)
        self.assertEqual(
            {'packages': {'org.fdroid.fdroid': [reports['1708238023.6572325']]}},
            verify.get_verified_json('does-not-exist'),
        )

    def test_get_verified_json_ignore_corrupt(self):
        f = 'verified.json'
        with open(f, 'w') as fp:
            fp.write("""{"packages": {"placeholder": {""")
        shutil.copy(self.apk_reports_json, self.tempdir.name)
        with open(self.apk_reports_json) as fp:
            reports = json.load(fp)
        self.assertEqual(
            {'packages': {'org.fdroid.fdroid': [reports['1708238023.6572325']]}},
            verify.get_verified_json(f),
        )

    def test_get_verified_json_ignore_apk_reports(self):
        """When an intact verified.json exists, it should ignore the .apk.json reports."""
        f = 'verified.json'
        placeholder = {'packages': {'placeholder': {}}}
        with open(f, 'w') as fp:
            json.dump(placeholder, fp)
        shutil.copy(self.apk_reports_json, self.tempdir.name)
        with open(self.apk_reports_json) as fp:
            json.load(fp)
        self.assertEqual(placeholder, verify.get_verified_json(f))

    @patch('fdroidserver.common.sha256sum')
    def test_write_json_report(self, sha256sum):
        sha256sum.return_value = (
            '70c2f776a2bac38a58a7d521f96ee0414c6f0fb1de973c3ca8b10862a009247d'
        )
        os.mkdir('tmp')
        os.mkdir('unsigned')
        verified_json = Path('unsigned/verified.json')
        packageName = 'com.politedroid'
        apk_name = packageName + '_6.apk'
        remote_apk = 'tmp/' + apk_name
        unsigned_apk = 'unsigned/' + apk_name
        # TODO common.use apk_strip_v1_signatures() on unsigned_apk
        shutil.copy(basedir / 'repo' / apk_name, remote_apk)
        shutil.copy(basedir / 'repo' / apk_name, unsigned_apk)
        url = TEST_APP_ENTRY['1539780240.3885746']['url']

        self.assertFalse(verified_json.exists())
        verify.write_json_report(url, remote_apk, unsigned_apk, {})
        self.assertTrue(verified_json.exists())
        # smoke check status JSON
        with verified_json.open() as fp:
            firstpass = json.load(fp)

        verify.write_json_report(url, remote_apk, unsigned_apk, {})
        with verified_json.open() as fp:
            secondpass = json.load(fp)

        self.assertEqual(firstpass, secondpass)
