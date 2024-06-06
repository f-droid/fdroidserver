#!/usr/bin/env python3

import json
import os
import unittest

from pathlib import Path
from unittest import mock, skipUnless

from fdroidserver import common, schedule_verify
from .shared_test_code import mkdtemp


basedir = Path(__file__).parent

FULL_LIST = [
    {'applicationId': 'org.maxsdkversion', 'versionCode': 4},
    {'applicationId': 'info.zwanenburg.caffeinetile', 'versionCode': 4},
    {'applicationId': 'no.min.target.sdk', 'versionCode': 987},
    {'applicationId': 'souch.smsbypass', 'versionCode': 9},
    {'applicationId': 'duplicate.permisssions', 'versionCode': 9999999},
    {'applicationId': 'com.politedroid', 'versionCode': 6},
    {'applicationId': 'com.politedroid', 'versionCode': 5},
    {'applicationId': 'com.politedroid', 'versionCode': 4},
    {'applicationId': 'com.politedroid', 'versionCode': 3},
    {'applicationId': 'obb.mainpatch.current', 'versionCode': 1619},
    {'applicationId': 'info.guardianproject.urzip', 'versionCode': 100},
    {'applicationId': 'obb.main.twoversions', 'versionCode': 1101617},
    {'applicationId': 'fake.ota.update', 'versionCode': 1234},
    {'applicationId': 'obb.main.twoversions', 'versionCode': 1101615},
    {'applicationId': 'obb.main.twoversions', 'versionCode': 1101613},
    {'applicationId': 'obb.main.oldversion', 'versionCode': 1444412523},
]


def _mock(repo):  # pylint: disable=unused-argument
    indexf = basedir / 'repo' / 'index-v2.json'
    return json.loads(indexf.read_text()), None


class Schedule_verifyTest(unittest.TestCase):
    def setUp(self):
        self._td = mkdtemp()
        self.testdir = self._td.name
        os.chdir(self.testdir)
        os.mkdir('unsigned')

    def tearDown(self):
        self._td.cleanup()
        common.config = None


@skipUnless(False, 'This involves downloading the full index')
class Schedule_verify_main(Schedule_verifyTest):
    def test_main_smokecheck(self):
        schedule_verify.main()


class Schedule_verify_get_versions(Schedule_verifyTest):
    def setUp(self):
        super().setUp()
        common.config = {'sdk_path': os.getenv('ANDROID_HOME')}
        common.config['jarsigner'] = common.find_sdk_tools_cmd('jarsigner')

    @mock.patch('fdroidserver.index.download_repo_index_v2', _mock)
    def test_get_versions_none_exist(self):
        self.assertEqual(FULL_LIST, schedule_verify.get_versions())

    @mock.patch('fdroidserver.index.download_repo_index_v2', _mock)
    def test_get_versions_all_json_exist(self):
        for d in FULL_LIST:
            appid = d['applicationId']
            if appid == 'fake.ota.update':
                ext = 'zip'
            else:
                ext = 'apk'
            Path(f"unsigned/{appid}_{d['versionCode']}.{ext}.json").write_text('{}')
        self.assertEqual([], schedule_verify.get_versions())

    @mock.patch('fdroidserver.index.download_repo_index_v2', _mock)
    def test_get_versions_all_apks_exist(self):
        for d in FULL_LIST:
            appid = d['applicationId']
            if appid != 'fake.ota.update':
                Path(f"unsigned/{appid}_{d['versionCode']}.apk.json").write_text('{}')
        self.assertEqual(
            [{'applicationId': 'fake.ota.update', 'versionCode': 1234}],
            schedule_verify.get_versions(),
        )


class Schedule_verify_get_scheduled(Schedule_verifyTest):
    def setUp(self):
        super().setUp()
        os.chdir(basedir)
        common.config = {'sdk_path': os.getenv('ANDROID_HOME')}
        common.config['jarsigner'] = common.find_sdk_tools_cmd('jarsigner')

    @mock.patch('fdroidserver.index.download_repo_index_v2', _mock)
    def test_get_scheduled_none_exist(self):
        versions = schedule_verify.get_versions(basedir / 'repo')
        self.assertEqual(
            [
                {'applicationId': 'souch.smsbypass', 'versionCode': 9},
                {'applicationId': 'com.politedroid', 'versionCode': 6},
                {'applicationId': 'com.politedroid', 'versionCode': 5},
                {'applicationId': 'com.politedroid', 'versionCode': 4},
                {'applicationId': 'com.politedroid', 'versionCode': 3},
            ],
            schedule_verify.get_scheduled(versions),
        )
