#!/usr/bin/env python3

import importlib
import os
import unittest

from pathlib import Path
from unittest import mock, skipIf

from fdroidserver import common, exception, pull
from .shared_test_code import mkdtemp, APPID, VERCODE, APPID_VERCODE


class PullTest(unittest.TestCase):
    basedir = Path(__file__).resolve().parent

    def setUp(self):
        self._td = mkdtemp()
        self.testdir = self._td.name
        os.chdir(self.testdir)
        common.config = dict()

    def tearDown(self):
        self._td.cleanup()
        common.config = None


class Pull_main(PullTest):
    def setUp(self):
        super().setUp()
        metadatapath = Path(common.get_metadatapath(APPID))
        metadatapath.parent.mkdir()
        metadatapath.write_text(f'Name: Test\nBuilds:\n - versionCode: {VERCODE}\n')

    @mock.patch('sys.argv', ['fdroid pull', APPID_VERCODE])
    @mock.patch('fdroidserver.pull.podman_pull')
    def test_podman(self, podman_pull):
        common.config['virt_container_type'] = 'podman'
        common.options = mock.Mock()
        pull.main()
        podman_pull.assert_called()

    @mock.patch('sys.argv', ['fdroid pull', APPID_VERCODE])
    @mock.patch('fdroidserver.pull.vagrant_pull')
    def test_vagrant(self, vagrant_pull):
        common.config['virt_container_type'] = 'vagrant'
        pull.main()
        vagrant_pull.assert_called()


@skipIf(importlib.util.find_spec("podman") is None, 'Requires podman-py to run.')
class Pull_podman_pull(PullTest):
    def setUp(self):
        try:
            common.get_podman_container(APPID, VERCODE)
        except exception.BuildException as e:
            self.skipTest(f'Requires Podman container {APPID_VERCODE} to run: {e}')
        super().setUp()

    def test_no_existing(self):
        appid = 'should.never.exist'
        with self.assertRaises(exception.BuildException) as e:
            pull.podman_pull(appid, 9999, 'unsigned/foo.apk')
        self.assertIn(appid, e.exception.value)

    def test_existing(self):
        """Check files get deposited in unsigned/."""
        filename = 'buildserverid'
        f = Path('unsigned') / filename
        self.assertFalse(f.exists())
        pull.podman_pull(APPID, VERCODE, filename)
        self.assertTrue(f.exists())


class Pull_make_file_list(PullTest):
    def setUp(self):
        super().setUp()
        self.metadatapath = Path(common.get_metadatapath(APPID))
        self.metadatapath.parent.mkdir()

    def test_implied(self):
        self.metadatapath.write_text(f"""Builds: [versionCode: {VERCODE}]""")
        self.assertEqual(
            [
                f'unsigned/{APPID}_{VERCODE}.apk',
                f'unsigned/{APPID}_{VERCODE}_src.tar.gz',
            ],
            pull.make_file_list(APPID, VERCODE),
        )

    def test_gradle(self):
        self.metadatapath.write_text(
            f"""Builds:
                      - versionCode: {VERCODE}
                        gradle: fdroid
            """
        )
        self.assertEqual(
            [
                f'unsigned/{APPID}_{VERCODE}.apk',
                f'unsigned/{APPID}_{VERCODE}_src.tar.gz',
            ],
            pull.make_file_list(APPID, VERCODE),
        )

    def test_raw(self):
        ext = 'foo'
        Path(common.get_metadatapath(APPID)).write_text(
            f"""Builds:
              - versionCode: {VERCODE}
                versionName: 1.0
                commit: cafebabe123
                output: path/to/output.{ext}
            """
        )
        self.assertEqual(
            [
                f'unsigned/{APPID}_{VERCODE}.{ext}',
                f'unsigned/{APPID}_{VERCODE}_src.tar.gz',
            ],
            pull.make_file_list(APPID, VERCODE),
        )
