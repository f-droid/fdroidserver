#!/usr/bin/env python3

import os
import unittest

from pathlib import Path
from unittest import mock

from fdroidserver import common, metadata, make_source_tarball
from .shared_test_code import mkdtemp, APPID, VERCODE, APPID_VERCODE


class MakeSourceTarballTest(unittest.TestCase):
    basedir = Path(__file__).resolve().parent

    def setUp(self):
        self._td = mkdtemp()
        self.testdir = self._td.name
        os.chdir(self.testdir)

    def tearDown(self):
        self._td.cleanup()


class MakeSourceTarball(MakeSourceTarballTest):
    def setUp(self):
        super().setUp()
        self.build = metadata.Build({'versionCode': VERCODE})
        self.app = metadata.App()
        self.app.id = APPID
        self.app.Builds.append(self.build)
        os.mkdir('build')
        os.mkdir(f'build/{self.app.id}')

    def test_empty(self):
        make_source_tarball.make_source_tarball(self.app, self.build)


@mock.patch('sys.argv', ['fdroid make_source_tarball', APPID_VERCODE])
class MakeSourceTarball_main(MakeSourceTarballTest):
    def setUp(self):
        super().setUp()
        metadatapath = Path(common.get_metadatapath(APPID))
        metadatapath.parent.mkdir()
        metadatapath.write_text(f'Builds:\n - versionCode: {VERCODE}\n')

    def test_main_no_build_dir(self):
        with self.assertRaises(SystemExit):
            make_source_tarball.main()

    def test_main_empty_build_dir(self):
        os.mkdir('build')
        with self.assertRaises(SystemExit):
            make_source_tarball.main()

    def test_main_empty_app_dir(self):
        os.mkdir('build')
        os.mkdir(f'build/{APPID}')
        make_source_tarball.main()
        tarname = common.get_src_tarball_name(APPID, VERCODE)
        self.assertTrue(os.path.exists(f'unsigned/{tarname}'))

    def test_main_app_dir(self):
        f = Path(f'build/{APPID}/testfile')
        f.parent.parent.mkdir()
        f.parent.mkdir()
        make_source_tarball.main()
        tarname = common.get_src_tarball_name(APPID, VERCODE)
        self.assertTrue(os.path.exists(f'unsigned/{tarname}'))
