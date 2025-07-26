#!/usr/bin/env python3

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from fdroidserver import common, gpgsign

basedir = Path(__file__).parent


class GpgsignTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.chdir(self.tempdir.name)
        self.repodir = Path('repo')
        self.repodir.mkdir()

        gpgsign.config = None
        config = common.read_config()
        config['verbose'] = True
        config['gpghome'] = str((basedir / 'gnupghome').resolve())
        config['gpgkey'] = '1DBA2E89'
        gpgsign.config = config

    def tearDown(self):
        self.tempdir.cleanup()

    @patch('sys.argv', ['fdroid gpgsign', '--verbose'])
    @patch('fdroidserver.gpgsign.FDroidPopen')
    def test_sign_index(self, FDroidPopen):
        """This skips running gpg because its hard to setup in a test env"""
        index_v1_json = 'repo/index-v1.json'
        shutil.copy(basedir / index_v1_json, 'repo')
        shutil.copy(basedir / 'SpeedoMeterApp.main_1.apk', 'repo')

        def _side_effect(gpg):
            f = gpg[-1]
            sig = gpg[3]
            self.assertTrue(sig.startswith(f))
            open(sig, 'w').close()
            p = MagicMock()
            p.returncode = 0
            return p

        FDroidPopen.side_effect = _side_effect
        gpgsign.main()
        self.assertTrue(FDroidPopen.called)
        self.assertTrue((self.repodir / 'index-v1.json').exists())
        self.assertTrue((self.repodir / 'index-v1.json.asc').exists())
        self.assertTrue((self.repodir / 'SpeedoMeterApp.main_1.apk.asc').exists())
        self.assertFalse((self.repodir / 'index.jar.asc').exists())
        # smoke check status JSON
        with (self.repodir / 'status/gpgsign.json').open() as fp:
            data = json.load(fp)
        self.assertIn('index-v1.json', data['signed'])
