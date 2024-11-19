#!/usr/bin/env python3

import os
import pathlib
import shutil
import sys
import unittest

import fdroidserver.common
import fdroidserver.init
from . import testcommon

basedir = pathlib.Path(__file__).parent


class InitTest(unittest.TestCase):
    '''fdroidserver/init.py'''

    def setUp(self):
        fdroidserver.common.config = None
        fdroidserver.init.config = None
        self._td = testcommon.mkdtemp()
        self.testdir = self._td.name
        os.chdir(self.testdir)

    def tearDown(self):
        os.chdir(basedir)
        self._td.cleanup()

    def test_disable_in_config(self):
        configfile = pathlib.Path('config.yml')
        configfile.write_text('keystore: NONE\nkeypass: mysupersecrets\n')
        configfile.chmod(0o600)
        config = fdroidserver.common.read_config()
        self.assertEqual('NONE', config['keystore'])
        self.assertEqual('mysupersecrets', config['keypass'])
        fdroidserver.init.disable_in_config('keypass', 'comment')
        self.assertIn('#keypass:', configfile.read_text())
        fdroidserver.common.config = None
        config = fdroidserver.common.read_config()
        self.assertIsNone(config.get('keypass'))

    @unittest.skipIf(os.name == 'nt', "calling main() like this hangs on Windows")
    def test_main_in_empty_dir(self):
        """Test that `fdroid init` will find apksigner and add it to the config"""

        shutil.copy(basedir / 'keystore.jks', self.testdir)

        bindir = os.path.join(os.getcwd(), 'bin')
        os.mkdir(bindir)
        apksigner = os.path.join(bindir, 'apksigner')
        open(apksigner, 'w').close()
        os.chmod(apksigner, 0o755)  # nosec B103

        sys.argv = ['fdroid init', '--keystore', 'keystore.jks', '--repo-keyalias=sova']
        with unittest.mock.patch.dict(os.environ, {'PATH': bindir}):
            fdroidserver.init.main()
        self.assertEqual(apksigner, fdroidserver.init.config.get('apksigner'))
