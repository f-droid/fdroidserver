#!/usr/bin/env python3

import os
import subprocess
import unittest

from pathlib import Path
from unittest import mock, skipUnless

from fdroidserver import common, exception, exec
from .shared_test_code import mkdtemp, APPID, VERCODE, APPID_VERCODE


class ExecTest(unittest.TestCase):
    def setUp(self):
        self._td = mkdtemp()
        self.testdir = self._td.name
        os.chdir(self.testdir)
        common.config = dict()

    def tearDown(self):
        self._td.cleanup()
        common.config = None


class Exec_main(ExecTest):
    @mock.patch('sys.argv', ['fdroid exec', APPID_VERCODE])
    @mock.patch('fdroidserver.common.get_default_cachedir')
    @mock.patch('fdroidserver.common.podman_exec')
    def test_podman(self, podman_exec, get_default_cachedir):
        get_default_cachedir.return_value = self.testdir
        common.config['virt_container_type'] = 'podman'
        exec.main()
        podman_exec.assert_called_once()


@skipUnless(os.path.isdir('/run/podman'), 'Requires Podman to run.')
class Exec_podman_exec(ExecTest):
    def _only_run_if_container_exists(self):
        try:
            common.get_podman_container(APPID, VERCODE)
        except exception.BuildException as e:
            # To run these tests, first do: `./fdroid up com.example:123`
            self.skipTest(f'Requires Podman container {APPID_VERCODE} to run: {e}')

    def test_no_existing_container(self):
        appid = 'should.never.exist'
        f = Path(f'metadata/{appid}.yml')
        f.parent.mkdir()
        f.write_text(f.name)
        with self.assertRaises(subprocess.CalledProcessError) as e:
            common.podman_exec(appid, 9999999999, ['ls'])
            self.assertEqual(e.exception.returncode, 1)

    def test_clean_run(self):
        self._only_run_if_container_exists()
        common.podman_exec(APPID, VERCODE, ['ls'])

    def test_error_run(self):
        self._only_run_if_container_exists()
        with self.assertRaises(subprocess.CalledProcessError) as e:
            common.podman_exec(APPID, VERCODE, ['/bin/false'])
            self.assertEqual(e.exception.returncode, 1)
