#!/usr/bin/env python3

import importlib
import os
import unittest

from pathlib import Path
from unittest import mock, skipIf

from fdroidserver import common, exception, push
from .shared_test_code import mkdtemp, APPID, VERCODE, APPID_VERCODE


class PushTest(unittest.TestCase):
    basedir = Path(__file__).resolve().parent

    def setUp(self):
        self._td = mkdtemp()
        self.testdir = self._td.name
        os.chdir(self.testdir)
        common.config = dict()

    def tearDown(self):
        self._td.cleanup()
        common.config = None


class Push_main(PushTest):
    def setUp(self):
        super().setUp()
        metadatapath = Path(common.get_metadatapath(APPID))
        metadatapath.parent.mkdir()
        metadatapath.write_text(f'Name: Test\nBuilds:\n - versionCode: {VERCODE}\n')

    @mock.patch('sys.argv', ['fdroid push', APPID_VERCODE])
    @mock.patch('fdroidserver.push.create_build_dirs')
    @mock.patch('fdroidserver.push.podman_push')
    def test_podman(self, podman_push, create_build_dirs):
        common.config['virt_container_type'] = 'podman'
        push.main()
        create_build_dirs.assert_called_once()
        podman_push.assert_called()

    @mock.patch('sys.argv', ['fdroid push', APPID_VERCODE])
    @mock.patch('fdroidserver.push.create_build_dirs')
    @mock.patch('fdroidserver.push.vagrant_push')
    def test_vagrant(self, vagrant_push, create_build_dirs):
        common.config['virt_container_type'] = 'vagrant'
        push.main()
        create_build_dirs.assert_called_once()
        vagrant_push.assert_called()


@skipIf(importlib.util.find_spec("podman") is None, 'Requires podman-py to run.')
class Push_podman_push(PushTest):
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
        with self.assertRaises(exception.BuildException):
            push.podman_push(f, appid, 9999)

    def test_bad_absolute_path(self):
        self._only_run_if_container_exists()
        with self.assertRaises(exception.BuildException):
            push.podman_push('/etc/passwd', APPID, VERCODE)

    def test_bad_relative_path(self):
        self._only_run_if_container_exists()
        with self.assertRaises(ValueError):
            push.podman_push('../../etc/passwd', APPID, VERCODE)

    def test_existing(self):
        self._only_run_if_container_exists()
        f = Path(f'metadata/{APPID}.yml')
        f.parent.mkdir()
        f.write_text(f.name)
        push.podman_push(f, APPID, VERCODE)
        common.inside_exec(APPID, VERCODE, ['test', '-e', str(f)], 'podman')
