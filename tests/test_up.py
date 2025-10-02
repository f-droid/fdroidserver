#!/usr/bin/env python3

import importlib
import os
import shutil
import unittest

from pathlib import Path
from unittest import mock, skipIf, skipUnless

from fdroidserver import common, exception, up
from .shared_test_code import mkdtemp, APPID, VERCODE, APPID_VERCODE


class UpTest(unittest.TestCase):
    basedir = Path(__file__).resolve().parent

    def setUp(self):
        self._td = mkdtemp()
        self.testdir = self._td.name
        os.chdir(self.testdir)

    def tearDown(self):
        self._td.cleanup()
        common.config = None


class Up_main(UpTest):
    def setUp(self):
        super().setUp()
        common.config = dict()

    @skipIf(
        importlib.util.find_spec("podman") is None or not shutil.which('podman'),
        'Requires podman and podman-py to run.',
    )
    @mock.patch('sys.argv', ['fdroid up', APPID_VERCODE])
    @mock.patch('fdroidserver.common.get_default_cachedir')
    @mock.patch('fdroidserver.up.run_podman')
    def test_podman(self, run_podman, get_default_cachedir):
        get_default_cachedir.return_value = self.testdir
        common.config['virt_container_type'] = 'podman'
        up.main()
        run_podman.assert_called_once()

    @mock.patch('sys.argv', ['fdroid up', APPID_VERCODE])
    @mock.patch('fdroidserver.common.get_default_cachedir')
    @mock.patch('fdroidserver.up.run_vagrant')
    def test_vagrant(self, run_vagrant, get_default_cachedir):
        get_default_cachedir.return_value = self.testdir
        common.config['virt_container_type'] = 'vagrant'
        up.main()
        run_vagrant.assert_called_once()


@skipIf(
    importlib.util.find_spec("podman") is None or not shutil.which('podman'),
    'Requires podman and podman-py to run.',
)
class Up_run_podman(UpTest):
    @skipUnless(
        os.path.exists(f'/run/user/{os.getuid()}/podman/podman.sock'),
        'Requires systemd podman.socket to run.',
    )
    def test_up_with_systemd_socket(self):
        common.get_podman_client()

    @skipIf(
        os.path.exists(f'/run/user/{os.getuid()}/podman/podman.sock'),
        'Requires the systemd podman.socket is not present.',
    )
    def test_up_with_podman_system_service_start(self):
        common.get_podman_client()

    def test_recreate_existing(self):
        try:
            common.get_podman_container(APPID, VERCODE)
        except exception.BuildException as e:
            # To run these tests, first do: `./fdroid up com.example:123`
            self.skipTest(f'Requires Podman container {APPID_VERCODE} to run: {e}')

        short_id = common.get_podman_container(APPID, VERCODE).short_id
        up.run_podman(APPID, VERCODE)
        self.assertNotEqual(
            short_id,
            common.get_podman_container(APPID, VERCODE).short_id,
            "This should never reuse an existing container.",
        )


@skipIf(importlib.util.find_spec("podman") is None, 'Requires podman-py to run.')
class Up_run_fake_podman(UpTest):
    @skipIf(
        os.path.exists(f'/run/user/{os.getuid()}/podman/podman.sock'),
        'Requires the systemd podman.socket is not present.',
    )
    @mock.patch.dict(os.environ, clear=True)
    @mock.patch("podman.PodmanClient.ping")
    def test_up_with_podman_system_service_start(self, mock_client_ping):
        """Test that the system service gets started if no socket is present."""
        os.environ['PATH'] = os.path.join(self.testdir, 'bin')
        os.mkdir('bin')
        podman = Path('bin/podman')
        podman.write_text('#!/bin/sh\nprintf "$1 $2" > args\n')
        os.chmod(podman, 0o700)
        common.get_podman_client()
        self.assertEqual('system service', Path('args').read_text())
        mock_client_ping.assert_called_once()


@skipIf(importlib.util.find_spec("vagrant") is None, 'Requires python-vagrant to run.')
class Up_run_vagrant(UpTest):
    def setUp(self):
        super().setUp()
        b = mock.Mock()
        b.name = 'buildserver'
        self.box_list_return = [b]
        name = common.get_container_name(APPID, VERCODE)
        self.vagrantdir = Path('tmp/buildserver') / name

    @mock.patch('vagrant.Vagrant.up')
    @mock.patch('vagrant.Vagrant.box_list')
    def test_no_existing(self, box_list, vagrant_up):
        box_list.return_value = self.box_list_return
        up.run_vagrant(APPID, VERCODE, 1, 1)
        vagrant_up.assert_called_once()
        self.assertTrue((Path(self.testdir) / self.vagrantdir).exists())
