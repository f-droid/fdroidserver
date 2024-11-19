#!/usr/bin/env python3

import os
import textwrap
import unittest

from pathlib import Path
from unittest.mock import Mock, patch

import fdroidserver
from fdroidserver import common, install
from fdroidserver.exception import BuildException, FDroidException


class InstallTest(unittest.TestCase):
    '''fdroidserver/install.py'''

    def tearDown(self):
        common.config = None

    def test_devices(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        try:
            config['adb'] = fdroidserver.common.find_sdk_tools_cmd('adb')
        except FDroidException as e:
            self.skipTest(f'Skipping test because: {e}')
        self.assertTrue(os.path.exists(config['adb']))
        self.assertTrue(os.path.isfile(config['adb']))
        devices = fdroidserver.install.devices()
        self.assertIsInstance(devices, list, 'install.devices() did not return a list!')
        for device in devices:
            self.assertIsInstance(device, str)

    def test_devices_fail(self):
        common.config = dict()
        common.fill_config_defaults(common.config)
        common.config['adb'] = '/bin/false'
        with self.assertRaises(FDroidException):
            fdroidserver.install.devices()

    def test_devices_fail_nonexistent(self):
        """This is mostly just to document this strange difference in behavior"""
        common.config = dict()
        common.fill_config_defaults(common.config)
        common.config['adb'] = '/nonexistent'
        with self.assertRaises(BuildException):
            fdroidserver.install.devices()

    @patch('fdroidserver.common.SdkToolsPopen')
    def test_devices_with_mock_none(self, mock_SdkToolsPopen):
        p = Mock()
        mock_SdkToolsPopen.return_value = p
        p.output = 'List of devices attached\n\n'
        p.returncode = 0
        common.config = dict()
        common.fill_config_defaults(common.config)
        self.assertEqual([], fdroidserver.install.devices())

    @patch('fdroidserver.common.SdkToolsPopen')
    def test_devices_with_mock_one(self, mock_SdkToolsPopen):
        p = Mock()
        mock_SdkToolsPopen.return_value = p
        p.output = 'List of devices attached\n05995813\tdevice\n\n'
        p.returncode = 0
        common.config = dict()
        common.fill_config_defaults(common.config)
        self.assertEqual(['05995813'], fdroidserver.install.devices())

    @patch('fdroidserver.common.SdkToolsPopen')
    def test_devices_with_mock_many(self, mock_SdkToolsPopen):
        p = Mock()
        mock_SdkToolsPopen.return_value = p
        p.output = textwrap.dedent(
            """* daemon not running; starting now at tcp:5037
            * daemon started successfully
            List of devices attached
            RZCT809FTQM	device
            05995813	device
            emulator-5556	device
            emulator-5554	unauthorized
            0a388e93	no permissions (missing udev rules? user is in the plugdev group); see [http://developer.android.com/tools/device.html]
            986AY133QL	device
            09301JEC215064	device
            015d165c3010200e	device
            4DCESKVGUC85VOTO	device

            """
        )
        p.returncode = 0
        common.config = dict()
        common.fill_config_defaults(common.config)
        self.assertEqual(
            [
                'RZCT809FTQM',
                '05995813',
                'emulator-5556',
                '986AY133QL',
                '09301JEC215064',
                '015d165c3010200e',
                '4DCESKVGUC85VOTO',
            ],
            fdroidserver.install.devices(),
        )

    @patch('fdroidserver.common.SdkToolsPopen')
    def test_devices_with_mock_error(self, mock_SdkToolsPopen):
        p = Mock()
        mock_SdkToolsPopen.return_value = p
        p.output = textwrap.dedent(
            """* daemon not running. starting it now on port 5037 *
            * daemon started successfully *
            ** daemon still not running
            error: cannot connect to daemon
            """
        )
        p.returncode = 0
        common.config = dict()
        common.fill_config_defaults(common.config)
        self.assertEqual([], fdroidserver.install.devices())

    @patch('fdroidserver.common.SdkToolsPopen')
    def test_devices_with_mock_no_permissions(self, mock_SdkToolsPopen):
        p = Mock()
        mock_SdkToolsPopen.return_value = p
        p.output = textwrap.dedent(
            """List of devices attached
            ????????????????	no permissions
            """
        )
        p.returncode = 0
        common.config = dict()
        common.fill_config_defaults(common.config)
        self.assertEqual([], fdroidserver.install.devices())

    @patch('fdroidserver.common.SdkToolsPopen')
    def test_devices_with_mock_unauthorized(self, mock_SdkToolsPopen):
        p = Mock()
        mock_SdkToolsPopen.return_value = p
        p.output = textwrap.dedent(
            """List of devices attached
            aeef5e4e	unauthorized
            """
        )
        p.returncode = 0
        common.config = dict()
        common.fill_config_defaults(common.config)
        self.assertEqual([], fdroidserver.install.devices())

    @patch('fdroidserver.common.SdkToolsPopen')
    def test_devices_with_mock_no_permissions_with_serial(self, mock_SdkToolsPopen):
        p = Mock()
        mock_SdkToolsPopen.return_value = p
        p.output = textwrap.dedent(
            """List of devices attached
             4DCESKVGUC85VOTO	no permissions (missing udev rules? user is in the plugdev group); see [http://developer.android.com/tools/device.html]

            """
        )
        p.returncode = 0
        common.config = dict()
        common.fill_config_defaults(common.config)
        self.assertEqual([], fdroidserver.install.devices())

    @staticmethod
    def _download_raise(privacy_mode):
        raise Exception('fake failed download')

    @patch('fdroidserver.install.download_apk')
    @patch('fdroidserver.install.download_fdroid_apk')
    @patch('fdroidserver.install.download_fdroid_apk_from_github')
    @patch('fdroidserver.install.download_fdroid_apk_from_ipns')
    @patch('fdroidserver.install.download_fdroid_apk_from_maven')
    def test_install_fdroid_apk_privacy_mode_true(
        self, maven, ipns, github, download_fdroid_apk, download_apk
    ):
        download_apk.side_effect = self._download_raise
        download_fdroid_apk.side_effect = self._download_raise
        github.side_effect = self._download_raise
        ipns.side_effect = self._download_raise
        maven.side_effect = self._download_raise
        fdroidserver.common.config = {'jarsigner': 'fakepath'}
        install.install_fdroid_apk(privacy_mode=True)
        download_apk.assert_not_called()
        download_fdroid_apk.assert_not_called()
        github.assert_called_once()
        ipns.assert_called_once()
        maven.assert_called_once()

    @patch('fdroidserver.install.download_apk')
    @patch('fdroidserver.install.download_fdroid_apk')
    @patch('fdroidserver.install.download_fdroid_apk_from_github')
    @patch('fdroidserver.install.download_fdroid_apk_from_ipns')
    @patch('fdroidserver.install.download_fdroid_apk_from_maven')
    def test_install_fdroid_apk_privacy_mode_false(
        self, maven, ipns, github, download_fdroid_apk, download_apk
    ):
        download_apk.side_effect = self._download_raise
        download_fdroid_apk.side_effect = self._download_raise
        github.side_effect = self._download_raise
        ipns.side_effect = self._download_raise
        maven.side_effect = self._download_raise
        fdroidserver.common.config = {'jarsigner': 'fakepath'}
        install.install_fdroid_apk(privacy_mode=False)
        download_apk.assert_called_once()
        download_fdroid_apk.assert_called_once()
        github.assert_called_once()
        ipns.assert_called_once()
        maven.assert_called_once()

    @patch('fdroidserver.install.download_apk')
    @patch('fdroidserver.install.download_fdroid_apk')
    @patch('fdroidserver.install.download_fdroid_apk_from_github')
    @patch('fdroidserver.install.download_fdroid_apk_from_ipns')
    @patch('fdroidserver.install.download_fdroid_apk_from_maven')
    @patch('locale.getlocale', lambda: ('zh_CN', 'UTF-8'))
    def test_install_fdroid_apk_privacy_mode_locale_auto(
        self, maven, ipns, github, download_fdroid_apk, download_apk
    ):
        download_apk.side_effect = self._download_raise
        download_fdroid_apk.side_effect = self._download_raise
        github.side_effect = self._download_raise
        ipns.side_effect = self._download_raise
        maven.side_effect = self._download_raise
        fdroidserver.common.config = {'jarsigner': 'fakepath'}
        install.install_fdroid_apk(privacy_mode=None)
        download_apk.assert_not_called()
        download_fdroid_apk.assert_not_called()
        github.assert_called_once()
        ipns.assert_called_once()
        maven.assert_called_once()

    @patch('fdroidserver.net.download_using_mirrors', lambda m: 'testvalue')
    def test_download_fdroid_apk_smokecheck(self):
        self.assertEqual('testvalue', install.download_fdroid_apk())

    @unittest.skipUnless(os.getenv('test_download_fdroid_apk'), 'requires net access')
    def test_download_fdroid_apk(self):
        f = install.download_fdroid_apk()
        self.assertTrue(Path(f).exists())

    @unittest.skipUnless(os.getenv('test_download_fdroid_apk'), 'requires net access')
    def test_download_fdroid_apk_from_maven(self):
        f = install.download_fdroid_apk_from_maven()
        self.assertTrue(Path(f).exists())

    @unittest.skipUnless(os.getenv('test_download_fdroid_apk'), 'requires net access')
    def test_download_fdroid_apk_from_ipns(self):
        f = install.download_fdroid_apk_from_ipns()
        self.assertTrue(Path(f).exists())

    @unittest.skipUnless(os.getenv('test_download_fdroid_apk'), 'requires net access')
    def test_download_fdroid_apk_from_github(self):
        f = install.download_fdroid_apk_from_github()
        self.assertTrue(Path(f).exists())
