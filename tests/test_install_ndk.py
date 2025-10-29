#!/usr/bin/env python3

import os
import unittest

from pathlib import Path
from unittest import mock

from fdroidserver import common, metadata, install_ndk
from .shared_test_code import mkdtemp, APPID, VERCODE, APPID_VERCODE

NDK_RELEASE = 'r24'
NDK_REVISION = '24.0.8215888'


class InstallNdkTest(unittest.TestCase):
    basedir = Path(__file__).resolve().parent

    def setUp(self):
        self._td = mkdtemp()
        self.testdir = self._td.name
        os.chdir(self.testdir)
        common.config = {'ndk_paths': {}, 'sdk_path': self.testdir}

    def tearDown(self):
        self._td.cleanup()
        common.config = None


def mock_sdkmanager_install(to_install, android_home=None):
    path = f'{android_home}/{to_install.replace(";", "/")}'
    ndk_dir = Path(path)
    ndk_dir.mkdir(parents=True)
    (ndk_dir / 'source.properties').write_text(f'Pkg.Revision = {NDK_REVISION}\n')


@mock.patch('sdkmanager.build_package_list', lambda use_net: None)
class InstallNdk_wrapper(InstallNdkTest):
    @mock.patch('sdkmanager.install')
    def test_with_ndk(self, sdkmanager_install):
        sdkmanager_install.side_effect = mock_sdkmanager_install
        build = metadata.Build({'versionCode': VERCODE, 'ndk': NDK_RELEASE})
        install_ndk.install_ndk_wrapper(build)
        sdkmanager_install.assert_called_once()

    @mock.patch('fdroidserver.common.auto_install_ndk')
    def test_without_ndk(self, auto_install_ndk):
        build = metadata.Build({'versionCode': VERCODE})
        install_ndk.install_ndk_wrapper(build)
        auto_install_ndk.assert_not_called()


@mock.patch('sys.argv', ['fdroid ndk', APPID_VERCODE])
@mock.patch('sdkmanager.build_package_list', lambda use_net: None)
@mock.patch('sdkmanager.install')
class InstallNdk_main(InstallNdkTest):
    def setUp(self):
        super().setUp()
        metadatapath = Path(common.get_metadatapath(APPID))
        metadatapath.parent.mkdir()
        metadatapath.write_text(
            f'Builds:\n - versionCode: {VERCODE}\n   ndk: {NDK_RELEASE}\n'
        )

    def test_ndk_main(self, sdkmanager_install):
        sdkmanager_install.side_effect = mock_sdkmanager_install
        install_ndk.main()
        sdkmanager_install.assert_called_once()
