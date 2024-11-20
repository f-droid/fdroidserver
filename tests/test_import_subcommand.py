#!/usr/bin/env python3

import logging
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import git
import requests
import yaml

from .testcommon import TmpCwd, mkdtemp, VerboseFalseOptions

import fdroidserver
import fdroidserver.import_subcommand

basedir = Path(__file__).parent
logging.basicConfig(level=logging.DEBUG)


class ImportTest(unittest.TestCase):
    '''fdroid import'''

    def setUp(self):
        os.chdir(basedir)
        self._td = mkdtemp()
        self.testdir = self._td.name

    def tearDown(self):
        os.chdir(basedir)
        self._td.cleanup()

    def test_get_all_gradle_and_manifests(self):
        """Test whether the function works with relative and absolute paths"""
        a = fdroidserver.import_subcommand.get_all_gradle_and_manifests(
            Path('source-files/cn.wildfirechat.chat')
        )
        paths = [
            'avenginekit/build.gradle',
            'build.gradle',
            'chat/build.gradle',
            'client/build.gradle',
            'client/src/main/AndroidManifest.xml',
            'emojilibrary/build.gradle',
            'gradle/build_libraries.gradle',
            'imagepicker/build.gradle',
            'mars-core-release/build.gradle',
            'push/build.gradle',
            'settings.gradle',
        ]
        paths = [Path('source-files/cn.wildfirechat.chat') / path for path in paths]
        self.assertEqual(sorted(paths), sorted(a))

        abspath = basedir / 'source-files/realm'
        p = fdroidserver.import_subcommand.get_all_gradle_and_manifests(abspath)
        self.assertEqual(1, len(p))
        self.assertTrue(p[0].is_relative_to(abspath))

    def test_get_gradle_subdir(self):
        subdirs = {
            'cn.wildfirechat.chat': 'chat',
            'com.anpmech.launcher': 'app',
            'org.tasks': 'app',
            'ut.ewh.audiometrytest': 'app',
            'org.noise_planet.noisecapture': 'app',
        }
        for k, v in subdirs.items():
            build_dir = Path('source-files') / k
            paths = fdroidserver.import_subcommand.get_all_gradle_and_manifests(
                build_dir
            )
            logging.info(paths)
            subdir = fdroidserver.import_subcommand.get_gradle_subdir(build_dir, paths)
            self.assertEqual(v, str(subdir))

    def test_import_gitlab(self):
        with tempfile.TemporaryDirectory() as testdir, TmpCwd(testdir):
            # FDroidPopen needs some config to work
            config = dict()
            fdroidserver.common.fill_config_defaults(config)
            fdroidserver.common.config = config

            url = 'https://gitlab.com/fdroid/ci-test-app'
            r = requests.head(url, timeout=300)
            if r.status_code != 200:
                print("ERROR", url, 'unreachable (', r.status_code, ')')
                print('Skipping ImportTest!')
                return

            fdroidserver.common.options = VerboseFalseOptions
            app = fdroidserver.import_subcommand.get_app_from_url(url)
            fdroidserver.import_subcommand.clone_to_tmp_dir(app)
            self.assertEqual(app.RepoType, 'git')
            self.assertEqual(app.Repo, 'https://gitlab.com/fdroid/ci-test-app.git')

    def test_get_app_from_url(self):
        with tempfile.TemporaryDirectory() as testdir, TmpCwd(testdir):
            testdir = Path(testdir)
            (testdir / 'tmp').mkdir()
            tmp_importer = testdir / 'tmp/importer'
            data = (
                (
                    'cn.wildfirechat.chat',
                    'https://github.com/wildfirechat/android-chat',
                    '0.6.9',
                    23,
                ),
                (
                    'com.anpmech.launcher',
                    'https://github.com/KeikaiLauncher/KeikaiLauncher',
                    'Unknown',
                    None,
                ),
                (
                    'ut.ewh.audiometrytest',
                    'https://github.com/ReeceStevens/ut_ewh_audiometer_2014',
                    '1.65',
                    14,
                ),
            )
            for appid, url, vn, vc in data:
                shutil.rmtree(
                    tmp_importer,
                    onerror=fdroidserver.import_subcommand.handle_retree_error_on_windows,
                )
                shutil.copytree(basedir / 'source-files' / appid, tmp_importer)

                app = fdroidserver.import_subcommand.get_app_from_url(url)
                with mock.patch(
                    'fdroidserver.common.getvcs',
                    lambda a, b, c: fdroidserver.common.vcs(url, testdir),
                ), mock.patch(
                    'fdroidserver.common.vcs.gotorevision', lambda s, rev: None
                ), mock.patch(
                    'shutil.rmtree', lambda a, onerror=None: None
                ):
                    build_dir = fdroidserver.import_subcommand.clone_to_tmp_dir(app)
                self.assertEqual('git', app.RepoType)
                self.assertEqual(url, app.Repo)
                self.assertEqual(url, app.SourceCode)
                logging.info(build_dir)
                paths = fdroidserver.import_subcommand.get_all_gradle_and_manifests(
                    build_dir
                )
                self.assertNotEqual(paths, [])
                (
                    versionName,
                    versionCode,
                    package,
                ) = fdroidserver.common.parse_androidmanifests(paths, app)
                self.assertEqual(vn, versionName)
                self.assertEqual(vc, versionCode)
                self.assertEqual(appid, package)

    def test_bad_urls(self):
        for url in (
            'asdf',
            'file://thing.git',
            'https:///github.com/my/project',
            'git:///so/many/slashes',
            'ssh:/notabug.org/missing/a/slash',
            'git:notabug.org/missing/some/slashes',
            'https//github.com/bar/baz',
        ):
            with self.assertRaises(ValueError):
                fdroidserver.import_subcommand.get_app_from_url(url)

    @mock.patch('sys.argv', ['fdroid import', '-u', 'https://example.com/mystery/url'])
    @mock.patch('fdroidserver.import_subcommand.clone_to_tmp_dir', lambda a: None)
    def test_unrecognized_url(self):
        """Test whether error is thrown when the RepoType was not found.

        clone_to_tmp_dir is mocked out to prevent this test from using
        the network, if it gets past the code that throws the error.

        """
        with self.assertRaises(fdroidserver.exception.FDroidException):
            fdroidserver.import_subcommand.main()

    @mock.patch('sys.argv', ['fdroid import', '-u', 'https://fake/git/url.git'])
    @mock.patch(
        'fdroidserver.import_subcommand.clone_to_tmp_dir', lambda a, r: Path('td')
    )
    def test_main_local_git(self):
        os.chdir(self.testdir)
        git.Repo.init('td')
        Path('td/build.gradle').write_text(
            'android { defaultConfig { applicationId "com.example" } }'
        )
        fdroidserver.import_subcommand.main()
        with open('metadata/com.example.yml') as fp:
            data = yaml.safe_load(fp)
        self.assertEqual(data['Repo'], sys.argv[2])
        self.assertEqual(data['RepoType'], 'git')
        self.assertEqual(1, len(data['Builds']))
