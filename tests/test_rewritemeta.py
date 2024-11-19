#!/usr/bin/env python3

import os
import unittest
import tempfile
import textwrap
from pathlib import Path
from unittest import mock

from fdroidserver import metadata, rewritemeta
from .testcommon import TmpCwd, mkdtemp

basedir = Path(__file__).parent


class RewriteMetaTest(unittest.TestCase):
    '''fdroidserver/publish.py'''

    def setUp(self):
        os.chdir(basedir)
        metadata.warnings_action = 'error'
        self._td = mkdtemp()
        self.testdir = self._td.name

    def tearDown(self):
        self._td.cleanup()

    def test_remove_blank_flags_from_builds_com_politedroid_3(self):
        """Unset fields in Builds: entries should be removed."""
        appid = 'com.politedroid'
        app = metadata.read_metadata({appid: -1})[appid]
        builds = rewritemeta.remove_blank_flags_from_builds(app.get('Builds'))
        self.assertEqual(
            builds[0],
            {
                'versionName': '1.2',
                'versionCode': 3,
                'commit': '6a548e4b19',
                'target': 'android-10',
                'antifeatures': {
                    'KnownVuln': {},
                    'UpstreamNonFree': {},
                    'NonFreeAssets': {},
                },
            },
        )

    def test_remove_blank_flags_from_builds_com_politedroid_4(self):
        """Unset fields in Builds: entries should be removed."""
        appid = 'com.politedroid'
        app = metadata.read_metadata({appid: -1})[appid]
        builds = rewritemeta.remove_blank_flags_from_builds(app.get('Builds'))
        self.assertEqual(
            builds[1],
            {
                'versionName': '1.3',
                'versionCode': 4,
                'commit': 'ad865b57bf3ac59580f38485608a9b1dda4fa7dc',
                'target': 'android-15',
            },
        )

    def test_remove_blank_flags_from_builds_org_adaway_52(self):
        """Unset fields in Builds: entries should be removed."""
        appid = 'org.adaway'
        app = metadata.read_metadata({appid: -1})[appid]
        builds = rewritemeta.remove_blank_flags_from_builds(app.get('Builds'))
        self.assertEqual(
            builds[-1],
            {
                'buildjni': ['yes'],
                'commit': 'v3.0',
                'gradle': ['yes'],
                'preassemble': ['renameExecutables'],
                'subdir': 'AdAway',
                'versionCode': 52,
                'versionName': '3.0',
            },
        )

    def test_remove_blank_flags_from_builds_no_builds(self):
        """Unset fields in Builds: entries should be removed."""
        self.assertEqual(
            rewritemeta.remove_blank_flags_from_builds(None),
            list(),
        )
        self.assertEqual(
            rewritemeta.remove_blank_flags_from_builds(dict()),
            list(),
        )
        self.assertEqual(
            rewritemeta.remove_blank_flags_from_builds(list()),
            list(),
        )
        self.assertEqual(
            rewritemeta.remove_blank_flags_from_builds(set()),
            list(),
        )
        self.assertEqual(
            rewritemeta.remove_blank_flags_from_builds(tuple()),
            list(),
        )

    def test_remove_blank_flags_from_builds_0_is_a_value(self):
        self.assertEqual(
            rewritemeta.remove_blank_flags_from_builds([{'versionCode': 0}]),
            [{'versionCode': 0}],
        )

    def test_remove_blank_flags_from_builds_values_to_purge(self):
        self.assertEqual(
            rewritemeta.remove_blank_flags_from_builds(
                [
                    {
                        'antifeatures': dict(),
                        'forceversion': False,
                        'init': None,
                        'rm': '',
                        'scandelete': list(),
                        'versionCode': 0,
                    },
                    {'antifeatures': list(), 'versionCode': 1},
                    {'antifeatures': '', 'versionCode': 2},
                ]
            ),
            [{'versionCode': 0}, {'versionCode': 1}, {'versionCode': 2}],
        )

    @mock.patch('sys.argv', ['fdroid rewritemeta', 'a'])
    def test_rewrite_no_builds(self):
        os.chdir(self.testdir)
        Path('metadata').mkdir()
        with Path('metadata/a.yml').open('w') as f:
            f.write('AutoName: a')
        rewritemeta.main()
        self.assertEqual(
            Path('metadata/a.yml').read_text(encoding='utf-8'),
            textwrap.dedent(
                '''\
                License: Unknown

                AutoName: a

                AutoUpdateMode: None
                UpdateCheckMode: None
                '''
            ),
        )

    @mock.patch('sys.argv', ['fdroid rewritemeta', 'a'])
    def test_rewrite_empty_build_field(self):
        os.chdir(self.testdir)
        Path('metadata').mkdir()
        with Path('metadata/a.yml').open('w') as fp:
            fp.write(
                textwrap.dedent(
                    """
                License: Apache-2.0
                Builds:
                  - versionCode: 4
                    versionName: a
                    rm:
                """
                )
            )
        rewritemeta.main()
        self.assertEqual(
            Path('metadata/a.yml').read_text(encoding='utf-8'),
            textwrap.dedent(
                '''\
                License: Apache-2.0

                Builds:
                  - versionName: a
                    versionCode: 4

                AutoUpdateMode: None
                UpdateCheckMode: None
                '''
            ),
        )

    def test_remove_blank_flags_from_builds_app_with_special_build_params(self):
        appid = 'app.with.special.build.params'
        app = metadata.read_metadata({appid: -1})[appid]
        builds = rewritemeta.remove_blank_flags_from_builds(app.get('Builds'))
        self.assertEqual(
            builds[-1],
            {
                'versionName': '2.1.2',
                'versionCode': 51,
                'disable': 'Labelled as pre-release, so skipped',
            },
        )

    def test_remove_blank_flags_from_builds_app_with_special_build_params_af(self):
        """Unset fields in Builds: entries should be removed."""
        appid = 'app.with.special.build.params'
        app = metadata.read_metadata({appid: -1})[appid]
        builds = rewritemeta.remove_blank_flags_from_builds(app.get('Builds'))
        self.assertEqual(
            builds[-2],
            {
                'antifeatures': {
                    'Ads': {'en-US': 'includes ad lib\n', 'zh-CN': '包括广告图书馆\n'},
                    'Tracking': {'en-US': 'standard suspects\n'},
                },
                'commit': '2.1.1',
                'maven': '2',
                'patch': [
                    'manifest-ads.patch',
                    'mobilecore.patch',
                ],
                'srclibs': ['FacebookSDK@sdk-version-3.0.2'],
                'versionCode': 50,
                'versionName': '2.1.1-c',
            },
        )

    @mock.patch('sys.argv', ['fdroid rewritemeta', 'a', 'b'])
    def test_rewrite_scenario_trivial(self):
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            Path('metadata').mkdir()
            with Path('metadata/a.yml').open('w') as f:
                f.write('AutoName: a')
            with Path('metadata/b.yml').open('w') as f:
                f.write('AutoName: b')

            rewritemeta.main()

            self.assertEqual(
                Path('metadata/a.yml').read_text(encoding='utf-8'),
                textwrap.dedent(
                    '''\
                    License: Unknown

                    AutoName: a

                    AutoUpdateMode: None
                    UpdateCheckMode: None
                    '''
                ),
            )

            self.assertEqual(
                Path('metadata/b.yml').read_text(encoding='utf-8'),
                textwrap.dedent(
                    '''\
                    License: Unknown

                    AutoName: b

                    AutoUpdateMode: None
                    UpdateCheckMode: None
                    '''
                ),
            )
