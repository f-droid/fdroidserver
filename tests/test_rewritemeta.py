#!/usr/bin/env python3

import io
import os
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from fdroidserver import metadata, rewritemeta

from .shared_test_code import TmpCwd, mkdtemp

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

    @mock.patch('sys.argv', ['fdroid', 'rewritemeta', '--stdin'])
    @mock.patch('sys.stdout', new_callable=io.StringIO)
    @mock.patch('sys.stdin', io.StringIO('UpdateCheckMode: None\nAutoUpdateMode: None'))
    def test_rewrite_from_stdin(self, stdout):
        rewritemeta.main()

        self.assertEqual(
            stdout.getvalue(), '\nAutoUpdateMode: None\nUpdateCheckMode: None\n'
        )
