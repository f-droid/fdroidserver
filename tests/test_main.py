#!/usr/bin/env python3

import os
import pkgutil
import textwrap
import unittest
import tempfile
from unittest import mock

import fdroidserver.__main__
from .testcommon import TmpCwd, TmpPyPath


class MainTest(unittest.TestCase):
    '''this tests fdroid.py'''

    def test_COMMANDS_check(self):
        """make sure the built in sub-command defs didn't change unintentionally"""
        self.assertListEqual(
            [x for x in fdroidserver.__main__.COMMANDS],
            [
                'build',
                'init',
                'publish',
                'gpgsign',
                'update',
                'deploy',
                'verify',
                'checkupdates',
                'import',
                'install',
                'readmeta',
                'rewritemeta',
                'lint',
                'scanner',
                'signindex',
                'btlog',
                'signatures',
                'nightly',
                'mirror',
            ],
        )

    def test_call_init(self):
        co = mock.Mock()
        with mock.patch('sys.argv', ['', 'init', '-h']):
            with mock.patch('fdroidserver.init.main', co):
                with mock.patch('sys.exit') as exit_mock:
                    fdroidserver.__main__.main()
                    # note: this is sloppy, if `init` changes
                    # this might need changing too
                    exit_mock.assert_called_once_with(0)
        co.assert_called_once_with()

    def test_call_deploy(self):
        co = mock.Mock()
        with mock.patch('sys.argv', ['', 'deploy', '-h']):
            with mock.patch('fdroidserver.deploy.main', co):
                with mock.patch('sys.exit') as exit_mock:
                    fdroidserver.__main__.main()
                    # note: this is sloppy, if `deploy` changes
                    # this might need changing too
                    exit_mock.assert_called_once_with(0)
        co.assert_called_once_with()

    def test_find_plugins(self):
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with open('fdroid_testy1.py', 'w') as f:
                f.write(
                    textwrap.dedent(
                        """\
                        fdroid_summary = "ttt"
                        main = lambda: 'all good'"""
                    )
                )
            with TmpPyPath(tmpdir):
                plugins = fdroidserver.__main__.find_plugins()
                self.assertIn('testy1', plugins.keys())
                self.assertEqual(plugins['testy1']['summary'], 'ttt')
                self.assertEqual(
                    __import__(
                        plugins['testy1']['name'], None, None, ['testy1']
                    ).main(),
                    'all good',
                )

    def test_main_plugin_lambda(self):
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with open('fdroid_testy2.py', 'w') as f:
                f.write(
                    textwrap.dedent(
                        """\
                        fdroid_summary = "ttt"
                        main = lambda: print('all good')"""
                    )
                )
            with TmpPyPath(tmpdir):
                with mock.patch('sys.argv', ['', 'testy2']):
                    with mock.patch('sys.exit') as exit_mock:
                        fdroidserver.__main__.main()
                        exit_mock.assert_called_once_with(0)

    def test_main_plugin_def(self):
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with open('fdroid_testy3.py', 'w') as f:
                f.write(
                    textwrap.dedent(
                        """\
                        fdroid_summary = "ttt"
                        def main():
                            print('all good')"""
                    )
                )
            with TmpPyPath(tmpdir):
                with mock.patch('sys.argv', ['', 'testy3']):
                    with mock.patch('sys.exit') as exit_mock:
                        fdroidserver.__main__.main()
                        exit_mock.assert_called_once_with(0)

    def test_main_broken_plugin(self):
        """making sure broken plugins get their exceptions through"""
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with open('fdroid_testy4.py', 'w') as f:
                f.write(
                    textwrap.dedent(
                        """\
                        fdroid_summary = "ttt"
                        def main():
                            raise Exception("this plugin is broken")"""
                    )
                )
            with TmpPyPath(tmpdir):
                with mock.patch('sys.argv', ['', 'testy4']):
                    with self.assertRaisesRegex(Exception, "this plugin is broken"):
                        fdroidserver.__main__.main()

    def test_main_malicious_plugin(self):
        """The purpose of this test is to make sure code in plugins
        doesn't get executed unintentionally.
        """
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with open('fdroid_testy5.py', 'w') as f:
                f.write(
                    textwrap.dedent(
                        """\
                        fdroid_summary = "ttt"
                        raise Exception("this plugin is malicious")
                        def main():
                            print("evil things")"""
                    )
                )
            with TmpPyPath(tmpdir):
                with mock.patch('sys.argv', ['', 'lint']):
                    with mock.patch('sys.exit') as exit_mock:
                        fdroidserver.__main__.main()
                        # note: this is sloppy, if `lint` changes
                        # this might need changing too
                        exit_mock.assert_called_once_with(0)

    def test_main_prevent_plugin_override(self):
        """making sure build-in subcommands cannot be overridden by plugins"""
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with open('fdroid_signatures.py', 'w') as f:
                f.write(
                    textwrap.dedent(
                        """\
                        fdroid_summary = "ttt"
                        def main():
                            raise("plugin overrides don't get prevent!")"""
                    )
                )
            with TmpPyPath(tmpdir):
                with mock.patch('sys.argv', ['', 'signatures']):
                    with mock.patch('sys.exit') as exit_mock:
                        fdroidserver.__main__.main()
                        # note: this is sloppy, if `signatures` changes
                        # this might need changing too
                        self.assertEqual(exit_mock.call_count, 2)

    def test_preparse_plugin_lookup_bad_name(self):
        self.assertRaises(
            ValueError,
            fdroidserver.__main__.preparse_plugin,
            "some.package",
            "/non/existent/module/path",
        )

    def test_preparse_plugin_lookup_bad_path(self):
        self.assertRaises(
            ValueError,
            fdroidserver.__main__.preparse_plugin,
            "fake_module_name",
            "/non/existent/module/path",
        )

    def test_preparse_plugin_lookup_summary_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with open('fdroid_testy6.py', 'w') as f:
                f.write("main = lambda: print('all good')")
            with TmpPyPath(tmpdir):
                p = [x for x in pkgutil.iter_modules() if x[1].startswith('fdroid_')]
                module_dir = p[0][0].path
                module_name = p[0][1]
                self.assertRaises(
                    NameError,
                    fdroidserver.__main__.preparse_plugin,
                    module_name,
                    module_dir,
                )

    def test_preparse_plugin_lookup_module_file(self):
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with open('fdroid_testy7.py', 'w') as f:
                f.write(
                    textwrap.dedent(
                        """\
                        fdroid_summary = "ttt"
                        main = lambda: pritn('all good')"""
                    )
                )
            with TmpPyPath(tmpdir):
                p = [x for x in pkgutil.iter_modules() if x[1].startswith('fdroid_')]
                module_path = p[0][0].path
                module_name = p[0][1]
                d = fdroidserver.__main__.preparse_plugin(module_name, module_path)
            self.assertDictEqual(d, {'name': 'fdroid_testy7', 'summary': 'ttt'})

    def test_preparse_plugin_lookup_module_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            os.mkdir(os.path.join(tmpdir, 'fdroid_testy8'))
            with open('fdroid_testy8/__main__.py', 'w') as f:
                f.write(
                    textwrap.dedent(
                        """\
                        fdroid_summary = "ttt"
                        main = lambda: print('all good')"""
                    )
                )
            with open('fdroid_testy8/__init__.py', 'w') as f:
                pass
            with TmpPyPath(tmpdir):
                p = [x for x in pkgutil.iter_modules() if x[1].startswith('fdroid_')]
                module_path = p[0][0].path
                module_name = p[0][1]
                d = fdroidserver.__main__.preparse_plugin(module_name, module_path)
            self.assertDictEqual(d, {'name': 'fdroid_testy8', 'summary': 'ttt'})
