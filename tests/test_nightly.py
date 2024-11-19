#!/usr/bin/env python3

import os
import platform
import requests
import shutil
import subprocess
import tempfile
import time
import unittest
import yaml

from pathlib import Path
from unittest.mock import patch

from fdroidserver import common, exception, index, nightly


DEBUG_KEYSTORE = '/u3+7QAAAAIAAAABAAAAAQAPYW5kcm9pZGRlYnVna2V5AAABNYhAuskAAAK8MIICuDAOBgorBgEEASoCEQEBBQAEggKkqRnFlhidQmVff83bsAeewXPIsF0jiymzJnvrnUAQtCK0MV9uZonu37Mrj/qKLn56mf6QcvEoKvpCstZxzftgYYpAHWMVLM+hy2Z707QZEHlY7Ukppt8DItj+dXkeqGt7f8KzOb2AQwDbt9lm1fJb+MefLowTaubtvrLMcKIne43CbCu2D8HyN7RPWpEkVetA2Qgr5W4sa3tIUT80afqo9jzwJjKCspuxY9A1M8EIM3/kvyLo2B9r0cuWwRjYZXJ6gmTYI2ARNz0KQnCZUok14NDg+mZTb1B7AzRfb0lfjbA6grbzuAL+WaEpO8/LgGfuOh7QBZBT498TElOaFfQ9toQWA79wAmrQCm4OoFukpPIy2m/l6VjJSmlK5Q+CMOl/Au7OG1sUUCTvPaIr0XKnsiwDJ7a71n9garnPWHkvuWapSRCzCNgaUoGQjB+fTMJFFrwT8P1aLfM6onc3KNrDStoQZuYe5ngCLlNS56bENkVGvJBfdkboxtHZjqDXXON9jWGSOI527J3o2D5sjSVyx3T9XPrsL4TA/nBtdU+c/+M6aoASZR2VymzAKdMrGfj9kE5GXp8vv2vkJj9+OJ4Jm5yeczocc/Idtojjb1yg+sq1yY8kAQxgezpY1rpgi2jF3tSN01c23DNvAaSJLJX2ZuH8sD40ACc80Y1Qp1nUTdpwBZUeaeNruBwx4PHU8GnC71FwtiUpwNs0OoSl0pgDUJ3ODC5bs8B5QmW1wu1eg7I4mMSmCsNGW6VN3sFcu+WEqnmTxPoZombdFZKxsr2oq359Nn4bJ6Uc9PBz/sXsns7Zx1vND/oK/Jv5Y269UVAMeKX/eGpfnxzagW3tqGbOu12C2p9Azo5VxiU2fG/tmk2PjaG5hV/ywReco7I6C1p8OWM2fwAAAAEABVguNTA5AAAB6TCCAeUwggFOoAMCAQICBE89gTUwDQYJKoZIhvcNAQEFBQAwNzELMAkGA1UEBhMCVVMxEDAOBgNVBAoTB0FuZHJvaWQxFjAUBgNVBAMTDUFuZHJvaWQgRGVidWcwHhcNMTIwMjE2MjIyMDM3WhcNNDIwMjA4MjIyMDM3WjA3MQswCQYDVQQGEwJVUzEQMA4GA1UEChMHQW5kcm9pZDEWMBQGA1UEAxMNQW5kcm9pZCBEZWJ1ZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA3AKU7S7JXhUjEwxWP1/LPHXieh61SaA/+xbpqsPA+yjGz1sAcGAyuG6bjNAVm56pq7nkjJzicX7Wi83nUBo58DEC/quxOLdy0C4PEOSAeTnTT1RJIwMDvOgiL1GFCErvQ7gCH6zuAID/JRFbN6nIkhDjs2DYnSBl7aJJf8wCLc0CAwEAATANBgkqhkiG9w0BAQUFAAOBgQAoq/TJffA0l+ZGf89xndmHdxrO6qi+TzSlByvLZ4eFfCovTh1iO+Edrd5V1yXGLxyyvdsadMAFZT8SaxMrP5xxhJ0nra0APWYLpA96M//auMhQBWPgqPntwgvEZuEH7f0kdItjBJ39yijbG8xfgwid6XqNUo0TDDkp/wNWKpJ9tJe+2PrGw1NAvrgSydoH2j8DI1Eq'
DEBUG_KEYSTORE_KEY_FILE_NAME = (
    'debug_keystore_QW+xRCJDGHXyyFtgCW8QRajj+6uYmsLwGWpCfYqYQ5M_id_rsa'
)

AOSP_TESTKEY_DEBUG_KEYSTORE = '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'
AOSP_TESTKEY_DEBUG_KEYSTORE_KEY_FILE_NAME = (
    'debug_keystore_k47SVrA85+oMZAexHc62PkgvIgO8TJBYN00U82xSlxc_id_rsa'
)

basedir = Path(__file__).parent
testroot = basedir.with_name('.testfiles')


class Options:
    allow_disabled_algorithms = False
    clean = False
    delete_unknown = False
    nosign = False
    pretty = True
    rename_apks = False
    verbose = False


@unittest.skipUnless(
    platform.system() == 'Linux',
    'skipping test_nightly, it currently only works GNU/Linux',
)
class NightlyTest(unittest.TestCase):
    path = os.environ['PATH']

    def setUp(self):
        common.config = None
        nightly.config = None
        testroot.mkdir(exist_ok=True)
        os.chdir(basedir)
        self.tempdir = tempfile.TemporaryDirectory(
            str(time.time()), self._testMethodName + '_', testroot
        )
        self.testdir = Path(self.tempdir.name)
        self.home = self.testdir / 'home'
        self.home.mkdir()
        self.dot_android = self.home / '.android'
        nightly.KEYSTORE_FILE = str(self.dot_android / 'debug.keystore')

    def tearDown(self):
        self.tempdir.cleanup()
        try:
            os.rmdir(testroot)
        except OSError:  # other test modules might have left stuff around
            pass

    def _copy_test_debug_keystore(self):
        self.dot_android.mkdir()
        shutil.copy(
            basedir / 'aosp_testkey_debug.keystore',
            self.dot_android / 'debug.keystore',
        )

    def _copy_debug_apk(self):
        outputdir = Path('app/build/output/apk/debug')
        outputdir.mkdir(parents=True)
        shutil.copy(basedir / 'urzip.apk', outputdir / 'urzip-debug.apk')

    def test_get_repo_base_url(self):
        for clone_url, repo_git_base, result in [
            (
                'https://github.com/onionshare/onionshare-android-nightly',
                'onionshare/onionshare-android-nightly',
                'https://raw.githubusercontent.com/onionshare/onionshare-android-nightly/master/fdroid',
            ),
            (
                'https://gitlab.com/fdroid/fdroidclient-nightly',
                'fdroid/fdroidclient-nightly',
                'https://gitlab.com/fdroid/fdroidclient-nightly/-/raw/master/fdroid',
            ),
        ]:
            url = nightly.get_repo_base_url(clone_url, repo_git_base)
            self.assertEqual(result, url)
            r = requests.head(os.path.join(url, 'repo/index-v1.jar'), timeout=300)
            # gitlab.com often returns 403 Forbidden from their cloudflare restrictions
            self.assertTrue(r.status_code in (200, 403), 'should not be a redirect')

    def test_get_keystore_secret_var(self):
        self.assertEqual(
            AOSP_TESTKEY_DEBUG_KEYSTORE,
            nightly._get_keystore_secret_var(basedir / 'aosp_testkey_debug.keystore'),
        )

    @patch.dict(os.environ, clear=True)
    def test_ssh_key_from_debug_keystore(self):
        os.environ['HOME'] = str(self.home)
        os.environ['PATH'] = self.path
        ssh_private_key_file = nightly._ssh_key_from_debug_keystore(
            basedir / 'aosp_testkey_debug.keystore'
        )
        with open(ssh_private_key_file) as fp:
            self.assertIn('-----BEGIN RSA PRIVATE KEY-----', fp.read())
        with open(ssh_private_key_file + '.pub') as fp:
            self.assertEqual(fp.read(8), 'ssh-rsa ')
        shutil.rmtree(os.path.dirname(ssh_private_key_file))

    @patch.dict(os.environ, clear=True)
    @patch('sys.argv', ['fdroid nightly', '--verbose'])
    def test_main_empty_dot_android(self):
        """Test that it exits with an error when ~/.android is empty"""
        os.environ['HOME'] = str(self.home)
        os.environ['PATH'] = self.path
        with self.assertRaises(SystemExit) as cm:
            nightly.main()
        self.assertEqual(cm.exception.code, 1)

    @patch.dict(os.environ, clear=True)
    @patch('sys.argv', ['fdroid nightly', '--verbose'])
    def test_main_empty_dot_ssh(self):
        """Test that it does not create ~/.ssh if it does not exist

        Careful!  If the test env is wrong, it can mess up the local
        SSH setup.

        """
        dot_ssh = self.home / '.ssh'
        self._copy_test_debug_keystore()
        os.environ['HOME'] = str(self.home)
        os.environ['PATH'] = self.path
        self.assertFalse(dot_ssh.exists())
        nightly.main()
        self.assertFalse(dot_ssh.exists())

    @patch.dict(os.environ, clear=True)
    @patch('sys.argv', ['fdroid nightly', '--verbose'])
    def test_main_on_user_machine(self):
        """Test that `fdroid nightly` runs on the user's machine

        Careful!  If the test env is wrong, it can mess up the local
        SSH setup.

        """
        dot_ssh = self.home / '.ssh'
        dot_ssh.mkdir()
        self._copy_test_debug_keystore()
        os.environ['HOME'] = str(self.home)
        os.environ['PATH'] = self.path
        nightly.main()
        self.assertTrue((dot_ssh / AOSP_TESTKEY_DEBUG_KEYSTORE_KEY_FILE_NAME).exists())
        self.assertTrue(
            (dot_ssh / (AOSP_TESTKEY_DEBUG_KEYSTORE_KEY_FILE_NAME + '.pub')).exists()
        )

    @patch('fdroidserver.common.vcs_git.git', lambda args, e: common.PopenResult(1))
    @patch('sys.argv', ['fdroid nightly', '--verbose'])
    def test_private_or_non_existent_git_mirror(self):
        """Test that this exits with an error when the git mirror repo won't work

        Careful!  If the test environment is setup wrong, it can mess
        up local files in ~/.ssh or ~/.android.

        """
        os.chdir(self.testdir)
        with patch.dict(
            os.environ,
            {
                'CI': 'true',
                'CI_PROJECT_PATH': 'thisshouldneverexist/orthistoo',
                'CI_PROJECT_URL': 'https://gitlab.com/thisshouldneverexist/orthistoo',
                'DEBUG_KEYSTORE': DEBUG_KEYSTORE,
                'GITLAB_USER_NAME': 'username',
                'GITLAB_USER_EMAIL': 'username@example.com',
                'HOME': str(self.testdir),
                'PATH': os.getenv('PATH'),
            },
            clear=True,
        ):
            with self.assertRaises(exception.VCSException):
                nightly.main()

    def _put_fdroid_in_args(self, args):
        """Find fdroid command that belongs to this source code tree"""
        fdroid = os.path.join(basedir.parent, 'fdroid')
        if not os.path.exists(fdroid):
            fdroid = os.getenv('fdroid')
        return [fdroid] + args[1:]

    @patch('sys.argv', ['fdroid nightly', '--verbose'])
    @patch('platform.node', lambda: 'example.com')
    def test_github_actions(self):
        """Careful! If the test env is bad, it'll mess up the local SSH setup

        https://docs.github.com/en/actions/learn-github-actions/environment-variables

        """

        called = []
        orig_check_call = subprocess.check_call
        os.chdir(self.testdir)
        os.makedirs('fdroid/git-mirror/fdroid/repo')  # fake this to avoid cloning
        self._copy_test_debug_keystore()
        self._copy_debug_apk()

        def _subprocess_check_call(args, cwd=None, env=None):
            if os.path.basename(args[0]) in ('keytool', 'openssl'):
                orig_check_call(args, cwd=cwd, env=env)
            elif args[:2] == ['fdroid', 'update']:
                orig_check_call(self._put_fdroid_in_args(args), cwd=cwd, env=env)
            else:
                called.append(args[:2])
                return

        with patch.dict(
            os.environ,
            {
                'CI': 'true',
                'DEBUG_KEYSTORE': DEBUG_KEYSTORE,
                'GITHUB_ACTIONS': 'true',
                'GITHUB_ACTOR': 'username',
                'GITHUB_REPOSITORY': 'f-droid/test',
                'GITHUB_SERVER_URL': 'https://github.com',
                'HOME': str(self.testdir),
                'PATH': os.getenv('PATH'),
                'fdroid': os.getenv('fdroid', ''),
            },
            clear=True,
        ):
            self.assertTrue(testroot == Path.home().parent)
            with patch('subprocess.check_call', _subprocess_check_call):
                try:
                    nightly.main()
                except exception.BuildException as e:
                    if "apksigner not found" in e.value:
                        self.skipTest("skipping, apksigner not found due to fake $HOME")
                    else:
                        raise

        self.assertEqual(called, [['ssh', '-Tvi'], ['fdroid', 'deploy']])
        self.assertFalse(os.path.exists('config.py'))
        git_url = 'git@github.com:f-droid/test-nightly'
        mirror_url = index.get_mirror_service_urls({"url": git_url})[0]
        expected = {
            'archive_description': 'Old nightly builds that have been archived.',
            'archive_name': 'f-droid/test-nightly archive',
            'archive_older': 20,
            'archive_url': mirror_url + '/archive',
            'keydname': 'CN=Android Debug,O=Android,C=US',
            'keypass': 'android',
            'keystore': nightly.KEYSTORE_FILE,
            'keystorepass': 'android',
            'make_current_version_link': False,
            'repo_description': 'Nightly builds from username@example.com',
            'repo_keyalias': 'androiddebugkey',
            'repo_name': 'f-droid/test-nightly',
            'repo_url': mirror_url + '/repo',
            'servergitmirrors': [{"url": git_url}],
        }
        with open('config.yml') as fp:
            config = yaml.safe_load(fp)
            # .ssh is random tmpdir set in nightly.py, so test basename only
            self.assertEqual(
                os.path.basename(config['identity_file']),
                DEBUG_KEYSTORE_KEY_FILE_NAME,
            )
            del config['identity_file']
            self.assertEqual(expected, config)

    @patch('sys.argv', ['fdroid nightly', '--verbose'])
    def test_gitlab_ci(self):
        """Careful!  If the test env is bad, it can mess up the local SSH setup"""
        called = []
        orig_check_call = subprocess.check_call
        os.chdir(self.testdir)
        os.makedirs('fdroid/git-mirror/fdroid/repo')  # fake this to avoid cloning
        self._copy_test_debug_keystore()
        self._copy_debug_apk()

        def _subprocess_check_call(args, cwd=None, env=None):
            if os.path.basename(args[0]) in ('keytool', 'openssl'):
                orig_check_call(args, cwd=cwd, env=env)
            elif args[:2] == ['fdroid', 'update']:
                orig_check_call(self._put_fdroid_in_args(args), cwd=cwd, env=env)
            else:
                called.append(args[:2])
                return

        with patch.dict(
            os.environ,
            {
                'CI': 'true',
                'CI_PROJECT_PATH': 'fdroid/test',
                'CI_PROJECT_URL': 'https://gitlab.com/fdroid/test',
                'DEBUG_KEYSTORE': DEBUG_KEYSTORE,
                'GITLAB_USER_NAME': 'username',
                'GITLAB_USER_EMAIL': 'username@example.com',
                'HOME': str(self.testdir),
                'PATH': os.getenv('PATH'),
                'fdroid': os.getenv('fdroid', ''),
            },
            clear=True,
        ):
            self.assertTrue(testroot == Path.home().parent)
            with patch('subprocess.check_call', _subprocess_check_call):
                try:
                    nightly.main()
                except exception.BuildException as e:
                    if "apksigner not found" in e.value:
                        self.skipTest("skipping, apksigner not found due to fake $HOME")
                    else:
                        raise

        self.assertEqual(called, [['ssh', '-Tvi'], ['fdroid', 'deploy']])
        self.assertFalse(os.path.exists('config.py'))
        expected = {
            'archive_description': 'Old nightly builds that have been archived.',
            'archive_name': 'fdroid/test-nightly archive',
            'archive_older': 20,
            'archive_url': 'https://gitlab.com/fdroid/test-nightly/-/raw/master/fdroid/archive',
            'keydname': 'CN=Android Debug,O=Android,C=US',
            'keypass': 'android',
            'keystore': nightly.KEYSTORE_FILE,
            'keystorepass': 'android',
            'make_current_version_link': False,
            'repo_description': 'Nightly builds from username@example.com',
            'repo_keyalias': 'androiddebugkey',
            'repo_name': 'fdroid/test-nightly',
            'repo_url': 'https://gitlab.com/fdroid/test-nightly/-/raw/master/fdroid/repo',
            'servergitmirrors': [{"url": 'git@gitlab.com:fdroid/test-nightly'}],
        }
        with open('config.yml') as fp:
            config = yaml.safe_load(fp)
            # .ssh is random tmpdir set in nightly.py, so test basename only
            self.assertEqual(
                os.path.basename(config['identity_file']),
                DEBUG_KEYSTORE_KEY_FILE_NAME,
            )
            del config['identity_file']
            self.assertEqual(expected, config)
