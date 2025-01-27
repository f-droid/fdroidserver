#!/usr/bin/env python3

import os
import shutil
import unittest
from pathlib import Path
from unittest import mock

import fdroidserver
from fdroidserver import common, signindex
from .shared_test_code import GP_FINGERPRINT, mkdtemp


basedir = Path(__file__).parent


class ApiTest(unittest.TestCase):
    """Test the public API in the base "fdroidserver" module

    This is mostly a smokecheck to make sure the public API as
    declared in fdroidserver/__init__.py is working.  The functions
    are all implemented in other modules, with their own tests.

    """

    def setUp(self):
        os.chdir(basedir)

        self._td = mkdtemp()
        self.testdir = self._td.name

        common.config = None
        config = common.read_config()
        config['jarsigner'] = common.find_sdk_tools_cmd('jarsigner')
        common.config = config
        signindex.config = config

    def tearDown(self):
        self._td.cleanup()

    def test_download_repo_index_no_fingerprint(self):
        with self.assertRaises(fdroidserver.VerificationException):
            fdroidserver.download_repo_index("http://example.org")

    @mock.patch('fdroidserver.net.http_get')
    def test_download_repo_index_url_parsing(self, mock_http_get):
        """Test whether it is trying to download the right file

        This passes the URL back via the etag return value just as a
        hack to check which URL was actually attempted.

        """
        mock_http_get.side_effect = lambda url, etag, timeout: (None, url)
        repo_url = 'https://example.org/fdroid/repo'
        index_url = 'https://example.org/fdroid/repo/index-v1.jar'
        for url in (repo_url, index_url):
            _ignored, etag_set_to_url = fdroidserver.download_repo_index(
                url, verify_fingerprint=False
            )
            self.assertEqual(index_url, etag_set_to_url)

    @mock.patch('fdroidserver.net.http_get')
    def test_download_repo_index_v1_url_parsing(self, mock_http_get):
        """Test whether it is trying to download the right file

        This passes the URL back via the etag return value just as a
        hack to check which URL was actually attempted.

        """
        mock_http_get.side_effect = lambda url, etag, timeout: (None, url)
        repo_url = 'https://example.org/fdroid/repo'
        index_url = 'https://example.org/fdroid/repo/index-v1.jar'
        for url in (repo_url, index_url):
            _ignored, etag_set_to_url = fdroidserver.download_repo_index_v1(
                url, verify_fingerprint=False
            )
            self.assertEqual(index_url, etag_set_to_url)

    @mock.patch('fdroidserver.net.download_using_mirrors')
    def test_download_repo_index_v2(self, mock_download_using_mirrors):
        """Basically a copy of IndexTest.test_download_repo_index_v2"""
        mock_download_using_mirrors.side_effect = lambda mirrors: os.path.join(
            self.testdir, 'repo', os.path.basename(mirrors[0]['url'])
        )
        os.chdir(self.testdir)
        signindex.config['keystore'] = os.path.join(basedir, 'keystore.jks')
        os.mkdir('repo')
        shutil.copy(basedir / 'repo' / 'entry.json', 'repo')
        shutil.copy(basedir / 'repo' / 'index-v2.json', 'repo')
        signindex.sign_index('repo', 'entry.json')
        repo_url = 'https://fake.url/fdroid/repo'
        entry_url = 'https://fake.url/fdroid/repo/entry.jar'
        index_url = 'https://fake.url/fdroid/repo/index-v2.json'
        fingerprint_url = 'https://fake.url/fdroid/repo?fingerprint=' + GP_FINGERPRINT
        slash_url = 'https://fake.url/fdroid/repo//?fingerprint=' + GP_FINGERPRINT
        for url in (repo_url, entry_url, index_url, fingerprint_url, slash_url):
            data, _ignored = fdroidserver.download_repo_index_v2(
                url, verify_fingerprint=False
            )
            self.assertEqual(['repo', 'packages'], list(data))
            self.assertEqual(
                'My First F-Droid Repo Demo', data['repo']['name']['en-US']
            )
