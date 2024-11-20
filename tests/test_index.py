#!/usr/bin/env python3

import copy
import datetime
import glob
import os
import unittest
from pathlib import Path
import yaml
import zipfile
from unittest.mock import patch
import requests
import tempfile
import json
import shutil

import fdroidserver
from fdroidserver import common, index, publish, signindex, update
from .testcommon import GP_FINGERPRINT, TmpCwd, mkdtemp


basedir = Path(__file__).parent


class Options:
    nosign = True
    pretty = False
    verbose = False


class IndexTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # TODO something should remove cls.index_v1_jar, but it was
        # causing the tests to be flaky.  There seems to be something
        # that is running the background somehow, maybe sign_index()
        # exits before jarsigner actually finishes?
        cls.index_v1_jar = basedir / 'repo' / 'index-v1.jar'

    def setUp(self):
        (basedir / 'config.py').chmod(0o600)
        os.chdir(basedir)  # so read_config() can find config.py

        common.config = None
        common.options = Options
        config = common.read_config()
        config['jarsigner'] = common.find_sdk_tools_cmd('jarsigner')
        common.config = config
        signindex.config = config
        update.config = config

        self._td = mkdtemp()
        self.testdir = self._td.name

    def tearDown(self):
        self._td.cleanup()

    def _sign_test_index_v1_jar(self):
        if not self.index_v1_jar.exists():
            signindex.sign_index(self.index_v1_jar.parent, 'index-v1.json')

    def test_get_public_key_from_jar_succeeds(self):
        source_dir = basedir / 'signindex'
        for f in ('testy.jar', 'guardianproject.jar'):
            testfile = os.path.join(source_dir, f)
            jar = zipfile.ZipFile(testfile)
            _, fingerprint = index.get_public_key_from_jar(jar)
            # comparing fingerprints should be sufficient
            if f == 'testy.jar':
                self.assertEqual(
                    fingerprint,
                    '818E469465F96B704E27BE2FEE4C63AB'
                    + '9F83DDF30E7A34C7371A4728D83B0BC1',
                )
            if f == 'guardianproject.jar':
                self.assertTrue(fingerprint == GP_FINGERPRINT)

    def test_get_public_key_from_jar_fails(self):
        source_dir = basedir / 'signindex'
        testfile = os.path.join(source_dir, 'unsigned.jar')
        jar = zipfile.ZipFile(testfile)
        with self.assertRaises(index.VerificationException):
            index.get_public_key_from_jar(jar)

    def test_download_repo_index_no_fingerprint(self):
        with self.assertRaises(index.VerificationException):
            index.download_repo_index("http://example.org")

    def test_download_repo_index_no_jar(self):
        with self.assertRaises(requests.exceptions.RequestException):
            index.download_repo_index("http://example.org?fingerprint=nope")

    def test_get_repo_key_fingerprint(self):
        self._sign_test_index_v1_jar()
        pubkey, fingerprint = index.extract_pubkey()
        (
            data,
            public_key,
            public_key_fingerprint,
        ) = index.get_index_from_jar(
            'repo/index-v1.jar', fingerprint, allow_deprecated=True
        )
        self.assertIsNotNone(data)
        self.assertIsNotNone(public_key)
        self.assertIsNotNone(public_key_fingerprint)

    def test_get_index_from_jar_with_bad_fingerprint(self):
        pubkey, fingerprint = index.extract_pubkey()
        fingerprint = fingerprint[:-1] + 'G'
        with self.assertRaises(fdroidserver.exception.VerificationException):
            index.get_index_from_jar(
                'repo/index-v1.jar', fingerprint, allow_deprecated=True
            )

    def test_get_index_from_jar_with_chars_to_be_stripped(self):
        self._sign_test_index_v1_jar()
        fingerprint = 'NOOOO F4 9A F3 F1 1E FD DF 20 DF FD 70 F5 E3 11 7B 99 76 67 41 67 AD CA 28 0E 6B 19 32 A0 60 1B 26 F6'
        index.get_index_from_jar(
            'repo/index-v1.jar', fingerprint, allow_deprecated=True
        )

    @patch('requests.head')
    def test_download_repo_index_same_etag(self, head):
        url = 'http://example.org?fingerprint=test'
        etag = '"4de5-54d840ce95cb9"'

        head.return_value.headers = {'ETag': etag}
        data, new_etag = index.download_repo_index(url, etag=etag)

        self.assertIsNone(data)
        self.assertEqual(etag, new_etag)

    @patch('requests.get')
    @patch('requests.head')
    def test_download_repo_index_new_etag(self, head, get):
        url = 'http://example.org?fingerprint=' + GP_FINGERPRINT
        etag = '"4de5-54d840ce95cb9"'

        # fake HTTP answers
        head.return_value.headers = {'ETag': 'new_etag'}
        get.return_value.headers = {'ETag': 'new_etag'}
        get.return_value.status_code = 200
        testfile = os.path.join('signindex', 'guardianproject-v1.jar')
        with open(testfile, 'rb') as file:
            get.return_value.content = file.read()

        data, new_etag = index.download_repo_index(url, etag=etag)

        # assert that the index was retrieved properly
        self.assertEqual('Guardian Project Official Releases', data['repo']['name'])
        self.assertEqual(GP_FINGERPRINT, data['repo']['fingerprint'])
        self.assertTrue(len(data['repo']['pubkey']) > 500)
        self.assertEqual(10, len(data['apps']))
        self.assertEqual(10, len(data['packages']))
        self.assertEqual('new_etag', new_etag)

    @patch('fdroidserver.net.http_get')
    def test_download_repo_index_url_parsing(self, mock_http_get):
        """Test whether it is trying to download the right file

        This passes the URL back via the etag return value just as a
        hack to check which URL was actually attempted.

        """
        mock_http_get.side_effect = lambda url, etag, timeout: (None, url)
        repo_url = 'https://fake.url/fdroid/repo'
        index_url = 'https://fake.url/fdroid/repo/index-v1.jar'
        fingerprint_url = 'https://fake.url/fdroid/repo?fingerprint=' + GP_FINGERPRINT
        slash_url = 'https://fake.url/fdroid/repo//?fingerprint=' + GP_FINGERPRINT
        for url in (repo_url, index_url, fingerprint_url, slash_url):
            ilist = index.download_repo_index(url, verify_fingerprint=False)
            self.assertEqual(index_url, ilist[1])  # etag item used to return URL

    @patch('fdroidserver.net.download_using_mirrors')
    def test_download_repo_index_v2(self, mock_download_using_mirrors):
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
            data, _ignored = index.download_repo_index_v2(url, verify_fingerprint=False)
            self.assertEqual(['repo', 'packages'], list(data.keys()))
            self.assertEqual(
                'My First F-Droid Repo Demo', data['repo']['name']['en-US']
            )

    @patch('fdroidserver.net.download_using_mirrors')
    def test_download_repo_index_v2_bad_fingerprint(self, mock_download_using_mirrors):
        mock_download_using_mirrors.side_effect = lambda mirrors: os.path.join(
            self.testdir, 'repo', os.path.basename(mirrors[0]['url'])
        )
        os.chdir(self.testdir)
        signindex.config['keystore'] = os.path.join(basedir, 'keystore.jks')
        os.mkdir('repo')
        shutil.copy(basedir / 'repo' / 'entry.json', 'repo')
        shutil.copy(basedir / 'repo' / 'index-v2.json', 'repo')
        signindex.sign_index('repo', 'entry.json')
        bad_fp = '0123456789001234567890012345678900123456789001234567890012345678'
        bad_fp_url = 'https://fake.url/fdroid/repo?fingerprint=' + bad_fp
        with self.assertRaises(fdroidserver.exception.VerificationException):
            data, _ignored = index.download_repo_index_v2(bad_fp_url)

    @patch('fdroidserver.net.download_using_mirrors')
    def test_download_repo_index_v2_entry_verify(self, mock_download_using_mirrors):
        def download_using_mirrors_def(mirrors):
            f = os.path.join(tempfile.mkdtemp(), os.path.basename(mirrors[0]['url']))
            Path(f).write_text('not the entry.jar file contents')
            return f

        mock_download_using_mirrors.side_effect = download_using_mirrors_def
        url = 'https://fake.url/fdroid/repo?fingerprint=' + GP_FINGERPRINT
        with self.assertRaises(fdroidserver.exception.VerificationException):
            data, _ignored = index.download_repo_index_v2(url)

    @patch('fdroidserver.net.download_using_mirrors')
    def test_download_repo_index_v2_index_verify(self, mock_download_using_mirrors):
        def download_using_mirrors_def(mirrors):
            f = os.path.join(tempfile.mkdtemp(), os.path.basename(mirrors[0]['url']))
            Path(f).write_text('not the index-v2.json file contents')
            return f

        mock_download_using_mirrors.side_effect = download_using_mirrors_def
        os.chdir(self.testdir)
        signindex.config['keystore'] = os.path.join(basedir, 'keystore.jks')
        os.mkdir('repo')
        shutil.copy(basedir / 'repo' / 'entry.json', 'repo')
        shutil.copy(basedir / 'repo' / 'index-v2.json', 'repo')
        signindex.sign_index('repo', 'entry.json')
        url = 'https://fake.url/fdroid/repo?fingerprint=' + GP_FINGERPRINT
        with self.assertRaises(fdroidserver.exception.VerificationException):
            data, _ignored = index.download_repo_index_v2(url)

    def test_v1_sort_packages(self):
        i = [
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'org.smssecure.smssecure_134.apk',
                'signer': 'b33a601a9da97c82e6eb121eb6b90adab561f396602ec4dc8b0019fb587e2af6',
                'versionCode': 134,
            },
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'org.smssecure.smssecure_134_b30bb97.apk',
                'signer': 'b30bb971af0d134866e158ec748fcd553df97c150f58b0a963190bbafbeb0868',
                'versionCode': 134,
            },
            {
                'packageName': 'b075b32b4ef1e8a869e00edb136bd48e34a0382b85ced8628f164d1199584e4e'
            },
            {
                'packageName': '43af70d1aca437c2f9974c4634cc5abe45bdc4d5d71529ac4e553488d3bb3ff6'
            },
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'org.smssecure.smssecure_135_b30bb97.apk',
                'signer': 'b30bb971af0d134866e158ec748fcd553df97c150f58b0a963190bbafbeb0868',
                'versionCode': 135,
            },
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'org.smssecure.smssecure_135.apk',
                'signer': 'b33a601a9da97c82e6eb121eb6b90adab561f396602ec4dc8b0019fb587e2af6',
                'versionCode': 135,
            },
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'org.smssecure.smssecure_133.apk',
                'signer': 'b33a601a9da97c82e6eb121eb6b90adab561f396602ec4dc8b0019fb587e2af6',
                'versionCode': 133,
            },
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'smssecure-weird-version.apk',
                'signer': '99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff',
                'versionCode': 133,
            },
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'smssecure-custom.apk',
                'signer': '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
                'versionCode': 133,
            },
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'smssecure-new-custom.apk',
                'signer': '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
                'versionCode': 135,
            },
        ]

        o = [
            {
                'packageName': '43af70d1aca437c2f9974c4634cc5abe45bdc4d5d71529ac4e553488d3bb3ff6'
            },
            {
                'packageName': 'b075b32b4ef1e8a869e00edb136bd48e34a0382b85ced8628f164d1199584e4e'
            },
            # app test data
            # # packages with reproducible developer signature
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'org.smssecure.smssecure_135_b30bb97.apk',
                'signer': 'b30bb971af0d134866e158ec748fcd553df97c150f58b0a963190bbafbeb0868',
                'versionCode': 135,
            },
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'org.smssecure.smssecure_134_b30bb97.apk',
                'signer': 'b30bb971af0d134866e158ec748fcd553df97c150f58b0a963190bbafbeb0868',
                'versionCode': 134,
            },
            # # packages build and signed by fdroid
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'org.smssecure.smssecure_135.apk',
                'signer': 'b33a601a9da97c82e6eb121eb6b90adab561f396602ec4dc8b0019fb587e2af6',
                'versionCode': 135,
            },
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'org.smssecure.smssecure_134.apk',
                'signer': 'b33a601a9da97c82e6eb121eb6b90adab561f396602ec4dc8b0019fb587e2af6',
                'versionCode': 134,
            },
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'org.smssecure.smssecure_133.apk',
                'signer': 'b33a601a9da97c82e6eb121eb6b90adab561f396602ec4dc8b0019fb587e2af6',
                'versionCode': 133,
            },
            # # packages signed with unkown keys
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'smssecure-new-custom.apk',
                'signer': '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
                'versionCode': 135,
            },
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'smssecure-custom.apk',
                'signer': '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
                'versionCode': 133,
            },
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'smssecure-weird-version.apk',
                'signer': '99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff99ff',
                'versionCode': 133,
            },
        ]

        common.config = {}
        common.fill_config_defaults(common.config)
        publish.config = common.config
        publish.config['keystorepass'] = '123456'
        publish.config['keypass'] = '123456'
        publish.config['keystore'] = os.path.join(os.getcwd(), 'dummy-keystore.jks')
        publish.config['repo_keyalias'] = 'repokey'

        testsmetadir = os.path.join(os.getcwd(), 'metadata')
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            shutil.copytree(testsmetadir, 'metadata')
            sigkeyfps = {
                "org.smssecure.smssecure": {
                    "signer": "b33a601a9da97c82e6eb121eb6b90adab561f396602ec4dc8b0019fb587e2af6"
                }
            }
            os.makedirs('stats')
            jarfile = 'stats/publishsigkeys.jar'
            with zipfile.ZipFile(jarfile, 'w', zipfile.ZIP_DEFLATED) as jar:
                jar.writestr('publishsigkeys.json', json.dumps(sigkeyfps))
            publish.sign_sig_key_fingerprint_list(jarfile)
            with open('config.py', 'w'):
                pass

            index.v1_sort_packages(
                i, common.load_stats_fdroid_signing_key_fingerprints()
            )
            self.maxDiff = None
            self.assertEqual(json.dumps(i, indent=2), json.dumps(o, indent=2))

            # and test it still works with get_first_signer_certificate
            outdir = os.path.join(self.testdir, 'publishsigkeys')
            os.mkdir(outdir)
            common.apk_extract_signatures(jarfile, outdir)
            certs = glob.glob(os.path.join(outdir, '*.RSA'))
            with open(certs[0], 'rb') as fp:
                self.assertEqual(
                    common.get_certificate(fp.read()),
                    common.get_first_signer_certificate(jarfile),
                )

    def test_make_v0_repo_only(self):
        os.chdir(self.testdir)
        os.mkdir('repo')
        repo_icons_dir = os.path.join('repo', 'icons')
        self.assertFalse(os.path.isdir(repo_icons_dir))
        repodict = {
            'address': 'https://example.com/fdroid/repo',
            'description': 'This is just a test',
            'icon': 'blahblah',
            'name': 'test',
            'timestamp': datetime.datetime.now(),
            'version': 12,
        }
        requestsdict = {'install': [], 'uninstall': []}
        common.config['repo_pubkey'] = 'ffffffffffffffffffffffffffffffffff'
        index.make_v0({}, [], 'repo', repodict, requestsdict, {})
        self.assertTrue(os.path.isdir(repo_icons_dir))
        self.assertTrue(
            os.path.exists(
                os.path.join(repo_icons_dir, common.default_config['repo_icon'])
            )
        )
        self.assertTrue(os.path.exists(os.path.join('repo', 'index.xml')))

    def test_make_v0(self):
        os.chdir(self.testdir)
        os.mkdir('metadata')
        os.mkdir('repo')
        metadatafile = 'metadata/info.zwanenburg.caffeinetile.yml'
        shutil.copy(os.path.join(basedir, metadatafile), metadatafile)
        repo_icons_dir = os.path.join('repo', 'icons')
        self.assertFalse(os.path.isdir(repo_icons_dir))
        repodict = {
            'address': 'https://example.com/fdroid/repo',
            'description': 'This is just a test',
            'icon': 'blahblah',
            'mirrors': [
                {'isPrimary': True, 'url': 'https://example.com/fdroid/repo'},
                {'extra': 'data', 'url': 'http://one/fdroid/repo'},
                {'url': 'http://two/fdroid/repo'},
            ],
            'name': 'test',
            'timestamp': datetime.datetime.now(),
            'version': 12,
        }
        app = fdroidserver.metadata.parse_metadata(metadatafile)
        app['icon'] = 'info.zwanenburg.caffeinetile.4.xml'
        app['CurrentVersionCode'] = 4
        apps = {app.id: app}
        orig_apps = copy.deepcopy(apps)
        apk = {
            'hash': 'dbbdd7deadb038862f426b71efe4a64df8c3edf25d669e935f349510e16f65db',
            'hashType': 'sha256',
            'uses-permission': [['android.permission.WAKE_LOCK', None]],
            'uses-permission-sdk-23': [],
            'features': [],
            'icons_src': {
                '160': 'res/drawable/ic_coffee_on.xml',
                '-1': 'res/drawable/ic_coffee_on.xml',
            },
            'icons': {'160': 'info.zwanenburg.caffeinetile.4.xml'},
            'antiFeatures': ['KnownVuln'],
            'packageName': 'info.zwanenburg.caffeinetile',
            'versionCode': 4,
            'name': 'Caffeine Tile',
            'versionName': '1.3',
            'minSdkVersion': 24,
            'targetSdkVersion': 25,
            'sig': '03f9b2f848d22fd1d8d1331e8b1b486d',
            'signer': '51cfa5c8a743833ad89acf81cb755936876a5c8b8eca54d1ffdcec0cdca25d0e',
            'size': 11740,
            'apkName': 'info.zwanenburg.caffeinetile_4.apk',
            'icon': 'info.zwanenburg.caffeinetile.4.xml',
            'added': datetime.datetime.fromtimestamp(1539122400),
        }
        requestsdict = {'install': [], 'uninstall': []}
        common.config['repo_pubkey'] = 'ffffffffffffffffffffffffffffffffff'
        common.config['make_current_version_link'] = True
        index.make_v0(apps, [apk], 'repo', repodict, requestsdict, {})
        self.assertTrue(os.path.isdir(repo_icons_dir))
        self.assertTrue(
            os.path.exists(
                os.path.join(repo_icons_dir, common.default_config['repo_icon'])
            )
        )
        self.assertTrue(os.path.exists(os.path.join('repo', 'index.xml')))
        self.assertEqual(orig_apps, apps, "apps was modified when building the index")

    def test_v0_invalid_config_exception(self):
        """Index v0 needs additional config values when using --nosign

        index.xml aka Index v0 includes the full repo public key in
        the XML itself.  So when running `fdroid update --nosign`,
        there needs to be either repo_pubkey or a full keystore config
        present.

        """
        os.chdir(self.testdir)
        os.mkdir('repo')
        repo_icons_dir = os.path.join('repo', 'icons')
        self.assertFalse(os.path.isdir(repo_icons_dir))
        repodict = {
            'address': 'https://example.com/fdroid/repo',
            'description': 'This is just a test',
            'icon': 'blahblah',
            'name': 'test',
            'timestamp': datetime.datetime.now(),
            'version': 12,
        }
        requestsdict = {'install': [], 'uninstall': []}

        common.options.nosign = False
        with self.assertRaises(fdroidserver.exception.FDroidException):
            index.make_v0({}, [], 'repo', repodict, requestsdict, {})

        common.options.nosign = True
        with self.assertRaises(fdroidserver.exception.FDroidException):
            index.make_v0({}, [], 'repo', repodict, requestsdict, {})

        common.config['repo_pubkey'] = 'ffffffffffffffffffffffffffffffffff'
        self.assertFalse(os.path.exists(os.path.join('repo', 'index.xml')))
        self.assertFalse(os.path.exists(os.path.join('repo', 'index_unsigned.jar')))
        self.assertFalse(os.path.exists(os.path.join('repo', 'index.jar')))
        index.make_v0({}, [], 'repo', repodict, requestsdict, {})
        self.assertTrue(os.path.exists(os.path.join('repo', 'index.xml')))
        self.assertTrue(os.path.exists(os.path.join('repo', 'index_unsigned.jar')))
        self.assertFalse(os.path.exists(os.path.join('repo', 'index.jar')))

    def test_make_v1_with_mirrors(self):
        os.chdir(self.testdir)
        os.mkdir('repo')
        repodict = {
            'address': 'https://example.com/fdroid/repo',
            'mirrors': [
                {'isPrimary': True, 'url': 'https://example.com/fdroid/repo'},
                {'extra': 'data', 'url': 'http://one/fdroid/repo'},
                {'url': 'http://two/fdroid/repo'},
            ],
        }
        index.make_v1({}, [], 'repo', repodict, {}, {})
        index_v1 = Path('repo/index-v1.json')
        self.assertTrue(index_v1.exists())
        with index_v1.open() as fp:
            self.assertEqual(
                json.load(fp)['repo']['mirrors'],
                ['http://one/fdroid/repo', 'http://two/fdroid/repo'],
            )

    def test_github_get_mirror_service_urls(self):
        for url in [
            'git@github.com:foo/bar',
            'git@github.com:foo/bar.git',
            'https://github.com/foo/bar',
            'https://github.com/foo/bar.git',
        ]:
            self.assertEqual(
                ['https://raw.githubusercontent.com/foo/bar/master/fdroid'],
                index.get_mirror_service_urls({"url": url}),
            )

    @patch.dict(os.environ, clear=True)
    def test_gitlab_get_mirror_service_urls(self):
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            git_mirror_path = Path('git-mirror/fdroid')
            git_mirror_path.mkdir(parents=True)
            ci_job_id = '12345678'
            artifacts_url = (
                'https://group.gitlab.io/-/project/-/jobs/%s/artifacts/public/fdroid'
                % ci_job_id
            )
            with (git_mirror_path / 'placeholder').open('w') as fp:
                fp.write('                                        ')
            for url in [
                'git@gitlab.com:group/project',
                'git@gitlab.com:group/project.git',
                'https://gitlab.com/group/project',
                'https://gitlab.com/group/project.git',
            ]:
                with patch('fdroidserver.common.GITLAB_COM_PAGES_MAX_SIZE', 1000):
                    expected = [
                        'https://group.gitlab.io/project/fdroid',
                        'https://gitlab.com/group/project/-/raw/master/fdroid',
                    ]
                    self.assertEqual(
                        expected,
                        index.get_mirror_service_urls({"url": url}),
                    )
                    with patch.dict(os.environ, clear=True):
                        os.environ['CI_JOB_ID'] = ci_job_id
                        self.assertEqual(
                            expected + [artifacts_url],
                            index.get_mirror_service_urls({"url": url}),
                        )
                with patch('fdroidserver.common.GITLAB_COM_PAGES_MAX_SIZE', 10):
                    expected = [
                        'https://gitlab.com/group/project/-/raw/master/fdroid',
                    ]
                    self.assertEqual(
                        expected,
                        index.get_mirror_service_urls({"url": url}),
                    )
                    with patch.dict(os.environ, clear=True):
                        os.environ['CI_JOB_ID'] = ci_job_id
                        self.assertEqual(
                            expected + [artifacts_url],
                            index.get_mirror_service_urls({"url": url}),
                        )

    def test_make_website(self):
        os.chdir(self.testdir)
        os.mkdir('metadata')
        os.mkdir('repo')

        repodict = {
            'address': 'https://example.com/fdroid/repo',
            'description': 'This is just a test',
            'icon': 'blahblah',
            'name': 'test',
            'timestamp': datetime.datetime.now(),
            'version': 12,
        }

        common.config['repo_pubkey'] = 'ffffffffffffffffffffffffffffffffff'

        index.make_website([], "repo", repodict)
        self.assertTrue(os.path.exists(os.path.join('repo', 'index.html')))
        self.assertTrue(os.path.exists(os.path.join('repo', 'index.css')))
        self.assertTrue(os.path.exists(os.path.join('repo', 'index.png')))

        try:
            from html5print import CSSBeautifier, HTMLBeautifier
        except ImportError:
            print('WARNING: skipping rest of test since html5print is missing!')
            return

        with open(os.path.join("repo", "index.html")) as f:
            html = f.read()
            pretty_html = HTMLBeautifier.beautify(html)
            self.maxDiff = None
            self.assertEqual(html, pretty_html)

        with open(os.path.join("repo", "index.css")) as f:
            css = f.read()
            pretty_css = CSSBeautifier.beautify(css)
            self.maxDiff = None
            self.assertEqual(css, pretty_css)

    def test_v1_sort_packages_with_invalid(self):
        i = [
            {
                'packageName': 'org.smssecure.smssecure',
                'apkName': 'smssecure-custom.fake',
                'signer': None,
                'versionCode': 11111,
            }
        ]

        index.v1_sort_packages(i, common.load_stats_fdroid_signing_key_fingerprints())

    def test_package_metadata(self):
        """A smoke check and format check of index.package_metadata()"""

        def _kn(key):
            return key[0].lower() + key[1:]

        apps = fdroidserver.metadata.read_metadata()
        update.insert_localized_app_metadata(apps)

        # smoke check all metadata files
        for appid, app in apps.items():
            metadata = index.package_metadata(app, 'repo')
            for k in ('Description', 'Name', 'Summary', 'video'):
                if app.get(k):
                    self.assertTrue(isinstance(metadata[_kn(k)], dict))
            for k in ('AuthorWebSite', 'IssueTracker', 'Translation', 'WebSite'):
                if app.get(k):
                    self.assertTrue(isinstance(metadata[_kn(k)], str))

        # make sure these known values were properly parsed and included
        appid = 'info.guardianproject.urzip'
        app = apps[appid]
        metadata = index.package_metadata(app, 'repo')
        # files
        self.assertEqual(
            os.path.getsize(f'repo/{appid}/en-US/featureGraphic.png'),
            metadata['featureGraphic']['en-US']['size'],
        )
        self.assertEqual(
            os.path.getsize(f'repo/{appid}/en-US/icon.png'),
            metadata['icon']['en-US']['size'],
        )
        # localized strings
        self.assertEqual({'en-US': 'title'}, metadata['name'])
        self.assertEqual({'en-US': 'video'}, metadata['video'])
        # strings
        self.assertEqual(
            'https://dev.guardianproject.info/projects/urzip',
            metadata['webSite'],
        )

    def test_add_mirrors_to_repodict(self):
        """Test based on the contents of tests/config.py"""
        repodict = {'address': common.config['repo_url']}
        index.add_mirrors_to_repodict('repo', repodict)
        self.assertEqual(
            repodict['mirrors'],
            [
                {'isPrimary': True, 'url': 'https://MyFirstFDroidRepo.org/fdroid/repo'},
                {'url': 'http://foobarfoobarfoobar.onion/fdroid/repo'},
                {'url': 'https://foo.bar/fdroid/repo'},
            ],
        )

    def test_custom_config_yml_with_mirrors(self):
        """Test based on custom contents of config.yml"""
        os.chdir(self.testdir)
        repo_url = 'https://example.com/fdroid/repo'
        c = {'repo_url': repo_url, 'mirrors': ['http://one/fdroid']}
        with open('config.yml', 'w') as fp:
            yaml.dump(c, fp)
        common.config = None
        common.read_config()
        repodict = {'address': common.config['repo_url']}
        index.add_mirrors_to_repodict('repo', repodict)
        self.assertEqual(
            repodict['mirrors'],
            [
                {'url': 'https://example.com/fdroid/repo', 'isPrimary': True},
                {'url': 'http://one/fdroid/repo'},
            ],
        )

    def test_no_mirrors_config(self):
        common.config = dict()
        repodict = {'address': 'https://example.com/fdroid/repo'}
        index.add_mirrors_to_repodict('repo', repodict)
        self.assertFalse('mirrors' in repodict)

    def test_add_metadata_to_canonical_in_mirrors_config(self):
        """It is possible to add extra metadata to the canonical URL"""
        common.config = {
            'repo_url': 'http://one/fdroid/repo',
            'mirrors': [
                {'url': 'http://one/fdroid', 'extra': 'data'},
                {'url': 'http://two/fdroid'},
            ],
        }
        repodict = {'address': common.config['repo_url']}
        index.add_mirrors_to_repodict('repo', repodict)
        self.assertEqual(
            repodict['mirrors'],
            [
                {'extra': 'data', 'isPrimary': True, 'url': 'http://one/fdroid/repo'},
                {'url': 'http://two/fdroid/repo'},
            ],
        )

    def test_duplicate_primary_in_mirrors_config(self):
        """There can be only one primary mirror aka canonical URL"""
        common.config = {
            'repo_url': 'http://one/fdroid',
            'mirrors': [
                {'url': 'http://one/fdroid', 'countryCode': 'SA'},
                {'url': 'http://two/fdroid'},
                {'url': 'http://one/fdroid'},
            ],
        }
        repodict = {'address': common.config['repo_url']}
        with self.assertRaises(fdroidserver.exception.FDroidException):
            index.add_mirrors_to_repodict('repo', repodict)

    def test_bad_type_in_mirrors_config(self):
        for i in (1, 2.3, b'asdf'):
            common.config = {'mirrors': i}
            repodict = dict()
            with self.assertRaises(fdroidserver.exception.FDroidException):
                index.add_mirrors_to_repodict('repo', repodict)

    def test_load_mirrors_config_from_file(self):
        # empty the dict for *.config, see setUp()
        for k in sorted(common.config.keys()):
            del common.config[k]

        os.chdir(self.testdir)
        os.mkdir('config')
        primary = 'https://primary.com/fdroid/repo'
        mirror = 'https://mirror.com/fdroid'
        with open('config/mirrors.yml', 'w') as fp:
            yaml.dump([{'url': mirror}], fp)
        repodict = {'address': primary}
        index.add_mirrors_to_repodict('repo', repodict)
        self.assertEqual(
            repodict['mirrors'],
            [
                {'isPrimary': True, 'url': primary},
                {'url': mirror + '/repo'},
            ],
        )

    def test_error_when_load_mirrors_from_config_and_file(self):
        # empty the dict for *.config, see setUp()
        for k in sorted(common.config.keys()):
            del common.config[k]

        os.chdir(self.testdir)
        os.mkdir('config')
        with open('config/mirrors.yml', 'w') as fp:
            yaml.dump([{'url': 'https://foo.com'}], fp)
        repodict = {
            'address': 'https://foo.com',
            'mirrors': {'url': 'http://two/fdroid/repo'},
        }
        with self.assertRaises(fdroidserver.exception.FDroidException):
            index.add_mirrors_to_repodict('repo', repodict)


class AltstoreIndexTest(unittest.TestCase):
    def test_make_altstore(self):
        self.maxDiff = None

        apps = {
            "app.fake": {
                "AutoName": "Fake App",
                "AuthorName": "Fake Author",
                "iconv2": {"en_US": "fake_icon.png"},
            }
        }
        apks = [
            {
                "packageName": "app.fake",
                "apkName": "app.fake_123.ipa",
                "versionName": "v123",
                "added": datetime.datetime(2000, 2, 2, 2, 2, 2),
                "size": 123,
                "ipa_MinimumOSVersion": "10.0",
                "ipa_DTPlatformVersion": "12.0",
                "ipa_permissions": [
                    "NSCameraUsageDescription",
                    "NSDocumentsFolderUsageDescription",
                ],
                "ipa_entitlements": [
                    "com.apple.developer.team-identifier",
                    "com.apple.developer.web-browser",
                    "keychain-access-groups",
                ],
            },
        ]
        config = {
            "repo_icon": "fake_repo_icon.png",
            "repo_name": "fake_repo",
            "repo_url": "gopher://fake-repo.com/fdroid/repo",
        }

        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            repodir = Path(tmpdir) / 'repo'
            repodir.mkdir()
            (repodir / "fake.ipa").touch()

            fdroidserver.index.make_altstore(
                apps,
                apks,
                config,
                repodir,
                True,
            )

            with open(repodir / "altstore-index.json", 'r') as f:
                self.assertDictEqual(
                    {
                        "apps": [
                            {
                                "appPermissions": {
                                    "entitlements": [
                                        'com.apple.developer.team-identifier',
                                        'com.apple.developer.web-browser',
                                        'keychain-access-groups',
                                    ],
                                    'privacy': [
                                        'NSCameraUsageDescription',
                                        'NSDocumentsFolderUsageDescription',
                                    ],
                                },
                                'bundleIdentifier': 'app.fake',
                                'developerName': 'Fake Author',
                                'iconURL': 'gopher://fake-repo.com/fdroid/repo',
                                'localizedDescription': '',
                                'name': 'Fake App',
                                'screenshots': [],
                                'versions': [
                                    {
                                        'date': '2000-02-02T02:02:02',
                                        'downloadURL': 'gopher://fake-repo.com/fdroid/repo/app.fake_123.ipa',
                                        'maxOSVersion': '12.0',
                                        'minOSVersion': '10.0',
                                        'size': 123,
                                        'version': 'v123',
                                    }
                                ],
                            },
                        ],
                        'name': 'fake_repo',
                        'news': [],
                    },
                    json.load(f),
                )
