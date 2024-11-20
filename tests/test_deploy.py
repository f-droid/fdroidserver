#!/usr/bin/env python3

import configparser
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import git

import fdroidserver
from .testcommon import TmpCwd, mkdtemp, VerboseFalseOptions

basedir = Path(__file__).parent


class DeployTest(unittest.TestCase):
    '''fdroidserver/deploy.py'''

    def setUp(self):
        os.chdir(basedir)
        self._td = mkdtemp()
        self.testdir = self._td.name

        fdroidserver.common.options = mock.Mock()
        fdroidserver.deploy.config = {}
        fdroidserver.deploy.USER_RCLONE_CONF = False

    def tearDown(self):
        self._td.cleanup()

    def test_update_serverwebroots_bad_None(self):
        with self.assertRaises(TypeError):
            fdroidserver.deploy.update_serverwebroots(None, 'repo')

    def test_update_serverwebroots_bad_int(self):
        with self.assertRaises(TypeError):
            fdroidserver.deploy.update_serverwebroots(9, 'repo')

    def test_update_serverwebroots_bad_float(self):
        with self.assertRaises(TypeError):
            fdroidserver.deploy.update_serverwebroots(1.0, 'repo')

    def test_update_serverwebroots(self):
        """rsync works with file paths, so this test uses paths for the URLs"""
        os.chdir(self.testdir)
        repo = Path('repo')
        repo.mkdir()
        fake_apk = repo / 'fake.apk'
        with fake_apk.open('w') as fp:
            fp.write('not an APK, but has the right filename')
        url0 = Path('url0/fdroid')
        url0.mkdir(parents=True)
        url1 = Path('url1/fdroid')
        url1.mkdir(parents=True)

        # setup parameters for this test run
        fdroidserver.common.options.identity_file = None
        fdroidserver.deploy.config['make_current_version_link'] = False

        dest_apk0 = url0 / fake_apk
        dest_apk1 = url1 / fake_apk
        self.assertFalse(dest_apk0.is_file())
        self.assertFalse(dest_apk1.is_file())
        fdroidserver.deploy.update_serverwebroots(
            [
                {'url': str(url0)},
                {'url': str(url1)},
            ],
            str(repo),
        )
        self.assertTrue(dest_apk0.is_file())
        self.assertTrue(dest_apk1.is_file())

    def test_update_serverwebroots_url_does_not_end_with_fdroid(self):
        with self.assertRaises(SystemExit):
            fdroidserver.deploy.update_serverwebroots([{'url': 'url'}], 'repo')

    def test_update_serverwebroots_bad_ssh_url(self):
        with self.assertRaises(SystemExit):
            fdroidserver.deploy.update_serverwebroots(
                [{'url': 'f@b.ar::/path/to/fdroid'}], 'repo'
            )

    def test_update_serverwebroots_unsupported_ssh_url(self):
        with self.assertRaises(SystemExit):
            fdroidserver.deploy.update_serverwebroots([{'url': 'ssh://nope'}], 'repo')

    @unittest.skipUnless(shutil.which('rclone'), '/usr/bin/rclone')
    def test_update_remote_storage_with_rclone(self):
        os.chdir(self.testdir)
        repo = Path('repo')
        repo.mkdir(parents=True, exist_ok=True)

        fake_apk = repo / 'another_fake.apk'
        with fake_apk.open('w') as fp:
            fp.write('not an APK, but has the right filename')
        fake_index = repo / fdroidserver.common.INDEX_FILES[0]
        with fake_index.open('w') as fp:
            fp.write('not an index, but has the right filename')

        # write out rclone config for test use
        rclone_config = configparser.ConfigParser()
        rclone_config.add_section("test-local-config")
        rclone_config.set("test-local-config", "type", "local")

        rclone_config_path = Path('rclone_config_path')
        rclone_config_path.mkdir(parents=True, exist_ok=True)
        rclone_file = rclone_config_path / 'rclone.conf'
        with open(rclone_file, 'w') as configfile:
            rclone_config.write(configfile)

        # setup parameters for this test run
        fdroidserver.deploy.config['awsbucket'] = 'test_bucket_folder'
        fdroidserver.deploy.config['rclone'] = True
        fdroidserver.deploy.config['rclone_config'] = 'test-local-config'
        fdroidserver.deploy.config['path_to_custom_rclone_config'] = str(rclone_file)
        fdroidserver.common.options = VerboseFalseOptions

        # write out destination path
        destination = Path('test_bucket_folder/fdroid')
        destination.mkdir(parents=True, exist_ok=True)
        dest_apk = Path(destination) / fake_apk
        dest_index = Path(destination) / fake_index
        self.assertFalse(dest_apk.is_file())
        self.assertFalse(dest_index.is_file())
        repo_section = str(repo)
        # fdroidserver.deploy.USER_RCLONE_CONF = str(rclone_file)
        fdroidserver.deploy.update_remote_storage_with_rclone(repo_section)
        self.assertTrue(dest_apk.is_file())
        self.assertTrue(dest_index.is_file())

    @unittest.skipUnless(shutil.which('rclone'), '/usr/bin/rclone')
    def test_update_remote_storage_with_rclone_in_index_only_mode(self):
        os.chdir(self.testdir)
        repo = Path('repo')
        repo.mkdir(parents=True, exist_ok=True)

        fake_apk = repo / 'another_fake.apk'
        with fake_apk.open('w') as fp:
            fp.write('not an APK, but has the right filename')
        fake_index = repo / fdroidserver.common.INDEX_FILES[0]
        with fake_index.open('w') as fp:
            fp.write('not an index, but has the right filename')

        # write out rclone config for test use
        rclone_config = configparser.ConfigParser()
        rclone_config.add_section("test-local-config")
        rclone_config.set("test-local-config", "type", "local")

        rclone_config_path = Path('rclone_config_path')
        rclone_config_path.mkdir(parents=True, exist_ok=True)
        rclone_file = rclone_config_path / 'rclone.conf'
        with open(rclone_file, 'w') as configfile:
            rclone_config.write(configfile)

        # setup parameters for this test run
        fdroidserver.deploy.config['awsbucket'] = 'test_bucket_folder'
        fdroidserver.deploy.config['rclone'] = True
        fdroidserver.deploy.config['rclone_config'] = 'test-local-config'
        fdroidserver.deploy.config['path_to_custom_rclone_config'] = str(rclone_file)
        fdroidserver.common.options = VerboseFalseOptions

        # write out destination path
        destination = Path('test_bucket_folder/fdroid')
        destination.mkdir(parents=True, exist_ok=True)
        dest_apk = Path(destination) / fake_apk
        dest_index = Path(destination) / fake_index
        self.assertFalse(dest_apk.is_file())
        self.assertFalse(dest_index.is_file())
        repo_section = str(repo)
        # fdroidserver.deploy.USER_RCLONE_CONF = str(rclone_file)
        fdroidserver.deploy.update_remote_storage_with_rclone(
            repo_section, is_index_only=True
        )
        self.assertFalse(dest_apk.is_file())
        self.assertTrue(dest_index.is_file())

    @mock.patch('subprocess.call')
    @mock.patch('subprocess.check_output', lambda cmd, text: '/path/to/rclone.conf')
    def test_update_remote_storage_with_rclone_mock(self, mock_call):
        def _mock_subprocess_call(cmd):
            self.assertEqual(
                cmd,
                [
                    'rclone',
                    'sync',
                    'repo',
                    'test_local_config:test_bucket_folder/fdroid/repo',
                ],
            )
            return 0

        mock_call.side_effect = _mock_subprocess_call

        fdroidserver.deploy.config = {
            'awsbucket': 'test_bucket_folder',
            'rclone': True,
            'rclone_config': 'test_local_config',
        }
        fdroidserver.deploy.update_remote_storage_with_rclone('repo')
        mock_call.assert_called_once()

    def test_update_serverwebroot(self):
        """rsync works with file paths, so this test uses paths for the URLs"""
        os.chdir(self.testdir)
        repo = Path('repo')
        repo.mkdir(parents=True)
        fake_apk = repo / 'fake.apk'
        with fake_apk.open('w') as fp:
            fp.write('not an APK, but has the right filename')
        fake_index = repo / fdroidserver.common.INDEX_FILES[0]
        with fake_index.open('w') as fp:
            fp.write('not an index, but has the right filename')
        url = Path('url')
        url.mkdir()

        # setup parameters for this test run
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.identity_file = None
        fdroidserver.common.options.identity_file = None
        fdroidserver.deploy.config['make_current_version_link'] = False

        dest_apk = Path(url) / fake_apk
        dest_index = Path(url) / fake_index
        self.assertFalse(dest_apk.is_file())
        self.assertFalse(dest_index.is_file())

        fdroidserver.deploy.update_serverwebroot({'url': str(url)}, 'repo')
        self.assertTrue(dest_apk.is_file())
        self.assertTrue(dest_index.is_file())

    def test_update_serverwebroot_in_index_only_mode(self):
        os.chdir(self.testdir)
        repo = Path('repo')
        repo.mkdir()
        fake_apk = repo / 'fake.apk'
        with fake_apk.open('w') as fp:
            fp.write('not an APK, but has the right filename')
        fake_index = repo / fdroidserver.common.INDEX_FILES[0]
        with fake_index.open('w') as fp:
            fp.write('not an index, but has the right filename')
        url = Path('url')
        url.mkdir()

        # setup parameters for this test run
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.identity_file = None
        fdroidserver.deploy.config['make_current_version_link'] = False

        dest_apk = Path(url) / fake_apk
        dest_index = Path(url) / fake_index
        self.assertFalse(dest_apk.is_file())
        self.assertFalse(dest_index.is_file())

        fdroidserver.deploy.update_serverwebroot(
            {'url': str(url), 'index_only': True}, 'repo'
        )
        self.assertFalse(dest_apk.is_file())
        self.assertTrue(dest_index.is_file())

    @mock.patch.dict(os.environ, clear=True)
    def test_update_serverwebroot_no_rsync_error(self):
        os.environ['PATH'] = self.testdir
        os.chdir(self.testdir)
        with self.assertRaises(fdroidserver.exception.FDroidException):
            fdroidserver.deploy.update_serverwebroot('serverwebroot', 'repo')

    def test_update_serverwebroot_make_cur_version_link(self):
        self.maxDiff = None

        # setup parameters for this test run
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.no_checksum = True
        fdroidserver.common.options.identity_file = None
        fdroidserver.common.options.verbose = False
        fdroidserver.common.options.quiet = True
        fdroidserver.common.options.index_only = False
        fdroidserver.deploy.config = {'make_current_version_link': True}
        url = "example.com:/var/www/fdroid"
        repo_section = 'repo'

        # setup function for asserting subprocess.call invocations
        call_iteration = 0

        def update_server_webroot_call(cmd):
            nonlocal call_iteration
            if call_iteration == 0:
                self.assertListEqual(
                    cmd,
                    [
                        'rsync',
                        '--archive',
                        '--delete-after',
                        '--safe-links',
                        '--quiet',
                        '--exclude',
                        'repo/altstore-index.json',
                        '--exclude',
                        'repo/altstore-index.json.asc',
                        '--exclude',
                        'repo/entry.jar',
                        '--exclude',
                        'repo/entry.json',
                        '--exclude',
                        'repo/entry.json.asc',
                        '--exclude',
                        'repo/index-v1.jar',
                        '--exclude',
                        'repo/index-v1.json',
                        '--exclude',
                        'repo/index-v1.json.asc',
                        '--exclude',
                        'repo/index-v2.json',
                        '--exclude',
                        'repo/index-v2.json.asc',
                        '--exclude',
                        'repo/index.css',
                        '--exclude',
                        'repo/index.html',
                        '--exclude',
                        'repo/index.jar',
                        '--exclude',
                        'repo/index.png',
                        '--exclude',
                        'repo/index.xml',
                        'repo',
                        'example.com:/var/www/fdroid',
                    ],
                )
            elif call_iteration == 1:
                self.assertListEqual(
                    cmd,
                    [
                        'rsync',
                        '--archive',
                        '--delete-after',
                        '--safe-links',
                        '--quiet',
                        'repo',
                        url,
                    ],
                )
            elif call_iteration == 2:
                self.assertListEqual(
                    cmd,
                    [
                        'rsync',
                        '--archive',
                        '--delete-after',
                        '--safe-links',
                        '--quiet',
                        'Sym.apk',
                        'Sym.apk.asc',
                        'Sym.apk.sig',
                        'example.com:/var/www/fdroid',
                    ],
                )
            else:
                self.fail('unexpected subprocess.call invocation')
            call_iteration += 1
            return 0

        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            os.mkdir('repo')
            os.symlink('repo/com.example.sym.apk', 'Sym.apk')
            os.symlink('repo/com.example.sym.apk.asc', 'Sym.apk.asc')
            os.symlink('repo/com.example.sym.apk.sig', 'Sym.apk.sig')
            with mock.patch('subprocess.call', side_effect=update_server_webroot_call):
                fdroidserver.deploy.update_serverwebroot({'url': url}, repo_section)
        self.assertEqual(call_iteration, 3, 'expected 3 invocations of subprocess.call')

    def test_update_serverwebroot_make_cur_version_link_in_index_only_mode(self):
        # setup parameters for this test run
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.no_checksum = True
        fdroidserver.common.options.identity_file = None
        fdroidserver.common.options.verbose = False
        fdroidserver.common.options.quiet = True
        fdroidserver.common.options.identity_file = None
        fdroidserver.deploy.config['make_current_version_link'] = True
        url = "example.com:/var/www/fdroid"
        repo_section = 'repo'

        # setup function for asserting subprocess.call invocations
        call_iteration = 0

        def update_server_webroot_call(cmd):
            nonlocal call_iteration
            if call_iteration == 0:
                self.assertListEqual(
                    cmd,
                    [
                        'rsync',
                        '--archive',
                        '--delete-after',
                        '--safe-links',
                        '--quiet',
                        'repo/altstore-index.json',
                        'repo/altstore-index.json.asc',
                        'repo/entry.jar',
                        'repo/entry.json',
                        'repo/entry.json.asc',
                        'repo/index-v1.jar',
                        'repo/index-v1.json',
                        'repo/index-v1.json.asc',
                        'repo/index-v2.json',
                        'repo/index-v2.json.asc',
                        'repo/index.css',
                        'repo/index.html',
                        'repo/index.jar',
                        'repo/index.png',
                        'repo/index.xml',
                        'example.com:/var/www/fdroid/repo/',
                    ],
                )
            elif call_iteration == 1:
                self.assertListEqual(
                    cmd,
                    [
                        'rsync',
                        '--archive',
                        '--delete-after',
                        '--safe-links',
                        '--quiet',
                        'repo',
                        url,
                    ],
                )
            elif call_iteration == 2:
                self.assertListEqual(
                    cmd,
                    [
                        'rsync',
                        '--archive',
                        '--delete-after',
                        '--safe-links',
                        '--quiet',
                        'Sym.apk',
                        'Sym.apk.asc',
                        'Sym.apk.sig',
                        'example.com:/var/www/fdroid',
                    ],
                )
            else:
                self.fail('unexpected subprocess.call invocation')
            call_iteration += 1
            return 0

        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            os.mkdir(repo_section)
            os.symlink('repo/com.example.sym.apk', 'Sym.apk')
            os.symlink('repo/com.example.sym.apk.asc', 'Sym.apk.asc')
            os.symlink('repo/com.example.sym.apk.sig', 'Sym.apk.sig')

            fake_files = fdroidserver.common.INDEX_FILES
            for filename in fake_files:
                fake_file = Path(repo_section) / filename
                with fake_file.open('w') as fp:
                    fp.write('not a real one, but has the right filename')

            with mock.patch('subprocess.call', side_effect=update_server_webroot_call):
                fdroidserver.deploy.update_serverwebroot(
                    {'url': url, 'index_only': True}, repo_section
                )
        self.assertEqual(call_iteration, 1, 'expected 1 invocations of subprocess.call')

    def test_update_serverwebroot_with_id_file(self):
        # setup parameters for this test run
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.identity_file = None
        fdroidserver.common.options.no_checksum = True
        fdroidserver.common.options.verbose = True
        fdroidserver.common.options.quiet = False
        fdroidserver.common.options.identity_file = None
        fdroidserver.common.options.index_only = False
        fdroidserver.deploy.config = {'identity_file': './id_rsa'}
        url = "example.com:/var/www/fdroid"
        repo_section = 'archive'

        # setup function for asserting subprocess.call invocations
        call_iteration = 0

        def update_server_webroot_call(cmd):
            nonlocal call_iteration
            if call_iteration == 0:
                self.assertListEqual(
                    cmd,
                    [
                        'rsync',
                        '--archive',
                        '--delete-after',
                        '--safe-links',
                        '--verbose',
                        '-e',
                        'ssh -oBatchMode=yes -oIdentitiesOnly=yes -i '
                        + fdroidserver.deploy.config['identity_file'],
                        '--exclude',
                        'archive/altstore-index.json',
                        '--exclude',
                        'archive/altstore-index.json.asc',
                        '--exclude',
                        'archive/entry.jar',
                        '--exclude',
                        'archive/entry.json',
                        '--exclude',
                        'archive/entry.json.asc',
                        '--exclude',
                        'archive/index-v1.jar',
                        '--exclude',
                        'archive/index-v1.json',
                        '--exclude',
                        'archive/index-v1.json.asc',
                        '--exclude',
                        'archive/index-v2.json',
                        '--exclude',
                        'archive/index-v2.json.asc',
                        '--exclude',
                        'archive/index.css',
                        '--exclude',
                        'archive/index.html',
                        '--exclude',
                        'archive/index.jar',
                        '--exclude',
                        'archive/index.png',
                        '--exclude',
                        'archive/index.xml',
                        'archive',
                        url,
                    ],
                )
            elif call_iteration == 1:
                self.assertListEqual(
                    cmd,
                    [
                        'rsync',
                        '--archive',
                        '--delete-after',
                        '--safe-links',
                        '--verbose',
                        '-e',
                        'ssh -oBatchMode=yes -oIdentitiesOnly=yes -i '
                        + fdroidserver.deploy.config['identity_file'],
                        'archive',
                        url,
                    ],
                )
            else:
                self.fail('unexpected subprocess.call invocation')
            call_iteration += 1
            return 0

        with mock.patch('subprocess.call', side_effect=update_server_webroot_call):
            fdroidserver.deploy.update_serverwebroot({'url': url}, repo_section)
        self.assertEqual(call_iteration, 2, 'expected 2 invocations of subprocess.call')

    def test_update_serverwebroot_with_id_file_in_index_only_mode(self):
        # setup parameters for this test run
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.no_chcksum = False
        fdroidserver.common.options.verbose = True
        fdroidserver.common.options.quiet = False
        fdroidserver.common.options.identity_file = None
        fdroidserver.deploy.config['identity_file'] = './id_rsa'
        fdroidserver.deploy.config['make_current_version_link'] = False
        url = "example.com:/var/www/fdroid"
        repo_section = 'archive'

        # setup function for asserting subprocess.call invocations
        call_iteration = 0

        def update_server_webroot_call(cmd):
            nonlocal call_iteration
            if call_iteration == 0:
                self.assertListEqual(
                    cmd,
                    [
                        'rsync',
                        '--archive',
                        '--delete-after',
                        '--safe-links',
                        '--verbose',
                        '-e',
                        'ssh -oBatchMode=yes -oIdentitiesOnly=yes -i '
                        + fdroidserver.deploy.config['identity_file'],
                        'archive/altstore-index.json',
                        'archive/altstore-index.json.asc',
                        'archive/entry.jar',
                        'archive/entry.json',
                        'archive/entry.json.asc',
                        'archive/index-v1.jar',
                        'archive/index-v1.json',
                        'archive/index-v1.json.asc',
                        'archive/index-v2.json',
                        'archive/index-v2.json.asc',
                        'archive/index.css',
                        'archive/index.html',
                        'archive/index.jar',
                        'archive/index.png',
                        'archive/index.xml',
                        "example.com:/var/www/fdroid/archive/",
                    ],
                )
            elif call_iteration == 1:
                self.assertListEqual(
                    cmd,
                    [
                        'rsync',
                        '--archive',
                        '--delete-after',
                        '--safe-links',
                        '--verbose',
                        '-e',
                        'ssh -oBatchMode=yes -oIdentitiesOnly=yes -i '
                        + fdroidserver.deploy.config['identity_file'],
                        "example.com:/var/www/fdroid/archive/",
                    ],
                )
            else:
                self.fail('unexpected subprocess.call invocation')
            call_iteration += 1
            return 0

        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with mock.patch('subprocess.call', side_effect=update_server_webroot_call):
                os.mkdir(repo_section)
                fake_files = fdroidserver.common.INDEX_FILES
                for filename in fake_files:
                    fake_file = Path(repo_section) / filename
                    with fake_file.open('w') as fp:
                        fp.write('not a real one, but has the right filename')

                fdroidserver.deploy.update_serverwebroot(
                    {'url': url, 'index_only': True}, repo_section
                )
        self.assertEqual(call_iteration, 1, 'expected 1 invocations of subprocess.call')

    @unittest.skipIf(
        not os.getenv('VIRUSTOTAL_API_KEY'), 'VIRUSTOTAL_API_KEY is not set'
    )
    def test_upload_to_virustotal(self):
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.verbose = True
        virustotal_apikey = os.getenv('VIRUSTOTAL_API_KEY')
        fdroidserver.deploy.upload_to_virustotal('repo', virustotal_apikey)

    def test_remote_hostname_regex(self):
        for remote_url, name in (
            ('git@github.com:guardianproject/fdroid-repo', 'github'),
            ('git@gitlab.com:guardianproject/fdroid-repo', 'gitlab'),
            ('https://github.com:guardianproject/fdroid-repo', 'github'),
            ('https://gitlab.com/guardianproject/fdroid-repo', 'gitlab'),
            ('https://salsa.debian.org/foo/repo', 'salsa'),
        ):
            self.assertEqual(
                name, fdroidserver.deploy.REMOTE_HOSTNAME_REGEX.sub(r'\1', remote_url)
            )

    def test_update_awsbucket_s3cmd(self):
        # setup parameters for this test run
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.no_checksum = True
        fdroidserver.common.options.verbose = False
        fdroidserver.common.options.quiet = True

        config = {}
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.deploy.config = config
        fdroidserver.deploy.config["awsbucket"] = "bucket"
        fdroidserver.deploy.config["awsaccesskeyid"] = "accesskeyid"
        fdroidserver.deploy.config["awssecretkey"] = "secretkey"
        fdroidserver.deploy.config["s3cmd"] = "s3cmd"

        repo_section = 'repo'

        # setup function for asserting subprocess.call invocations
        call_iteration = 0

        def update_awsbucket_s3cmd_call(cmd):
            nonlocal call_iteration
            if call_iteration == 0:
                self.assertListEqual(
                    cmd,
                    [
                        's3cmd',
                        f"--config={fdroidserver.deploy.AUTO_S3CFG}",
                        'info',
                        f"s3://{fdroidserver.deploy.config['awsbucket']}",
                    ],
                )
            elif call_iteration == 1:
                self.assertListEqual(
                    cmd,
                    [
                        's3cmd',
                        f"--config={fdroidserver.deploy.AUTO_S3CFG}",
                        'sync',
                        '--acl-public',
                        '--quiet',
                        '--exclude',
                        'repo/altstore-index.json',
                        '--exclude',
                        'repo/altstore-index.json.asc',
                        '--exclude',
                        'repo/entry.jar',
                        '--exclude',
                        'repo/entry.json',
                        '--exclude',
                        'repo/entry.json.asc',
                        '--exclude',
                        'repo/index-v1.jar',
                        '--exclude',
                        'repo/index-v1.json',
                        '--exclude',
                        'repo/index-v1.json.asc',
                        '--exclude',
                        'repo/index-v2.json',
                        '--exclude',
                        'repo/index-v2.json.asc',
                        '--exclude',
                        'repo/index.css',
                        '--exclude',
                        'repo/index.html',
                        '--exclude',
                        'repo/index.jar',
                        '--exclude',
                        'repo/index.png',
                        '--exclude',
                        'repo/index.xml',
                        '--no-check-md5',
                        '--skip-existing',
                        repo_section,
                        f"s3://{fdroidserver.deploy.config['awsbucket']}/fdroid/",
                    ],
                )
            elif call_iteration == 2:
                self.assertListEqual(
                    cmd,
                    [
                        's3cmd',
                        f"--config={fdroidserver.deploy.AUTO_S3CFG}",
                        'sync',
                        '--acl-public',
                        '--quiet',
                        '--exclude',
                        'repo/altstore-index.json',
                        '--exclude',
                        'repo/altstore-index.json.asc',
                        '--exclude',
                        'repo/entry.jar',
                        '--exclude',
                        'repo/entry.json',
                        '--exclude',
                        'repo/entry.json.asc',
                        '--exclude',
                        'repo/index-v1.jar',
                        '--exclude',
                        'repo/index-v1.json',
                        '--exclude',
                        'repo/index-v1.json.asc',
                        '--exclude',
                        'repo/index-v2.json',
                        '--exclude',
                        'repo/index-v2.json.asc',
                        '--exclude',
                        'repo/index.css',
                        '--exclude',
                        'repo/index.html',
                        '--exclude',
                        'repo/index.jar',
                        '--exclude',
                        'repo/index.png',
                        '--exclude',
                        'repo/index.xml',
                        '--no-check-md5',
                        repo_section,
                        f"s3://{fdroidserver.deploy.config['awsbucket']}/fdroid/",
                    ],
                )
            elif call_iteration == 3:
                self.assertListEqual(
                    cmd,
                    [
                        's3cmd',
                        f"--config={fdroidserver.deploy.AUTO_S3CFG}",
                        'sync',
                        '--acl-public',
                        '--quiet',
                        '--delete-removed',
                        '--delete-after',
                        '--no-check-md5',
                        repo_section,
                        f"s3://{fdroidserver.deploy.config['awsbucket']}/fdroid/",
                    ],
                )
            else:
                self.fail('unexpected subprocess.call invocation')
            call_iteration += 1
            return 0

        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            os.mkdir('repo')
            os.symlink('repo/com.example.sym.apk', 'Sym.apk')
            os.symlink('repo/com.example.sym.apk.asc', 'Sym.apk.asc')
            os.symlink('repo/com.example.sym.apk.sig', 'Sym.apk.sig')
            with mock.patch('subprocess.call', side_effect=update_awsbucket_s3cmd_call):
                fdroidserver.deploy.update_awsbucket_s3cmd(repo_section)
        self.assertEqual(call_iteration, 4, 'expected 4 invocations of subprocess.call')

    def test_update_awsbucket_s3cmd_in_index_only_mode(self):
        # setup parameters for this test run
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.no_checksum = True
        fdroidserver.common.options.verbose = False
        fdroidserver.common.options.quiet = True

        config = {}
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.deploy.config = config
        fdroidserver.deploy.config["awsbucket"] = "bucket"
        fdroidserver.deploy.config["awsaccesskeyid"] = "accesskeyid"
        fdroidserver.deploy.config["awssecretkey"] = "secretkey"
        fdroidserver.deploy.config["s3cmd"] = "s3cmd"

        repo_section = 'repo'

        # setup function for asserting subprocess.call invocations
        call_iteration = 0

        def update_awsbucket_s3cmd_call(cmd):
            nonlocal call_iteration
            if call_iteration == 0:
                self.assertListEqual(
                    cmd,
                    [
                        's3cmd',
                        f"--config={fdroidserver.deploy.AUTO_S3CFG}",
                        'info',
                        f"s3://{fdroidserver.deploy.config['awsbucket']}",
                    ],
                )
            elif call_iteration == 1:
                self.assertListEqual(
                    cmd,
                    [
                        's3cmd',
                        f"--config={fdroidserver.deploy.AUTO_S3CFG}",
                        'sync',
                        '--acl-public',
                        '--quiet',
                        '--include',
                        'repo/altstore-index.json',
                        '--include',
                        'repo/altstore-index.json.asc',
                        '--include',
                        'repo/entry.jar',
                        '--include',
                        'repo/entry.json',
                        '--include',
                        'repo/entry.json.asc',
                        '--include',
                        'repo/index-v1.jar',
                        '--include',
                        'repo/index-v1.json',
                        '--include',
                        'repo/index-v1.json.asc',
                        '--include',
                        'repo/index-v2.json',
                        '--include',
                        'repo/index-v2.json.asc',
                        '--include',
                        'repo/index.css',
                        '--include',
                        'repo/index.html',
                        '--include',
                        'repo/index.jar',
                        '--include',
                        'repo/index.png',
                        '--include',
                        'repo/index.xml',
                        '--delete-removed',
                        '--delete-after',
                        '--no-check-md5',
                        repo_section,
                        f"s3://{fdroidserver.deploy.config['awsbucket']}/fdroid/",
                    ],
                )
            else:
                self.fail('unexpected subprocess.call invocation')
            call_iteration += 1
            return 0

        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            os.mkdir('repo')
            os.symlink('repo/com.example.sym.apk', 'Sym.apk')
            os.symlink('repo/com.example.sym.apk.asc', 'Sym.apk.asc')
            os.symlink('repo/com.example.sym.apk.sig', 'Sym.apk.sig')
            with mock.patch('subprocess.call', side_effect=update_awsbucket_s3cmd_call):
                fdroidserver.deploy.update_awsbucket_s3cmd(
                    repo_section, is_index_only=True
                )
        self.assertEqual(call_iteration, 2, 'expected 2 invocations of subprocess.call')

    def test_update_awsbucket_libcloud(self):
        from libcloud.storage.base import Container

        # setup parameters for this test run
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.no_checksum = True
        fdroidserver.common.options.verbose = False
        fdroidserver.common.options.quiet = True

        config = {}
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.deploy.config = config
        fdroidserver.deploy.config["awsbucket"] = "bucket"
        fdroidserver.deploy.config["awsaccesskeyid"] = "accesskeyid"
        fdroidserver.deploy.config["awssecretkey"] = "secretkey"
        fdroidserver.deploy.config["s3cmd"] = "s3cmd"

        repo_section = 'repo'

        os.chdir(self.testdir)
        repo = Path('repo')
        repo.mkdir(parents=True)
        fake_apk = repo / 'Sym.apk'
        with fake_apk.open('w') as fp:
            fp.write('not an APK, but has the right filename')
        fake_index = repo / fdroidserver.common.INDEX_FILES[0]
        with fake_index.open('w') as fp:
            fp.write('not an index, but has the right filename')

        with mock.patch(
            'libcloud.storage.drivers.s3.S3StorageDriver'
        ) as mock_driver_class:
            mock_driver = mock_driver_class.return_value
            mock_container = mock.MagicMock(spec=Container)
            mock_container.list_objects.return_value = [
                mock.MagicMock(name='Sym.apk'),
                mock.MagicMock(name=fdroidserver.common.INDEX_FILES[0]),
            ]

            mock_driver.get_container.return_value = mock_container
            mock_driver.upload_object_via_stream.return_value = None

            fdroidserver.deploy.update_awsbucket_libcloud(repo_section)

            mock_driver.get_container.assert_called_once_with(
                container_name=fdroidserver.deploy.config["awsbucket"]
            )
            mock_container.list_objects.assert_called_once_with()
            files_to_upload = [
                'fdroid/repo/Sym.apk',
                f"fdroid/repo/{fdroidserver.common.INDEX_FILES[0]}",
            ]
            calls = [
                mock.call(
                    iterator=mock.ANY,
                    container=mock_container,
                    object_name=file,
                    extra={'acl': 'public-read'},
                )
                for file in files_to_upload
            ]
            mock_driver.upload_object_via_stream.assert_has_calls(calls, any_order=True)
            self.assertEqual(mock_driver.upload_object_via_stream.call_count, 2)

    def test_update_awsbucket_libcloud_in_index_only_mode(self):
        from libcloud.storage.base import Container

        # setup parameters for this test run
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.no_checksum = True
        fdroidserver.common.options.verbose = False
        fdroidserver.common.options.quiet = True

        config = {}
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.deploy.config = config
        fdroidserver.deploy.config["awsbucket"] = "bucket"
        fdroidserver.deploy.config["awsaccesskeyid"] = "accesskeyid"
        fdroidserver.deploy.config["awssecretkey"] = "secretkey"
        fdroidserver.deploy.config["s3cmd"] = "s3cmd"

        repo_section = 'repo'

        os.chdir(self.testdir)
        repo = Path('repo')
        repo.mkdir(parents=True)
        fake_apk = repo / 'Sym.apk'
        with fake_apk.open('w') as fp:
            fp.write('not an APK, but has the right filename')
        fake_index = repo / fdroidserver.common.INDEX_FILES[0]
        with fake_index.open('w') as fp:
            fp.write('not an index, but has the right filename')

        with mock.patch(
            'libcloud.storage.drivers.s3.S3StorageDriver'
        ) as mock_driver_class:
            mock_driver = mock_driver_class.return_value
            mock_container = mock.MagicMock(spec=Container)
            mock_container.list_objects.return_value = [
                mock.MagicMock(name='Sym.apk'),
                mock.MagicMock(name=fdroidserver.common.INDEX_FILES[0]),
            ]

            mock_driver.get_container.return_value = mock_container
            mock_driver.upload_object_via_stream.return_value = None

            fdroidserver.deploy.update_awsbucket_libcloud(
                repo_section, is_index_only=True
            )

            mock_driver.get_container.assert_called_once_with(
                container_name=fdroidserver.deploy.config["awsbucket"]
            )
            mock_container.list_objects.assert_called_once_with()
            files_to_upload = [f"fdroid/repo/{fdroidserver.common.INDEX_FILES[0]}"]
            calls = [
                mock.call(
                    iterator=mock.ANY,
                    container=mock_container,
                    object_name=file,
                    extra={'acl': 'public-read'},
                )
                for file in files_to_upload
            ]
            mock_driver.upload_object_via_stream.assert_has_calls(
                calls,
                any_order=False,
            )
            self.assertEqual(mock_driver.upload_object_via_stream.call_count, 1)

    def test_update_servergitmirrors(self):
        # setup parameters for this test run
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.identity_file = None
        fdroidserver.common.options.no_keep_git_mirror_archive = False
        fdroidserver.common.options.verbose = False
        fdroidserver.common.options.quiet = True

        config = {}
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.deploy.config = config

        os.chdir(self.testdir)

        repo_section = 'repo'
        initial_branch = fdroidserver.deploy.GIT_BRANCH

        remote_repo = Path(self.testdir) / 'remote'
        remote_repo.mkdir(parents=True)
        remote_git_repo = git.Repo.init(
            remote_repo, initial_branch=initial_branch, bare=True
        )
        fdroidserver.deploy.config["servergitmirrors"] = [{"url": str(remote_repo)}]

        os.chdir(self.testdir)
        repo = Path('repo')
        repo.mkdir(parents=True)
        fake_apk = 'Sym.apk'
        fake_files = fdroidserver.common.INDEX_FILES + [fake_apk]
        for filename in fake_files:
            fake_file = repo / filename
            with fake_file.open('w') as fp:
                fp.write('not a real one, but has the right filename')

        fdroidserver.deploy.update_servergitmirrors(
            fdroidserver.deploy.config["servergitmirrors"], repo_section
        )

        verify_repo = remote_git_repo.clone(
            Path(self.testdir) / 'verify',
        )

        for filename in fake_files:
            remote_file = f"fdroid/{repo_section}/{filename}"

            self.assertIsNotNone(verify_repo.working_tree_dir)
            if verify_repo.working_tree_dir is not None:
                self.assertTrue(
                    (Path(verify_repo.working_tree_dir) / remote_file).exists()
                )

    def test_update_servergitmirrors_in_index_only_mode(self):
        # setup parameters for this test run
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.identity_file = None
        fdroidserver.common.options.no_keep_git_mirror_archive = False
        fdroidserver.common.options.verbose = False
        fdroidserver.common.options.quiet = True

        config = {}
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.deploy.config = config

        os.chdir(self.testdir)

        repo_section = 'repo'
        initial_branch = fdroidserver.deploy.GIT_BRANCH

        remote_repo = Path(self.testdir) / 'remote'
        remote_repo.mkdir(parents=True)
        remote_git_repo = git.Repo.init(
            remote_repo, initial_branch=initial_branch, bare=True
        )
        fdroidserver.deploy.config["servergitmirrors"] = [
            {"url": str(remote_repo), "index_only": True}
        ]

        os.chdir(self.testdir)
        repo = Path('repo')
        repo.mkdir(parents=True)
        fake_apk = 'Sym.apk'
        fake_files = fdroidserver.common.INDEX_FILES + [fake_apk]
        for filename in fake_files:
            fake_file = repo / filename
            with fake_file.open('w') as fp:
                fp.write('not a real one, but has the right filename')

        fdroidserver.deploy.update_servergitmirrors(
            fdroidserver.deploy.config["servergitmirrors"], repo_section
        )

        verify_repo = remote_git_repo.clone(
            Path(self.testdir) / 'verify',
        )

        for filename in fdroidserver.common.INDEX_FILES:
            remote_file = f"fdroid/{repo_section}/{filename}"

            self.assertIsNotNone(verify_repo.working_tree_dir)
            if verify_repo.working_tree_dir is not None:
                self.assertTrue(
                    (Path(verify_repo.working_tree_dir) / remote_file).exists()
                )

        # Should not have the APK file
        remote_file = f"fdroid/{repo_section}/{fake_apk}"
        if verify_repo.working_tree_dir is not None:
            self.assertFalse(
                (Path(verify_repo.working_tree_dir) / remote_file).exists()
            )

    def test_upload_to_servergitmirror_in_index_only_mode(self):
        # setup parameters for this test run
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.identity_file = None
        fdroidserver.common.options.no_keep_git_mirror_archive = False
        fdroidserver.common.options.verbose = False
        fdroidserver.common.options.quiet = True
        fdroidserver.common.options.identity_file = None

        config = {}
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.deploy.config = config

        repo_section = 'repo'
        initial_branch = fdroidserver.deploy.GIT_BRANCH

        os.chdir(self.testdir)

        local_git_repo_path = Path(self.testdir) / 'local'
        local_git_repo = git.Repo.init(
            local_git_repo_path, initial_branch=initial_branch
        )

        fdroid_dir = local_git_repo_path / 'fdroid'
        repo_dir = fdroid_dir / repo_section
        repo_dir.mkdir(parents=True)
        fake_apk = 'Sym.apk'
        fake_files = fdroidserver.common.INDEX_FILES + [fake_apk]
        for filename in fake_files:
            fake_file = repo_dir / filename
            with fake_file.open('w') as fp:
                fp.write('not a real one, but has the right filename')

        # The remote repo must be a bare repo to allow being pushed to
        remote_git_repo_dir = Path(self.testdir) / 'remote'
        remote_git_repo = git.Repo.init(
            remote_git_repo_dir, initial_branch=initial_branch, bare=True
        )

        mirror_config = {"url": str(remote_git_repo_dir), "index_only": True}
        enabled_remotes = []
        ssh_cmd = 'ssh -oBatchMode=yes'
        fdroidserver.deploy.upload_to_servergitmirror(
            mirror_config=mirror_config,
            local_repo=local_git_repo,
            enabled_remotes=enabled_remotes,
            repo_section=repo_section,
            is_index_only=mirror_config['index_only'],
            fdroid_dir=str(fdroid_dir),
            git_mirror_path=str(local_git_repo_path),
            ssh_cmd=ssh_cmd,
            progress=git.RemoteProgress(),
        )

        verify_repo = remote_git_repo.clone(
            Path(self.testdir) / 'verify',
        )

        for filename in fdroidserver.common.INDEX_FILES:
            remote_file = f"fdroid/{repo_section}/{filename}"

            self.assertIsNotNone(verify_repo.working_tree_dir)
            if verify_repo.working_tree_dir is not None:
                self.assertTrue(
                    (Path(verify_repo.working_tree_dir) / remote_file).exists()
                )

        # Should not have the APK file
        remote_file = f"fdroid/{repo_section}/{fake_apk}"
        if verify_repo.working_tree_dir is not None:
            self.assertFalse(
                (Path(verify_repo.working_tree_dir) / remote_file).exists()
            )


class GitHubReleasesTest(unittest.TestCase):
    def test_find_release_infos(self):
        self.maxDiff = None

        index_mock = b"""
            {
                "packages": {
                    "com.example.app": {
                        "versions": {
                            "2e6f263c1927506015bfc98bce0818247836f2e7fe29a04e1af2b33c97848750": {
                                "file": {
                                    "name": "/com.example.app_123.apk"
                                },
                                "whatsNew": {
                                    "en-US": "fake what's new"
                                },
                                "manifest": {
                                    "versionName": "1.2.3",
                                    "versionCode": "123"
                                }
                            },
                            "8a6f263c8327506015bfc98bce0815247836f2e7fe29a04e1af2bffa6409998d": {
                                "file": {
                                    "name": "/com.example.app_100.apk"
                                },
                                "manifest": {
                                    "versionName": "1.0-alpha",
                                    "versionCode": "123"
                                },
                                "releaseChannels": ["alpha"]
                            }
                        }
                    },
                    "another.app": {
                        "versions": {
                            "30602ffc19a7c0601bbfa93bce00082c78a6f2ddfe29a04e1af253fc9f84eda0": {
                                "file": {
                                    "name": "/another.app_1.apk"
                                },
                                "manifest": {
                                    "versionName": "1",
                                    "versionCode": "1"
                                }
                            }
                        }
                    },
                    "fildered.app": {
                        "versions": {
                            "93ae02fc19a7c0601adfa93bce0443fc78a6f2ddfe3df04e1af093fca9a1ff09": {
                                "file": {
                                    "name": "/another.app_1.apk"
                                },
                                "manifest": {
                                    "versionName": "1",
                                    "versionCode": "1"
                                }
                            }
                        }
                    }
                }
            }
        """
        with unittest.mock.patch(
            "fdroidserver.deploy.open", unittest.mock.mock_open(read_data=index_mock)
        ):
            release_infos = fdroidserver.deploy.find_release_infos(
                "fake_path",
                Path('fake_repo'),
                ["com.example.app", "another.app"],
            )

        self.assertDictEqual(
            release_infos,
            {
                "another.app": {
                    "1": {
                        "files": [Path('fake_repo') / "another.app_1.apk"],
                        "hasReleaseChannels": False,
                        "whatsNew": None,
                    },
                },
                "com.example.app": {
                    "1.0-alpha": {
                        "files": [
                            Path("fake_repo") / "com.example.app_100.apk",
                        ],
                        "hasReleaseChannels": True,
                        "whatsNew": None,
                    },
                    "1.2.3": {
                        "files": [
                            Path("fake_repo") / "com.example.app_123.apk",
                        ],
                        "hasReleaseChannels": False,
                        "whatsNew": "fake what's new",
                    },
                },
            },
        )

    def test_upload_to_github_releases(self):
        gh_config = [
            {
                "projectUrl": "https://github.com/example/app",
                "packageNames": ["com.example.app", "another.app"],
            },
            {
                "projectUrl": "https://github.com/custom/app",
                "packageNames": ["more.custom.app"],
                "token": "custom_token",
            },
        ]

        fri_mock = unittest.mock.Mock(return_value="fri_result")
        urr_mock = unittest.mock.Mock()
        with unittest.mock.patch(
            "fdroidserver.deploy.find_release_infos", fri_mock
        ), unittest.mock.patch(
            "fdroidserver.deploy.upload_to_github_releases_repo", urr_mock
        ), tempfile.TemporaryDirectory() as tmpdir:
            with open(Path(tmpdir) / "index-v2.json", "w") as f:
                f.write("")

            fdroidserver.deploy.upload_to_github_releases(
                tmpdir, gh_config, "fake_global_token"
            )

            fri_mock.assert_called_once_with(
                Path(tmpdir) / "index-v2.json",
                Path(tmpdir),
                ["com.example.app", "another.app", "more.custom.app"],
            )

        self.maxDiff = None
        self.assertListEqual(
            urr_mock.call_args_list,
            [
                unittest.mock.call(
                    {
                        "projectUrl": "https://github.com/example/app",
                        "packageNames": ["com.example.app", "another.app"],
                    },
                    "fri_result",
                    "fake_global_token",
                ),
                unittest.mock.call(
                    {
                        "projectUrl": "https://github.com/custom/app",
                        "packageNames": ["more.custom.app"],
                        "token": "custom_token",
                    },
                    "fri_result",
                    "fake_global_token",
                ),
            ],
        )


class Test_UploadToGithubReleasesRepo(unittest.TestCase):
    def setUp(self):
        self.repo_conf = {
            "projectUrl": "https://github.com/example/app",
            "packageNames": ["com.example.app", "com.example.altapp", "another.app"],
        }
        self.release_infos = {
            "com.example.app": {
                "1.0.0": {
                    "files": [
                        Path("fake_repo") / "com.example.app_100100.apk",
                    ],
                    "hasReleaseChannels": False,
                    "whatsNew": "what's new com.example.app 1.0.0",
                },
                "1.0.0-beta1": {
                    "files": [
                        Path("fake_repo") / "com.example.app_100007.apk",
                    ],
                    "hasReleaseChannels": True,
                    "whatsNew": None,
                },
            },
            "com.example.altapp": {
                "1.0.0": {
                    "files": [
                        Path("fake_repo") / "com.example.altapp_100100.apk",
                        Path("fake_repo") / "com.example.altapp_100100.apk.asc",
                        Path("fake_repo") / "com.example.altapp_100100.apk.idsig",
                    ],
                    "whatsNew": "what's new com.example.altapp 1.0.0",
                },
            },
        }

        self.api = unittest.mock.Mock()
        self.api.list_unreleased_tags = lambda: ["1.0.0", "1.0.0-beta1"]
        self.api_constructor = unittest.mock.Mock(return_value=self.api)

    def test_global_token(self):
        with unittest.mock.patch("fdroidserver.github.GithubApi", self.api_constructor):
            fdroidserver.deploy.upload_to_github_releases_repo(
                self.repo_conf,
                self.release_infos,
                "global_token",
            )

        self.api_constructor.assert_called_once_with(
            "global_token", "https://github.com/example/app"
        )

        self.assertListEqual(
            self.api.create_release.call_args_list,
            [
                unittest.mock.call(
                    "1.0.0",
                    [
                        Path("fake_repo/com.example.app_100100.apk"),
                        Path("fake_repo/com.example.altapp_100100.apk"),
                        Path("fake_repo/com.example.altapp_100100.apk.asc"),
                        Path("fake_repo/com.example.altapp_100100.apk.idsig"),
                    ],
                    "what's new com.example.app 1.0.0",
                ),
            ],
        )

    def test_local_token(self):
        self.repo_conf["token"] = "local_token"  # nosec B105
        with unittest.mock.patch("fdroidserver.github.GithubApi", self.api_constructor):
            fdroidserver.deploy.upload_to_github_releases_repo(
                self.repo_conf,
                self.release_infos,
                "global_token",
            )

        self.api_constructor.assert_called_once_with(
            "local_token", "https://github.com/example/app"
        )

        self.assertListEqual(
            self.api.create_release.call_args_list,
            [
                unittest.mock.call(
                    "1.0.0",
                    [
                        Path("fake_repo/com.example.app_100100.apk"),
                        Path("fake_repo/com.example.altapp_100100.apk"),
                        Path("fake_repo/com.example.altapp_100100.apk.asc"),
                        Path("fake_repo/com.example.altapp_100100.apk.idsig"),
                    ],
                    "what's new com.example.app 1.0.0",
                ),
            ],
        )
