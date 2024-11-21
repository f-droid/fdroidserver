#!/usr/bin/env python3

import git
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

import fdroidserver
import fdroidserver.checkupdates


basedir = Path(__file__).parent


class CheckupdatesTest(unittest.TestCase):
    '''fdroidserver/checkupdates.py'''

    def setUp(self):
        os.chdir(basedir)
        self.testdir = tempfile.TemporaryDirectory(
            str(time.time()), self._testMethodName + '_'
        )

    def tearDown(self):
        self.testdir.cleanup()

    def test_autoupdatemode_no_suffix(self):
        fdroidserver.checkupdates.config = {}

        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.CurrentVersion = '1.1.8-fdroid'
        app.CurrentVersionCode = 10108
        app.UpdateCheckMode = 'HTTP'
        app.AutoUpdateMode = 'Version %v'

        build = fdroidserver.metadata.Build()
        build.versionCode = app.CurrentVersionCode
        build.versionName = app.CurrentVersion
        app['Builds'].append(build)

        with mock.patch(
            'fdroidserver.checkupdates.check_http', lambda app: ('1.1.9', 10109)
        ):
            with mock.patch('fdroidserver.metadata.write_metadata', mock.Mock()):
                with mock.patch('subprocess.call', lambda cmd: 0):
                    fdroidserver.checkupdates.checkupdates_app(app, auto=True)

        build = app['Builds'][-1]
        self.assertEqual(build.versionName, '1.1.9')
        self.assertEqual(build.commit, '1.1.9')

        with mock.patch(
            'fdroidserver.checkupdates.check_http', lambda app: ('1.7.9', 10107)
        ):
            with mock.patch('fdroidserver.metadata.write_metadata', mock.Mock()):
                with mock.patch('subprocess.call', lambda cmd: 0):
                    with self.assertRaises(fdroidserver.exception.FDroidException):
                        fdroidserver.checkupdates.checkupdates_app(app, auto=True)

        build = app['Builds'][-1]
        self.assertEqual(build.versionName, '1.1.9')
        self.assertEqual(build.commit, '1.1.9')

    def test_autoupdatemode_suffix(self):
        fdroidserver.checkupdates.config = {}

        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.CurrentVersion = '1.1.8-fdroid'
        app.CurrentVersionCode = 10108
        app.UpdateCheckMode = 'HTTP'
        app.AutoUpdateMode = r'Version +.%c-fdroid v%v_%c'

        build = fdroidserver.metadata.Build()
        build.versionCode = app.CurrentVersionCode
        build.versionName = app.CurrentVersion
        app['Builds'].append(build)

        with mock.patch(
            'fdroidserver.checkupdates.check_http', lambda app: ('1.1.9', 10109)
        ):
            with mock.patch('fdroidserver.metadata.write_metadata', mock.Mock()):
                with mock.patch('subprocess.call', lambda cmd: 0):
                    fdroidserver.checkupdates.checkupdates_app(app, auto=True)

        build = app['Builds'][-1]
        self.assertEqual(build.versionName, '1.1.9.10109-fdroid')
        self.assertEqual(build.commit, 'v1.1.9_10109')

    def test_autoupdate_multi_variants(self):
        fdroidserver.checkupdates.config = {}

        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.CurrentVersion = '1.1.8'
        app.CurrentVersionCode = 101083
        app.UpdateCheckMode = 'Tags'
        app.AutoUpdateMode = r'Version'
        app.VercodeOperation = [
            "10*%c+1",
            "10*%c+3",
        ]

        build = fdroidserver.metadata.Build()
        build.versionCode = app.CurrentVersionCode - 2
        build.versionName = app.CurrentVersion
        build.gradle = ["arm"]
        app['Builds'].append(build)

        build = fdroidserver.metadata.Build()
        build.versionCode = app.CurrentVersionCode
        build.versionName = app.CurrentVersion
        build.gradle = ["x86"]
        app['Builds'].append(build)

        with mock.patch(
            'fdroidserver.checkupdates.check_tags',
            lambda app, pattern: ('1.1.9', 10109, 'v1.1.9'),
        ):
            with mock.patch('fdroidserver.metadata.write_metadata', mock.Mock()):
                with mock.patch('subprocess.call', lambda cmd: 0):
                    fdroidserver.checkupdates.checkupdates_app(app, auto=True)

        build = app['Builds'][-2]
        self.assertEqual(build.versionName, '1.1.9')
        self.assertEqual(build.versionCode, 101091)
        self.assertEqual(build.gradle, ["arm"])

        build = app['Builds'][-1]
        self.assertEqual(build.versionName, '1.1.9')
        self.assertEqual(build.versionCode, 101093)
        self.assertEqual(build.gradle, ["x86"])

        self.assertEqual(app.CurrentVersion, '1.1.9')
        self.assertEqual(app.CurrentVersionCode, 101093)

    def test_checkupdates_app_http(self):
        fdroidserver.checkupdates.config = {}

        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.CurrentVersionCode = 10108
        app.UpdateCheckMode = 'HTTP'
        app.UpdateCheckData = 'mock'

        with mock.patch(
            'fdroidserver.checkupdates.check_http', lambda app: (None, 'bla')
        ):
            with self.assertRaises(fdroidserver.exception.FDroidException):
                fdroidserver.checkupdates.checkupdates_app(app, auto=True)

        with mock.patch(
            'fdroidserver.checkupdates.check_http', lambda app: ('1.1.9', 10109)
        ):
            with mock.patch(
                'fdroidserver.metadata.write_metadata', mock.Mock()
            ) as wrmock:
                with mock.patch('subprocess.call', lambda cmd: 0):
                    fdroidserver.checkupdates.checkupdates_app(app, auto=True)
                wrmock.assert_called_with(app.metadatapath, app)

    def test_checkupdates_app_tags(self):
        fdroidserver.checkupdates.config = {}

        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.CurrentVersion = '1.1.8'
        app.CurrentVersionCode = 10108
        app.UpdateCheckMode = 'Tags'
        app.AutoUpdateMode = 'Version'

        build = fdroidserver.metadata.Build()
        build.versionCode = app.CurrentVersionCode
        build.versionName = app.CurrentVersion
        app['Builds'].append(build)

        with mock.patch(
            'fdroidserver.checkupdates.check_tags',
            lambda app, pattern: (None, 'bla', None),
        ):
            with self.assertRaises(fdroidserver.exception.FDroidException):
                fdroidserver.checkupdates.checkupdates_app(app, auto=True)

        with mock.patch(
            'fdroidserver.checkupdates.check_tags',
            lambda app, pattern: ('1.1.9', 10109, 'v1.1.9'),
        ):
            with mock.patch('fdroidserver.metadata.write_metadata', mock.Mock()):
                with mock.patch('subprocess.call', lambda cmd: 0):
                    fdroidserver.checkupdates.checkupdates_app(app, auto=True)

        build = app['Builds'][-1]
        self.assertEqual(build.versionName, '1.1.9')
        self.assertEqual(build.commit, 'v1.1.9')

    def test_check_http(self):
        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.CurrentVersionCode = 10108
        app.UpdateCheckMode = 'HTTP'
        app.UpdateCheckData = r'https://a.net/b.txt|c(.*)|https://d.net/e.txt|v(.*)'
        app.UpdateCheckIgnore = 'beta'

        respmock = mock.Mock()
        respmock.read = lambda: 'v1.1.9\nc10109'.encode('utf-8')
        with mock.patch('urllib.request.urlopen', lambda a, b, c: respmock):
            vername, vercode = fdroidserver.checkupdates.check_http(app)
        self.assertEqual(vername, '1.1.9')
        self.assertEqual(vercode, 10109)

    def test_check_http_blocks_unknown_schemes(self):
        app = fdroidserver.metadata.App()
        for scheme in ('file', 'ssh', 'http', ';pwn'):
            app.id = scheme
            faked = scheme + '://fake.url/for/testing/scheme'
            app.UpdateCheckData = faked + '|ignored|' + faked + '|ignored'
            app.metadatapath = 'metadata/' + app.id + '.yml'
            with self.assertRaises(fdroidserver.exception.FDroidException):
                fdroidserver.checkupdates.check_http(app)

    def test_check_http_ignore(self):
        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.CurrentVersionCode = 10108
        app.UpdateCheckMode = 'HTTP'
        app.UpdateCheckData = r'https://a.net/b.txt|c(.*)|https://d.net/e.txt|v(.*)'
        app.UpdateCheckIgnore = 'beta'

        respmock = mock.Mock()
        respmock.read = lambda: 'v1.1.9-beta\nc10109'.encode('utf-8')
        with mock.patch('urllib.request.urlopen', lambda a, b, c: respmock):
            vername, vercode = fdroidserver.checkupdates.check_http(app)
        self.assertEqual(vername, None)

    def test_check_tags_data(self):
        app = fdroidserver.metadata.App()
        app.id = 'loop.starts.shooting'
        app.metadatapath = 'metadata/' + app.id + '.yml'
        app.RepoType = 'git'
        app.CurrentVersionCode = 10108
        app.UpdateCheckMode = 'Tags'
        app.UpdateCheckData = r'b.txt|c(.*)|e.txt|v(.*)'

        vcs = mock.Mock()
        vcs.latesttags.return_value = ['1.1.9', '1.1.8']
        with mock.patch(
            'pathlib.Path.read_text', lambda a: 'v1.1.9\nc10109'
        ) as _ignored, mock.patch.object(Path, 'is_file') as mock_path, mock.patch(
            'fdroidserver.common.getvcs', return_value=vcs
        ):
            _ignored  # silence the linters
            mock_path.is_file.return_falue = True
            vername, vercode, _tag = fdroidserver.checkupdates.check_tags(app, None)
        self.assertEqual(vername, '1.1.9')
        self.assertEqual(vercode, 10109)

        app.UpdateCheckData = r'b.txt|c(.*)|.|v(.*)'
        with mock.patch(
            'pathlib.Path.read_text', lambda a: 'v1.1.0\nc10109'
        ) as _ignored, mock.patch.object(Path, 'is_file') as mock_path, mock.patch(
            'fdroidserver.common.getvcs', return_value=vcs
        ):
            _ignored  # silence the linters
            mock_path.is_file.return_falue = True
            vername, vercode, _tag = fdroidserver.checkupdates.check_tags(app, None)
        self.assertEqual(vername, '1.1.0')
        self.assertEqual(vercode, 10109)

        app.UpdateCheckData = r'b.txt|c(.*)||'
        with mock.patch(
            'pathlib.Path.read_text', lambda a: 'v1.1.9\nc10109'
        ) as _ignored, mock.patch.object(Path, 'is_file') as mock_path, mock.patch(
            'fdroidserver.common.getvcs', return_value=vcs
        ):
            _ignored  # silence the linters
            mock_path.is_file.return_falue = True
            vername, vercode, _tag = fdroidserver.checkupdates.check_tags(app, None)
        self.assertEqual(vername, '1.1.9')
        self.assertEqual(vercode, 10109)

        vcs.latesttags.return_value = ['Android-1.1.0', '1.1.8']
        app.UpdateCheckData = r'b.txt|c(.*)||Android-([\d.]+)'
        with mock.patch(
            'pathlib.Path.read_text', lambda a: 'v1.1.9\nc10109'
        ) as _ignored, mock.patch.object(Path, 'is_file') as mock_path, mock.patch(
            'fdroidserver.common.getvcs', return_value=vcs
        ):
            _ignored  # silence the linters
            mock_path.is_file.return_falue = True
            vername, vercode, _tag = fdroidserver.checkupdates.check_tags(app, None)
        self.assertEqual(vername, '1.1.0')
        self.assertEqual(vercode, 10109)

        app.UpdateCheckData = r'|\+(\d+)||Android-([\d.]+)'
        vcs.latesttags.return_value = ['Android-1.1.0+1']
        with mock.patch('fdroidserver.common.getvcs', return_value=vcs):
            vername, vercode, _tag = fdroidserver.checkupdates.check_tags(app, None)
        self.assertEqual(vername, '1.1.0')
        self.assertEqual(vercode, 1)

        app.UpdateCheckData = '|||'
        vcs.latesttags.return_value = ['2']
        with mock.patch('fdroidserver.common.getvcs', return_value=vcs):
            vername, vercode, _tag = fdroidserver.checkupdates.check_tags(app, None)
        self.assertEqual(vername, '2')
        self.assertEqual(vercode, 2)

    def _get_test_git_repos(self):
        testdir = self.testdir.name
        os.chdir(testdir)
        os.mkdir('metadata')
        for f in (basedir / 'metadata').glob('*.yml'):
            shutil.copy(f, 'metadata')
        git_repo = git.Repo.init(testdir)
        with git_repo.config_writer() as cw:
            cw.set_value('user', 'name', 'Foo Bar')
            cw.set_value('user', 'email', 'foo@bar.com')
        git_repo.git.add(all=True)
        git_repo.index.commit("all metadata files")

        git_remote_upstream = os.path.join(testdir, 'git_remote_upstream')
        upstream_repo = git.Repo.init(git_remote_upstream, bare=True)
        with upstream_repo.config_writer() as cw:
            cw.set_value('receive', 'advertisePushOptions', True)
        git_repo.create_remote('upstream', 'file://' + git_remote_upstream)

        git_remote_origin = os.path.join(testdir, 'git_remote_origin')
        origin_repo = git.Repo.init(git_remote_origin, bare=True)
        with origin_repo.config_writer() as cw:
            cw.set_value('receive', 'advertisePushOptions', True)
        git_repo.create_remote('origin', 'file://' + git_remote_origin)

        return git_repo, origin_repo, upstream_repo

    def test_get_changes_versus_ref(self):
        def _make_commit_new_app(git_repo, metadata_file):
            app = fdroidserver.metadata.App()
            fdroidserver.metadata.write_metadata(metadata_file, app)
            git_repo.git.add(metadata_file)
            git_repo.git.commit(metadata_file, message=f'changed {metadata_file}')

        git_repo, origin_repo, upstream_repo = self._get_test_git_repos()
        for remote in git_repo.remotes:
            remote.push(git_repo.active_branch)
        appid = 'com.testvalue'
        metadata_file = f'metadata/{appid}.yml'

        # set up remote branch with change to app
        git_repo.git.checkout('-b', appid)
        _make_commit_new_app(git_repo, metadata_file)
        git_repo.remotes.origin.push(appid)

        # reset local branch and there should be differences
        upstream_main = fdroidserver.checkupdates.get_upstream_main_branch(git_repo)
        git_repo.git.reset(upstream_main)
        self.assertTrue(
            fdroidserver.checkupdates.get_changes_versus_ref(
                git_repo, f'origin/{appid}', metadata_file
            )
        )
        # make new commit that matches the previous, different commit, no diff
        _make_commit_new_app(git_repo, metadata_file)
        self.assertFalse(
            fdroidserver.checkupdates.get_changes_versus_ref(
                git_repo, f'origin/{appid}', metadata_file
            )
        )

    def test_push_commits(self):
        git_repo, origin_repo, upstream_repo = self._get_test_git_repos()
        for remote in git_repo.remotes:
            remote.push(git_repo.active_branch)
        self.assertEqual(git_repo.head, upstream_repo.head)
        self.assertEqual(origin_repo.head, upstream_repo.head)
        # pretend that checkupdates ran but didn't create any new commits
        fdroidserver.checkupdates.push_commits()

        appid = 'org.adaway'
        self.assertNotIn(appid, git_repo.branches)
        self.assertNotIn(appid, origin_repo.branches)
        self.assertNotIn(appid, upstream_repo.branches)
        self.assertNotIn('checkupdates', git_repo.branches)

        # now make commit
        app = fdroidserver.metadata.read_metadata({appid: -1})[appid]
        build = fdroidserver.metadata.Build()
        build.versionName = 'fake'
        build.versionCode = 999999999
        app.Builds.append(build)
        metadata_file = 'metadata/%s.yml' % appid
        fdroidserver.metadata.write_metadata(metadata_file, app)
        git_repo.index.add(metadata_file)
        git_repo.index.commit('changed ' + appid)

        # and push the new commit to the dynamic branch
        fdroidserver.checkupdates.push_commits()
        self.assertIn(appid, git_repo.branches)
        self.assertIn(appid, git_repo.remotes.origin.refs)
        self.assertNotIn('checkupdates', git_repo.branches)
        self.assertNotIn(appid, git_repo.remotes.upstream.refs)

    def test_push_commits_verbose(self):
        class Options:
            verbose = True

        fdroidserver.checkupdates.options = Options
        repos = self._get_test_git_repos()
        git_repo = repos[0]
        git_repo.remotes.origin.push(git_repo.active_branch)
        git_repo.remotes.upstream.push(git_repo.active_branch)

        # make commit
        appid = 'org.adaway'
        app = fdroidserver.metadata.read_metadata({appid: -1})[appid]
        build = fdroidserver.metadata.Build()
        build.versionName = 'fake'
        build.versionCode = 999999999
        app.Builds.append(build)
        metadata_file = 'metadata/%s.yml' % appid
        fdroidserver.metadata.write_metadata(metadata_file, app)
        git_repo.index.add(metadata_file)
        git_repo.index.commit('changed ' + appid)

        # and push the new commit to the dynamic branch
        fdroidserver.checkupdates.push_commits()
        self.assertIn(appid, git_repo.branches)
        self.assertIn(appid, git_repo.remotes.origin.refs)

    def test_prune_empty_appid_branches(self):
        git_repo, origin_repo, upstream_repo = self._get_test_git_repos()
        for remote in git_repo.remotes:
            remote.push(git_repo.active_branch)
        self.assertEqual(git_repo.head, upstream_repo.head)
        self.assertEqual(origin_repo.head, upstream_repo.head)

        appid = 'org.adaway'
        git_repo.create_head(appid, force=True)
        git_repo.remotes.origin.push(appid, force=True)
        self.assertIn(appid, git_repo.branches)
        self.assertIn(appid, origin_repo.branches)
        self.assertIn(appid, git_repo.remotes.origin.refs)
        self.assertNotIn(appid, git_repo.remotes.upstream.refs)
        fdroidserver.checkupdates.prune_empty_appid_branches()
        self.assertNotIn(appid, origin_repo.branches)
        self.assertNotIn(appid, git_repo.remotes.origin.refs)
        self.assertNotIn(appid, git_repo.remotes.upstream.refs)

    @mock.patch('sys.exit')
    @mock.patch('fdroidserver.metadata.read_metadata')
    def test_merge_requests_flag(self, read_metadata, sys_exit):
        def _sys_exit(return_code=0):
            self.assertNotEqual(return_code, 0)
            raise fdroidserver.exception.FDroidException('sys.exit() ran')

        def _read_metadata(a=None, b=None):
            raise StopIteration('read_metadata() ran, test is successful')

        appid = 'com.example'
        # read_metadata.return_value = dict()  # {appid: dict()}
        read_metadata.side_effect = _read_metadata
        sys_exit.side_effect = _sys_exit

        # set up clean git repo
        os.chdir(self.testdir.name)
        git_repo = git.Repo.init()
        open('foo', 'w').close()
        git_repo.git.add(all=True)
        git_repo.index.commit("all files")

        with mock.patch('sys.argv', ['fdroid checkupdates', '--merge-request']):
            with self.assertRaises(fdroidserver.exception.FDroidException):
                fdroidserver.checkupdates.main()
        sys_exit.assert_called()

        sys_exit.reset_mock()
        with mock.patch('sys.argv', ['fdroid checkupdates', '--merge-request', appid]):
            with self.assertRaises(StopIteration):
                fdroidserver.checkupdates.main()
        sys_exit.assert_not_called()

    def test_get_upstream_main_branch(self):
        os.chdir(self.testdir.name)
        testvalue = 'foo'
        git_repo = git.Repo.init('.', initial_branch=testvalue)

        open('foo', 'w').close()
        git_repo.git.add(all=True)
        git_repo.index.commit("all files")
        git_repo.create_remote('upstream', os.getcwd()).fetch()

        branch = fdroidserver.checkupdates.get_upstream_main_branch(git_repo)
        self.assertEqual(
            f'upstream/{testvalue}',
            branch,
            f'The default branch should be called {testvalue}!',
        )

    def test_get_upstream_main_branch_git_config(self):
        os.chdir(self.testdir.name)
        testvalue = 'foo'
        git_repo = git.Repo.init('.', initial_branch=testvalue)
        with git_repo.config_writer() as cw:
            cw.set_value('init', 'defaultBranch', testvalue)

        open('foo', 'w').close()
        git_repo.git.add(all=True)
        git_repo.index.commit("all files")
        git_repo.git.branch('somethingelse')  # make another remote branch
        git_repo.create_remote('upstream', os.getcwd()).fetch()

        branch = fdroidserver.checkupdates.get_upstream_main_branch(git_repo)
        self.assertEqual(
            f'upstream/{testvalue}',
            branch,
            f'The default branch should be called {testvalue}!',
        )

    def test_checkout_appid_branch_does_not_exist(self):
        appid = 'com.example'
        os.chdir(self.testdir.name)
        git_repo = git.Repo.init('.')
        open('foo', 'w').close()
        git_repo.git.add(all=True)
        git_repo.index.commit("all files")
        # --merge-request assumes remotes called 'origin' and 'upstream'
        git_repo.create_remote('origin', os.getcwd()).fetch()
        git_repo.create_remote('upstream', os.getcwd()).fetch()
        self.assertNotIn(appid, git_repo.heads)
        fdroidserver.checkupdates.checkout_appid_branch(appid)
        self.assertIn(appid, git_repo.heads)

    def test_checkout_appid_branch_exists(self):
        appid = 'com.example'

        upstream_dir = os.path.join(self.testdir.name, 'upstream_git')
        os.mkdir(upstream_dir)
        upstream_repo = git.Repo.init(upstream_dir)
        (Path(upstream_dir) / 'README').write_text('README')
        upstream_repo.git.add(all=True)
        upstream_repo.index.commit("README")
        upstream_repo.create_head(appid)

        local_dir = os.path.join(self.testdir.name, 'local_git')
        git.Repo.clone_from(upstream_dir, local_dir)
        os.chdir(local_dir)
        git_repo = git.Repo.init('.')
        # --merge-request assumes remotes called 'origin' and 'upstream'
        git_repo.create_remote('upstream', upstream_dir).fetch()

        self.assertNotIn(appid, git_repo.heads)
        fdroidserver.checkupdates.checkout_appid_branch(appid)
        self.assertIn(appid, git_repo.heads)

    def test_checkout_appid_branch_skip_bot_commit(self):
        appid = 'com.example'

        upstream_dir = os.path.join(self.testdir.name, 'upstream_git')
        os.mkdir(upstream_dir)
        upstream_repo = git.Repo.init(upstream_dir)
        (Path(upstream_dir) / 'README').write_text('README')
        upstream_repo.git.add(all=True)
        upstream_repo.index.commit("README")
        upstream_repo.create_head(appid)

        local_dir = os.path.join(self.testdir.name, 'local_git')
        git.Repo.clone_from(upstream_dir, local_dir)
        os.chdir(local_dir)
        git_repo = git.Repo.init('.')
        # --merge-request assumes remotes called 'origin' and 'upstream'
        git_repo.create_remote('upstream', upstream_dir).fetch()

        os.mkdir('metadata')
        git_repo.create_head(appid, f'origin/{appid}', force=True)
        git_repo.git.checkout(appid)

        # fake checkupdates-bot commit
        Path(f'metadata/{appid}.yml').write_text('AutoName: Example\n')
        with git_repo.config_writer() as cw:
            cw.set_value('user', 'email', fdroidserver.checkupdates.BOT_EMAIL)
        git_repo.git.add(all=True)
        git_repo.index.commit("Example")

        # set up starting from remote branch
        git_repo.remotes.origin.push(appid)
        upstream_main = fdroidserver.checkupdates.get_upstream_main_branch(git_repo)
        git_repo.git.checkout(upstream_main.split('/')[1])
        git_repo.delete_head(appid, force=True)

        self.assertTrue(
            fdroidserver.checkupdates.checkout_appid_branch(appid),
            'This should have been true since there are only bot commits.',
        )

    def test_checkout_appid_branch_skip_human_edits(self):
        appid = 'com.example'

        upstream_dir = os.path.join(self.testdir.name, 'upstream_git')
        os.mkdir(upstream_dir)
        upstream_repo = git.Repo.init(upstream_dir)
        (Path(upstream_dir) / 'README').write_text('README')
        upstream_repo.git.add(all=True)
        upstream_repo.index.commit("README")
        upstream_repo.create_head(appid)

        local_dir = os.path.join(self.testdir.name, 'local_git')
        git.Repo.clone_from(upstream_dir, local_dir)
        os.chdir(local_dir)
        git_repo = git.Repo.init('.')
        # --merge-request assumes remotes called 'origin' and 'upstream'
        git_repo.create_remote('upstream', upstream_dir).fetch()

        os.mkdir('metadata')
        git_repo.create_head(appid, f'origin/{appid}', force=True)
        git_repo.git.checkout(appid)

        with git_repo.config_writer() as cw:
            cw.set_value('user', 'email', fdroidserver.checkupdates.BOT_EMAIL)

        # fake checkupdates-bot commit
        Path(f'metadata/{appid}.yml').write_text('AutoName: Example\n')
        git_repo.git.add(all=True)
        git_repo.index.commit("Example")

        # fake commit added on top by a human
        Path(f'metadata/{appid}.yml').write_text('AutoName: Example\nName: Foo\n')
        with git_repo.config_writer() as cw:
            cw.set_value('user', 'email', 'human@bar.com')
        git_repo.git.add(all=True)
        git_repo.index.commit("Example")

        # set up starting from remote branch
        git_repo.remotes.origin.push(appid)
        upstream_main = fdroidserver.checkupdates.get_upstream_main_branch(git_repo)
        git_repo.git.reset(upstream_main.split('/')[1])

        self.assertFalse(
            fdroidserver.checkupdates.checkout_appid_branch(appid),
            'This should have been false since there are human edits.',
        )

    @mock.patch('git.remote.Remote.push')
    @mock.patch('sys.exit')
    @mock.patch('fdroidserver.common.read_app_args')
    @mock.patch('fdroidserver.checkupdates.checkupdates_app')
    def test_merge_requests_branch(
        self, checkupdates_app, read_app_args, sys_exit, push
    ):
        def _sys_exit(return_code=0):
            self.assertEqual(return_code, 0)

        def _checkupdates_app(app, auto, commit):  # pylint: disable=unused-argument
            os.mkdir('metadata')
            Path(f'metadata/{app["packageName"]}.yml').write_text('AutoName: Example')
            git_repo.git.add(all=True)
            git_repo.index.commit("Example")

        def _read_app_args(apps=[]):
            appid = apps[0]
            return {appid: {'packageName': appid}}

        appid = 'com.example'
        read_app_args.side_effect = _read_app_args
        checkupdates_app.side_effect = _checkupdates_app
        sys_exit.side_effect = _sys_exit

        # set up clean git repo
        os.chdir(self.testdir.name)
        git_repo = git.Repo.init()
        open('foo', 'w').close()
        git_repo.git.add(all=True)
        git_repo.index.commit("all files")
        # --merge-request assumes remotes called 'origin' and 'upstream'
        git_repo.create_remote('origin', os.getcwd()).fetch()
        git_repo.create_remote('upstream', os.getcwd()).fetch()

        self.assertNotIn(appid, git_repo.heads)
        with mock.patch('sys.argv', ['fdroid checkupdates', '--merge-request', appid]):
            fdroidserver.checkupdates.main()
        push.assert_called_once()
        sys_exit.assert_called_once()
        self.assertIn(appid, git_repo.heads)
