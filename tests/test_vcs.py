#!/usr/bin/env python3

import os
import unittest

from git import Repo

import fdroidserver.common
import fdroidserver.metadata
from .testcommon import mkdtemp, VerboseFalseOptions


class VCSTest(unittest.TestCase):
    """For some reason the VCS classes are in fdroidserver/common.py"""

    def setUp(self):
        self._td = mkdtemp()
        os.chdir(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    def test_remote_set_head_can_fail(self):
        # First create an upstream repo with one commit
        upstream_repo = Repo.init("upstream_repo")
        with open(upstream_repo.working_dir + "/file", 'w') as f:
            f.write("Hello World!")
        upstream_repo.index.add([upstream_repo.working_dir + "/file"])
        upstream_repo.index.commit("initial commit")
        commitid = upstream_repo.head.commit.hexsha

        # Now clone it once manually, like gitlab runner gitlab-runner sets up a repo during CI
        clone1 = Repo.init("clone1")
        clone1.create_remote("upstream", "file://" + upstream_repo.working_dir)
        clone1.remote("upstream").fetch()
        clone1.head.reference = clone1.commit(commitid)
        clone1.head.reset(index=True, working_tree=True)
        self.assertTrue(clone1.head.is_detached)

        # and now we want to use this clone as a source repo for fdroid build
        config = {}
        os.mkdir("build")
        config['sdk_path'] = 'MOCKPATH'
        config['ndk_paths'] = {'r10d': os.getenv('ANDROID_NDK_HOME')}
        config['java_paths'] = {'fake': 'fake'}
        fdroidserver.common.config = config
        app = fdroidserver.metadata.App()
        app.RepoType = 'git'
        app.Repo = clone1.working_dir
        app.id = 'com.gpl.rpg.AndorsTrail'
        build = fdroidserver.metadata.Build()
        build.commit = commitid
        build.androidupdate = ['no']
        vcs, build_dir = fdroidserver.common.setup_vcs(app)
        # force an init of the repo, the remote head error only occurs on the second gotorevision call

        fdroidserver.common.options = VerboseFalseOptions
        vcs.gotorevision(build.commit)
        fdroidserver.common.prepare_source(
            vcs,
            app,
            build,
            build_dir=build_dir,
            srclib_dir="ignore",
            extlib_dir="ignore",
        )
        self.assertTrue(os.path.isfile("build/com.gpl.rpg.AndorsTrail/file"))
