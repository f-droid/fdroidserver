#!/usr/bin/env python3

import difflib
import git
import glob
import importlib
import inspect
import json
import logging
import os
import re
import ruamel.yaml
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import textwrap
import yaml
import gzip
from argparse import ArgumentParser
from datetime import datetime, timezone
from zipfile import BadZipFile, ZipFile
from unittest import mock
from pathlib import Path


import fdroidserver
import fdroidserver.signindex
import fdroidserver.common
import fdroidserver.metadata
from .testcommon import TmpCwd, mkdtemp
from fdroidserver.common import ANTIFEATURES_CONFIG_NAME, CATEGORIES_CONFIG_NAME
from fdroidserver.exception import FDroidException, VCSException,\
    MetaDataException, VerificationException
from fdroidserver.looseversion import LooseVersion


basedir = Path(__file__).parent


def _mock_common_module_options_instance():
    """Helper method to deal with difficult visibility of the module-level options."""
    fdroidserver.common.options = mock.Mock()
    fdroidserver.common.options.verbose = False


class CommonTest(unittest.TestCase):
    '''fdroidserver/common.py'''

    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        logger = logging.getLogger('androguard.axml')
        logger.setLevel(logging.INFO)  # tame the axml debug messages
        self.tmpdir = os.path.abspath(os.path.join(basedir, '..', '.testfiles'))
        if not os.path.exists(self.tmpdir):
            os.makedirs(self.tmpdir)
        os.chdir(basedir)

        # these are declared as None at the top of the module file
        fdroidserver.common.config = None
        fdroidserver.common.options = None
        fdroidserver.metadata.srclibs = None

        self._td = mkdtemp()
        self.testdir = self._td.name

    def tearDown(self):
        fdroidserver.common.config = None
        fdroidserver.common.options = None
        os.chdir(basedir)
        self._td.cleanup()
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_parse_human_readable_size(self):
        for k, v in (
            (9827, 9827),
            (123.456, 123),
            ('123b', 123),
            ('1.2', 1),
            ('10.43 KiB', 10680),
            ('11GB', 11000000000),
            ('59kb', 59000),
            ('343.1 mb', 343100000),
            ('99.9GiB', 107266808217),
            ('1MB', 1000000),
        ):
            self.assertEqual(fdroidserver.common.parse_human_readable_size(k), v)
        for v in ((12, 123), '0xfff', [], None, '12,123', '123GG', '982374bb', self):
            with self.assertRaises(ValueError):
                fdroidserver.common.parse_human_readable_size(v)

    def test_assert_config_keystore(self):
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with self.assertRaises(FDroidException):
                fdroidserver.common.assert_config_keystore({})

        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            c = {
                'repo_keyalias': 'localhost',
                'keystore': 'keystore.jks',
                'keystorepass': '12345',
                'keypass': '12345',
            }
            with open('keystore.jks', 'w'):
                pass
            fdroidserver.common.assert_config_keystore(c)

    def _set_build_tools(self):
        build_tools = os.path.join(
            fdroidserver.common.config['sdk_path'], 'build-tools'
        )
        if os.path.exists(build_tools):
            for f in sorted(os.listdir(build_tools), reverse=True):
                versioned = os.path.join(build_tools, f)
                if os.path.isdir(versioned) and os.path.isfile(
                    os.path.join(versioned, 'apksigner')
                ):
                    break
            return True
        else:
            print('no build-tools found: ' + build_tools)
            return False

    def _find_all(self):
        tools = ['aapt', 'adb', 'jarsigner']
        if os.path.exists(os.path.join(os.getenv('ANDROID_HOME'), 'tools', 'android')):
            tools.append('android')
        for cmd in tools:
            try:
                path = fdroidserver.common.find_sdk_tools_cmd(cmd)
                self.assertTrue(os.path.exists(path))
                self.assertTrue(os.path.isfile(path))
            except fdroidserver.exception.FDroidException:
                pass

    @unittest.skipUnless(os.getenv('ANDROID_HOME'), "Needs ANDROID_HOME env var")
    def test_find_sdk_tools_cmd(self):
        fdroidserver.common.config = dict()
        # TODO add this once everything works without sdk_path set in config
        # self._find_all()
        sdk_path = os.getenv('ANDROID_HOME')
        if os.path.exists(sdk_path):
            fdroidserver.common.config['sdk_path'] = sdk_path
            build_tools = os.path.join(sdk_path, 'build-tools')
            if self._set_build_tools() or os.path.exists('/usr/bin/aapt'):
                self._find_all()
            else:
                print('no build-tools found: ' + build_tools)

    def test_find_java_root_path(self):
        os.chdir(self.tmpdir)

        all_pathlists = [
            (
                [  # Debian
                    '/usr/lib/jvm/java-1.5.0-gcj-5-amd64',
                    '/usr/lib/jvm/java-8-openjdk-amd64',
                    '/usr/lib/jvm/java-1.8.0-openjdk-amd64',
                ],
                '/usr/lib/jvm/java-8-openjdk-amd64',
            ),
            (
                [  # OSX
                    '/Library/Java/JavaVirtualMachines/jdk1.8.0_202.jdk',
                    '/Library/Java/JavaVirtualMachines/jdk1.8.0_45.jdk',
                    '/System/Library/Java/JavaVirtualMachines/jdk1.7.0_80.jdk',
                ],
                '/Library/Java/JavaVirtualMachines/jdk1.8.0_202.jdk',
            ),
        ]

        for pathlist, choice in all_pathlists:
            # strip leading / to make relative paths to test without root
            pathlist = [p[1:] for p in pathlist]

            # create test file used in common._add_java_paths_to_config()
            for p in pathlist:
                if p.startswith('/System') or p.startswith('/Library'):
                    _dir = os.path.join(p, 'Contents', 'Home', 'bin')
                else:
                    _dir = os.path.join(p, 'bin')
                os.makedirs(_dir)
                open(os.path.join(_dir, 'javac'), 'w').close()

            config = dict()
            config['java_paths'] = dict()
            fdroidserver.common._add_java_paths_to_config(pathlist, config)
            self.assertEqual(config['java_paths']['8'], choice[1:])

    def test_is_debuggable_or_testOnly(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config

        # these are set debuggable
        for apkfile in ('urzip.apk', 'urzip-badsig.apk', 'urzip-badcert.apk'):
            self.assertTrue(
                fdroidserver.common.is_debuggable_or_testOnly(str(basedir / apkfile)),
                "debuggable APK state was not properly parsed!",
            )

        # these are set NOT debuggable
        testfiles = 'urzip-release.apk', 'urzip-release-unsigned.apk', 'v2.only.sig_2.apk'
        for apkfile in testfiles:
            self.assertFalse(
                fdroidserver.common.is_debuggable_or_testOnly(apkfile),
                "debuggable APK state was not properly parsed!",
            )

    VALID_STRICT_PACKAGE_NAMES = [
        "An.stop",
        "SpeedoMeterApp.main",
        "a2dp.Vol",
        "au.com.darkside.XServer",
        "click.dummer.UartSmartwatch",
        "com.Bisha.TI89EmuDonation",
        "com.MarcosDiez.shareviahttp",
        "com.Pau.ImapNotes2",
        "com.app.Zensuren",
        "com.darshancomputing.BatteryIndicator",
        "com.geecko.QuickLyric",
        "com.genonbeta.TrebleShot",
        "com.gpl.rpg.AndorsTrail",
        "com.hobbyone.HashDroid",
        "com.moez.QKSMS",
        "com.platypus.SAnd",
        "com.prhlt.aemus.Read4SpeechExperiments",
        "de.syss.MifareClassicTool",
        "org.fdroid.fdroid",
        "org.f_droid.fdr0ID",
    ]

    def test_is_valid_package_name(self):
        for name in self.VALID_STRICT_PACKAGE_NAMES + [
            "_SpeedoMeterApp.main",
            "05041684efd9b16c2888b1eddbadd0359f655f311b89bdd1737f560a10d20fb8",
        ]:
            self.assertTrue(
                fdroidserver.common.is_valid_package_name(name),
                "{0} should be a valid package name".format(name),
            )
        for name in [
            "0rg.fdroid.fdroid",
            ".f_droid.fdr0ID",
            "trailingdot.",
            "org.fdroid/fdroid",
            "/org.fdroid.fdroid",
        ]:
            self.assertFalse(
                fdroidserver.common.is_valid_package_name(name),
                "{0} should not be a valid package name".format(name),
            )

    def test_is_strict_application_id(self):
        """see also tests/valid-package-names/"""
        for name in self.VALID_STRICT_PACKAGE_NAMES:
            self.assertTrue(
                fdroidserver.common.is_strict_application_id(name),
                "{0} should be a strict application id".format(name),
            )
        for name in [
            "0rg.fdroid.fdroid",
            ".f_droid.fdr0ID",
            "oneword",
            "trailingdot.",
            "cafebabe",
            "org.fdroid/fdroid",
            "/org.fdroid.fdroid",
            "_SpeedoMeterApp.main",
            "05041684efd9b16c2888b1eddbadd0359f655f311b89bdd1737f560a10d20fb8",
        ]:
            self.assertFalse(
                fdroidserver.common.is_strict_application_id(name),
                "{0} should not be a strict application id".format(name),
            )

    def test_prepare_sources(self):
        testint = 99999999
        teststr = 'FAKE_STR_FOR_TESTING'

        shutil.copytree(
            os.path.join(basedir, 'source-files'),
            os.path.join(self.tmpdir, 'source-files'),
        )

        fdroidclient_testdir = os.path.join(
            self.tmpdir, 'source-files', 'fdroid', 'fdroidclient'
        )

        config = dict()
        config['sdk_path'] = os.getenv('ANDROID_HOME')
        config['ndk_paths'] = {'r10d': os.getenv('ANDROID_NDK_HOME')}
        fdroidserver.common.config = config
        app = fdroidserver.metadata.App()
        app.id = 'org.fdroid.froid'
        build = fdroidserver.metadata.Build()
        build.commit = 'master'
        build.forceversion = True
        build.forcevercode = True
        build.gradle = ['yes']
        build.target = 'android-' + str(testint)
        build.versionName = teststr
        build.versionCode = testint

        class FakeVcs:
            # no need to change to the correct commit here
            def gotorevision(self, rev, refresh=True):
                pass

            # no srclib info needed, but it could be added...
            def getsrclib(self):
                return None

            def deinitsubmodules(self):
                pass

        fdroidserver.common.prepare_source(FakeVcs(), app, build,
                                           fdroidclient_testdir, fdroidclient_testdir, fdroidclient_testdir)

        fdroidclient_testdir = Path(fdroidclient_testdir)
        build_gradle = fdroidclient_testdir / 'build.gradle'
        filedata = build_gradle.read_text(encoding='utf-8')
        self.assertIsNotNone(
            re.search(r"\s+compileSdkVersion %s\s+" % testint, filedata)
        )

        androidmanifest_xml = fdroidclient_testdir / 'AndroidManifest.xml'
        filedata = androidmanifest_xml.read_text(encoding='utf-8')
        self.assertIsNone(re.search('android:debuggable', filedata))
        self.assertIsNotNone(
            re.search('android:versionName="%s"' % build.versionName, filedata)
        )
        self.assertIsNotNone(
            re.search('android:versionCode="%s"' % build.versionCode, filedata)
        )

    @unittest.skipIf(os.name == 'nt', "`fdroid build` assumes POSIX scripting")
    def test_prepare_sources_with_prebuild_subdir(self):
        app_build_dir = os.path.join(self.testdir, 'build', 'com.example')
        shutil.copytree(
            basedir / 'source-files' / 'fdroid' / 'fdroidclient',
            app_build_dir,
        )

        subdir = 'baz/bar'
        subdir_path = Path(app_build_dir) / subdir
        subdir_path.mkdir(parents=True, exist_ok=True)
        build_gradle = subdir_path / 'build.gradle'
        build_gradle.write_text('// just a test placeholder', encoding='utf-8')

        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        _mock_common_module_options_instance()

        srclibname = 'FakeSrcLib'
        srclib_testdir = os.path.join(self.testdir, 'build', 'srclib')
        os.makedirs(os.path.join(srclib_testdir, srclibname, 'testdirshouldexist'))
        fdroidserver.metadata.srclibs = {
            srclibname: {
                'RepoType': 'git',
                'Repo': 'https://example.com/foo/fakesrclib',
                'Subdir': None,
                'Prepare': None,
            }
        }

        app = fdroidserver.metadata.App()
        app.id = 'app.has.srclibs'
        build = fdroidserver.metadata.Build()
        build.commit = 'master'
        build.gradle = ['yes']
        build.prebuild = ['test -d $$FakeSrcLib$$/testdirshouldexist']  # actual test condition
        build.srclibs = [srclibname + '@1.2.3']
        build.subdir = subdir
        build.versionCode = 0xCAFE
        build.versionName = 'vCAFE'

        class FakeVcs:
            # no need to change to the correct commit here
            def gotorevision(self, rev, refresh=True):
                pass

            # no srclib info needed, but it could be added...
            def getsrclib(self):
                return None

            def deinitsubmodules(self):
                pass

        fdroidserver.common.prepare_source(FakeVcs(), app, build,
                                           app_build_dir, srclib_testdir, app_build_dir,
                                           onserver=True, refresh=False)  # do not clone in this test

    def test_prepare_sources_refresh(self):
        _mock_common_module_options_instance()
        packageName = 'org.fdroid.ci.test.app'
        os.chdir(self.tmpdir)
        os.mkdir('build')
        os.mkdir('metadata')

        # use a local copy if available to avoid hitting the network
        tmprepo = os.path.join(basedir, 'tmp', 'importer')
        if os.path.exists(tmprepo):
            git_url = tmprepo
        else:
            git_url = 'https://gitlab.com/fdroid/ci-test-app.git'

        metadata = dict()
        metadata['Description'] = 'This is just a test app'
        metadata['RepoType'] = 'git'
        metadata['Repo'] = git_url
        with open(os.path.join('metadata', packageName + '.yml'), 'w') as fp:
            yaml.dump(metadata, fp)

        gitrepo = os.path.join(self.tmpdir, 'build', packageName)
        vcs0 = fdroidserver.common.getvcs('git', git_url, gitrepo)
        vcs0.gotorevision('0.3', refresh=True)
        vcs1 = fdroidserver.common.getvcs('git', git_url, gitrepo)
        vcs1.gotorevision('0.3', refresh=False)

    def test_setup_vcs_srclib(self):
        app = fdroidserver.metadata.App(
            {
                'RepoType': 'srclib',
                'Repo': 'TransportsRennes',
            }
        )
        srclib = {
            'RepoType': 'git',
            'Repo': 'https://github.com/ybonnel/TransportsRennes',
        }
        fdroidserver.metadata.srclibs = {'TransportsRennes': srclib}
        vcs, build_dir = fdroidserver.common.setup_vcs(app)
        self.assertIsNotNone(vcs)
        self.assertEqual(build_dir, Path('build/srclib/TransportsRennes'))

    def test_getvcs_srclib(self):
        vcstype = 'srclib'
        remote = 'TransportsRennes'
        local = 'build/srclib/' + remote
        fdroidserver.metadata.srclibs = {
            remote: {
                'RepoType': 'git',
                'Repo': 'https://github.com/ybonnel/TransportsRennes',
            }
        }
        self.assertIsNotNone(fdroidserver.common.getvcs(vcstype, remote, local))
        self.assertIsNotNone(fdroidserver.common.getvcs(vcstype, Path(remote), local))
        self.assertIsNotNone(fdroidserver.common.getvcs(vcstype, remote, Path(local)))
        self.assertIsNotNone(fdroidserver.common.getvcs(
            vcstype, Path(remote), Path(local)
        ))
        with self.assertRaises(VCSException):
            fdroidserver.common.getvcs(vcstype, remote, 'bad')
        with self.assertRaises(VCSException):
            fdroidserver.common.getvcs(vcstype, remote, Path('bad'))
        with self.assertRaises(VCSException):
            fdroidserver.common.getvcs(vcstype, Path(remote), 'bad')
        with self.assertRaises(VCSException):
            fdroidserver.common.getvcs(vcstype, Path(remote), Path('bad'))

    def test_fdroid_popen_stderr_redirect(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        _mock_common_module_options_instance()

        commands = ['sh', '-c', 'echo stdout message && echo stderr message 1>&2']

        p = fdroidserver.common.FDroidPopen(commands)
        self.assertEqual(p.output, 'stdout message\nstderr message\n')

        p = fdroidserver.common.FDroidPopen(commands, stderr_to_stdout=False)
        self.assertEqual(p.output, 'stdout message\n')

    def test_signjar(self):
        _mock_common_module_options_instance()
        config = fdroidserver.common.read_config()
        config['jarsigner'] = fdroidserver.common.find_sdk_tools_cmd('jarsigner')
        fdroidserver.common.config = config
        fdroidserver.signindex.config = config

        sourcedir = os.path.join(basedir, 'signindex')
        with tempfile.TemporaryDirectory(
            prefix=inspect.currentframe().f_code.co_name, dir=self.tmpdir
        ) as testsdir:
            for f in ('testy.jar', 'guardianproject.jar'):
                sourcefile = os.path.join(sourcedir, f)
                testfile = os.path.join(testsdir, f)
                shutil.copy(sourcefile, testsdir)
                fdroidserver.signindex.sign_jar(testfile, use_old_algs=True)
                # these should be resigned, and therefore different
                self.assertNotEqual(
                    open(sourcefile, 'rb').read(), open(testfile, 'rb').read()
                )

    def test_verify_apk_signature(self):
        _mock_common_module_options_instance()
        config = fdroidserver.common.read_config()
        fdroidserver.common.config = config

        self.assertTrue(fdroidserver.common.verify_apk_signature('bad-unicode-πÇÇ现代通用字-български-عربي1.apk'))
        if 'apksigner' in fdroidserver.common.config:  # apksigner considers MD5 signatures valid
            self.assertTrue(fdroidserver.common.verify_apk_signature('org.bitbucket.tickytacky.mirrormirror_1.apk'))
            self.assertTrue(fdroidserver.common.verify_apk_signature('org.bitbucket.tickytacky.mirrormirror_2.apk'))
            self.assertTrue(fdroidserver.common.verify_apk_signature('org.bitbucket.tickytacky.mirrormirror_3.apk'))
            self.assertTrue(fdroidserver.common.verify_apk_signature('org.bitbucket.tickytacky.mirrormirror_4.apk'))
        else:
            self.assertFalse(fdroidserver.common.verify_apk_signature('org.bitbucket.tickytacky.mirrormirror_1.apk'))
            self.assertFalse(fdroidserver.common.verify_apk_signature('org.bitbucket.tickytacky.mirrormirror_2.apk'))
            self.assertFalse(fdroidserver.common.verify_apk_signature('org.bitbucket.tickytacky.mirrormirror_3.apk'))
            self.assertFalse(fdroidserver.common.verify_apk_signature('org.bitbucket.tickytacky.mirrormirror_4.apk'))
        self.assertTrue(fdroidserver.common.verify_apk_signature('org.dyndns.fules.ck_20.apk'))
        self.assertTrue(fdroidserver.common.verify_apk_signature('urzip.apk'))
        self.assertFalse(fdroidserver.common.verify_apk_signature('urzip-badcert.apk'))
        self.assertFalse(fdroidserver.common.verify_apk_signature('urzip-badsig.apk'))
        self.assertTrue(fdroidserver.common.verify_apk_signature('urzip-release.apk'))
        self.assertFalse(fdroidserver.common.verify_apk_signature('urzip-release-unsigned.apk'))

    def test_verify_old_apk_signature(self):
        _mock_common_module_options_instance()
        config = fdroidserver.common.read_config()
        config['jarsigner'] = fdroidserver.common.find_sdk_tools_cmd('jarsigner')
        fdroidserver.common.config = config

        try:
            fdroidserver.common.verify_deprecated_jar_signature('bad-unicode-πÇÇ现代通用字-български-عربي1.apk')
            fdroidserver.common.verify_deprecated_jar_signature('org.bitbucket.tickytacky.mirrormirror_1.apk')
            fdroidserver.common.verify_deprecated_jar_signature('org.bitbucket.tickytacky.mirrormirror_2.apk')
            fdroidserver.common.verify_deprecated_jar_signature('org.bitbucket.tickytacky.mirrormirror_3.apk')
            fdroidserver.common.verify_deprecated_jar_signature('org.bitbucket.tickytacky.mirrormirror_4.apk')
            fdroidserver.common.verify_deprecated_jar_signature('org.dyndns.fules.ck_20.apk')
            fdroidserver.common.verify_deprecated_jar_signature('urzip.apk')
            fdroidserver.common.verify_deprecated_jar_signature('urzip-release.apk')
        except VerificationException:
            self.fail("failed to jarsigner failed to verify an old apk")
        self.assertRaises(VerificationException, fdroidserver.common.verify_deprecated_jar_signature, 'urzip-badcert.apk')
        self.assertRaises(VerificationException, fdroidserver.common.verify_deprecated_jar_signature, 'urzip-badsig.apk')
        self.assertRaises(VerificationException, fdroidserver.common.verify_deprecated_jar_signature, 'urzip-release-unsigned.apk')

    def test_verify_jar_signature(self):
        """Sign entry.jar and make sure it validates"""
        config = fdroidserver.common.read_config()
        config['jarsigner'] = fdroidserver.common.find_sdk_tools_cmd('jarsigner')
        config['keystore'] = os.path.join(basedir, 'keystore.jks')
        config['repo_keyalias'] = 'sova'
        config['keystorepass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        config['keypass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        fdroidserver.common.config = config
        fdroidserver.signindex.config = config
        repo_dir = Path(self.testdir) / 'repo'
        repo_dir.mkdir()
        shutil.copy('repo/entry.json', repo_dir)
        shutil.copy('repo/index-v2.json', repo_dir)
        os.chdir(self.testdir)
        fdroidserver.signindex.sign_index('repo', 'entry.json')
        fdroidserver.common.verify_jar_signature('repo/entry.jar')

    def test_verify_jar_signature_fails(self):
        """Test verify_jar_signature fails on unsigned and deprecated algorithms"""
        config = fdroidserver.common.read_config()
        config['jarsigner'] = fdroidserver.common.find_sdk_tools_cmd('jarsigner')
        fdroidserver.common.config = config
        source_dir = os.path.join(basedir, 'signindex')
        for f in ('unsigned.jar', 'testy.jar', 'guardianproject.jar', 'guardianproject-v1.jar'):
            testfile = os.path.join(source_dir, f)
            with self.assertRaises(fdroidserver.index.VerificationException):
                fdroidserver.common.verify_jar_signature(testfile)

    def test_verify_deprecated_jar_signature(self):
        config = fdroidserver.common.read_config()
        config['jarsigner'] = fdroidserver.common.find_sdk_tools_cmd('jarsigner')
        fdroidserver.common.config = config
        source_dir = os.path.join(basedir, 'signindex')
        for f in ('testy.jar', 'guardianproject.jar'):
            testfile = os.path.join(source_dir, f)
            fdroidserver.common.verify_deprecated_jar_signature(testfile)

        testfile = os.path.join(source_dir, 'unsigned.jar')
        with self.assertRaises(fdroidserver.index.VerificationException):
            fdroidserver.common.verify_deprecated_jar_signature(testfile)

    def test_verify_apks(self):
        config = fdroidserver.common.read_config()
        fdroidserver.common.config = config
        _mock_common_module_options_instance()

        sourceapk = os.path.join(basedir, 'urzip.apk')

        copyapk = os.path.join(self.testdir, 'urzip-copy.apk')
        shutil.copy(sourceapk, copyapk)
        self.assertTrue(fdroidserver.common.verify_apk_signature(copyapk))
        self.assertIsNone(
            fdroidserver.common.verify_apks(sourceapk, copyapk, self.tmpdir)
        )

        unsignedapk = os.path.join(self.testdir, 'urzip-unsigned.apk')
        with ZipFile(sourceapk, 'r') as apk:
            with ZipFile(unsignedapk, 'w') as testapk:
                for info in apk.infolist():
                    if not info.filename.startswith('META-INF/'):
                        testapk.writestr(info, apk.read(info.filename))
        self.assertIsNone(
            fdroidserver.common.verify_apks(sourceapk, unsignedapk, self.tmpdir)
        )

        twosigapk = os.path.join(self.testdir, 'urzip-twosig.apk')
        otherapk = ZipFile(os.path.join(basedir, 'urzip-release.apk'), 'r')
        with ZipFile(sourceapk, 'r') as apk:
            with ZipFile(twosigapk, 'w') as testapk:
                for info in apk.infolist():
                    testapk.writestr(info, apk.read(info.filename))
                    if info.filename.startswith('META-INF/'):
                        testapk.writestr(info.filename, otherapk.read(info.filename))
        otherapk.close()
        self.assertFalse(fdroidserver.common.verify_apk_signature(twosigapk))
        self.assertIsNone(fdroidserver.common.verify_apks(sourceapk, twosigapk, self.tmpdir))

    def test_get_certificate_with_chain_sandisk(self):
        """Test that APK signatures with a cert chain are parsed like apksigner.

        SanDisk signs their APKs with a X.509 certificate chain of
        trust, so there are actually three certificates
        included. apksigner only cares about the certificate in the
        chain that actually signs the manifest.

        The correct value comes from:
        apksigner verify --print-certs 883cbdae7aeb2e4b122e8ee8d89966c7062d0d49107a130235fa220a5b994a79.apk

        """
        cert = fdroidserver.common.get_certificate(
            signature_block_file=Path('SANAPPSI.RSA').read_bytes(),
            signature_file=Path('SANAPPSI.SF').read_bytes(),
        )
        self.assertEqual(
            'ea0abbf2a142e4b167405d516b2cc408c4af4b29cd50ba281aa4470d4aab3e53',
            fdroidserver.common.signer_fingerprint(cert),
        )

    def test_write_to_config(self):
        with tempfile.TemporaryDirectory() as tmpPath:
            cfgPath = os.path.join(tmpPath, 'config.py')
            with open(cfgPath, 'w') as f:
                f.write(
                    textwrap.dedent(
                        """\
                    # abc
                    # test = 'example value'
                    default_me= '%%%'

                    # comment
                    do_not_touch = "good value"
                    default_me="!!!"

                    key="123"    # inline"""
                    )
                )

            cfg = {'key': '111', 'default_me_orig': 'orig'}
            fdroidserver.common.write_to_config(cfg, 'key', config_file=cfgPath)
            fdroidserver.common.write_to_config(cfg, 'default_me', config_file=cfgPath)
            fdroidserver.common.write_to_config(cfg, 'test', value='test value', config_file=cfgPath)
            fdroidserver.common.write_to_config(cfg, 'new_key', value='new', config_file=cfgPath)

            with open(cfgPath, 'r') as f:
                self.assertEqual(
                    f.read(),
                    textwrap.dedent(
                        """\
                    # abc
                    test = 'test value'
                    default_me = 'orig'

                    # comment
                    do_not_touch = "good value"

                    key = "111"    # inline

                    new_key = "new"
                    """
                    ),
                )

    def test_write_to_config_when_empty(self):
        with tempfile.TemporaryDirectory() as tmpPath:
            cfgPath = os.path.join(tmpPath, 'config.py')
            with open(cfgPath, 'w') as f:
                pass
            fdroidserver.common.write_to_config({}, 'key', 'val', cfgPath)
            with open(cfgPath, 'r') as f:
                self.assertEqual(
                    f.read(),
                    textwrap.dedent(
                        """\

                key = "val"
                """
                    ),
                )

    def test_apk_name_regex(self):
        good = [
            'urzipπÇÇπÇÇ现代汉语通用字българскиعربي1234ö_-123456.apk',
            'urzipπÇÇπÇÇ现代汉语通用字българскиعربي1234ö_123456_abcdef0.apk',
            'urzip_-123456.apk',
            'a0_0.apk',
            'Z0_0.apk',
            'a0_0_abcdef0.apk',
            'a_a_a_a_0_abcdef0.apk',
            'a_____0.apk',
            'a_____123456_abcdef0.apk',
            'org.fdroid.fdroid_123456.apk',
            # valid, but "_99999" is part of packageName rather than versionCode
            'org.fdroid.fdroid_99999_123456.apk',
            # should be valid, but I can't figure out the regex since \w includes digits
            # 'πÇÇπÇÇ现代汉语通用字българскиعربي1234ö_0_123bafd.apk',
        ]
        for name in good:
            m = fdroidserver.common.APK_NAME_REGEX.match(name)
            self.assertIsNotNone(m)
            self.assertIn(m.group(2), ('-123456', '0', '123456'))
            self.assertIn(m.group(3), ('abcdef0', None))

        bad = [
            'urzipπÇÇπÇÇ现代汉语通用字българскиعربي1234ö_123456_abcdefg.apk',
            'urzip-_-198274.apk',
            'urzip-_0_123bafd.apk',
            'no spaces allowed_123.apk',
            '0_0.apk',
            '0_0_abcdef0.apk',
        ]
        for name in bad:
            self.assertIsNone(fdroidserver.common.APK_NAME_REGEX.match(name))

    def test_standard_file_name_regex(self):
        good = [
            'urzipπÇÇπÇÇ现代汉语通用字българскиعربي1234ö_-123456.mp3',
            'urzipπÇÇπÇÇ现代汉语通用字българскиعربي1234ö_123456.mov',
            'Document_-123456.pdf',
            'WTF_0.MOV',
            'Z0_0.ebk',
            'a_a_a_a_0.txt',
            'org.fdroid.fdroid.privileged.ota_123456.zip',
            'πÇÇπÇÇ现代汉语通用字българскиعربي1234ö_0.jpeg',
            'a_____0.PNG',
            # valid, but "_99999" is part of packageName rather than versionCode
            'a_____99999_123456.zip',
            'org.fdroid.fdroid_99999_123456.zip',
        ]
        for name in good:
            m = fdroidserver.common.STANDARD_FILE_NAME_REGEX.match(name)
            self.assertIsNotNone(m)
            self.assertIn(m.group(2), ('-123456', '0', '123456'))

        bad = [
            'urzipπÇÇπÇÇ现代汉语通用字българскиعربي1234ö_abcdefg.JPEG',
            'urzip-_-198274.zip',
            'urzip-_123bafd.pdf',
            'no spaces allowed_123.foobar',
            'a_____0.',
        ]
        for name in bad:
            self.assertIsNone(fdroidserver.common.STANDARD_FILE_NAME_REGEX.match(name))

    def test_apk_signer_fingerprint(self):

        # fingerprints fetched with: keytool -printcert -file ____.RSA
        testapks = (('repo/obb.main.oldversion_1444412523.apk',
                     '818e469465f96b704e27be2fee4c63ab9f83ddf30e7a34c7371a4728d83b0bc1'),
                    ('repo/obb.main.twoversions_1101613.apk',
                     '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6'),
                    ('repo/obb.main.twoversions_1101617.apk',
                     '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6'))

        for apkfile, keytoolcertfingerprint in testapks:
            self.assertEqual(keytoolcertfingerprint,
                             fdroidserver.common.apk_signer_fingerprint(apkfile))

    def test_apk_signer_fingerprint_short(self):

        # fingerprints fetched with: keytool -printcert -file ____.RSA
        testapks = (('repo/obb.main.oldversion_1444412523.apk', '818e469'),
                    ('repo/obb.main.twoversions_1101613.apk', '32a2362'),
                    ('repo/obb.main.twoversions_1101617.apk', '32a2362'))

        for apkfile, keytoolcertfingerprint in testapks:
            self.assertEqual(keytoolcertfingerprint,
                             fdroidserver.common.apk_signer_fingerprint_short(apkfile))

    def test_find_apksigner_system_package_default_path(self):
        """apksigner should be automatically used from the PATH"""
        usr_bin_apksigner = '/usr/bin/apksigner'
        if not os.path.isfile(usr_bin_apksigner):
            self.skipTest('SKIPPING since %s is not installed!' % usr_bin_apksigner)
        with mock.patch.dict(os.environ, clear=True):
            os.environ['PATH'] = '/usr/local/bin:/usr/bin:/bin'
            config = {}
            fdroidserver.common.find_apksigner(config)
            self.assertEqual(usr_bin_apksigner, config.get('apksigner'))

    def test_find_apksigner_config_overrides(self):
        """apksigner should come from config before any auto-detection"""
        os.chdir(self.tmpdir)
        android_home = os.path.join(self.tmpdir, 'ANDROID_HOME')
        do_not_use = os.path.join(android_home, 'build-tools', '30.0.3', 'apksigner')
        os.makedirs(os.path.dirname(do_not_use))
        with open(do_not_use, 'w') as fp:
            fp.write('#!/bin/sh\ndate\n')
        os.chmod(do_not_use, 0o0755)  # nosec B103
        apksigner = os.path.join(self.tmpdir, 'apksigner')
        config = {'apksigner': apksigner}
        with mock.patch.dict(os.environ, clear=True):
            os.environ['ANDROID_HOME'] = android_home
            os.environ['PATH'] = '%s:/usr/local/bin:/usr/bin:/bin' % android_home
            fdroidserver.common.find_apksigner(config)
            self.assertEqual(apksigner, config.get('apksigner'))

    def test_find_apksigner_prefer_path(self):
        """apksigner should come from PATH before ANDROID_HOME"""
        os.chdir(self.tmpdir)
        apksigner = os.path.join(self.tmpdir, 'apksigner')
        with open(apksigner, 'w') as fp:
            fp.write('#!/bin/sh\ndate\n')
        os.chmod(apksigner, 0o0755)  # nosec B103

        android_home = os.path.join(self.tmpdir, 'ANDROID_HOME')
        do_not_use = os.path.join(android_home, 'build-tools', '30.0.3', 'apksigner')
        os.makedirs(os.path.dirname(do_not_use))
        with open(do_not_use, 'w') as fp:
            fp.write('#!/bin/sh\ndate\n')
        os.chmod(do_not_use, 0o0755)  # nosec B103

        config = {'sdk_path': android_home}
        with mock.patch.dict(os.environ, clear=True):
            os.environ['ANDROID_HOME'] = android_home
            os.environ['PATH'] = '%s:/usr/local/bin:/usr/bin:/bin' % os.path.dirname(apksigner)
            fdroidserver.common.find_apksigner(config)
            self.assertEqual(apksigner, config.get('apksigner'))

    def test_find_apksigner_prefer_newest(self):
        """apksigner should be the newest available in ANDROID_HOME"""
        os.chdir(self.tmpdir)
        android_home = os.path.join(self.tmpdir, 'ANDROID_HOME')

        apksigner = os.path.join(android_home, 'build-tools', '30.0.3', 'apksigner')
        os.makedirs(os.path.dirname(apksigner))
        with open(apksigner, 'w') as fp:
            fp.write('#!/bin/sh\necho 30.0.3\n')
        os.chmod(apksigner, 0o0755)  # nosec B103

        do_not_use = os.path.join(android_home, 'build-tools', '29.0.3', 'apksigner')
        os.makedirs(os.path.dirname(do_not_use))
        with open(do_not_use, 'w') as fp:
            fp.write('#!/bin/sh\necho 29.0.3\n')
        os.chmod(do_not_use, 0o0755)  # nosec B103

        config = {'sdk_path': android_home}
        with mock.patch.dict(os.environ, clear=True):
            os.environ['PATH'] = '/fake/path/to/avoid/conflicts'
            fdroidserver.common.find_apksigner(config)
            self.assertEqual(apksigner, config.get('apksigner'))

    def test_find_apksigner_system_package_android_home(self):
        """Test that apksigner v30 or newer is found"""
        os.chdir(self.tmpdir)
        android_home = os.getenv('ANDROID_HOME')
        if not android_home or not os.path.isdir(android_home):
            self.skipTest('SKIPPING since ANDROID_HOME (%s) is not a dir!' % android_home)
        build_tools = glob.glob(os.path.join(android_home, 'build-tools', '*', 'apksigner'))
        if not build_tools:
            self.skipTest('SKIPPING since ANDROID_HOME (%s) build-tools has no apksigner!' % android_home)
        min_version = fdroidserver.common.MINIMUM_APKSIGNER_BUILD_TOOLS_VERSION
        version = '0'
        for bt in sorted(build_tools):
            v = bt.split('/')[-2]
            if v == 'debian':
                continue
            if LooseVersion(version) < LooseVersion(v):
                version = v
        if LooseVersion(version) < LooseVersion(min_version):
            self.skipTest('SKIPPING since build-tools %s or higher is required!' % min_version)
        fdroidserver.common.config = {'sdk_path': android_home}
        with mock.patch.dict(os.environ, clear=True):
            os.environ['PATH'] = '/fake/path/to/avoid/conflicts'
            config = fdroidserver.common.read_config()
            fdroidserver.common.find_apksigner(config)
            self.assertEqual(
                os.path.join(android_home, 'build-tools'),
                os.path.dirname(os.path.dirname(config.get('apksigner'))),
            )

    def test_sign_apk(self):
        _mock_common_module_options_instance()
        config = fdroidserver.common.read_config()
        if 'apksigner' not in config:
            self.skipTest('SKIPPING test_sign_apk, apksigner not installed!')

        config['keyalias'] = 'sova'
        config['keystorepass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        config['keypass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        config['keystore'] = os.path.join(basedir, 'keystore.jks')
        fdroidserver.common.config = config
        fdroidserver.signindex.config = config

        unsigned = os.path.join(self.testdir, 'urzip-release-unsigned.apk')
        signed = os.path.join(self.testdir, 'urzip-release.apk')
        shutil.copy(os.path.join(basedir, 'urzip-release-unsigned.apk'), self.testdir)

        self.assertFalse(fdroidserver.common.verify_apk_signature(unsigned))

        fdroidserver.common.sign_apk(unsigned, signed, config['keyalias'])
        self.assertTrue(os.path.isfile(signed))
        self.assertFalse(os.path.isfile(unsigned))
        self.assertTrue(fdroidserver.common.verify_apk_signature(signed))

        # now sign an APK with minSdkVersion >= 18
        unsigned = os.path.join(self.testdir, 'duplicate.permisssions_9999999-unsigned.apk')
        signed = os.path.join(self.testdir, 'duplicate.permisssions_9999999.apk')
        shutil.copy(
            os.path.join(basedir, 'repo', 'duplicate.permisssions_9999999.apk'),
            os.path.join(unsigned),
        )
        fdroidserver.common.apk_strip_v1_signatures(unsigned, strip_manifest=True)
        fdroidserver.common.sign_apk(unsigned, signed, config['keyalias'])
        self.assertTrue(os.path.isfile(signed))
        self.assertFalse(os.path.isfile(unsigned))
        self.assertTrue(fdroidserver.common.verify_apk_signature(signed))
        self.assertEqual('18', fdroidserver.common.get_androguard_APK(signed).get_min_sdk_version())

        shutil.copy(os.path.join(basedir, 'minimal_targetsdk_30_unsigned.apk'), self.testdir)
        unsigned = os.path.join(self.testdir, 'minimal_targetsdk_30_unsigned.apk')
        signed = os.path.join(self.testdir, 'minimal_targetsdk_30.apk')

        self.assertFalse(fdroidserver.common.verify_apk_signature(unsigned))
        fdroidserver.common.sign_apk(unsigned, signed, config['keyalias'])

        self.assertTrue(os.path.isfile(signed))
        self.assertFalse(os.path.isfile(unsigned))
        self.assertTrue(fdroidserver.common.verify_apk_signature(signed))
        # verify it has a v2 signature
        self.assertTrue(fdroidserver.common.get_androguard_APK(signed).is_signed_v2())

        shutil.copy(os.path.join(basedir, 'no_targetsdk_minsdk30_unsigned.apk'), self.testdir)
        unsigned = os.path.join(self.testdir, 'no_targetsdk_minsdk30_unsigned.apk')
        signed = os.path.join(self.testdir, 'no_targetsdk_minsdk30_signed.apk')

        fdroidserver.common.sign_apk(unsigned, signed, config['keyalias'])
        self.assertTrue(fdroidserver.common.verify_apk_signature(signed))
        self.assertTrue(fdroidserver.common.get_androguard_APK(signed).is_signed_v2())

        shutil.copy(os.path.join(basedir, 'no_targetsdk_minsdk1_unsigned.apk'), self.testdir)
        unsigned = os.path.join(self.testdir, 'no_targetsdk_minsdk1_unsigned.apk')
        signed = os.path.join(self.testdir, 'no_targetsdk_minsdk1_signed.apk')

        self.assertFalse(fdroidserver.common.verify_apk_signature(unsigned))
        fdroidserver.common.sign_apk(unsigned, signed, config['keyalias'])

        self.assertTrue(os.path.isfile(signed))
        self.assertFalse(os.path.isfile(unsigned))
        self.assertTrue(fdroidserver.common.verify_apk_signature(signed))

    @unittest.skipIf(os.getuid() == 0, 'This is meaningless when run as root')
    def test_sign_apk_fail(self):
        _mock_common_module_options_instance()
        config = fdroidserver.common.read_config()
        if 'apksigner' not in config:
            self.skipTest('SKIPPING test_sign_apk_fail, apksigner not installed!')

        config['keyalias'] = 'sova'
        config['keystorepass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        config['keypass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        config['keystore'] = os.path.join(basedir, 'keystore.jks')
        fdroidserver.common.config = config
        fdroidserver.signindex.config = config

        unsigned = os.path.join(self.testdir, 'urzip-release-unsigned.apk')
        signed = os.path.join(self.testdir, 'urzip-release.apk')
        shutil.copy(os.path.join(basedir, 'urzip-release-unsigned.apk'), self.testdir)

        os.chmod(unsigned, 0o000)
        with self.assertRaises(fdroidserver.exception.BuildException):
            fdroidserver.common.sign_apk(unsigned, signed, config['keyalias'])
        os.chmod(unsigned, 0o777)  # nosec B103
        self.assertTrue(os.path.isfile(unsigned))
        self.assertFalse(os.path.isfile(signed))

    def test_sign_apk_corrupt(self):
        _mock_common_module_options_instance()
        config = fdroidserver.common.read_config()
        if 'apksigner' not in config:
            self.skipTest('SKIPPING test_sign_apk_corrupt, apksigner not installed!')

        config['keyalias'] = 'sova'
        config['keystorepass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        config['keypass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        config['keystore'] = os.path.join(basedir, 'keystore.jks')
        fdroidserver.common.config = config
        fdroidserver.signindex.config = config

        unsigned = os.path.join(self.testdir, 'urzip-release-unsigned.apk')
        signed = os.path.join(self.testdir, 'urzip-release.apk')
        with open(unsigned, 'w') as fp:
            fp.write('this is a corrupt APK')

        with self.assertRaises(fdroidserver.exception.BuildException):
            fdroidserver.common.sign_apk(unsigned, signed, config['keyalias'])
        self.assertTrue(os.path.isfile(unsigned))
        self.assertFalse(os.path.isfile(signed))

    @unittest.skipUnless(
        os.path.exists('tests/SystemWebView-repack.apk'), "file too big for sdist"
    )
    def test_resign_apk(self):
        """When using apksigner, it should resign signed APKs"""
        _mock_common_module_options_instance()
        config = fdroidserver.common.read_config()
        if 'apksigner' not in config:
            self.skipTest('SKIPPING test_resign_apk, apksigner not installed!')

        config['keyalias'] = 'sova'
        config['keystorepass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        config['keypass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        config['keystore'] = os.path.join(basedir, 'keystore.jks')
        fdroidserver.common.config = config
        fdroidserver.signindex.config = config

        os.chdir(self.tmpdir)
        os.mkdir('unsigned')
        os.mkdir('repo')

        for apk in (
            'org.bitbucket.tickytacky.mirrormirror_4.apk',
            'v2.only.sig_2.apk',
            'SystemWebView-repack.apk',
        ):
            original = os.path.join(basedir, apk)
            unsigned = os.path.join('unsigned', apk)
            resign = os.path.join('repo', apk)
            shutil.copy(original, unsigned)
            fdroidserver.common.sign_apk(unsigned, resign, config['keyalias'])
            self.assertTrue(
                fdroidserver.common.verify_apk_signature(resign), apk + " verifies"
            )
            self.assertTrue(os.path.isfile(resign))
            self.assertFalse(os.path.isfile(unsigned))
            self.assertNotEqual(
                fdroidserver.common.get_first_signer_certificate(original),
                fdroidserver.common.get_first_signer_certificate(resign)
            )

    def test_get_apk_id(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        self._set_build_tools()
        try:
            config['aapt'] = fdroidserver.common.find_sdk_tools_cmd('aapt')
        except fdroidserver.exception.FDroidException:
            pass  # aapt is not required if androguard is present

        testcases = [
            ('repo/obb.main.twoversions_1101613.apk', 'obb.main.twoversions', 1101613, '0.1'),
            ('org.bitbucket.tickytacky.mirrormirror_1.apk', 'org.bitbucket.tickytacky.mirrormirror', 1, '1.0'),
            ('org.bitbucket.tickytacky.mirrormirror_2.apk', 'org.bitbucket.tickytacky.mirrormirror', 2, '1.0.1'),
            ('org.bitbucket.tickytacky.mirrormirror_3.apk', 'org.bitbucket.tickytacky.mirrormirror', 3, '1.0.2'),
            ('org.bitbucket.tickytacky.mirrormirror_4.apk', 'org.bitbucket.tickytacky.mirrormirror', 4, '1.0.3'),
            ('org.dyndns.fules.ck_20.apk', 'org.dyndns.fules.ck', 20, 'v1.6pre2'),
            ('issue-1128-min-sdk-30-poc.apk', 'org.fdroid.ci', 1, '1.0'),
            ('issue-1128-poc1.apk', 'android.appsecurity.cts.tinyapp', 10, '1.0'),
            ('issue-1128-poc2.apk', 'android.appsecurity.cts.tinyapp', 10, '1.0'),
            ('issue-1128-poc3a.apk', 'android.appsecurity.cts.tinyapp', 10, '1.0'),
            ('issue-1128-poc3b.apk', 'android.appsecurity.cts.tinyapp', 10, '1.0'),
            ('urzip.apk', 'info.guardianproject.urzip', 100, '0.1'),
            ('urzip-badcert.apk', 'info.guardianproject.urzip', 100, '0.1'),
            ('urzip-badsig.apk', 'info.guardianproject.urzip', 100, '0.1'),
            ('urzip-release.apk', 'info.guardianproject.urzip', 100, '0.1'),
            ('urzip-release-unsigned.apk', 'info.guardianproject.urzip', 100, '0.1'),
            ('repo/com.politedroid_3.apk', 'com.politedroid', 3, '1.2'),
            ('repo/com.politedroid_4.apk', 'com.politedroid', 4, '1.3'),
            ('repo/com.politedroid_5.apk', 'com.politedroid', 5, '1.4'),
            ('repo/com.politedroid_6.apk', 'com.politedroid', 6, '1.5'),
            ('repo/duplicate.permisssions_9999999.apk', 'duplicate.permisssions', 9999999, ''),
            ('repo/info.zwanenburg.caffeinetile_4.apk', 'info.zwanenburg.caffeinetile', 4, '1.3'),
            ('repo/obb.main.oldversion_1444412523.apk', 'obb.main.oldversion', 1444412523, '0.1'),
            ('repo/obb.mainpatch.current_1619_another-release-key.apk', 'obb.mainpatch.current', 1619, '0.1'),
            ('repo/obb.mainpatch.current_1619.apk', 'obb.mainpatch.current', 1619, '0.1'),
            ('repo/obb.main.twoversions_1101613.apk', 'obb.main.twoversions', 1101613, '0.1'),
            ('repo/obb.main.twoversions_1101615.apk', 'obb.main.twoversions', 1101615, '0.1'),
            ('repo/obb.main.twoversions_1101617.apk', 'obb.main.twoversions', 1101617, '0.1'),
            ('repo/urzip-; Рахма́, [rɐxˈmanʲɪnəf] سيرجي_رخمانينوف 谢·.apk', 'info.guardianproject.urzip', 100, '0.1'),
        ]
        for apkfilename, appid, versionCode, versionName in testcases:
            a, vc, vn = fdroidserver.common.get_apk_id(apkfilename)
            self.assertEqual(appid, a, 'androguard appid parsing failed for ' + apkfilename)
            self.assertEqual(versionName, vn, 'androguard versionName parsing failed for ' + apkfilename)
            self.assertEqual(versionCode, vc, 'androguard versionCode parsing failed for ' + apkfilename)
            if 'aapt' in config:
                a, vc, vn = fdroidserver.common.get_apk_id_aapt(apkfilename)
                self.assertEqual(appid, a, 'aapt appid parsing failed for ' + apkfilename)
                self.assertEqual(versionCode, vc, 'aapt versionCode parsing failed for ' + apkfilename)
                self.assertEqual(versionName, vn, 'aapt versionName parsing failed for ' + apkfilename)

    def test_get_apk_id_bad_apk(self):
        """get_apk_id should never return None on error, only raise exceptions"""
        with self.assertRaises(KeyError):
            fdroidserver.common.get_apk_id('Norway_bouvet_europe_2.obf.zip')
        shutil.copy('Norway_bouvet_europe_2.obf.zip', self.tmpdir)
        os.chdir(self.tmpdir)
        with ZipFile('Norway_bouvet_europe_2.obf.zip', 'a') as zipfp:
            zipfp.writestr('AndroidManifest.xml', 'not a manifest')
        with self.assertRaises(KeyError):
            fdroidserver.common.get_apk_id('Norway_bouvet_europe_2.obf.zip')

    def test_get_apk_id_bad_path(self):
        with self.assertRaises(FDroidException):
            fdroidserver.common.get_apk_id('nope')

    def test_get_apk_id_api_call(self):
        self.assertEqual(
            ('info.guardianproject.urzip', 100, '0.1'),
            fdroidserver.common.get_apk_id('urzip.apk'),
        )

    def test_get_apk_id_bad_zip(self):
        os.chdir(self.tmpdir)
        badzip = 'badzip.apk'
        with open(badzip, 'w') as fp:
            fp.write('not a ZIP')
        with self.assertRaises(BadZipFile):
            fdroidserver.common.get_apk_id(badzip)

    def test_get_apk_id_aapt_regex(self):
        files = glob.glob(os.path.join(basedir, 'build-tools', '[1-9]*.*', '*.txt'))
        self.assertNotEqual(0, len(files))
        for f in files:
            appid, versionCode = os.path.splitext(os.path.basename(f))[0][12:].split('_')
            with open(f, encoding='utf-8') as fp:
                m = fdroidserver.common.APK_ID_TRIPLET_REGEX.match(fp.read())
                if m:
                    self.assertEqual(appid, m.group(1))
                    self.assertEqual(versionCode, m.group(2))
                else:
                    self.fail('could not parse aapt output: {}'.format(f))

    def test_get_native_code(self):
        testcases = [
            ('repo/obb.main.twoversions_1101613.apk', []),
            ('org.bitbucket.tickytacky.mirrormirror_1.apk', []),
            ('org.bitbucket.tickytacky.mirrormirror_2.apk', []),
            ('org.bitbucket.tickytacky.mirrormirror_3.apk', []),
            ('org.bitbucket.tickytacky.mirrormirror_4.apk', []),
            ('org.dyndns.fules.ck_20.apk', ['arm64-v8a', 'armeabi', 'armeabi-v7a', 'mips', 'mips64', 'x86', 'x86_64']),
            ('urzip.apk', []),
            ('urzip-badcert.apk', []),
            ('urzip-badsig.apk', []),
            ('urzip-release.apk', []),
            ('urzip-release-unsigned.apk', []),
            ('repo/com.politedroid_3.apk', []),
            ('repo/com.politedroid_4.apk', []),
            ('repo/com.politedroid_5.apk', []),
            ('repo/com.politedroid_6.apk', []),
            ('repo/duplicate.permisssions_9999999.apk', []),
            ('repo/info.zwanenburg.caffeinetile_4.apk', []),
            ('repo/obb.main.oldversion_1444412523.apk', []),
            ('repo/obb.mainpatch.current_1619_another-release-key.apk', []),
            ('repo/obb.mainpatch.current_1619.apk', []),
            ('repo/obb.main.twoversions_1101613.apk', []),
            ('repo/obb.main.twoversions_1101615.apk', []),
            ('repo/obb.main.twoversions_1101617.apk', []),
            ('repo/urzip-; Рахма́, [rɐxˈmanʲɪnəf] سيرجي_رخمانينوف 谢·.apk', []),
        ]
        for apkfilename, native_code in testcases:
            nc = fdroidserver.common.get_native_code(apkfilename)
            self.assertEqual(native_code, nc)

    def test_get_sdkversions_androguard(self):
        """This is a sanity test that androguard isn't broken"""

        def get_minSdkVersion(apkfile):
            apk = fdroidserver.common.get_androguard_APK(apkfile)
            return fdroidserver.common.get_min_sdk_version(apk)

        def get_targetSdkVersion(apkfile):
            apk = fdroidserver.common.get_androguard_APK(apkfile)
            return apk.get_effective_target_sdk_version()

        self.assertEqual(4, get_minSdkVersion('bad-unicode-πÇÇ现代通用字-български-عربي1.apk'))
        self.assertEqual(30, get_minSdkVersion('issue-1128-min-sdk-30-poc.apk'))
        self.assertEqual(29, get_minSdkVersion('issue-1128-poc1.apk'))
        self.assertEqual(29, get_minSdkVersion('issue-1128-poc2.apk'))
        self.assertEqual(23, get_minSdkVersion('issue-1128-poc3a.apk'))
        self.assertEqual(23, get_minSdkVersion('issue-1128-poc3b.apk'))
        self.assertEqual(14, get_minSdkVersion('org.bitbucket.tickytacky.mirrormirror_1.apk'))
        self.assertEqual(14, get_minSdkVersion('org.bitbucket.tickytacky.mirrormirror_2.apk'))
        self.assertEqual(14, get_minSdkVersion('org.bitbucket.tickytacky.mirrormirror_3.apk'))
        self.assertEqual(14, get_minSdkVersion('org.bitbucket.tickytacky.mirrormirror_4.apk'))
        self.assertEqual(7, get_minSdkVersion('org.dyndns.fules.ck_20.apk'))
        self.assertEqual(4, get_minSdkVersion('urzip.apk'))
        self.assertEqual(4, get_minSdkVersion('urzip-badcert.apk'))
        self.assertEqual(4, get_minSdkVersion('urzip-badsig.apk'))
        self.assertEqual(4, get_minSdkVersion('urzip-release.apk'))
        self.assertEqual(4, get_minSdkVersion('urzip-release-unsigned.apk'))
        self.assertEqual(27, get_minSdkVersion('v2.only.sig_2.apk'))
        self.assertEqual(3, get_minSdkVersion('repo/com.politedroid_3.apk'))
        self.assertEqual(3, get_minSdkVersion('repo/com.politedroid_4.apk'))
        self.assertEqual(3, get_minSdkVersion('repo/com.politedroid_5.apk'))
        self.assertEqual(14, get_minSdkVersion('repo/com.politedroid_6.apk'))
        self.assertEqual(4, get_minSdkVersion('repo/obb.main.oldversion_1444412523.apk'))
        self.assertEqual(4, get_minSdkVersion('repo/obb.mainpatch.current_1619_another-release-key.apk'))
        self.assertEqual(4, get_minSdkVersion('repo/obb.mainpatch.current_1619.apk'))
        self.assertEqual(4, get_minSdkVersion('repo/obb.main.twoversions_1101613.apk'))
        self.assertEqual(4, get_minSdkVersion('repo/obb.main.twoversions_1101615.apk'))
        self.assertEqual(4, get_minSdkVersion('repo/obb.main.twoversions_1101617.apk'))
        self.assertEqual(4, get_minSdkVersion('repo/urzip-; Рахма́, [rɐxˈmanʲɪnəf] سيرجي_رخمانينوف 谢·.apk'))

        self.assertEqual(30, get_targetSdkVersion('minimal_targetsdk_30_unsigned.apk'))
        self.assertEqual(1, get_targetSdkVersion('no_targetsdk_minsdk1_unsigned.apk'))
        self.assertEqual(30, get_targetSdkVersion('no_targetsdk_minsdk30_unsigned.apk'))

    def test_apk_release_name(self):
        appid, vercode, sigfp = fdroidserver.common.apk_parse_release_filename('com.serwylo.lexica_905.apk')
        self.assertEqual(appid, 'com.serwylo.lexica')
        self.assertEqual(vercode, 905)
        self.assertEqual(sigfp, None)

        appid, vercode, sigfp = fdroidserver.common.apk_parse_release_filename('com.serwylo.lexica_905_c82e0f6.apk')
        self.assertEqual(appid, 'com.serwylo.lexica')
        self.assertEqual(vercode, 905)
        self.assertEqual(sigfp, 'c82e0f6')

        appid, vercode, sigfp = fdroidserver.common.apk_parse_release_filename('beverly_hills-90210.apk')
        self.assertEqual(appid, None)
        self.assertEqual(vercode, None)
        self.assertEqual(sigfp, None)

    def test_metadata_find_developer_signature(self):
        sig = fdroidserver.common.metadata_find_developer_signature('org.smssecure.smssecure')
        self.assertEqual('b30bb971af0d134866e158ec748fcd553df97c150f58b0a963190bbafbeb0868', sig)

    def test_parse_xml(self):
        manifest = Path('source-files/fdroid/fdroidclient/AndroidManifest.xml')
        parsed = fdroidserver.common.parse_xml(manifest)
        self.assertIsNotNone(parsed)
        self.assertEqual(str(type(parsed)), "<class 'xml.etree.ElementTree.Element'>")

    def test_parse_androidmanifests(self):
        app = fdroidserver.metadata.App()
        app.id = 'org.fdroid.fdroid'
        paths = [
            Path('source-files/fdroid/fdroidclient/AndroidManifest.xml'),
            Path('source-files/fdroid/fdroidclient/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('0.94-test', 940, 'org.fdroid.fdroid'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        app.AutoName = 'android-chat'
        app.RepoType = 'git'
        url = 'https://github.com/wildfirechat/android-chat.git'
        app.SourceCode = url.rstrip('.git')
        app.Repo = url
        paths = [
            Path('source-files/cn.wildfirechat.chat/avenginekit/build.gradle'),
            Path('source-files/cn.wildfirechat.chat/build.gradle'),
            Path('source-files/cn.wildfirechat.chat/client/build.gradle'),
            Path('source-files/cn.wildfirechat.chat/client/src/main/AndroidManifest.xml'),
            Path('source-files/cn.wildfirechat.chat/emojilibrary/build.gradle'),
            Path('source-files/cn.wildfirechat.chat/gradle/build_libraries.gradle'),
            Path('source-files/cn.wildfirechat.chat/imagepicker/build.gradle'),
            Path('source-files/cn.wildfirechat.chat/mars-core-release/build.gradle'),
            Path('source-files/cn.wildfirechat.chat/push/build.gradle'),
            Path('source-files/cn.wildfirechat.chat/settings.gradle'),
            Path('source-files/cn.wildfirechat.chat/chat/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('0.6.9', 23, 'cn.wildfirechat.chat'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        app.Repo = 'https://github.com/Integreight/1Sheeld-Android-App'
        paths = [
            Path('source-files/com.integreight.onesheeld/pagerIndicator/src/main/AndroidManifest.xml'),
            Path('source-files/com.integreight.onesheeld/pagerIndicator/build.gradle'),
            Path('source-files/com.integreight.onesheeld/oneSheeld/src/main/AndroidManifest.xml'),
            Path('source-files/com.integreight.onesheeld/oneSheeld/build.gradle'),
            Path('source-files/com.integreight.onesheeld/localeapi/src/main/AndroidManifest.xml'),
            Path('source-files/com.integreight.onesheeld/localeapi/build.gradle'),
            Path('source-files/com.integreight.onesheeld/build.gradle'),
            Path('source-files/com.integreight.onesheeld/settings.gradle'),
            Path('source-files/com.integreight.onesheeld/quickReturnHeader/src/main/AndroidManifest.xml'),
            Path('source-files/com.integreight.onesheeld/quickReturnHeader/build.gradle'),
            Path('source-files/com.integreight.onesheeld/pullToRefreshlibrary/src/main/AndroidManifest.xml'),
            Path('source-files/com.integreight.onesheeld/pullToRefreshlibrary/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('1.9.0', 170521, 'com.integreight.onesheeld'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        app.id = 'dev.patrickgold.florisboard'
        paths = [
            Path('source-files/dev.patrickgold.florisboard/app/build.gradle.kts'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('0.3.10', 29, 'dev.patrickgold.florisboard'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        app.id = 'com.ubergeek42.WeechatAndroid'
        paths = [
            Path('source-files/com.ubergeek42.WeechatAndroid/app/build.gradle.kts'),
            Path('source-files/com.ubergeek42.WeechatAndroid/app/src/main/res/values/strings.xml'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('1.8.1', 10801, None),
                         fdroidserver.common.parse_androidmanifests(paths, app))

    def test_parse_androidmanifests_ignore(self):
        app = fdroidserver.metadata.App()
        app.id = 'org.fdroid.fdroid'
        app.UpdateCheckIgnore = '-test'
        paths = [
            Path('source-files/fdroid/fdroidclient/AndroidManifest.xml'),
            Path('source-files/fdroid/fdroidclient/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('Ignore', None, 'org.fdroid.fdroid'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

    def test_parse_androidmanifests_with_flavor(self):
        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.gradle = ['devVersion']
        app['Builds'] = [build]
        app.id = 'org.fdroid.fdroid.dev'
        paths = [
            Path('source-files/fdroid/fdroidclient/AndroidManifest.xml'),
            Path('source-files/fdroid/fdroidclient/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('0.95-dev', 949, 'org.fdroid.fdroid.dev'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.gradle = ['free']
        app['Builds'] = [build]
        app.id = 'eu.siacs.conversations'
        paths = [
            Path('source-files/eu.siacs.conversations/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('1.23.1', 245, 'eu.siacs.conversations'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.gradle = ['generic']
        app['Builds'] = [build]
        app.id = 'com.nextcloud.client'
        paths = [
            Path('source-files/com.nextcloud.client/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('2.0.0', 20000099, 'com.nextcloud.client'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.gradle = ['versionDev']
        app['Builds'] = [build]
        app.id = 'com.nextcloud.android.beta'
        paths = [
            Path('source-files/com.nextcloud.client/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('20171223', 20171223, 'com.nextcloud.android.beta'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.gradle = ['standard']
        app['Builds'] = [build]
        app.id = 'at.bitfire.davdroid'
        paths = [
            Path('source-files/at.bitfire.davdroid/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('1.9.8.1-ose', 197, 'at.bitfire.davdroid'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.gradle = ['libre']
        app['Builds'] = [build]
        app.id = 'com.kunzisoft.fdroidtest.applicationidsuffix.libre'
        paths = [
            Path('source-files/com.kunzisoft.testcase/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('1.0-libre', 1, 'com.kunzisoft.fdroidtest.applicationidsuffix.libre'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.gradle = ['pro']
        app['Builds'] = [build]
        app.id = 'com.kunzisoft.fdroidtest.applicationidsuffix.pro'
        paths = [
            Path('source-files/com.kunzisoft.testcase/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('20180430-pro', 20180430, 'com.kunzisoft.fdroidtest.applicationidsuffix.pro'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.gradle = ['free']
        app['Builds'] = [build]
        app.id = 'com.kunzisoft.fdroidtest.applicationidsuffix'
        paths = [
            Path('source-files/com.kunzisoft.testcase/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('1.0-free', 1, 'com.kunzisoft.fdroidtest.applicationidsuffix'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.gradle = ['underscore']
        app['Builds'] = [build]
        app.id = 'com.kunzisoft.fdroidtest.applicationidsuffix.underscore'
        paths = [
            Path('source-files/com.kunzisoft.testcase/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('20180430-underscore', 20180430, 'com.kunzisoft.fdroidtest.applicationidsuffix.underscore'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.gradle = ['underscore_first']
        app['Builds'] = [build]
        app.id = 'com.kunzisoft.fdroidtest.applicationidsuffix.underscore_first'
        paths = [
            Path('source-files/com.kunzisoft.testcase/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('1.0', 1, 'com.kunzisoft.fdroidtest.applicationidsuffix.underscore_first'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.gradle = ['fdroid']
        app['Builds'] = [build]
        app.id = 'com.github.jameshnsears.quoteunquote'
        paths = [
            Path('source-files/com.github.jameshnsears.quoteunquote/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('2.5.2-fdroid', 73, 'com.github.jameshnsears.quoteunquote'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.gradle = ['fdroidFlavor']
        app['Builds'] = [build]
        app.id = 'com.jens.automation2'
        paths = [
            Path('source-files/com.jens.automation2/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('1.6.34-fdroid', 105, 'com.jens.automation2'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.gradle = ['VAR', 'prod']
        app['Builds'] = [build]
        app.id = 'de.varengold.activeTAN'
        paths = [
            Path('source-files/de.varengold.activeTAN/build.gradle'),
        ]
        for path in paths:
            self.assertTrue(os.path.isfile(path))
        self.assertEqual(('2021-06-30', 34, 'de.varengold.activeTAN'),
                         fdroidserver.common.parse_androidmanifests(paths, app))

    def test_parse_srclib_spec_good(self):
        self.assertEqual(fdroidserver.common.parse_srclib_spec('osmand-external-skia@android/oreo'),
                         ('osmand-external-skia', 'android/oreo', None, None))
        self.assertEqual(fdroidserver.common.parse_srclib_spec('1:appcompat@v7'),
                         ('appcompat', 'v7', '1', None))
        self.assertEqual(fdroidserver.common.parse_srclib_spec('1:Support/v7/appcompat@android-4.4_r1.1'),
                         ('Support', 'android-4.4_r1.1', '1', 'v7/appcompat'))

    def test_parse_srclib_spec_many_ats(self):
        self.assertEqual(
            fdroidserver.common.parse_srclib_spec('foo@@v2'), ('foo', '@v2', None, None)
        )
        self.assertEqual(
            fdroidserver.common.parse_srclib_spec('bar@2@f'), ('bar', '2@f', None, None)
        )

    def test_parse_srclib_spec_none(self):
        with self.assertRaises(MetaDataException):
            fdroidserver.common.parse_srclib_spec(None)

    def test_parse_srclib_spec_no_ref(self):
        with self.assertRaises(MetaDataException):
            fdroidserver.common.parse_srclib_spec('no-ref')
        with self.assertRaises(MetaDataException):
            fdroidserver.common.parse_srclib_spec('noref@')

    def test_parse_srclib_spec_no_name(self):
        with self.assertRaises(MetaDataException):
            fdroidserver.common.parse_srclib_spec('@ref')

    def test_remove_signing_keys(self):
        shutil.copytree(
            os.path.join(basedir, 'source-files'),
            os.path.join(self.tmpdir, 'source-files'),
        )
        os.chdir(self.tmpdir)
        with_signingConfigs = [
            'source-files/com.seafile.seadroid2/app/build.gradle',
            'source-files/eu.siacs.conversations/build.gradle',
            'source-files/info.guardianproject.ripple/build.gradle',
            'source-files/open-keychain/open-keychain/build.gradle',
            'source-files/open-keychain/open-keychain/OpenKeychain/build.gradle',
            'source-files/org.tasks/app/build.gradle.kts',
            'source-files/osmandapp/osmand/build.gradle',
            'source-files/ut.ewh.audiometrytest/app/build.gradle',
        ]
        for f in with_signingConfigs:
            build_dir = os.path.join(*f.split(os.sep)[:2])
            if not os.path.isdir(build_dir):
                continue
            fdroidserver.common.remove_signing_keys(build_dir)
            fromfile = os.path.join(basedir, f)
            with open(f) as fp:
                content = fp.read()
            if 'signingConfig' in content:
                with open(f) as fp:
                    b = fp.readlines()
                with open(fromfile) as fp:
                    a = fp.readlines()
                diff = difflib.unified_diff(a, b, fromfile, f)
                sys.stdout.writelines(diff)
                self.assertFalse(True)
        do_not_modify = [
            'source-files/Zillode/syncthing-silk/build.gradle',
            'source-files/at.bitfire.davdroid/build.gradle',
            'source-files/com.kunzisoft.testcase/build.gradle',
            'source-files/com.nextcloud.client/build.gradle',
            'source-files/fdroid/fdroidclient/build.gradle',
            'source-files/firebase-suspect/app/build.gradle',
            'source-files/firebase-suspect/build.gradle',
            'source-files/firebase-allowlisted/app/build.gradle',
            'source-files/firebase-allowlisted/build.gradle',
            'source-files/org.mozilla.rocket/app/build.gradle',
            'source-files/realm/react-native/android/build.gradle',
            'triple-t-2/build/org.piwigo.android/app/build.gradle',
        ]
        for f in do_not_modify:
            build_dir = os.path.join(*f.split(os.sep)[:2])
            if not os.path.isdir(build_dir):
                continue
            fdroidserver.common.remove_signing_keys(build_dir)
            fromfile = os.path.join(basedir, f)
            with open(fromfile) as fp:
                a = fp.readlines()
            with open(f) as fp:
                b = fp.readlines()
            diff = list(difflib.unified_diff(a, b, fromfile, f))
            self.assertEqual(0, len(diff), 'This file should not have been modified:\n' + ''.join(diff))

    def test_calculate_math_string(self):
        self.assertEqual(1234,
                         fdroidserver.common.calculate_math_string('1234'))
        self.assertEqual((1 + 1) * 2,
                         fdroidserver.common.calculate_math_string('(1 + 1) * 2'))
        self.assertEqual((1 - 1) * 2 + 3 * 1 - 1,
                         fdroidserver.common.calculate_math_string('(1 - 1) * 2 + 3 * 1 - 1'))
        self.assertEqual(0 - 12345,
                         fdroidserver.common.calculate_math_string('0 - 12345'))
        self.assertEqual(0xffff,
                         fdroidserver.common.calculate_math_string('0xffff'))
        self.assertEqual(0xcafe * 123,
                         fdroidserver.common.calculate_math_string('0xcafe * 123'))
        self.assertEqual(-1,
                         fdroidserver.common.calculate_math_string('-1'))
        with self.assertRaises(SyntaxError):
            fdroidserver.common.calculate_math_string('__import__("urllib")')
        with self.assertRaises(SyntaxError):
            fdroidserver.common.calculate_math_string('self')
        with self.assertRaises(SyntaxError):
            fdroidserver.common.calculate_math_string('Ox9()')
        with self.assertRaises(SyntaxError):
            fdroidserver.common.calculate_math_string('1+1; print(1)')
        with self.assertRaises(SyntaxError):
            fdroidserver.common.calculate_math_string('1-1 # no comment')

    def test_calculate_IPFS_cid_with_no_tool(self):
        fdroidserver.common.config = {'ipfs_cid': None}
        self.assertIsNone(fdroidserver.common.calculate_IPFS_cid('urzip.apk'))
        self.assertIsNone(fdroidserver.common.calculate_IPFS_cid('FileDoesNotExist'))

    @unittest.skipUnless(shutil.which('ipfs_cid'), 'calculate_IPFS_cid needs ipfs_cid')
    def test_calculate_IPFS_cid(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        self.assertIsNone(fdroidserver.common.calculate_IPFS_cid('FileDoesNotExist'))
        self.assertEqual(
            fdroidserver.common.calculate_IPFS_cid('urzip.apk'),
            "bafybeigmtgrwyvj77jaflje2rf533haeqtpu2wtwsctryjusjnsawacsam",
        )

    def test_deploy_build_log_with_rsync_with_id_file(self):

        mocklogcontent = bytes(
            textwrap.dedent(
                """\
            build started
            building...
            build completed
            profit!"""
            ),
            'utf-8',
        )

        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.verbose = False
        fdroidserver.common.options.quiet = False
        fdroidserver.common.config = {}
        fdroidserver.common.config['serverwebroot'] = [
            {'url': 'example.com:/var/www/fdroid/'},
            {'url': 'example.com:/var/www/fbot/'},
        ]
        fdroidserver.common.config['deploy_process_logs'] = True
        fdroidserver.common.config['identity_file'] = 'ssh/id_rsa'

        assert_subprocess_call_iteration = 0

        def assert_subprocess_call(cmd):
            nonlocal assert_subprocess_call_iteration
            logging.debug(cmd)
            if assert_subprocess_call_iteration == 0:
                self.assertListEqual(['rsync',
                                      '--archive',
                                      '--delete-after',
                                      '--safe-links',
                                      '-e',
                                      'ssh -oBatchMode=yes -oIdentitiesOnly=yes -i ssh/id_rsa',
                                      cmd[6],
                                      'example.com:/var/www/fdroid/repo/'],
                                     cmd)
                self.assertTrue(cmd[6].endswith('/com.example.app_4711.log.gz'))
                with gzip.open(cmd[6], 'r') as f:
                    self.assertTrue(f.read(), mocklogcontent)
            elif assert_subprocess_call_iteration == 1:
                self.assertListEqual(['rsync',
                                      '--archive',
                                      '--delete-after',
                                      '--safe-links',
                                      '-e',
                                      'ssh -oBatchMode=yes -oIdentitiesOnly=yes -i ssh/id_rsa',
                                      cmd[6],
                                      'example.com:/var/www/fbot/repo/'],
                                     cmd)
                self.assertTrue(cmd[6].endswith('/com.example.app_4711.log.gz'))
                with gzip.open(cmd[6], 'r') as f:
                    self.assertTrue(f.read(), mocklogcontent)
            else:
                self.fail('unexpected subprocess.call invocation ({})'
                          .format(assert_subprocess_call_iteration))
            assert_subprocess_call_iteration += 1
            return 0

        with mock.patch('subprocess.call',
                        side_effect=assert_subprocess_call):
            with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
                fdroidserver.common.deploy_build_log_with_rsync(
                    'com.example.app', 4711, mocklogcontent)

                expected_log_path = os.path.join(tmpdir, 'repo', 'com.example.app_4711.log.gz')
                self.assertTrue(os.path.isfile(expected_log_path))
                with gzip.open(expected_log_path, 'r') as f:
                    self.assertEqual(f.read(), mocklogcontent)

    def test_deploy_status_json(self):
        os.chdir(self.tmpdir)
        fakesubcommand = 'fakesubcommand'
        fake_timestamp = 1234567890
        fakeserver = 'example.com:/var/www/fbot/'
        expected_dir = os.path.join(self.tmpdir, fakeserver.replace(':', ''), 'repo', 'status')

        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.config = {}
        fdroidserver.common.config['serverwebroot'] = [{'url': fakeserver}]
        fdroidserver.common.config['identity_file'] = 'ssh/id_rsa'

        def assert_subprocess_call(cmd):
            dest_path = os.path.join(self.tmpdir, cmd[-1].replace(':', ''))
            if not os.path.exists(dest_path):
                os.makedirs(dest_path)
            return subprocess.run(cmd[:-1] + [dest_path]).returncode

        with mock.patch('subprocess.call', side_effect=assert_subprocess_call):
            with mock.patch.object(sys, 'argv', ['fdroid ' + fakesubcommand]):
                output = fdroidserver.common.setup_status_output(time.localtime(fake_timestamp))
                self.assertFalse(os.path.exists(os.path.join(expected_dir, 'running.json')))
                with mock.patch.object(sys, 'argv', ['fdroid ' + fakesubcommand]):
                    fdroidserver.common.write_status_json(output)
                self.assertFalse(os.path.exists(os.path.join(expected_dir, fakesubcommand + '.json')))

                fdroidserver.common.config['deploy_process_logs'] = True

                output = fdroidserver.common.setup_status_output(time.localtime(fake_timestamp))
                expected_path = os.path.join(expected_dir, 'running.json')
                self.assertTrue(os.path.isfile(expected_path))
                with open(expected_path) as fp:
                    data = json.load(fp)
                self.assertEqual(fake_timestamp * 1000, data['startTimestamp'])
                self.assertFalse('endTimestamp' in data)

                testvalue = 'asdfasd'
                output['testvalue'] = testvalue

                fdroidserver.common.write_status_json(output)
                expected_path = os.path.join(expected_dir, fakesubcommand + '.json')
                self.assertTrue(os.path.isfile(expected_path))
                with open(expected_path) as fp:
                    data = json.load(fp)
                self.assertEqual(fake_timestamp * 1000, data['startTimestamp'])
                self.assertTrue('endTimestamp' in data)
                self.assertEqual(testvalue, output.get('testvalue'))

    def test_string_is_integer(self):
        self.assertTrue(fdroidserver.common.string_is_integer('0x10'))
        self.assertTrue(fdroidserver.common.string_is_integer('010'))
        self.assertTrue(fdroidserver.common.string_is_integer('123'))
        self.assertFalse(fdroidserver.common.string_is_integer('0xgg'))
        self.assertFalse(fdroidserver.common.string_is_integer('01g'))
        self.assertFalse(fdroidserver.common.string_is_integer('o123'))

    def test_version_code_string_to_int(self):
        self.assertEqual(16, fdroidserver.common.version_code_string_to_int('0x10'))
        self.assertEqual(198712389, fdroidserver.common.version_code_string_to_int('198712389'))
        self.assertEqual(8, fdroidserver.common.version_code_string_to_int('0o10'))
        self.assertEqual(10, fdroidserver.common.version_code_string_to_int('010'))
        self.assertEqual(123, fdroidserver.common.version_code_string_to_int('0000123'))
        self.assertEqual(-42, fdroidserver.common.version_code_string_to_int('-42'))

    def test_getsrclibvcs(self):
        fdroidserver.metadata.srclibs = {'somelib': {'RepoType': 'git'},
                                         'yeslib': {'RepoType': 'hg'},
                                         'nolib': {'RepoType': 'git-svn'}}
        self.assertEqual(fdroidserver.common.getsrclibvcs('somelib'), 'git')
        self.assertEqual(fdroidserver.common.getsrclibvcs('yeslib'), 'hg')
        self.assertEqual(fdroidserver.common.getsrclibvcs('nolib'), 'git-svn')
        with self.assertRaises(VCSException):
            fdroidserver.common.getsrclibvcs('nonexistentlib')

    def test_getsrclib_not_found(self):
        fdroidserver.common.config = {'sdk_path': '',
                                      'java_paths': {}}
        fdroidserver.metadata.srclibs = {}

        with self.assertRaisesRegex(VCSException, 'srclib SDL not found.'):
            fdroidserver.common.getsrclib('SDL@release-2.0.3', 'srclib')

    def test_getsrclib_gotorevision_raw(self):
        fdroidserver.common.config = {'sdk_path': '',
                                      'java_paths': {}}
        fdroidserver.metadata.srclibs = {'SDL': {'RepoType': 'git',
                                                 'Repo': ''}}

        vcs = mock.Mock()

        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            os.makedirs(os.path.join('srclib', 'SDL'))
            with mock.patch('fdroidserver.common.getvcs', return_value=vcs):
                ret = fdroidserver.common.getsrclib('SDL', 'srclib', raw=True)
                self.assertEqual(vcs.srclib, ('SDL', None, 'srclib/SDL'))
                self.assertEqual(ret, vcs)

    def test_getsrclib_gotorevision_ref(self):
        fdroidserver.common.config = {'sdk_path': '',
                                      'java_paths': {}}
        fdroidserver.metadata.srclibs = {'ACRA': {'RepoType': 'git',
                                                  'Repo': 'https://github.com/ACRA/acra.git',
                                                  'Subdir': None,
                                                  'Prepare': None}}

        vcs = mock.Mock()
        skm = mock.Mock()
        dfm = mock.Mock()

        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            os.makedirs(os.path.join('srclib', 'ACRA'))
            with mock.patch('fdroidserver.common.getvcs', return_value=vcs):
                with mock.patch('fdroidserver.common.remove_signing_keys', skm):
                    with mock.patch('fdroidserver.common.remove_debuggable_flags', dfm):
                        ret = fdroidserver.common.getsrclib('ACRA@acra-4.6.2', 'srclib')
                        self.assertEqual(vcs.srclib, ('ACRA', None, 'srclib/ACRA'))
                        vcs.gotorevision.assert_called_once_with('acra-4.6.2', True)
                        skm.assert_called_once_with('srclib/ACRA')
                        dfm.assert_called_once_with('srclib/ACRA')
                        self.assertEqual(ret, ('ACRA', None, 'srclib/ACRA'))

    def test_run_yamllint_wellformed(self):
        try:
            import yamllint.config

            yamllint.config  # make pyflakes ignore this
        except ImportError:
            self.skipTest('yamllint not installed')
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with open('wellformed.yml', 'w') as f:
                f.write(
                    textwrap.dedent(
                        '''\
                    yaml:
                        file:
                            - for
                            - test
                        purposeses: true
                    '''
                    )
                )
            result = fdroidserver.common.run_yamllint('wellformed.yml')
            self.assertEqual(result, '')

    def test_run_yamllint_malformed(self):
        try:
            import yamllint.config

            yamllint.config  # make pyflakes ignore this
        except ImportError:
            self.skipTest('yamllint not installed')
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with open('malformed.yml', 'w') as f:
                f.write(
                    textwrap.dedent(
                        '''\
                    yaml:
                          - that
                     fails
                          - test
                    '''
                    )
                )
            result = fdroidserver.common.run_yamllint('malformed.yml')
            self.assertIsNotNone(result)
            self.assertNotEqual(result, '')

    def test_with_no_config(self):
        """It should set defaults if no config file is found"""
        os.chdir(self.tmpdir)
        self.assertFalse(os.path.exists('config.yml'))
        self.assertFalse(os.path.exists('config.py'))
        config = fdroidserver.common.read_config()
        self.assertIsNotNone(config.get('char_limits'))

    def test_with_zero_size_config(self):
        """It should set defaults if config file has nothing in it"""
        os.chdir(self.tmpdir)
        open('config.yml', 'w').close()
        self.assertTrue(os.path.exists('config.yml'))
        self.assertFalse(os.path.exists('config.py'))
        config = fdroidserver.common.read_config()
        self.assertIsNotNone(config.get('char_limits'))

    def test_with_config_yml(self):
        """Make sure it is possible to use config.yml alone."""
        os.chdir(self.tmpdir)
        with open('config.yml', 'w') as fp:
            fp.write('apksigner: yml')
        self.assertTrue(os.path.exists('config.yml'))
        self.assertFalse(os.path.exists('config.py'))
        config = fdroidserver.common.read_config()
        self.assertEqual('yml', config.get('apksigner'))

    def test_with_config_yml_utf8(self):
        """Make sure it is possible to use config.yml in UTF-8 encoding."""
        os.chdir(self.tmpdir)
        teststr = '/πÇÇ现代通用字-български-عربي1/ö/yml'
        with open('config.yml', 'w', encoding='utf-8') as fp:
            fp.write('apksigner: ' + teststr)
        self.assertTrue(os.path.exists('config.yml'))
        self.assertFalse(os.path.exists('config.py'))
        config = fdroidserver.common.read_config()
        self.assertEqual(teststr, config.get('apksigner'))

    def test_with_config_yml_utf8_as_ascii(self):
        """Make sure it is possible to use config.yml Unicode encoded as ASCII."""
        os.chdir(self.tmpdir)
        teststr = '/πÇÇ现代通用字-български-عربي1/ö/yml'
        with open('config.yml', 'w') as fp:
            yaml.dump({'apksigner': teststr}, fp)
        self.assertTrue(os.path.exists('config.yml'))
        self.assertFalse(os.path.exists('config.py'))
        config = fdroidserver.common.read_config()
        self.assertEqual(teststr, config.get('apksigner'))

    def test_with_config_yml_with_env_var(self):
        """Make sure it is possible to use config.yml alone."""
        os.chdir(self.tmpdir)
        with mock.patch.dict(os.environ):
            os.environ['SECRET'] = 'mysecretpassword'  # nosec B105
            with open('config.yml', 'w') as fp:
                fp.write("""keypass: {'env': 'SECRET'}""")
            self.assertTrue(os.path.exists('config.yml'))
            self.assertFalse(os.path.exists('config.py'))
            config = fdroidserver.common.read_config()
            self.assertEqual(os.getenv('SECRET', 'fail'), config.get('keypass'))

    def test_with_config_yml_is_dict(self):
        os.chdir(self.tmpdir)
        Path('config.yml').write_text('apksigner = /placeholder/path')
        with self.assertRaises(TypeError):
            fdroidserver.common.read_config()

    def test_with_config_yml_is_not_mixed_type(self):
        os.chdir(self.tmpdir)
        Path('config.yml').write_text('k: v\napksigner = /placeholder/path')
        with self.assertRaises(yaml.scanner.ScannerError):
            fdroidserver.common.read_config()

    def test_with_config_py(self):
        """Make sure it is still possible to use config.py alone."""
        os.chdir(self.tmpdir)
        with open('config.py', 'w') as fp:
            fp.write('apksigner = "py"')
        self.assertFalse(os.path.exists('config.yml'))
        self.assertTrue(os.path.exists('config.py'))
        config = fdroidserver.common.read_config()
        self.assertEqual("py", config.get('apksigner'))

    def test_config_perm_warning(self):
        """Exercise the code path that issues a warning about unsafe permissions."""
        os.chdir(self.tmpdir)
        with open('config.yml', 'w') as fp:
            fp.write('keystore: foo.jks')
        self.assertTrue(os.path.exists(fp.name))
        os.chmod(fp.name, 0o666)  # nosec B103
        fdroidserver.common.read_config()
        os.remove(fp.name)
        fdroidserver.common.config = None

        with open('config.py', 'w') as fp:
            fp.write('keystore = "foo.jks"')
        self.assertTrue(os.path.exists(fp.name))
        os.chmod(fp.name, 0o666)  # nosec B103
        fdroidserver.common.read_config()

    def test_with_both_config_yml_py(self):
        """If config.yml and config.py are present, config.py should be ignored."""
        os.chdir(self.tmpdir)
        with open('config.yml', 'w') as fp:
            fp.write('apksigner: yml')
        with open('config.py', 'w') as fp:
            fp.write('apksigner = "py"')
        self.assertTrue(os.path.exists('config.yml'))
        self.assertTrue(os.path.exists('config.py'))
        config = fdroidserver.common.read_config()
        self.assertEqual('yml', config.get('apksigner'))

    def test_config_repo_url(self):
        """repo_url ends in /repo, archive_url ends in /archive."""
        os.chdir(self.tmpdir)
        with open('config.yml', 'w') as fp:
            fp.write('repo_url: https://MyFirstFDroidRepo.org/fdroid/repo\n')
            fp.write('archive_url: https://MyFirstFDroidRepo.org/fdroid/archive')
        config = fdroidserver.common.read_config()
        self.assertEqual('https://MyFirstFDroidRepo.org/fdroid/repo', config.get('repo_url'))
        self.assertEqual('https://MyFirstFDroidRepo.org/fdroid/archive', config.get('archive_url'))

    def test_config_repo_url_extra_slash(self):
        """repo_url ends in /repo, archive_url ends in /archive."""
        os.chdir(self.tmpdir)
        with open('config.yml', 'w') as fp:
            fp.write('repo_url: https://MyFirstFDroidRepo.org/fdroid/repo/')
        with self.assertRaises(FDroidException):
            fdroidserver.common.read_config()

    def test_config_repo_url_not_repo(self):
        """repo_url ends in /repo, archive_url ends in /archive."""
        os.chdir(self.tmpdir)
        with open('config.yml', 'w') as fp:
            fp.write('repo_url: https://MyFirstFDroidRepo.org/fdroid/foo')
        with self.assertRaises(FDroidException):
            fdroidserver.common.read_config()

    def test_config_archive_url_extra_slash(self):
        """repo_url ends in /repo, archive_url ends in /archive."""
        os.chdir(self.tmpdir)
        with open('config.yml', 'w') as fp:
            fp.write('archive_url: https://MyFirstFDroidRepo.org/fdroid/archive/')
        with self.assertRaises(FDroidException):
            fdroidserver.common.read_config()

    def test_config_archive_url_not_repo(self):
        """repo_url ends in /repo, archive_url ends in /archive."""
        os.chdir(self.tmpdir)
        with open('config.yml', 'w') as fp:
            fp.write('archive_url: https://MyFirstFDroidRepo.org/fdroid/foo')
        with self.assertRaises(FDroidException):
            fdroidserver.common.read_config()

    def test_write_to_config_yml(self):
        os.chdir(self.tmpdir)
        with open('config.yml', 'w') as fp:
            fp.write('apksigner: yml')
        self.assertTrue(os.path.exists(fp.name))
        self.assertFalse(os.path.exists('config.py'))
        config = fdroidserver.common.read_config()
        self.assertFalse('keypass' in config)
        self.assertEqual('yml', config.get('apksigner'))
        fdroidserver.common.write_to_config(config, 'keypass', 'mysecretpassword')
        with open(fp.name) as fp:
            print(fp.read())
        fdroidserver.common.config = None
        config = fdroidserver.common.read_config()
        self.assertEqual('mysecretpassword', config['keypass'])

    def test_write_to_config_py(self):
        os.chdir(self.tmpdir)
        with open('config.py', 'w') as fp:
            fp.write('apksigner = "py"')
        self.assertTrue(os.path.exists(fp.name))
        self.assertFalse(os.path.exists('config.yml'))
        config = fdroidserver.common.read_config()
        self.assertFalse('keypass' in config)
        self.assertEqual('py', config.get('apksigner'))
        fdroidserver.common.write_to_config(config, 'keypass', 'mysecretpassword')
        fdroidserver.common.config = None
        config = fdroidserver.common.read_config()
        self.assertEqual('mysecretpassword', config['keypass'])

    def test_config_dict_with_int_keys(self):
        os.chdir(self.tmpdir)
        with open('config.yml', 'w') as fp:
            fp.write('java_paths:\n  8: /usr/lib/jvm/java-8-openjdk\n')
        self.assertTrue(os.path.exists(fp.name))
        self.assertFalse(os.path.exists('config.py'))
        config = fdroidserver.common.read_config()
        self.assertEqual('/usr/lib/jvm/java-8-openjdk', config.get('java_paths', {}).get('8'))

    @mock.patch.dict(os.environ, {'PATH': os.getenv('PATH')}, clear=True)
    def test_test_sdk_exists_fails_on_bad_sdk_path(self):
        config = {'sdk_path': 'nothinghere'}
        self.assertFalse(fdroidserver.common.test_sdk_exists(config))

    @mock.patch.dict(os.environ, {'PATH': os.getenv('PATH')}, clear=True)
    def test_test_sdk_exists_fails_on_empty(self):
        self.assertFalse(fdroidserver.common.test_sdk_exists(dict()))

    @mock.patch.dict(os.environ, {'PATH': os.getenv('PATH')}, clear=True)
    def test_test_sdk_exists_fails_on_non_existent(self):
        config = {'sdk_path': os.path.join(self.testdir, 'non_existent')}
        self.assertFalse(fdroidserver.common.test_sdk_exists(config))

    @mock.patch.dict(os.environ, {'PATH': os.getenv('PATH')}, clear=True)
    def test_test_sdk_exists_fails_on_file(self):
        f = os.path.join(self.testdir, 'testfile')
        open(f, 'w').close()
        config = {'sdk_path': f}
        self.assertFalse(fdroidserver.common.test_sdk_exists(config))

    @mock.patch.dict(os.environ, {'PATH': '/nonexistent'}, clear=True)
    def test_test_sdk_exists_valid_apksigner_in_config(self):
        apksigner = os.path.join(
            self.testdir,
            'build-tools',
            fdroidserver.common.MINIMUM_APKSIGNER_BUILD_TOOLS_VERSION,
            'apksigner',
        )
        os.makedirs(os.path.dirname(apksigner))
        with open(apksigner, 'w') as fp:
            fp.write('#!/bin/sh\ndate\n')
        os.chmod(apksigner, 0o0755)  # nosec B103
        config = {'apksigner': apksigner}
        self.assertTrue(fdroidserver.common.test_sdk_exists(config))

    @mock.patch.dict(os.environ, {'PATH': '/nonexistent'}, clear=True)
    def test_test_sdk_exists_old_apksigner_in_config(self):
        apksigner = os.path.join(self.testdir, 'build-tools', '28.0.0', 'apksigner')
        os.makedirs(os.path.dirname(apksigner))
        with open(apksigner, 'w') as fp:
            fp.write('#!/bin/sh\ndate\n')
        os.chmod(apksigner, 0o0755)  # nosec B103
        config = {'apksigner': apksigner}
        self.assertFalse(fdroidserver.common.test_sdk_exists(config))

    @mock.patch.dict(os.environ, {'PATH': '/nonexistent'}, clear=True)
    def test_test_sdk_exists_with_valid_apksigner(self):
        apksigner = (
            Path(self.testdir)
            / 'build-tools'
            / fdroidserver.common.MINIMUM_APKSIGNER_BUILD_TOOLS_VERSION
            / 'apksigner'
        )
        apksigner.parent.mkdir(parents=True)
        apksigner.write_text('#!/bin/sh\ndate\n')
        apksigner.chmod(0o0755)
        config = {'sdk_path': self.testdir}
        self.assertTrue(fdroidserver.common.test_sdk_exists(config))

    @mock.patch.dict(os.environ, {'PATH': '/nonexistent'}, clear=True)
    def test_test_sdk_exists_with_old_apksigner(self):
        apksigner = Path(self.testdir) / 'build-tools' / '17.0.0' / 'apksigner'
        apksigner.parent.mkdir(parents=True)
        apksigner.write_text('#!/bin/sh\ndate\n')
        apksigner.chmod(0o0755)
        config = {'sdk_path': self.testdir}
        self.assertFalse(fdroidserver.common.test_sdk_exists(config))

    def test_loading_config_buildserver_yml(self):
        """Smoke check to make sure this file is properly parsed"""
        os.chdir(self.tmpdir)
        shutil.copy(os.path.join(basedir, '..', 'buildserver', 'config.buildserver.yml'),
                    'config.yml')
        self.assertFalse(os.path.exists('config.py'))
        fdroidserver.common.read_config()

    def test_setup_status_output(self):
        os.chdir(self.tmpdir)
        start_timestamp = time.gmtime()
        subcommand = 'test'

        fakecmd = ['fdroid ' + subcommand, '--option']
        sys.argv = fakecmd
        fdroidserver.common.config = dict()
        fdroidserver.common.setup_status_output(start_timestamp)
        with open(os.path.join('repo', 'status', 'running.json')) as fp:
            data = json.load(fp)
        self.assertFalse(os.path.exists('.git'))
        self.assertFalse('fdroiddata' in data)
        self.assertEqual(fakecmd, data['commandLine'])
        self.assertEqual(subcommand, data['subcommand'])

    def test_setup_status_output_in_git_repo(self):
        os.chdir(self.tmpdir)
        logging.getLogger('git.cmd').setLevel(logging.INFO)
        git_repo = git.Repo.init(self.tmpdir)
        file_in_git = 'README.md'
        with open(file_in_git, 'w') as fp:
            fp.write('this is just a test')
        git_repo.git.add(all=True)
        git_repo.index.commit("update README")

        start_timestamp = time.gmtime()
        fakecmd = ['fdroid test2', '--option']
        sys.argv = fakecmd
        fdroidserver.common.config = dict()
        fdroidserver.common.setup_status_output(start_timestamp)
        with open(os.path.join('repo', 'status', 'running.json')) as fp:
            data = json.load(fp)
        self.assertTrue(os.path.exists('.git'))
        self.assertIsNotNone(re.match(r'[0-9a-f]{40}', data['fdroiddata']['commitId']),
                             'Must be a valid git SHA1 commit ID!')
        self.assertFalse(data['fdroiddata']['isDirty'])
        self.assertEqual(fakecmd, data['commandLine'])

        self.assertEqual([],
                         data['fdroiddata']['untrackedFiles'])
        dirtyfile = 'dirtyfile'
        with open(dirtyfile, 'w', encoding='utf-8') as fp:
            fp.write('this is just a test')
        with open(file_in_git, 'a', encoding='utf-8') as fp:
            fp.write('\nappend some stuff')
        self.assertEqual([],
                         data['fdroiddata']['modifiedFiles'])
        fdroidserver.common.setup_status_output(start_timestamp)
        with open(os.path.join('repo', 'status', 'running.json')) as fp:
            data = json.load(fp)
        self.assertTrue(data['fdroiddata']['isDirty'])
        self.assertEqual([file_in_git],
                         data['fdroiddata']['modifiedFiles'])
        self.assertEqual([dirtyfile, 'repo/status/running.json'],
                         data['fdroiddata']['untrackedFiles'])

    def test_get_app_display_name(self):
        testvalue = 'WIN!'
        for app in [
                {'Name': testvalue},
                {'AutoName': testvalue},
                {'id': testvalue},
                {'id': 'a', 'localized': {'de-AT': {'name': testvalue}}},
                {'id': 'a', 'localized': {
                    'de-AT': {'name': 'nope'},
                    'en-US': {'name': testvalue},
                }},
                {'AutoName': 'ignore me', 'Name': testvalue, 'id': 'nope'},
                {'AutoName': testvalue, 'id': 'nope'}]:
            self.assertEqual(testvalue, fdroidserver.common.get_app_display_name(app))

    @mock.patch.dict(os.environ, {'PATH': os.getenv('PATH')}, clear=True)
    def test_get_android_tools_versions(self):
        sdk_path = os.path.join(basedir, 'get_android_tools_versions/android-sdk')
        config = {
            'ndk_paths': {'r10e': os.path.join(sdk_path, '..', 'android-ndk-r10e')},
            'sdk_path': sdk_path,
        }
        fdroidserver.common.config = config
        fdroidserver.common.fill_config_defaults(config)
        components = fdroidserver.common.get_android_tools_versions()
        expected = (
            ('../android-ndk-r10e', 'r10e'),
            ('ndk-bundle', '21.4.7075529'),
            ('ndk/11.2.2725575', '11.2.2725575'),
            ('ndk/17.2.4988734', '17.2.4988734'),
            ('ndk/21.3.6528147', '21.3.6528147'),
            ('patcher/v4', '1'),
            ('platforms/android-30', '3'),
            ('skiaparser/1', '6'),
            ('tools', '26.1.1'),
        )
        self.assertSequenceEqual(expected, sorted(components))

    @mock.patch.dict(os.environ, {'PATH': os.getenv('PATH')}, clear=True)
    def test_get_android_tools_versions_no_ndk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sdk_path = Path(tmpdir) / 'get_android_tools_versions'
            shutil.copytree(
                os.path.join(basedir, 'get_android_tools_versions'), sdk_path
            )
            shutil.rmtree(sdk_path / 'android-ndk-r10e')
            shutil.rmtree(sdk_path / 'android-sdk/ndk')
            shutil.rmtree(sdk_path / 'android-sdk/ndk-bundle')
            fdroidserver.common.config = {'sdk_path': str(sdk_path)}
            components = fdroidserver.common.get_android_tools_versions()
            expected = (
                ('android-sdk/patcher/v4', '1'),
                ('android-sdk/platforms/android-30', '3'),
                ('android-sdk/skiaparser/1', '6'),
                ('android-sdk/tools', '26.1.1'),
            )
        self.assertSequenceEqual(expected, sorted(components))

    def test_read_pkg_args(self):
        allow_vercodes = False
        self.assertEqual(
            {'org.fdroid.fdroid': []},
            fdroidserver.common.read_pkg_args(['org.fdroid.fdroid'], allow_vercodes),
        )
        self.assertNotEqual(
            {'com.example': [123456]},
            fdroidserver.common.read_pkg_args(['com.example:123456'], allow_vercodes),
        )

        allow_vercodes = True
        self.assertEqual(
            {'org.fdroid.fdroid': []},
            fdroidserver.common.read_pkg_args(['org.fdroid.fdroid'], allow_vercodes),
        )
        self.assertEqual(
            {'com.example': [123456]},
            fdroidserver.common.read_pkg_args(['com.example:123456'], allow_vercodes),
        )
        self.assertEqual(
            {'org.debian_kit': [6]},
            fdroidserver.common.read_pkg_args(['org.debian_kit_6.apk'], allow_vercodes),
        )
        appid_versionCode_pairs = (
            'org.fdroid.fdroid:1',
            'com.example:12345',
            'com.example:67890',
        )
        self.assertEqual(
            {'com.example': [12345, 67890], 'org.fdroid.fdroid': [1]},
            fdroidserver.common.read_pkg_args(appid_versionCode_pairs, allow_vercodes),
        )
        appid_versionCode_pairs = (
            'com.example:67890',
            'org.c_base.c_beam_29.apk',
        )
        self.assertEqual(
            {'com.example': [67890], 'org.c_base.c_beam': [29]},
            fdroidserver.common.read_pkg_args(appid_versionCode_pairs, allow_vercodes),
        )

    def test_read_pkg_args_errors(self):
        allow_vercodes = True
        with self.assertRaises(FDroidException):
            fdroidserver.common.read_pkg_args(['org.fdroid.fdroid:'], allow_vercodes),
        with self.assertRaises(FDroidException):
            fdroidserver.common.read_pkg_args(['org.fdroid.fdroid:foo'], allow_vercodes),

    def test_apk_strip_v1_signatures(self):
        before = os.path.join(basedir, 'no_targetsdk_minsdk1_unsigned.apk')
        after = os.path.join(self.testdir, 'after.apk')
        shutil.copy(before, after)
        fdroidserver.common.apk_strip_v1_signatures(after, strip_manifest=False)

    def test_metadata_find_developer_signing_files(self):
        appid = 'org.smssecure.smssecure'

        self.assertIsNone(
            fdroidserver.common.metadata_find_developer_signing_files(appid, 133)
        )

        vc = '135'
        self.assertEqual(
            (
                os.path.join('metadata', appid, 'signatures', vc, '28969C09.RSA'),
                os.path.join('metadata', appid, 'signatures', vc, '28969C09.SF'),
                os.path.join('metadata', appid, 'signatures', vc, 'MANIFEST.MF'),
                None,
            ),
            fdroidserver.common.metadata_find_developer_signing_files(appid, vc),
        )

        vc = '134'
        self.assertEqual(
            (
                os.path.join('metadata', appid, 'signatures', vc, '28969C09.RSA'),
                os.path.join('metadata', appid, 'signatures', vc, '28969C09.SF'),
                os.path.join('metadata', appid, 'signatures', vc, 'MANIFEST.MF'),
                None,
            ),
            fdroidserver.common.metadata_find_developer_signing_files(appid, vc),
        )

    @mock.patch('sdkmanager.build_package_list', lambda use_net: None)
    def test_auto_install_ndk(self):
        """Test all possible field data types for build.ndk"""
        fdroidserver.common.config = {'sdk_path': self.testdir}
        sdk_path = self.testdir
        build = fdroidserver.metadata.Build()

        none_entry = mock.Mock()
        with mock.patch('sdkmanager.install', none_entry):
            fdroidserver.common.auto_install_ndk(build)
            none_entry.assert_not_called()

        empty_list = mock.Mock()
        build.ndk = []
        with mock.patch('sdkmanager.install', empty_list):
            fdroidserver.common.auto_install_ndk(build)
            empty_list.assert_not_called()

        release_entry = mock.Mock()
        build.ndk = 'r21e'
        with mock.patch('sdkmanager.install', release_entry):
            fdroidserver.common.auto_install_ndk(build)
            release_entry.assert_called_once_with('ndk;r21e', sdk_path)

        revision_entry = mock.Mock()
        build.ndk = '21.4.7075529'
        with mock.patch('sdkmanager.install', revision_entry):
            fdroidserver.common.auto_install_ndk(build)
            revision_entry.assert_called_once_with('ndk;21.4.7075529', sdk_path)

        list_entry = mock.Mock()
        calls = []
        build.ndk = ['r10e', '11.0.2655954', 'r12b', 'r21e']
        for n in build.ndk:
            calls.append(mock.call(f'ndk;{n}', sdk_path))
        with mock.patch('sdkmanager.install', list_entry):
            fdroidserver.common.auto_install_ndk(build)
            list_entry.assert_has_calls(calls)

    @unittest.skipIf(importlib.util.find_spec('sdkmanager') is None, 'needs sdkmanager')
    @mock.patch('sdkmanager.build_package_list', lambda use_net: None)
    @mock.patch('sdkmanager._install_zipball_from_cache', lambda a, b: None)
    @mock.patch('sdkmanager._generate_package_xml', lambda a, b, c: None)
    def test_auto_install_ndk_mock_dl(self):
        """Test NDK installs by actually calling sdkmanager"""
        import sdkmanager
        import pkg_resources

        sdkmanager_version = LooseVersion(
            pkg_resources.get_distribution('sdkmanager').version
        )
        if sdkmanager_version < LooseVersion('0.6.4'):
            raise unittest.SkipTest('needs fdroid sdkmanager >= 0.6.4')

        fdroidserver.common.config = {'sdk_path': 'placeholder'}
        build = fdroidserver.metadata.Build()
        url = 'https://dl.google.com/android/repository/android-ndk-r24-linux.zip'
        path = sdkmanager.get_cachedir() / os.path.basename(url)
        sdkmanager.packages = {
            ('ndk', '24.0.8215888'): url,
            ('ndk', 'r24'): url,
        }
        build.ndk = 'r24'
        firstrun = mock.Mock()
        with mock.patch('sdkmanager.download_file', firstrun):
            fdroidserver.common.auto_install_ndk(build)
            firstrun.assert_called_once_with(url, path)
        build.ndk = '24.0.8215888'
        secondrun = mock.Mock()
        with mock.patch('sdkmanager.download_file', secondrun):
            fdroidserver.common.auto_install_ndk(build)
            secondrun.assert_called_once_with(url, path)

    @unittest.skip("This test downloads and unzips a 1GB file.")
    def test_install_ndk(self):
        """NDK r10e is a special case since its missing source.properties"""
        config = {'sdk_path': self.tmpdir}
        fdroidserver.common.config = config
        fdroidserver.common._install_ndk('r10e')
        r10e = os.path.join(self.tmpdir, 'ndk', 'r10e')
        self.assertEqual('r10e', fdroidserver.common.get_ndk_version(r10e))
        fdroidserver.common.fill_config_defaults(config)
        self.assertEqual({'r10e': r10e}, config['ndk_paths'])

    def test_fill_config_defaults(self):
        """Test the auto-detection of NDKs installed in standard paths"""
        ndk_bundle = os.path.join(self.tmpdir, 'ndk-bundle')
        os.makedirs(ndk_bundle)
        with open(os.path.join(ndk_bundle, 'source.properties'), 'w') as fp:
            fp.write('Pkg.Desc = Android NDK\nPkg.Revision = 17.2.4988734\n')
        config = {'sdk_path': self.tmpdir}
        fdroidserver.common.fill_config_defaults(config)
        self.assertEqual({'17.2.4988734': ndk_bundle}, config['ndk_paths'])

        r21e = os.path.join(self.tmpdir, 'ndk', '21.4.7075529')
        os.makedirs(r21e)
        with open(os.path.join(r21e, 'source.properties'), 'w') as fp:
            fp.write('Pkg.Desc = Android NDK\nPkg.Revision = 21.4.7075529\n')
        config = {'sdk_path': self.tmpdir}
        fdroidserver.common.fill_config_defaults(config)
        self.assertEqual(
            {'17.2.4988734': ndk_bundle, '21.4.7075529': r21e},
            config['ndk_paths'],
        )

        r10e = os.path.join(self.tmpdir, 'ndk', 'r10e')
        os.makedirs(r10e)
        with open(os.path.join(r10e, 'RELEASE.TXT'), 'w') as fp:
            fp.write('r10e-rc4 (64-bit)\n')
        config = {'sdk_path': self.tmpdir}
        fdroidserver.common.fill_config_defaults(config)
        self.assertEqual(
            {'r10e': r10e, '17.2.4988734': ndk_bundle, '21.4.7075529': r21e},
            config['ndk_paths'],
        )

    @unittest.skipIf(not os.path.isdir('/usr/lib/jvm/default-java'), 'uses Debian path')
    def test_fill_config_defaults_java(self):
        """Test the auto-detection of Java installed in standard paths"""
        config = {'sdk_path': self.tmpdir}
        fdroidserver.common.fill_config_defaults(config)
        java_paths = []
        # use presence of javac to make sure its JDK not just JRE
        for f in glob.glob('/usr/lib/jvm/java-*-openjdk-*/bin/javac'):
            jdk = os.path.dirname(os.path.dirname(f))
            if not os.path.islink(jdk):
                java_paths.append(jdk)
        self.assertEqual(
            len(java_paths),
            len(config['java_paths'])
        )
        for f in config['java_paths'].values():
            self.assertTrue(f in java_paths)
            self.assertTrue(isinstance(f, str))  # paths in config must be str

    @mock.patch.dict(os.environ, clear=True)
    def test_sdk_path_in_config_must_be_strings(self):
        """All paths in config must be strings, and never pathlib.Path instances"""
        os.environ['PATH'] = '/usr/bin:/usr/sbin'
        config = {'sdk_path': Path('/opt/android-sdk')}
        fdroidserver.common.fill_config_defaults(config)
        build = fdroidserver.metadata.Build()
        with self.assertRaises(TypeError):
            fdroidserver.common.set_FDroidPopen_env(build)

    @mock.patch.dict(os.environ, clear=True)
    def test_ndk_paths_in_config_must_be_strings(self):
        """All paths in config must be strings, and never pathlib.Path instances"""
        fdroidserver.common.config = {
            'ndk_paths': {'r21d': Path('/opt/android-sdk/ndk/r21d')}
        }
        build = fdroidserver.metadata.Build()
        build.ndk = 'r21d'
        os.environ['PATH'] = '/usr/bin:/usr/sbin'
        with self.assertRaises(TypeError):
            fdroidserver.common.set_FDroidPopen_env(build)

    @mock.patch.dict(os.environ, clear=True)
    def test_FDroidPopen_envs_paths_can_be_pathlib(self):
        _mock_common_module_options_instance()
        os.environ['PATH'] = '/usr/bin:/usr/sbin'
        envs = {'PATHLIB': Path('/pathlib/path'), 'STRING': '/string/path'}
        p = fdroidserver.common.FDroidPopen(['/bin/sh', '-c', 'export'], envs=envs)
        self.assertIn('/string/path', p.output)
        self.assertIn('/pathlib/path', p.output)

    def test_vcs_git_latesttags(self):
        tags = [
            "1.1.1",
            "2.2.2",
            "v3.0",
            "0.0.4",
            "0.5.0-beta",
            "666(6)",
            "seven",
        ]
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            repo = git.Repo.init(Path.cwd())
            f = Path("test")
            date = 10 ** 9
            for tag in tags:
                date += 1
                f.write_text(tag)
                repo.index.add([str(f)])
                repo.index.commit(tag, commit_date=str(date) + " +0000")
                repo.create_tag(tag)

            vcs = fdroidserver.common.vcs_git(None, Path.cwd())
            self.assertEqual(vcs.latesttags(), tags[::-1])

    def test_vcs_git_getref(self):

        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            repo = git.Repo.init(Path.cwd())
            tag = "1.1.1"
            f = Path("test")
            f.write_text(tag)
            repo.index.add([str(f)])
            repo.index.commit("foo")
            repo.create_tag(tag)

            vcs = fdroidserver.common.vcs_git(None, Path.cwd())

            self.assertIsNotNone(vcs.getref("1.1.1"))
            self.assertIsNone(vcs.getref("invalid"))

    def test_get_release_filename(self):
        app = fdroidserver.metadata.App()
        app.id = 'test.app'
        build = fdroidserver.metadata.Build()
        build.versionCode = 123

        build.output = 'build/apk/*'
        self.assertEqual(
            fdroidserver.common.get_release_filename(app, build),
            "%s_%s.apk" % (app.id, build.versionCode),
        )

        build.output = 'build/apk/*.zip'
        self.assertEqual(
            fdroidserver.common.get_release_filename(app, build),
            "%s_%s.zip" % (app.id, build.versionCode),
        )

        build.output = 'build/apk/*.apk'
        self.assertEqual(
            fdroidserver.common.get_release_filename(app, build),
            "%s_%s.apk" % (app.id, build.versionCode),
        )

        build.output = 'build/apk/*.apk'
        self.assertEqual(
            fdroidserver.common.get_release_filename(app, build, 'exe'),
            "%s_%s.exe" % (app.id, build.versionCode),
        )

    def test_no_zero_length_ndk_path_prefixes(self):
        fdroidserver.common.config = {'ndk_paths': {}}
        build = fdroidserver.metadata.Build()

        with mock.patch.dict(os.environ, clear=True):
            os.environ['PATH'] = '/usr/bin:/usr/sbin'
            fdroidserver.common.set_FDroidPopen_env(build)
            self.assertNotIn('', os.getenv('PATH').split(os.pathsep))

    def test_is_repo_file(self):
        is_repo_file = fdroidserver.common.is_repo_file
        self.assertFalse(is_repo_file('does-not-exist'))

        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            Path('repo').mkdir()
            repo_files = [
                'repo/com.example.test.helloworld_1.apk',
                'repo/com.politedroid_6.apk',
                'repo/duplicate.permisssions_9999999.apk',
                'repo/fake.ota.update_1234.zip',
                'repo/info.guardianproject.index-v1.jar_123.apk',
                'repo/info.zwanenburg.caffeinetile_4.apk',
                'repo/main.1101613.obb.main.twoversions.obb',
            ]
            index_files = [
                'repo/entry.jar',
                'repo/entry.json',
                'repo/index-v1.jar',
                'repo/index-v1.json',
                'repo/index-v2.json',
                'repo/index.css',
                'repo/index.html',
                'repo/index.jar',
                'repo/index.png',
                'repo/index.xml',
            ]
            for f in repo_files + index_files:
                open(f, 'w').close()

            repo_dirs = [
                'repo/com.politedroid',
                'repo/info.guardianproject.index-v1.jar',
                'repo/status',
            ]
            for d in repo_dirs:
                os.mkdir(d)

            for f in repo_files:
                self.assertTrue(os.path.exists(f), f + ' was created')
                self.assertTrue(is_repo_file(f), f + ' is repo file')

            for f in index_files:
                self.assertTrue(os.path.exists(f), f + ' was created')
                self.assertFalse(is_repo_file(f), f + ' is repo file')
                gpg_signed = [
                    'repo/entry.json',
                    'repo/index-v1.json',
                    'repo/index-v2.json',
                ]
                self.assertEqual(
                    (f in gpg_signed or is_repo_file(f, for_gpg_signing=False)),
                    is_repo_file(f, for_gpg_signing=True),
                    f + ' gpg signable?',
                )

            for d in repo_dirs:
                self.assertTrue(os.path.exists(d), d + ' was created')
                self.assertFalse(is_repo_file(d), d + ' not repo file')

    def test_get_apksigner_smartcardoptions(self):
        os.chdir(self.tmpdir)
        with open('config.yml', 'w') as fp:
            d = {
                'smartcardoptions': '-storetype PKCS11'
                ' -providerName SunPKCS11-OpenSC'
                ' -providerClass sun.security.pkcs11.SunPKCS11'
                ' -providerArg opensc-fdroid.cfg'
            }
            yaml.dump(d, fp)
        config = fdroidserver.common.read_config()
        fdroidserver.common.config = config
        self.assertTrue(isinstance(d['smartcardoptions'], str))
        self.assertTrue(isinstance(config['smartcardoptions'], list))
        self.assertEqual(
            [
                '--ks-type',
                'PKCS11',
                '--provider-class',
                'sun.security.pkcs11.SunPKCS11',
                '--provider-arg',
                'opensc-fdroid.cfg',
            ],
            fdroidserver.common.get_apksigner_smartcardoptions(
                config['smartcardoptions']
            ),
        )

    def test_get_smartcardoptions_list(self):
        os.chdir(self.tmpdir)
        with open('config.yml', 'w') as fp:
            fp.write(
                textwrap.dedent(
                    """
                    smartcardoptions:
                      - -storetype
                      -  PKCS11
                      - -providerName
                      -  SunPKCS11-OpenSC
                      - -providerClass
                      -  sun.security.pkcs11.SunPKCS11
                      - -providerArg
                      -  opensc-fdroid.cfg
                    """
                )
            )
        config = fdroidserver.common.read_config()
        fdroidserver.common.config = config
        self.assertTrue(isinstance(config['smartcardoptions'], list))
        self.assertEqual(
            [
                '-storetype',
                'PKCS11',
                '-providerName',
                'SunPKCS11-OpenSC',
                '-providerClass',
                'sun.security.pkcs11.SunPKCS11',
                '-providerArg',
                'opensc-fdroid.cfg',
            ],
            config['smartcardoptions'],
        )

    def test_get_smartcardoptions_spaces(self):
        os.chdir(self.tmpdir)
        with open('config.yml', 'w') as fp:
            fp.write(
                textwrap.dedent(
                    """smartcardoptions: |
                         -storetype      PKCS11
                         -providerClass  sun.security.pkcs11.SunPKCS11
                         -providerArg    /etc/pkcs11_java.cfg

                    """
                )
            )
        config = fdroidserver.common.read_config()
        fdroidserver.common.config = config
        self.assertTrue(isinstance(config['smartcardoptions'], list))
        self.assertEqual(
            [
                '-storetype',
                'PKCS11',
                '-providerClass',
                'sun.security.pkcs11.SunPKCS11',
                '-providerArg',
                '/etc/pkcs11_java.cfg',
            ],
            config['smartcardoptions'],
        )

    def test_get_smartcardoptions_config_py(self):
        os.chdir(self.tmpdir)
        with open('config.py', 'w') as fp:
            fp.write(
                textwrap.dedent(
                    """
                    smartcardoptions = '''
                    \t-storetype\tPKCS11
                    \t-providerClass\tsun.security.pkcs11.SunPKCS11
                    \t-providerArg\t/etc/pkcs11_java.cfg

                     '''
                    """
                )
            )
        config = fdroidserver.common.read_config()
        fdroidserver.common.config = config
        self.assertEqual(
            [
                '-storetype',
                'PKCS11',
                '-providerClass',
                'sun.security.pkcs11.SunPKCS11',
                '-providerArg',
                '/etc/pkcs11_java.cfg',
            ],
            config['smartcardoptions'],
        )

    def test_load_localized_config(self):
        """It should load"""
        antiFeatures = fdroidserver.common.load_localized_config(
            ANTIFEATURES_CONFIG_NAME, 'repo'
        )
        self.assertEqual(
            [
                'Ads',
                'DisabledAlgorithm',
                'KnownVuln',
                'NSFW',
                'NoSourceSince',
                'NonFreeAdd',
                'NonFreeAssets',
                'NonFreeDep',
                'NonFreeNet',
                'Tracking',
                'UpstreamNonFree',
            ],
            list(antiFeatures.keys()),
        )
        self.assertEqual(
            ['de', 'en-US', 'fa', 'ro', 'zh-rCN'],
            list(antiFeatures['Ads']['description'].keys()),
        )
        self.assertEqual(
            ['en-US'],
            list(antiFeatures['NoSourceSince']['description'].keys()),
        )
        # it should have copied the icon files into place
        for v in antiFeatures.values():
            p = Path(os.path.dirname(__file__) + '/repo' + v['icon']['en-US']['name'])
            self.assertTrue(p.exists())

    def test_load_localized_config_categories(self):
        """It should load"""
        categories = fdroidserver.common.load_localized_config(
            CATEGORIES_CONFIG_NAME, 'repo'
        )
        self.assertEqual(
            [
                'Time',
                'Development',
                'GuardianProject',
                'Multimedia',
                'Phone & SMS',
                'Security',
                'System',
            ],
            list(categories.keys()),
        )
        self.assertEqual(['en-US'], list(categories['GuardianProject']['name'].keys()))

    def test_load_localized_config_0_file(self):
        os.chdir(self.testdir)
        os.mkdir('config')
        Path('config/categories.yml').write_text('')
        with self.assertRaises(TypeError):
            fdroidserver.common.load_localized_config(CATEGORIES_CONFIG_NAME, 'repo')

    def test_load_localized_config_string(self):
        os.chdir(self.testdir)
        os.mkdir('config')
        Path('config/categories.yml').write_text('this is a string')
        with self.assertRaises(TypeError):
            fdroidserver.common.load_localized_config(CATEGORIES_CONFIG_NAME, 'repo')

    def test_load_localized_config_list(self):
        os.chdir(self.testdir)
        os.mkdir('config')
        Path('config/categories.yml').write_text('- System')
        with self.assertRaises(TypeError):
            fdroidserver.common.load_localized_config(CATEGORIES_CONFIG_NAME, 'repo')

    def test_config_type_check_config_yml_dict(self):
        fdroidserver.common.config_type_check('config.yml', dict())

    def test_config_type_check_config_yml_list(self):
        with self.assertRaises(TypeError):
            fdroidserver.common.config_type_check('config.yml', list())

    def test_config_type_check_config_yml_set(self):
        with self.assertRaises(TypeError):
            fdroidserver.common.config_type_check('config.yml', set())

    def test_config_type_check_config_yml_str(self):
        with self.assertRaises(TypeError):
            fdroidserver.common.config_type_check('config.yml', str())

    def test_config_type_check_mirrors_list(self):
        fdroidserver.common.config_type_check('config/mirrors.yml', list())

    def test_config_type_check_mirrors_dict(self):
        with self.assertRaises(TypeError):
            fdroidserver.common.config_type_check('config/mirrors.yml', dict())

    def test_config_type_check_mirrors_set(self):
        with self.assertRaises(TypeError):
            fdroidserver.common.config_type_check('config/mirrors.yml', set())

    def test_config_type_check_mirrors_str(self):
        with self.assertRaises(TypeError):
            fdroidserver.common.config_type_check('config/mirrors.yml', str())

    def test_config_serverwebroot_str(self):
        os.chdir(self.testdir)
        Path('config.yml').write_text("""serverwebroot: 'foo@example.com:/var/www'""")
        self.assertEqual(
            [{'url': 'foo@example.com:/var/www/'}],
            fdroidserver.common.read_config()['serverwebroot'],
        )

    def test_config_serverwebroot_list(self):
        os.chdir(self.testdir)
        Path('config.yml').write_text("""serverwebroot:\n  - foo@example.com:/var/www""")
        self.assertEqual(
            [{'url': 'foo@example.com:/var/www/'}],
            fdroidserver.common.read_config()['serverwebroot'],
        )

    def test_config_serverwebroot_dict(self):
        os.chdir(self.testdir)
        Path('config.yml').write_text("""serverwebroot:\n  - url: 'foo@example.com:/var/www'""")
        self.assertEqual(
            [{'url': 'foo@example.com:/var/www/'}],
            fdroidserver.common.read_config()['serverwebroot'],
        )

    def test_parse_mirrors_config_str(self):
        s = 'foo@example.com:/var/www'
        mirrors = ruamel.yaml.YAML(typ='safe').load("""'%s'""" % s)
        self.assertEqual(
            [{'url': s}], fdroidserver.common.parse_mirrors_config(mirrors)
        )

    def test_parse_mirrors_config_list(self):
        s = 'foo@example.com:/var/www'
        mirrors = ruamel.yaml.YAML(typ='safe').load("""- '%s'""" % s)
        self.assertEqual(
            [{'url': s}], fdroidserver.common.parse_mirrors_config(mirrors)
        )

    def test_parse_mirrors_config_dict(self):
        s = 'foo@example.com:/var/www'
        mirrors = ruamel.yaml.YAML(typ='safe').load("""- url: '%s'""" % s)
        self.assertEqual(
            [{'url': s}], fdroidserver.common.parse_mirrors_config(mirrors)
        )

    def test_KnownApks_recordapk(self):
        """Test that added dates are being fetched from the index.

        There are more related tests in tests/run-tests.

        """
        now = datetime.now(timezone.utc)
        knownapks = fdroidserver.common.KnownApks()
        for apkName in knownapks.apks:
            knownapks.recordapk(apkName, default_date=now)
        for added in knownapks.apks.values():
            self.assertNotEqual(added, now)

    def test_KnownApks_recordapk_new(self):
        """Test that new added dates work, and are not replaced later.

        There are more related tests in tests/run-tests.

        """
        now = datetime.now(timezone.utc)
        knownapks = fdroidserver.common.KnownApks()
        fake_apk = 'fake.apk'
        knownapks.recordapk(fake_apk, default_date=now)
        for apk, added in knownapks.apks.items():
            if apk == fake_apk:
                self.assertEqual(added, now)
            else:
                self.assertNotEqual(added, now)
        knownapks.recordapk(fake_apk, default_date=datetime.now(timezone.utc))
        self.assertEqual(knownapks.apks[fake_apk], now)

    def test_get_mirrors_fdroidorg(self):
        mirrors = fdroidserver.common.get_mirrors(
            'https://f-droid.org/repo', 'entry.jar'
        )
        self.assertEqual(
            'https://f-droid.org/repo/entry.jar',
            mirrors[0]['url'],
        )

    def test_get_mirrors_other(self):
        self.assertEqual(
            [{'url': 'https://example.com/fdroid/repo/index-v2.json'}],
            fdroidserver.common.get_mirrors(
                'https://example.com/fdroid/repo', 'index-v2.json'
            ),
        )

    def test_append_filename_to_mirrors(self):
        filename = 'test.apk'
        url = 'https://example.com/fdroid/repo'
        mirrors = [{'url': url}]
        self.assertEqual(
            [{'url': url + '/' + filename}],
            fdroidserver.common.append_filename_to_mirrors(filename, mirrors),
        )

    def test_append_filename_to_mirrors_full(self):
        filename = 'test.apk'
        mirrors = fdroidserver.common.FDROIDORG_MIRRORS
        for mirror in fdroidserver.common.append_filename_to_mirrors(filename, mirrors):
            self.assertTrue(mirror['url'].endswith('/' + filename))


APKS_WITH_JAR_SIGNATURES = (
    (
        'SpeedoMeterApp.main_1.apk',
        '2e6b3126fb7e0db6a9d4c2a06df690620655454d6e152cf244cc9efe9787a77d',
    ),
    (
        'apk.embedded_1.apk',
        '764f0eaac0cdcde35023658eea865c4383ab580f9827c62fdd3daf9e654199ee',
    ),
    (
        'bad-unicode-πÇÇ现代通用字-български-عربي1.apk',
        '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
    ),
    (
        'issue-1128-poc3a.apk',
        '1dbb8be012293e988a0820f7d455b07abd267d2c0b500fc793fcfd80141cb5ce',
    ),
    (
        'issue-1128-poc3b.apk',
        '1dbb8be012293e988a0820f7d455b07abd267d2c0b500fc793fcfd80141cb5ce',
    ),
    (
        'janus.apk',
        'ebb0fedf1942a099b287c3db00ff732162152481abb2b6c7cbcdb2ba5894a768',
    ),
    (
        'org.bitbucket.tickytacky.mirrormirror_1.apk',
        'feaa63df35b4635cf091513dfcd6d11209632555efdfc47e33b70d4e4eb5ba28',
    ),
    (
        'org.bitbucket.tickytacky.mirrormirror_2.apk',
        'feaa63df35b4635cf091513dfcd6d11209632555efdfc47e33b70d4e4eb5ba28',
    ),
    (
        'org.bitbucket.tickytacky.mirrormirror_3.apk',
        'feaa63df35b4635cf091513dfcd6d11209632555efdfc47e33b70d4e4eb5ba28',
    ),
    (
        'org.bitbucket.tickytacky.mirrormirror_4.apk',
        'feaa63df35b4635cf091513dfcd6d11209632555efdfc47e33b70d4e4eb5ba28',
    ),
    (
        'org.dyndns.fules.ck_20.apk',
        '9326a2cc1a2f148202bc7837a0af3b81200bd37fd359c9e13a2296a71d342056',
    ),
    (
        'org.sajeg.fallingblocks_3.apk',
        '033389681f4288fdb3e72a28058c8506233ca50de75452ab6c9c76ea1ca2d70f',
    ),
    (
        'repo/com.example.test.helloworld_1.apk',
        'c3a5ca5465a7585a1bda30218ae4017083605e3576867aa897d724208d99696c',
    ),
    (
        'repo/com.politedroid_3.apk',
        '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
    ),
    (
        'repo/com.politedroid_4.apk',
        '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
    ),
    (
        'repo/com.politedroid_5.apk',
        '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
    ),
    (
        'repo/com.politedroid_6.apk',
        '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
    ),
    (
        'repo/duplicate.permisssions_9999999.apk',
        '659e1fd284549f70d13fb02c620100e27eeea3420558cce62b0f5d4cf2b77d84',
    ),
    (
        'repo/info.zwanenburg.caffeinetile_4.apk',
        '51cfa5c8a743833ad89acf81cb755936876a5c8b8eca54d1ffdcec0cdca25d0e',
    ),
    (
        'repo/no.min.target.sdk_987.apk',
        '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
    ),
    (
        'repo/obb.main.oldversion_1444412523.apk',
        '818e469465f96b704e27be2fee4c63ab9f83ddf30e7a34c7371a4728d83b0bc1',
    ),
    (
        'repo/obb.main.twoversions_1101613.apk',
        '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
    ),
    (
        'repo/obb.main.twoversions_1101615.apk',
        '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
    ),
    (
        'repo/obb.main.twoversions_1101617.apk',
        '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
    ),
    (
        'repo/obb.mainpatch.current_1619.apk',
        '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
    ),
    (
        'repo/obb.mainpatch.current_1619_another-release-key.apk',
        'ce9e200667f02d96d49891a2e08a3c178870e91853d61bdd33ef5f0b54701aa5',
    ),
    (
        'repo/souch.smsbypass_9.apk',
        'd3aec784b1fd71549fc22c999789122e3639895db6bd585da5835fbe3db6985c',
    ),
    (
        'repo/urzip-; Рахма́, [rɐxˈmanʲɪnəf] سيرجي_رخمانينوف 谢·.apk',
        '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
    ),
    (
        'repo/v1.v2.sig_1020.apk',
        '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
    ),
    (
        'urzip-release.apk',
        '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
    ),
    (
        'urzip.apk',
        '7eabd8c15de883d1e82b5df2fd4f7f769e498078e9ad6dc901f0e96db77ceac3',
    ),
)
APKS_WITHOUT_JAR_SIGNATURES = (
    (
        'issue-1128-poc1.apk',  # APK v3 Signature only
        '1dbb8be012293e988a0820f7d455b07abd267d2c0b500fc793fcfd80141cb5ce',
    ),
    (
        'issue-1128-poc2.apk',  # APK v3 Signature only
        '1dbb8be012293e988a0820f7d455b07abd267d2c0b500fc793fcfd80141cb5ce',
    ),
    (
        'issue-1128-min-sdk-30-poc.apk',  # APK v3 Signature only
        '09350d5f3460a8a0ea5cf6b68ccd296a58754f7e683ba6aa08c19be8353504f3',
    ),
    (
        'v2.only.sig_2.apk',
        '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
    ),
)


class SignerExtractionTest(unittest.TestCase):
    """Test extraction of the signer certificate from JARs and APKs

    These fingerprints can be confirmed with:
    apksigner verify --print-certs foo.apk | grep SHA-256
    keytool -printcert -file ____.RSA
    """

    def setUp(self):
        os.chdir(basedir)
        self._td = mkdtemp()
        self.testdir = self._td.name

        self.apksigner = shutil.which('apksigner')
        self.keytool = shutil.which('keytool')

    def tearDown(self):
        self._td.cleanup()

    def test_get_first_signer_certificate_with_jars(self):
        for jar in (
            'signindex/guardianproject-v1.jar',
            'signindex/guardianproject.jar',
            'signindex/testy.jar',
        ):
            outdir = os.path.join(self.testdir, jar[:-4].replace('/', '_'))
            os.mkdir(outdir)
            fdroidserver.common.apk_extract_signatures(jar, outdir)
            certs = glob.glob(os.path.join(outdir, '*.RSA'))
            with open(certs[0], 'rb') as fp:
                self.assertEqual(
                    fdroidserver.common.get_certificate(fp.read()),
                    fdroidserver.common.get_first_signer_certificate(jar),
                )

    @unittest.skip("slow and only needed when adding to APKS_WITH_JAR_SIGNATURES")
    def test_vs_keytool(self):
        if not self.keytool:
            self.skipTest('requires keytool to run')
        pat = re.compile(r'[0-9A-F:]{95}')
        cmd = [self.keytool, '-printcert', '-jarfile']
        for apk, fingerprint in APKS_WITH_JAR_SIGNATURES:
            o = subprocess.check_output(cmd + [apk], text=True)
            try:
                self.assertEqual(
                    fingerprint,
                    pat.search(o).group().replace(':', '').lower(),
                )
            except AttributeError as e:
                print(e, o)

    @unittest.skip("slow and only needed when adding to APKS_WITH_JAR_SIGNATURES")
    def test_vs_apksigner(self):
        if not self.apksigner:
            self.skipTest('requires apksigner to run')
        pat = re.compile(r'\s[0-9a-f]{64}\s')
        cmd = [self.apksigner, 'verify', '--print-certs']
        for apk, fingerprint in APKS_WITH_JAR_SIGNATURES + APKS_WITHOUT_JAR_SIGNATURES:
            output = subprocess.check_output(cmd + [apk], text=True)
            self.assertEqual(
                fingerprint,
                pat.search(output).group().strip(),
                apk + " should have matching signer fingerprints",
            )

    def test_apk_signer_fingerprint_with_v1_apks(self):
        for apk, fingerprint in APKS_WITH_JAR_SIGNATURES:
            self.assertEqual(
                fingerprint,
                fdroidserver.common.apk_signer_fingerprint(apk),
                f'apk_signer_fingerprint should match stored fingerprint for {apk}',
            )

    def test_apk_signer_fingerprint_without_v1_apks(self):
        for apk, fingerprint in APKS_WITHOUT_JAR_SIGNATURES:
            self.assertEqual(
                fingerprint,
                fdroidserver.common.apk_signer_fingerprint(apk),
                f'apk_signer_fingerprint should match stored fingerprint for {apk}',
            )

    def test_get_first_signer_certificate_with_unsigned_jar(self):
        self.assertIsNone(
            fdroidserver.common.get_first_signer_certificate('signindex/unsigned.jar')
        )

    def test_apk_extract_fingerprint(self):
        """Test extraction of JAR signatures (does not cover APK v2+ extraction)."""
        for apk, fingerprint in APKS_WITH_JAR_SIGNATURES:
            outdir = os.path.join(self.testdir, apk[:-4].replace('/', '_'))
            os.mkdir(outdir)
            try:
                fdroidserver.common.apk_extract_signatures(apk, outdir)
            except fdroidserver.apksigcopier.APKSigCopierError:
                # nothing to test here when this error is thrown
                continue
            v1_certs = [str(cert) for cert in Path(outdir).glob('*.[DR]SA')]
            cert = fdroidserver.common.get_certificate(
                signature_block_file=Path(v1_certs[0]).read_bytes(),
                signature_file=Path(v1_certs[0][:-4] + '.SF').read_bytes(),
            )
            self.assertEqual(
                fingerprint,
                fdroidserver.common.signer_fingerprint(cert),
            )
            apkobject = fdroidserver.common.get_androguard_APK(apk, skip_analysis=True)
            v2_certs = apkobject.get_certificates_der_v2()
            if v2_certs:
                if v1_certs:
                    self.assertEqual(len(v1_certs), len(v2_certs))
                self.assertEqual(
                    fingerprint,
                    fdroidserver.common.signer_fingerprint(v2_certs[0]),
                )
            v3_certs = apkobject.get_certificates_der_v3()
            if v3_certs:
                if v2_certs:
                    self.assertEqual(len(v2_certs), len(v3_certs))
                self.assertEqual(
                    fingerprint,
                    fdroidserver.common.signer_fingerprint(v3_certs[0]),
                )


class ConfigOptionsScopeTest(unittest.TestCase):
    """Test assumptions about variable scope for "config" and "options".

    The ancient architecture of config and options in fdroidserver has
    weird issues around unexpected scope, like there are cases where
    the global config is not the same as the module-level config, and
    more.

    This is about describing what is happening, it is not about
    documenting behaviors that are good design. The config and options
    handling should really be refactored into a well-known, workable
    Pythonic pattern.

    """

    def setUp(self):
        # these are declared as None at the top of the module file
        fdroidserver.common.config = None
        fdroidserver.common.options = None

    def tearDown(self):
        fdroidserver.common.config = None
        fdroidserver.common.options = None
        if 'config' in globals():
            global config
            del config
        if 'options' in globals():
            global options
            del options

    def test_parse_args(self):
        """Test that options is properly set up at the module-level and not global."""
        self.assertFalse('options' in globals())
        self.assertIsNone(fdroidserver.common.options)
        parser = ArgumentParser()
        fdroidserver.common.setup_global_opts(parser)
        with mock.patch('sys.argv', ['$0']):
            o = fdroidserver.common.parse_args(parser)
        self.assertEqual(o, fdroidserver.common.options)

        # No function should set options as a global, and the global
        # keyword does not create the variable.
        global options
        with self.assertRaises(NameError):
            options
        self.assertFalse('options' in globals())

    def test_parse_args_without_args(self):
        """Test that the parsing function works fine when there are no args."""
        parser = ArgumentParser()
        fdroidserver.common.setup_global_opts(parser)
        with mock.patch('sys.argv', ['$0']):
            o = fdroidserver.common.parse_args(parser)
        self.assertFalse(o.verbose)

    def test_parse_args_with_args(self):
        parser = ArgumentParser()
        fdroidserver.common.setup_global_opts(parser)
        with mock.patch('sys.argv', ['$0', '-v']):
            o = fdroidserver.common.parse_args(parser)
        self.assertTrue(o.verbose)

    def test_get_config(self):
        """Show how the module-level variables are initialized."""
        self.assertTrue('config' not in vars() and 'config' not in globals())
        self.assertIsNone(fdroidserver.common.config)
        config = fdroidserver.common.read_config()
        self.assertIsNotNone(fdroidserver.common.config)
        self.assertEqual(dict, type(config))
        self.assertEqual(config, fdroidserver.common.config)

    def test_get_config_global(self):
        """Test assumptions about variable scope using global keyword."""
        global config
        self.assertTrue('config' not in vars() and 'config' not in globals())
        self.assertIsNone(fdroidserver.common.config)
        c = fdroidserver.common.read_config()
        self.assertIsNotNone(fdroidserver.common.config)
        self.assertEqual(dict, type(c))
        self.assertEqual(c, fdroidserver.common.config)
        self.assertTrue(
            'config' not in vars() and 'config' not in globals(),
            "The config should not be set in the global context, only module-level.",
        )
