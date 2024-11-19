#!/usr/bin/env python3

import os
import shutil
import tempfile
import textwrap
import unittest
import yaml
from pathlib import Path
from unittest import mock

from .testcommon import TmpCwd, mkdtemp

import fdroidserver.build
import fdroidserver.common


class FakeProcess:
    output = 'fake output'
    returncode = 0

    def __init__(self, args, **kwargs):
        print('FakeFDroidPopen', args, kwargs)


class Options:
    keep_when_not_allowed = False


class BuildTest(unittest.TestCase):
    '''fdroidserver/build.py'''

    def setUp(self):
        self.basedir = str(Path(__file__).parent)
        os.chdir(self.basedir)
        fdroidserver.common.config = None
        fdroidserver.build.config = None
        fdroidserver.build.options = None
        self._td = mkdtemp()
        self.testdir = self._td.name

    def tearDown(self):
        os.chdir(self.basedir)
        self._td.cleanup()

    def create_fake_android_home(self, d):
        os.makedirs(os.path.join(d, 'build-tools'), exist_ok=True)
        os.makedirs(os.path.join(d, 'platform-tools'), exist_ok=True)
        os.makedirs(os.path.join(d, 'tools'), exist_ok=True)

    def test_get_apk_metadata(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.build.config = config
        try:
            config['aapt'] = fdroidserver.common.find_sdk_tools_cmd('aapt')
        except fdroidserver.exception.FDroidException:
            pass  # aapt is not required if androguard is present

        testcases = [
            (
                'repo/obb.main.twoversions_1101613.apk',
                'obb.main.twoversions',
                1101613,
                '0.1',
                None,
            ),
            (
                'org.bitbucket.tickytacky.mirrormirror_1.apk',
                'org.bitbucket.tickytacky.mirrormirror',
                1,
                '1.0',
                None,
            ),
            (
                'org.bitbucket.tickytacky.mirrormirror_2.apk',
                'org.bitbucket.tickytacky.mirrormirror',
                2,
                '1.0.1',
                None,
            ),
            (
                'org.bitbucket.tickytacky.mirrormirror_3.apk',
                'org.bitbucket.tickytacky.mirrormirror',
                3,
                '1.0.2',
                None,
            ),
            (
                'org.bitbucket.tickytacky.mirrormirror_4.apk',
                'org.bitbucket.tickytacky.mirrormirror',
                4,
                '1.0.3',
                None,
            ),
            (
                'org.dyndns.fules.ck_20.apk',
                'org.dyndns.fules.ck',
                20,
                'v1.6pre2',
                [
                    'arm64-v8a',
                    'armeabi',
                    'armeabi-v7a',
                    'mips',
                    'mips64',
                    'x86',
                    'x86_64',
                ],
            ),
            ('urzip.apk', 'info.guardianproject.urzip', 100, '0.1', None),
            ('urzip-badcert.apk', 'info.guardianproject.urzip', 100, '0.1', None),
            ('urzip-badsig.apk', 'info.guardianproject.urzip', 100, '0.1', None),
            ('urzip-release.apk', 'info.guardianproject.urzip', 100, '0.1', None),
            (
                'urzip-release-unsigned.apk',
                'info.guardianproject.urzip',
                100,
                '0.1',
                None,
            ),
            ('repo/com.politedroid_3.apk', 'com.politedroid', 3, '1.2', None),
            ('repo/com.politedroid_4.apk', 'com.politedroid', 4, '1.3', None),
            ('repo/com.politedroid_5.apk', 'com.politedroid', 5, '1.4', None),
            ('repo/com.politedroid_6.apk', 'com.politedroid', 6, '1.5', None),
            (
                'repo/duplicate.permisssions_9999999.apk',
                'duplicate.permisssions',
                9999999,
                '',
                None,
            ),
            (
                'repo/info.zwanenburg.caffeinetile_4.apk',
                'info.zwanenburg.caffeinetile',
                4,
                '1.3',
                None,
            ),
            (
                'repo/obb.main.oldversion_1444412523.apk',
                'obb.main.oldversion',
                1444412523,
                '0.1',
                None,
            ),
            (
                'repo/obb.mainpatch.current_1619_another-release-key.apk',
                'obb.mainpatch.current',
                1619,
                '0.1',
                None,
            ),
            (
                'repo/obb.mainpatch.current_1619.apk',
                'obb.mainpatch.current',
                1619,
                '0.1',
                None,
            ),
            (
                'repo/obb.main.twoversions_1101613.apk',
                'obb.main.twoversions',
                1101613,
                '0.1',
                None,
            ),
            (
                'repo/obb.main.twoversions_1101615.apk',
                'obb.main.twoversions',
                1101615,
                '0.1',
                None,
            ),
            (
                'repo/obb.main.twoversions_1101617.apk',
                'obb.main.twoversions',
                1101617,
                '0.1',
                None,
            ),
            (
                'repo/urzip-; Рахма́, [rɐxˈmanʲɪnəf] سيرجي_رخمانينوف 谢·.apk',
                'info.guardianproject.urzip',
                100,
                '0.1',
                None,
            ),
        ]
        for apkfilename, appid, versionCode, versionName, nativecode in testcases:
            app = fdroidserver.metadata.App()
            app.id = appid
            build = fdroidserver.metadata.Build()
            build.buildjni = ['yes'] if nativecode else build.buildjni
            build.versionCode = versionCode
            build.versionName = versionName
            vc, vn = fdroidserver.build.get_metadata_from_apk(app, build, apkfilename)
            self.assertEqual(versionCode, vc)
            self.assertEqual(versionName, vn)

    @mock.patch('fdroidserver.common.get_apk_id')
    @mock.patch('fdroidserver.build.FDroidPopen')
    @mock.patch('fdroidserver.common.is_debuggable_or_testOnly', lambda f: False)
    @mock.patch('fdroidserver.common.get_native_code', lambda f: 'x86')
    def test_build_local_maven(self, fake_FDroidPopen, fake_get_apk_id):
        """Test build_local() with a maven project"""

        # pylint: disable=unused-argument
        def _side_effect(cmd, cwd=None):
            p = mock.MagicMock()
            p.output = '[INFO] fake apkbuilder target/no.apk'
            with open(os.path.join(self.testdir, 'target', 'no.apk'), 'w') as fp:
                fp.write('placeholder')
            p.returncode = 0
            return p

        fake_FDroidPopen.side_effect = _side_effect
        os.chdir(self.testdir)
        os.mkdir('target')
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.build.config = config
        fdroidserver.build.options = mock.Mock()
        fdroidserver.build.options.scan_binary = False
        fdroidserver.build.options.notarball = True
        fdroidserver.build.options.skipscan = False

        app = fdroidserver.metadata.App()
        app.id = 'mocked.app.id'
        build = fdroidserver.metadata.Build()
        build.commit = '1.0'
        build.versionCode = 1
        build.versionName = '1.0'
        fake_get_apk_id.side_effect = lambda f: (
            app.id,
            build.versionCode,
            build.versionName,
        )
        vcs = mock.Mock()

        build.maven = 'yes@..'
        fdroidserver.build.build_local(
            app,
            build,
            vcs,
            build_dir=self.testdir,
            output_dir=self.testdir,
            log_dir=os.getcwd(),
            srclib_dir=None,
            extlib_dir=None,
            tmp_dir=None,
            force=False,
            onserver=True,
            refresh=False,
        )

        build.maven = 'yes'
        fdroidserver.build.build_local(
            app,
            build,
            vcs,
            build_dir=self.testdir,
            output_dir=self.testdir,
            log_dir=os.getcwd(),
            srclib_dir=None,
            extlib_dir=None,
            tmp_dir=None,
            force=False,
            onserver=True,
            refresh=False,
        )

    @mock.patch('sdkmanager.build_package_list', lambda use_net: None)
    def test_build_local_ndk(self):
        """Test if `fdroid build` detects installed NDKs and auto-installs when missing"""
        with tempfile.TemporaryDirectory() as testdir, TmpCwd(
            testdir
        ), tempfile.TemporaryDirectory() as sdk_path:
            config = {'ndk_paths': {}, 'sdk_path': sdk_path}
            fdroidserver.common.config = config
            fdroidserver.build.config = config
            fdroidserver.build.options = mock.Mock()
            fdroidserver.build.options.scan_binary = False
            fdroidserver.build.options.notarball = True
            fdroidserver.build.options.skipscan = True

            app = fdroidserver.metadata.App()
            app.id = 'mocked.app.id'
            build = fdroidserver.metadata.Build()
            build.commit = '1.0'
            build.output = app.id + '.apk'
            build.versionCode = 1
            build.versionName = '1.0'
            build.ndk = 'r21e'  # aka 21.4.7075529
            ndk_version = '21.4.7075529'
            ndk_dir = Path(config['sdk_path']) / 'ndk' / ndk_version
            vcs = mock.Mock()

            def make_fake_apk(output, build):
                with open(build.output, 'w') as fp:
                    fp.write('APK PLACEHOLDER')
                return output

            # pylint: disable=unused-argument
            def fake_sdkmanager_install(to_install, android_home=None):
                ndk_dir.mkdir(parents=True)
                self.assertNotEqual(ndk_version, to_install)  # converts r21e to version
                with (ndk_dir / 'source.properties').open('w') as fp:
                    fp.write('Pkg.Revision = %s\n' % ndk_version)

            # use "as _ignored" just to make a pretty layout
            with mock.patch(
                'fdroidserver.common.replace_build_vars', wraps=make_fake_apk
            ) as _ignored, mock.patch(
                'fdroidserver.common.get_native_code', return_value='x86'
            ) as _ignored, mock.patch(
                'fdroidserver.common.get_apk_id',
                return_value=(app.id, build.versionCode, build.versionName),
            ) as _ignored, mock.patch(
                'fdroidserver.common.sha256sum',
                return_value='ad7ce5467e18d40050dc51b8e7affc3e635c85bd8c59be62de32352328ed467e',
            ) as _ignored, mock.patch(
                'fdroidserver.common.is_debuggable_or_testOnly',
                return_value=False,
            ) as _ignored, mock.patch(
                'fdroidserver.build.FDroidPopen', FakeProcess
            ) as _ignored, mock.patch(
                'sdkmanager.install', wraps=fake_sdkmanager_install
            ) as _ignored:
                _ignored  # silence the linters
                with self.assertRaises(
                    fdroidserver.exception.FDroidException,
                    msg="No NDK setup, `fdroid build` should fail with error",
                ):
                    fdroidserver.build.build_local(
                        app,
                        build,
                        vcs,
                        build_dir=testdir,
                        output_dir=testdir,
                        log_dir=None,
                        srclib_dir=None,
                        extlib_dir=None,
                        tmp_dir=None,
                        force=False,
                        onserver=False,
                        refresh=False,
                    )
                # now run `fdroid build --onserver`
                print('now run `fdroid build --onserver`')
                self.assertFalse(ndk_dir.exists())
                self.assertFalse('r21e' in config['ndk_paths'])
                self.assertFalse(ndk_version in config['ndk_paths'])
                fdroidserver.build.build_local(
                    app,
                    build,
                    vcs,
                    build_dir=testdir,
                    output_dir=testdir,
                    log_dir=os.getcwd(),
                    srclib_dir=None,
                    extlib_dir=None,
                    tmp_dir=None,
                    force=False,
                    onserver=True,
                    refresh=False,
                )
                self.assertTrue(ndk_dir.exists())
                self.assertTrue(os.path.exists(config['ndk_paths'][ndk_version]))
                # All paths in the config must be strings, never pathlib.Path instances
                self.assertIsInstance(config['ndk_paths'][ndk_version], str)

    @mock.patch('sdkmanager.build_package_list', lambda use_net: None)
    @mock.patch('fdroidserver.build.FDroidPopen', FakeProcess)
    @mock.patch('fdroidserver.common.get_native_code', lambda _ignored: 'x86')
    @mock.patch('fdroidserver.common.is_debuggable_or_testOnly', lambda _ignored: False)
    @mock.patch(
        'fdroidserver.common.sha256sum',
        lambda f: 'ad7ce5467e18d40050dc51b8e7affc3e635c85bd8c59be62de32352328ed467e',
    )
    def test_build_local_ndk_some_installed(self):
        """Test if `fdroid build` detects installed NDKs and auto-installs when missing"""
        with tempfile.TemporaryDirectory() as testdir, TmpCwd(
            testdir
        ), tempfile.TemporaryDirectory() as sdk_path:
            ndk_r24 = os.path.join(sdk_path, 'ndk', '24.0.8215888')
            os.makedirs(ndk_r24)
            with open(os.path.join(ndk_r24, 'source.properties'), 'w') as fp:
                fp.write('Pkg.Revision = 24.0.8215888\n')
            config = {'ndk_paths': {'r24': ndk_r24}, 'sdk_path': sdk_path}
            fdroidserver.common.config = config
            fdroidserver.build.config = config
            fdroidserver.build.options = mock.Mock()
            fdroidserver.build.options.scan_binary = False
            fdroidserver.build.options.notarball = True
            fdroidserver.build.options.skipscan = True

            app = fdroidserver.metadata.App()
            app.id = 'mocked.app.id'
            build = fdroidserver.metadata.Build()
            build.commit = '1.0'
            build.output = app.id + '.apk'
            build.versionCode = 1
            build.versionName = '1.0'
            build.ndk = 'r21e'  # aka 21.4.7075529
            ndk_version = '21.4.7075529'
            ndk_dir = Path(config['sdk_path']) / 'ndk' / ndk_version
            vcs = mock.Mock()

            def make_fake_apk(output, build):
                with open(build.output, 'w') as fp:
                    fp.write('APK PLACEHOLDER')
                return output

            # pylint: disable=unused-argument
            def fake_sdkmanager_install(to_install, android_home=None):
                ndk_dir.mkdir(parents=True)
                self.assertNotEqual(ndk_version, to_install)  # converts r21e to version
                with (ndk_dir / 'source.properties').open('w') as fp:
                    fp.write('Pkg.Revision = %s\n' % ndk_version)

            # use "as _ignored" just to make a pretty layout
            with mock.patch(
                'fdroidserver.common.replace_build_vars', wraps=make_fake_apk
            ) as _ignored, mock.patch(
                'fdroidserver.common.get_apk_id',
                return_value=(app.id, build.versionCode, build.versionName),
            ) as _ignored, mock.patch(
                'sdkmanager.install', wraps=fake_sdkmanager_install
            ) as _ignored:
                _ignored  # silence the linters
                self.assertFalse(ndk_dir.exists())
                self.assertFalse('r21e' in config['ndk_paths'])
                self.assertFalse(ndk_version in config['ndk_paths'])
                fdroidserver.build.build_local(
                    app,
                    build,
                    vcs,
                    build_dir=testdir,
                    output_dir=testdir,
                    log_dir=os.getcwd(),
                    srclib_dir=None,
                    extlib_dir=None,
                    tmp_dir=None,
                    force=False,
                    onserver=True,
                    refresh=False,
                )
                self.assertTrue(ndk_dir.exists())
                self.assertTrue(os.path.exists(config['ndk_paths'][ndk_version]))

    def test_build_local_clean(self):
        """Test if `fdroid build` cleans ant and gradle build products"""
        os.chdir(self.testdir)
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.build.config = config
        fdroidserver.build.options = mock.Mock()
        fdroidserver.build.options.scan_binary = False
        fdroidserver.build.options.notarball = True
        fdroidserver.build.options.skipscan = False

        app = fdroidserver.metadata.App()
        app.id = 'mocked.app.id'
        build = fdroidserver.metadata.Build()
        build.commit = '1.0'
        build.output = app.id + '.apk'
        build.scandelete = ['baz.so']
        build.scanignore = ['foo.aar']
        build.versionCode = 1
        build.versionName = '1.0'
        vcs = mock.Mock()

        os.mkdir('reports')
        os.mkdir('target')

        for f in ('baz.so', 'foo.aar', 'gradle-wrapper.jar'):
            with open(f, 'w') as fp:
                fp.write('placeholder')
            self.assertTrue(os.path.exists(f))

        os.mkdir('build')
        os.mkdir('build/reports')
        with open('build.gradle', 'w', encoding='utf-8') as fp:
            fp.write('// placeholder')

        os.mkdir('bin')
        os.mkdir('gen')
        with open('build.xml', 'w', encoding='utf-8') as fp:
            fp.write(
                textwrap.dedent(
                    """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
                <project basedir="." default="clean" name="mockapp">
                <target name="release"/>
                <target name="clean"/>
                </project>"""
                )
            )

        def make_fake_apk(output, build):
            with open(build.output, 'w') as fp:
                fp.write('APK PLACEHOLDER')
            return output

        with mock.patch('fdroidserver.common.replace_build_vars', wraps=make_fake_apk):
            with mock.patch('fdroidserver.common.get_native_code', return_value='x86'):
                with mock.patch(
                    'fdroidserver.common.get_apk_id',
                    return_value=(app.id, build.versionCode, build.versionName),
                ):
                    with mock.patch(
                        'fdroidserver.common.is_debuggable_or_testOnly',
                        return_value=False,
                    ):
                        fdroidserver.build.build_local(
                            app,
                            build,
                            vcs,
                            build_dir=self.testdir,
                            output_dir=self.testdir,
                            log_dir=None,
                            srclib_dir=None,
                            extlib_dir=None,
                            tmp_dir=None,
                            force=False,
                            onserver=False,
                            refresh=False,
                        )

        self.assertTrue(os.path.exists('foo.aar'))
        self.assertTrue(os.path.isdir('build'))
        self.assertTrue(os.path.isdir('reports'))
        self.assertTrue(os.path.isdir('target'))
        self.assertFalse(os.path.exists('baz.so'))
        self.assertFalse(os.path.exists('bin'))
        self.assertFalse(os.path.exists('build/reports'))
        self.assertFalse(os.path.exists('gen'))
        self.assertFalse(os.path.exists('gradle-wrapper.jar'))

    def test_scan_with_extlib(self):
        os.chdir(self.testdir)
        os.mkdir("build")

        config = fdroidserver.common.read_config()
        config['sdk_path'] = os.getenv('ANDROID_HOME')
        config['ndk_paths'] = {'r10d': os.getenv('ANDROID_NDK_HOME')}
        fdroidserver.common.config = config
        app = fdroidserver.metadata.App()
        app.id = 'com.gpl.rpg.AndorsTrail'
        build = fdroidserver.metadata.Build()
        build.commit = 'master'
        build.androidupdate = ['no']
        os.makedirs("extlib/android")
        # write a fake binary jar file the scanner should definitely error on
        with open('extlib/android/android-support-v4r11.jar', 'wb') as file:
            file.write(
                b'PK\x03\x04\x14\x00\x08\x00\x08\x00-\x0eiA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x04\x00META-INF/\xfe\xca\x00\x00\x03\x00PK\x07\x08\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00'
            )

        class FakeVcs:
            # no need to change to the correct commit here
            def gotorevision(self, rev, refresh=True):
                pass

            def getsrclib(self):
                return None

            def deinitsubmodules(self):
                pass

        # Test we trigger a scanner error without extlibs
        build.extlibs = []
        os.makedirs('build/libs')
        shutil.copy('extlib/android/android-support-v4r11.jar', 'build/libs')
        fdroidserver.common.prepare_source(
            FakeVcs(), app, build, "build", "ignore", "extlib"
        )
        count = fdroidserver.scanner.scan_source("build", build)
        self.assertEqual(1, count, "Should produce a scanner error without extlib")

        # Now try again as an extlib
        build.extlibs = ['android/android-support-v4r11.jar']
        fdroidserver.common.prepare_source(
            FakeVcs(), app, build, "build", "ignore", "extlib"
        )
        count = fdroidserver.scanner.scan_source("build", build)
        self.assertEqual(0, count, "Shouldn't error on jar from extlib")

    def test_failed_verifies_are_not_in_unsigned(self):
        os.chdir(self.testdir)
        sdk_path = os.path.join(self.testdir, 'android-sdk')
        self.create_fake_android_home(sdk_path)
        with open('config.yml', 'w') as fp:
            yaml.dump({'sdk_path': sdk_path, 'keep_when_not_allowed': True}, fp)
        os.chmod('config.yml', 0o600)
        fdroidserver.build.config = fdroidserver.common.read_config()

        os.mkdir('metadata')
        appid = 'info.guardianproject.checkey'
        metadata_file = os.path.join('metadata', appid + '.yml')
        shutil.copy(os.path.join(self.basedir, metadata_file), 'metadata')
        with open(metadata_file) as fp:
            app = fdroidserver.metadata.App(yaml.safe_load(fp))
        app['RepoType'] = 'git'
        app[
            'Binaries'
        ] = 'https://example.com/fdroid/repo/info.guardianproject.checkey_%v.apk'
        build = fdroidserver.metadata.Build(
            {
                'versionCode': 123,
                'versionName': '1.2.3',
                'commit': '1.2.3',
                'disable': False,
            }
        )
        app['Builds'] = [build]
        fdroidserver.metadata.write_metadata(metadata_file, app)

        os.makedirs(os.path.join('unsigned', 'binaries'))
        production_result = os.path.join(
            'unsigned', '%s_%d.apk' % (appid, build['versionCode'])
        )
        production_compare_file = os.path.join(
            'unsigned', 'binaries', '%s_%d.binary.apk' % (appid, build['versionCode'])
        )
        os.makedirs(os.path.join('tmp', 'binaries'))
        test_result = os.path.join('tmp', '%s_%d.apk' % (appid, build['versionCode']))
        test_compare_file = os.path.join(
            'tmp', 'binaries', '%s_%d.binary.apk' % (appid, build['versionCode'])
        )
        with mock.patch(
            'fdroidserver.common.force_exit', lambda *args: None
        ) as a, mock.patch(
            'fdroidserver.common.get_android_tools_version_log', lambda: 'fake'
        ) as b, mock.patch(
            'fdroidserver.common.FDroidPopen', FakeProcess
        ) as c, mock.patch(
            'fdroidserver.build.FDroidPopen', FakeProcess
        ) as d, mock.patch(
            'fdroidserver.build.trybuild', lambda *args: True
        ) as e, mock.patch(
            'fdroidserver.net.download_file', lambda *args, **kwargs: None
        ) as f:
            a, b, c, d, e, f  # silence linters' "unused" warnings

            with mock.patch('sys.argv', ['fdroid build', appid]):
                # successful comparison
                open(production_result, 'w').close()
                open(production_compare_file, 'w').close()
                with mock.patch('fdroidserver.common.verify_apks', lambda *args: None):
                    fdroidserver.build.main()
                self.assertTrue(os.path.exists(production_result))
                self.assertTrue(os.path.exists(production_compare_file))
                # failed comparison
                open(production_result, 'w').close()
                open(production_compare_file, 'w').close()
                with mock.patch(
                    'fdroidserver.common.verify_apks', lambda *args: 'failed'
                ):
                    fdroidserver.build.main()
                self.assertFalse(os.path.exists(production_result))
                self.assertFalse(os.path.exists(production_compare_file))

            with mock.patch('sys.argv', ['fdroid build', '--test', appid]):
                # successful comparison
                open(test_result, 'w').close()
                open(test_compare_file, 'w').close()
                with mock.patch('fdroidserver.common.verify_apks', lambda *args: None):
                    fdroidserver.build.main()
                self.assertTrue(os.path.exists(test_result))
                self.assertTrue(os.path.exists(test_compare_file))
                self.assertFalse(os.path.exists(production_result))
                self.assertFalse(os.path.exists(production_compare_file))
                # failed comparison
                open(test_result, 'w').close()
                open(test_compare_file, 'w').close()
                with mock.patch(
                    'fdroidserver.common.verify_apks', lambda *args: 'failed'
                ):
                    fdroidserver.build.main()
                self.assertTrue(os.path.exists(test_result))
                self.assertFalse(os.path.exists(test_compare_file))
                self.assertFalse(os.path.exists(production_result))
                self.assertFalse(os.path.exists(production_compare_file))

    def test_failed_allowedapksigningkeys_are_not_in_unsigned(self):
        os.chdir(self.testdir)
        os.mkdir('metadata')
        appid = 'info.guardianproject.checkey'
        metadata_file = os.path.join('metadata', appid + '.yml')
        shutil.copy(os.path.join(self.basedir, metadata_file), 'metadata')
        with open(metadata_file) as fp:
            app = fdroidserver.metadata.App(yaml.safe_load(fp))
        app['RepoType'] = 'git'
        app[
            'Binaries'
        ] = 'https://example.com/fdroid/repo/info.guardianproject.checkey_%v.apk'
        build = fdroidserver.metadata.Build(
            {
                'versionCode': 123,
                'versionName': '1.2.3',
                'commit': '1.2.3',
                'disable': False,
            }
        )
        app['Builds'] = [build]
        expected_key = 'a' * 64
        bogus_key = 'b' * 64
        app['AllowedAPKSigningKeys'] = [expected_key]
        fdroidserver.metadata.write_metadata(metadata_file, app)

        os.makedirs(os.path.join('unsigned', 'binaries'))
        production_result = os.path.join(
            'unsigned', '%s_%d.apk' % (appid, build['versionCode'])
        )
        production_compare_file = os.path.join(
            'unsigned', 'binaries', '%s_%d.binary.apk' % (appid, build['versionCode'])
        )
        os.makedirs(os.path.join('tmp', 'binaries'))
        test_result = os.path.join('tmp', '%s_%d.apk' % (appid, build['versionCode']))
        test_compare_file = os.path.join(
            'tmp', 'binaries', '%s_%d.binary.apk' % (appid, build['versionCode'])
        )
        with mock.patch(
            'fdroidserver.common.force_exit', lambda *args: None
        ) as a, mock.patch(
            'fdroidserver.common.get_android_tools_version_log', lambda: 'fake'
        ) as b, mock.patch(
            'fdroidserver.common.FDroidPopen', FakeProcess
        ) as c, mock.patch(
            'fdroidserver.build.FDroidPopen', FakeProcess
        ) as d, mock.patch(
            'fdroidserver.build.trybuild', lambda *args: True
        ) as e, mock.patch(
            'fdroidserver.net.download_file', lambda *args, **kwargs: None
        ) as f:
            a, b, c, d, e, f  # silence linters' "unused" warnings

            with mock.patch('sys.argv', ['fdroid build', appid]):
                # successful comparison, successful signer
                open(production_result, 'w').close()
                open(production_compare_file, 'w').close()
                with mock.patch(
                    'fdroidserver.common.verify_apks', lambda *args: None
                ) as g, mock.patch(
                    'fdroidserver.common.apk_signer_fingerprint',
                    lambda *args: expected_key,
                ) as h:
                    g, h
                    fdroidserver.build.main()
                self.assertTrue(os.path.exists(production_result))
                self.assertTrue(os.path.exists(production_compare_file))
                # successful comparison, failed signer
                open(production_result, 'w').close()
                open(production_compare_file, 'w').close()
                with mock.patch(
                    'fdroidserver.common.verify_apks', lambda *args: None
                ) as g, mock.patch(
                    'fdroidserver.common.apk_signer_fingerprint',
                    lambda *args: bogus_key,
                ) as h:
                    g, h
                    fdroidserver.build.main()
                self.assertFalse(os.path.exists(production_result))
                self.assertFalse(os.path.exists(production_compare_file))
                # failed comparison
                open(production_result, 'w').close()
                open(production_compare_file, 'w').close()
                with mock.patch(
                    'fdroidserver.common.verify_apks', lambda *args: 'failed'
                ):
                    fdroidserver.build.main()
                self.assertFalse(os.path.exists(production_result))
                self.assertFalse(os.path.exists(production_compare_file))

            with mock.patch('sys.argv', ['fdroid build', '--test', appid]):
                # successful comparison, successful signer
                open(test_result, 'w').close()
                open(test_compare_file, 'w').close()
                with mock.patch(
                    'fdroidserver.common.verify_apks', lambda *args: None
                ) as g, mock.patch(
                    'fdroidserver.common.apk_signer_fingerprint',
                    lambda *args: expected_key,
                ) as h:
                    g, h
                    fdroidserver.build.main()
                self.assertTrue(os.path.exists(test_result))
                self.assertTrue(os.path.exists(test_compare_file))
                self.assertFalse(os.path.exists(production_result))
                self.assertFalse(os.path.exists(production_compare_file))
                # successful comparison, failed signer
                open(test_result, 'w').close()
                open(test_compare_file, 'w').close()
                with mock.patch(
                    'fdroidserver.common.verify_apks', lambda *args: None
                ) as g, mock.patch(
                    'fdroidserver.common.apk_signer_fingerprint',
                    lambda *args: bogus_key,
                ) as h:
                    g, h
                    fdroidserver.build.main()
                self.assertTrue(os.path.exists(test_result))
                self.assertFalse(os.path.exists(test_compare_file))
                self.assertFalse(os.path.exists(production_result))
                self.assertFalse(os.path.exists(production_compare_file))
                # failed comparison
                open(test_result, 'w').close()
                open(test_compare_file, 'w').close()
                with mock.patch(
                    'fdroidserver.common.verify_apks', lambda *args: 'failed'
                ):
                    fdroidserver.build.main()
                self.assertTrue(os.path.exists(test_result))
                self.assertFalse(os.path.exists(test_compare_file))
                self.assertFalse(os.path.exists(production_result))
                self.assertFalse(os.path.exists(production_compare_file))

    @mock.patch('fdroidserver.vmtools.get_build_vm')
    @mock.patch('fdroidserver.vmtools.get_clean_builder')
    @mock.patch('paramiko.SSHClient')
    @mock.patch('subprocess.check_output')
    def test_build_server_cmdline(
        self,
        subprocess_check_output,
        paramiko_SSHClient,
        fdroidserver_vmtools_get_clean_builder,
        fdroidserver_vmtools_get_build_vm,
    ):
        """Test command line flags passed to the buildserver"""
        global cmdline_args
        test_flag = ['', False]

        def _exec_command(args):
            flag = test_flag[0]
            if test_flag[1]:
                self.assertTrue(flag in args, flag + ' should be present')
            else:
                self.assertFalse(flag in args, flag + ' should not be present')

        os.chdir(self.testdir)
        os.mkdir('tmp')

        chan = mock.MagicMock()
        chan.exec_command = _exec_command
        chan.recv_exit_status = lambda: 0
        transport = mock.MagicMock()
        transport.open_session = mock.Mock(return_value=chan)
        sshs = mock.MagicMock()
        sshs.get_transport = mock.Mock(return_value=transport)
        paramiko_SSHClient.return_value = sshs
        subprocess_check_output.return_value = (
            b'0123456789abcdef0123456789abcdefcafebabe'
        )
        fdroidserver_vmtools_get_clean_builder.side_effect = lambda s: {
            'hostname': 'example.com',
            'idfile': '/path/to/id/file',
            'port': 123,
            'user': 'fake',
        }
        fdroidserver.common.config = {'sdk_path': '/fake/android/sdk/path'}
        fdroidserver.build.options = mock.MagicMock()
        vcs = mock.Mock()
        vcs.getsrclib = mock.Mock(return_value=None)
        app = fdroidserver.metadata.App()
        app['metadatapath'] = 'metadata/fake.id.yml'
        app['id'] = 'fake.id'
        app['RepoType'] = 'git'
        build = fdroidserver.metadata.Build(
            {
                'versionCode': 123,
                'versionName': '1.2.3',
                'commit': '1.2.3',
                'disable': False,
            }
        )
        app['Builds'] = [build]

        test_flag = ('--on-server', True)
        fdroidserver.build.build_server(app, build, vcs, '', '', '', False)
        self.assertTrue(fdroidserver_vmtools_get_build_vm.called)

        for force in (True, False):
            test_flag = ('--force', force)
            fdroidserver.build.build_server(app, build, vcs, '', '', '', force)

        fdroidserver.build.options.notarball = True
        test_flag = ('--no-tarball', True)
        fdroidserver.build.build_server(app, build, vcs, '', '', '', False)
        fdroidserver.build.options.notarball = False
        test_flag = ('--no-tarball', False)
        fdroidserver.build.build_server(app, build, vcs, '', '', '', False)

        fdroidserver.build.options.skipscan = False
        test_flag = ('--scan-binary', True)
        fdroidserver.build.build_server(app, build, vcs, '', '', '', False)
        fdroidserver.build.options.skipscan = True
        test_flag = ('--scan-binary', False)
        fdroidserver.build.build_server(app, build, vcs, '', '', '', False)
        test_flag = ('--skip-scan', True)
        fdroidserver.build.build_server(app, build, vcs, '', '', '', False)

    @mock.patch('fdroidserver.vmtools.get_build_vm')
    @mock.patch('fdroidserver.vmtools.get_clean_builder')
    @mock.patch('paramiko.SSHClient')
    @mock.patch('subprocess.check_output')
    @mock.patch('fdroidserver.common.getsrclib')
    @mock.patch('fdroidserver.common.prepare_source')
    @mock.patch('fdroidserver.build.build_local')
    @mock.patch('fdroidserver.common.get_android_tools_version_log', lambda: 'versions')
    @mock.patch('fdroidserver.common.deploy_build_log_with_rsync', lambda a, b, c: None)
    def test_build_server_no_local_prepare(
        self,
        build_build_local,
        common_prepare_source,
        common_getsrclib,
        subprocess_check_output,
        paramiko_SSHClient,
        fdroidserver_vmtools_get_clean_builder,
        fdroidserver_vmtools_get_build_vm,  # pylint: disable=unused-argument
    ):
        """srclibs Prepare: should only be executed in the buildserver"""

        def _exec_command(args):
            print('chan.exec_command', args)

        def _getsrclib(
            spec,
            srclib_dir,
            basepath=False,
            raw=False,
            prepare=True,
            preponly=False,
            refresh=True,
            build=None,
        ):
            # pylint: disable=unused-argument
            name, ref = spec.split('@')
            libdir = os.path.join(srclib_dir, name)
            os.mkdir(libdir)
            self.assertFalse(prepare, 'Prepare: scripts should never run on host')
            return name, None, libdir  # TODO

        os.chdir(self.testdir)

        chan = mock.MagicMock()
        chan.exec_command = _exec_command
        chan.recv_exit_status = lambda: 0
        transport = mock.MagicMock()
        transport.open_session = mock.Mock(return_value=chan)
        sshs = mock.MagicMock()
        sshs.get_transport = mock.Mock(return_value=transport)
        paramiko_SSHClient.return_value = sshs
        subprocess_check_output.return_value = (
            b'0123456789abcdef0123456789abcdefcafebabe'
        )
        fdroidserver_vmtools_get_clean_builder.side_effect = lambda s: {
            'hostname': 'example.com',
            'idfile': '/path/to/id/file',
            'port': 123,
            'user': 'fake',
        }

        fdroidserver.metadata.srclibs = {
            'flutter': {
                'RepoType': 'git',
                'Repo': 'https://github.com/flutter/flutter',
            }
        }
        os.mkdir('srclibs')
        with open('srclibs/flutter.yml', 'w') as fp:
            yaml.dump(fdroidserver.metadata.srclibs, fp)
        common_getsrclib.side_effect = _getsrclib

        options = mock.MagicMock()
        options.force = False
        options.notarball = True
        options.onserver = False
        options.refresh = False
        options.scan_binary = False
        options.server = True
        options.skipscan = True
        options.test = False
        options.verbose = True
        fdroidserver.build.options = options
        fdroidserver.build.config = {'sdk_path': '/fake/android/sdk/path'}

        vcs = mock.Mock()
        vcs.getsrclib = mock.Mock(return_value=None)
        app = fdroidserver.metadata.App()
        app['metadatapath'] = 'metadata/fake.id.yml'
        app['id'] = 'fake.id'
        app['RepoType'] = 'git'
        spec = 'flutter@v1.7.8'
        build = fdroidserver.metadata.Build(
            {
                'versionCode': 123,
                'versionName': '1.2.3',
                'commit': '1.2.3',
                'disable': False,
                'srclibs': [spec],
            }
        )
        app['Builds'] = [build]

        build_dir = 'build'
        srclib_dir = os.path.join(build_dir, 'srclib')
        extlib_dir = os.path.join(build_dir, 'extlib')
        os.mkdir('tmp')
        os.mkdir(build_dir)
        os.mkdir(srclib_dir)

        fdroidserver.build.trybuild(
            app,
            build,
            build_dir,
            'unsigned',
            'logs',
            None,
            srclib_dir,
            extlib_dir,
            'tmp',
            'repo',
            vcs,
            options.test,
            options.server,
            options.force,
            options.onserver,
            options.refresh,
        )

        common_getsrclib.assert_called_once_with(
            spec, srclib_dir, basepath=True, prepare=False
        )
        common_prepare_source.assert_not_called()
        build_build_local.assert_not_called()

    def test_keep_when_not_allowed_default(self):
        self.assertFalse(fdroidserver.build.keep_when_not_allowed())

    def test_keep_when_not_allowed_config_true(self):
        fdroidserver.build.config = {'keep_when_not_allowed': True}
        self.assertTrue(fdroidserver.build.keep_when_not_allowed())

    def test_keep_when_not_allowed_config_false(self):
        fdroidserver.build.config = {'keep_when_not_allowed': False}
        self.assertFalse(fdroidserver.build.keep_when_not_allowed())

    def test_keep_when_not_allowed_options_true(self):
        fdroidserver.build.options = Options
        fdroidserver.build.options.keep_when_not_allowed = True
        self.assertTrue(fdroidserver.build.keep_when_not_allowed())

    def test_keep_when_not_allowed_options_false(self):
        fdroidserver.build.options = Options
        fdroidserver.build.options.keep_when_not_allowed = False
        self.assertFalse(fdroidserver.build.keep_when_not_allowed())

    def test_keep_when_not_allowed_options_true_override_config(self):
        fdroidserver.build.options = Options
        fdroidserver.build.options.keep_when_not_allowed = True
        fdroidserver.build.config = {'keep_when_not_allowed': False}
        self.assertTrue(fdroidserver.build.keep_when_not_allowed())

    def test_keep_when_not_allowed_options_default_does_not_override(self):
        fdroidserver.build.options = Options
        fdroidserver.build.options.keep_when_not_allowed = False
        fdroidserver.build.config = {'keep_when_not_allowed': True}
        self.assertTrue(fdroidserver.build.keep_when_not_allowed())

    def test_keep_when_not_allowed_all_true(self):
        fdroidserver.build.options = Options
        fdroidserver.build.options.keep_when_not_allowed = True
        fdroidserver.build.config = {'keep_when_not_allowed': True}
        self.assertTrue(fdroidserver.build.keep_when_not_allowed())

    def test_keep_when_not_allowed_all_false(self):
        fdroidserver.build.options = Options
        fdroidserver.build.options.keep_when_not_allowed = False
        fdroidserver.build.config = {'keep_when_not_allowed': False}
        self.assertFalse(fdroidserver.build.keep_when_not_allowed())
