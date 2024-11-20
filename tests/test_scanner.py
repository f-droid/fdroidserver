#!/usr/bin/env python3

import os
import pathlib
import re
import shutil
import sys
import tempfile
import textwrap
import unittest
import uuid
import zipfile
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from unittest import mock

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib
import yaml

import fdroidserver.build
import fdroidserver.common
import fdroidserver.metadata
import fdroidserver.scanner
from .testcommon import TmpCwd, mkdtemp, mock_open_to_str

basedir = pathlib.Path(__file__).parent


# Always use built-in default rules so changes in downloaded rules don't break tests.
@mock.patch(
    'fdroidserver.scanner.SUSSDataController.load',
    fdroidserver.scanner.SUSSDataController.load_from_defaults,
)
class ScannerTest(unittest.TestCase):
    def setUp(self):
        os.chdir(basedir)
        self._td = mkdtemp()
        self.testdir = self._td.name
        fdroidserver.scanner.ScannerTool.refresh_allowed = False

    def tearDown(self):
        os.chdir(basedir)
        self._td.cleanup()

    def test_scan_source_files(self):
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.json = False
        projects = {
            'OtakuWorld': 2,
            'Zillode': 1,
            'cn.wildfirechat.chat': 4,
            'com.github.shadowsocks': 9,
            'com.integreight.onesheeld': 17,
            'com.jens.automation2': 3,
            'firebase-suspect': 1,
            'org.mozilla.rocket': 2,
            'org.tasks': 3,
            'realm': 1,
            'se.manyver': 3,
            'lockfile.test': 1,
            'com.lolo.io.onelist': 6,
            'catalog.test': 22,
        }
        for d in (basedir / 'source-files').iterdir():
            build = fdroidserver.metadata.Build()
            fatal_problems = fdroidserver.scanner.scan_source(d, build)
            should = projects.get(d.name, 0)
            self.assertEqual(
                should, fatal_problems, f'{d} should have {should} errors!'
            )

    def test_get_gradle_compile_commands_without_catalog(self):
        test_files = [
            ('source-files/fdroid/fdroidclient/build.gradle', 'yes', 15),
            ('source-files/com.nextcloud.client/build.gradle', 'generic', 24),
            ('source-files/com.kunzisoft.testcase/build.gradle', 'libre', 3),
            ('source-files/cn.wildfirechat.chat/chat/build.gradle', 'yes', 30),
            ('source-files/org.tasks/app/build.gradle.kts', 'generic', 41),
            ('source-files/at.bitfire.davdroid/build.gradle', 'standard', 15),
            ('source-files/se.manyver/android/app/build.gradle', 'indie', 26),
            ('source-files/osmandapp/osmand/build.gradle', 'free', 2),
            ('source-files/eu.siacs.conversations/build.gradle', 'free', 21),
            ('source-files/org.mozilla.rocket/app/build.gradle', 'focus', 40),
            ('source-files/com.jens.automation2/app/build.gradle', 'fdroidFlavor', 5),
        ]

        for f, flavor, count in test_files:
            i = 0
            build = fdroidserver.metadata.Build()
            build.gradle = [flavor]
            regexs = fdroidserver.scanner.get_gradle_compile_commands_without_catalog(
                build
            )
            with open(f, encoding='utf-8') as fp:
                for line in fp.readlines():
                    for regex in regexs:
                        m = regex.match(line)
                        if m:
                            i += 1
            self.assertEqual(count, i)

    def test_get_gradle_compile_commands_with_catalog(self):
        test_files = [
            ('source-files/com.lolo.io.onelist/build.gradle.kts', 'yes', 5),
            ('source-files/com.lolo.io.onelist/app/build.gradle.kts', 'yes', 26),
            ('source-files/catalog.test/build.gradle.kts', 'yes', 3),
            ('source-files/catalog.test/app/build.gradle', 'yes', 2),
        ]

        for f, flavor, count in test_files:
            i = 0
            build = fdroidserver.metadata.Build()
            build.gradle = [flavor]
            regexs = fdroidserver.scanner.get_gradle_compile_commands_with_catalog(
                build, "libs"
            )
            with open(f, encoding='utf-8') as fp:
                for line in fp.readlines():
                    for regex in regexs:
                        m = regex.match(line)
                        if m:
                            i += 1
            self.assertEqual(count, i)

    def test_catalog(self):
        accessor_coordinate_pairs = {
            'firebase.crash': ['com.google.firebase:firebase-crash:1.1.1'],
            'firebase.core': ['com.google.firebase:firebase-core:2.2.2'],
            'play.service.ads': ['com.google.android.gms:play-services-ads:1.2.1'],
            'jacoco': ['org.jacoco:org.jacoco.core:0.8.7'],
            'plugins.google.services': ['com.google.gms.google-services:1.2.1'],
            'plugins.firebase.crashlytics': ['com.google.firebase.crashlytics:1.1.1'],
            'bundles.firebase': [
                'com.google.firebase:firebase-crash:1.1.1',
                'com.google.firebase:firebase-core:2.2.2',
            ],
        }
        with open('source-files/catalog.test/gradle/libs.versions.toml', 'rb') as f:
            catalog = fdroidserver.scanner.GradleVersionCatalog(tomllib.load(f))
        for accessor, coordinate in accessor_coordinate_pairs.items():
            self.assertEqual(catalog.get_coordinate(accessor), coordinate)

    def test_get_catalogs(self):
        test_files = [
            ('source-files/com.lolo.io.onelist/', 1),
            ('source-files/catalog.test/', 3),
            ('source-files/org.piepmeyer.gauguin/', 1),
        ]

        for root, count in test_files:
            self.assertEqual(count, len(fdroidserver.scanner.get_catalogs(root)))

    def test_scan_source_files_sneaky_maven(self):
        """Check for sneaking in banned maven repos"""
        os.chdir(self.testdir)
        fdroidserver.scanner.config = None
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.json = True
        with open('build.gradle', 'w', encoding='utf-8') as fp:
            fp.write(
                textwrap.dedent(
                    """
                 maven {
                    "https://jitpack.io"
                    url 'https://maven.fabric.io/public'
                 }
                 maven {
                    "https://maven.google.com"
                    setUrl('https://evilcorp.com/maven')
                 }
            """
                )
            )
        count = fdroidserver.scanner.scan_source(self.testdir)
        self.assertEqual(2, count, 'there should be this many errors')

    def test_scan_source_file_types(self):
        """Build product files are not allowed, test they are detected

        This test runs as if `fdroid build` running to test the
        difference between absolute and relative paths.

        """
        build_dir = os.path.join('build', 'fake.app')
        abs_build_dir = os.path.join(self.testdir, build_dir)
        os.makedirs(abs_build_dir, exist_ok=True)
        os.chdir(abs_build_dir)

        fdroidserver.scanner.config = None
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.json = True

        keep = [
            'arg.jar',
            'ascii.out',
            'baz.so',
            'classes.dex',
            'sqlcipher.aar',
            'static.a',
            'src/test/resources/classes.dex',
        ]
        remove = ['gradle-wrapper.jar', 'gradlew', 'gradlew.bat']
        os.makedirs('src/test/resources', exist_ok=True)
        for f in keep + remove:
            with open(f, 'w') as fp:
                fp.write('placeholder')
            self.assertTrue(os.path.exists(f))
        binaries = ['binary.out', 'fake.png', 'snippet.png']
        with open('binary.out', 'wb') as fp:
            fp.write(b'\x00\x00')
            fp.write(uuid.uuid4().bytes)
        shutil.copyfile('binary.out', 'fake.png')
        os.chmod('fake.png', 0o755)  # nosec B103
        with open('snippet.png', 'wb') as fp:
            fp.write(
                b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x000\x00\x00'
                b'\x000\x08\x06\x00\x00\x00W\x02\xf9\x87\x00\x00\x00\x04sB'
                b'IT\x08\x08\x08\x08|\x08d\x88\x00\x00\x00\tpHYs\x00\x00\n'
                b'a\x00\x00\na\x01\xfc\xccJ%\x00\x00\x00\x19tEXtSoftware'
            )
        os.chmod('snippet.png', 0o755)  # nosec B103

        # run scanner as if from `fdroid build`
        os.chdir(self.testdir)
        json_per_build = fdroidserver.scanner.MessageStore()
        count = fdroidserver.scanner.scan_source(
            build_dir, json_per_build=json_per_build
        )
        self.assertEqual(6, count, 'there should be this many errors')
        os.chdir(build_dir)

        for f in keep + binaries:
            self.assertTrue(os.path.exists(f), f + ' should still be there')
        for f in remove:
            self.assertFalse(os.path.exists(f), f + ' should have been removed')

        json_per_build_asdict = asdict(json_per_build)
        files = dict()
        for section in ('errors', 'infos', 'warnings'):
            files[section] = []
            for msg, f in json_per_build_asdict[section]:
                files[section].append(f)

        self.assertFalse(
            'ascii.out' in files['errors'], 'ASCII .out file is not an error'
        )
        self.assertFalse(
            'snippet.png' in files['errors'], 'executable valid image is not an error'
        )

        self.assertTrue('arg.jar' in files['errors'], 'all JAR files are errors')
        self.assertTrue('baz.so' in files['errors'], 'all .so files are errors')
        self.assertTrue(
            'binary.out' in files['errors'], 'a binary .out file is an error'
        )
        self.assertTrue(
            'classes.dex' in files['errors'], 'all classes.dex files are errors'
        )
        self.assertTrue('sqlcipher.aar' in files['errors'], 'all AAR files are errors')
        self.assertTrue('static.a' in files['errors'], 'all .a files are errors')

        self.assertTrue(
            'fake.png' in files['warnings'],
            'a random binary that is executable that is not an image is a warning',
        )
        self.assertTrue(
            'src/test/resources/classes.dex' in files['warnings'],
            'suspicious file but in a test dir is a warning',
        )

        for f in remove:
            self.assertTrue(
                f in files['infos'], '%s should be removed with an info message' % f
            )

    def test_build_local_scanner(self):
        """`fdroid build` calls scanner functions, test them here"""
        os.chdir(self.testdir)
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.build.config = config
        fdroidserver.build.options = mock.Mock()
        fdroidserver.build.options.json = False
        fdroidserver.build.options.scan_binary = False
        fdroidserver.build.options.notarball = True
        fdroidserver.build.options.skipscan = False
        fdroidserver.common.options = fdroidserver.build.options

        app = fdroidserver.metadata.App()
        app.id = 'mocked.app.id'
        build = fdroidserver.metadata.Build()
        build.commit = '1.0'
        build.output = app.id + '.apk'
        build.scanignore = ['baz.so', 'foo.aar']
        build.versionCode = 1
        build.versionName = '1.0'
        vcs = mock.Mock()

        for f in ('baz.so', 'foo.aar', 'gradle-wrapper.jar'):
            with open(f, 'w') as fp:
                fp.write('placeholder')
            self.assertTrue(os.path.exists(f))

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
        self.assertTrue(os.path.exists('baz.so'))
        self.assertTrue(os.path.exists('foo.aar'))
        self.assertFalse(os.path.exists('gradle-wrapper.jar'))

    def test_gradle_maven_url_regex(self):
        """Check the regex can find all the cases"""
        with open(basedir / 'gradle-maven-blocks.yaml') as fp:
            data = yaml.safe_load(fp)

        urls = []
        for entry in data:
            found = False
            for m in fdroidserver.scanner.MAVEN_URL_REGEX.findall(entry):
                urls.append(m)
                found = True
            self.assertTrue(found, 'this block should produce a URL:\n' + entry)
        self.assertEqual(len(data), len(urls), 'each data example should produce a URL')

    def test_scan_gradle_file_with_multiple_problems(self):
        """Check that the scanner can handle scandelete with gradle files with multiple problems"""
        os.chdir(self.testdir)
        fdroidserver.scanner.config = None
        fdroidserver.common.options = mock.Mock()
        build = fdroidserver.metadata.Build()
        build.scandelete = ['build.gradle']
        with open('build.gradle', 'w', encoding='utf-8') as fp:
            fp.write(
                textwrap.dedent(
                    """
                 maven {
                    url 'https://maven.fabric.io/public'
                 }
                 maven {
                    url 'https://evilcorp.com/maven'
                 }
            """
                )
            )
        count = fdroidserver.scanner.scan_source(self.testdir, build)
        self.assertFalse(os.path.exists("build.gradle"))
        self.assertEqual(0, count, 'there should be this many errors')

    def test_get_embedded_classes(self):
        config = dict()
        fdroidserver.common.config = config
        fdroidserver.common.fill_config_defaults(config)
        for f in (
            'apk.embedded_1.apk',
            'bad-unicode-πÇÇ现代通用字-български-عربي1.apk',
            'janus.apk',
            'minimal_targetsdk_30_unsigned.apk',
            'no_targetsdk_minsdk1_unsigned.apk',
            'org.bitbucket.tickytacky.mirrormirror_1.apk',
            'org.bitbucket.tickytacky.mirrormirror_2.apk',
            'org.bitbucket.tickytacky.mirrormirror_3.apk',
            'org.bitbucket.tickytacky.mirrormirror_4.apk',
            'org.dyndns.fules.ck_20.apk',
            'SpeedoMeterApp.main_1.apk',
            'urzip.apk',
            'urzip-badcert.apk',
            'urzip-badsig.apk',
            'urzip-release.apk',
            'urzip-release-unsigned.apk',
            'repo/com.example.test.helloworld_1.apk',
            'repo/com.politedroid_3.apk',
            'repo/com.politedroid_4.apk',
            'repo/com.politedroid_5.apk',
            'repo/com.politedroid_6.apk',
            'repo/duplicate.permisssions_9999999.apk',
            'repo/info.zwanenburg.caffeinetile_4.apk',
            'repo/no.min.target.sdk_987.apk',
            'repo/obb.main.oldversion_1444412523.apk',
            'repo/obb.mainpatch.current_1619_another-release-key.apk',
            'repo/obb.mainpatch.current_1619.apk',
            'repo/obb.main.twoversions_1101613.apk',
            'repo/obb.main.twoversions_1101615.apk',
            'repo/obb.main.twoversions_1101617.apk',
            'repo/souch.smsbypass_9.apk',
            'repo/urzip-; Рахма́, [rɐxˈmanʲɪnəf] سيرجي_رخمانينوف 谢·.apk',
            'repo/v1.v2.sig_1020.apk',
        ):
            self.assertNotEqual(
                set(),
                fdroidserver.scanner.get_embedded_classes(f),
                'should return results for ' + f,
            )

    def test_get_embedded_classes_empty_archives(self):
        config = dict()
        fdroidserver.common.config = config
        fdroidserver.common.fill_config_defaults(config)
        print('basedir')
        for f in (
            'Norway_bouvet_europe_2.obf.zip',
            'repo/fake.ota.update_1234.zip',
        ):
            self.assertEqual(
                set(),
                fdroidserver.scanner.get_embedded_classes(f),
                'should return not results for ' + f,
            )

    @unittest.skipIf(
        sys.hexversion < 0x03090000, 'Python < 3.9 has a limited zipfile.is_zipfile()'
    )
    def test_get_embedded_classes_secret_apk(self):
        """Try to hide an APK+DEX in an APK and see if we can find it"""
        config = dict()
        fdroidserver.common.config = config
        fdroidserver.common.fill_config_defaults(config)
        apk = 'urzip.apk'
        mapzip = 'Norway_bouvet_europe_2.obf.zip'
        secretfile = os.path.join(
            basedir, 'org.bitbucket.tickytacky.mirrormirror_1.apk'
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            shutil.copy(apk, tmpdir)
            shutil.copy(mapzip, tmpdir)
            os.chdir(tmpdir)
            with zipfile.ZipFile(mapzip, 'a') as zipfp:
                zipfp.write(secretfile, 'secretapk')
                with zipfile.ZipFile(apk) as readfp:
                    with readfp.open('classes.dex') as cfp:
                        zipfp.writestr('secretdex', cfp.read())
            with zipfile.ZipFile(apk, 'a') as zipfp:
                zipfp.write(mapzip)

            cls = fdroidserver.scanner.get_embedded_classes(apk)
            self.assertTrue(
                'org/bitbucket/tickytacky/mirrormirror/MainActivity' in cls,
                'this should find the classes in the hidden, embedded APK',
            )
            self.assertTrue(
                'DEX file with fake name: secretdex' in cls,
                'badly named embedded DEX fils should throw an error',
            )
            self.assertTrue(
                'ZIP file without proper file extension: secretapk' in cls,
                'badly named embedded ZIPs should throw an error',
            )


class Test_scan_binary(unittest.TestCase):
    def setUp(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.common.options = mock.Mock()

        fdroidserver.scanner._SCANNER_TOOL = mock.Mock()
        fdroidserver.scanner._SCANNER_TOOL.regexs = {}
        fdroidserver.scanner._SCANNER_TOOL.regexs['err_code_signatures'] = {
            "java/lang/Object": re.compile(
                r'.*java/lang/Object', re.IGNORECASE | re.UNICODE
            )
        }
        fdroidserver.scanner._SCANNER_TOOL.regexs['warn_code_signatures'] = {}

    def test_code_signature_match(self):
        apkfile = os.path.join(basedir, 'no_targetsdk_minsdk1_unsigned.apk')
        self.assertEqual(
            1,
            fdroidserver.scanner.scan_binary(apkfile),
            "Did not find expected code signature '{}' in binary '{}'".format(
                fdroidserver.scanner._SCANNER_TOOL.regexs[
                    'err_code_signatures'
                ].values(),
                apkfile,
            ),
        )

    @unittest.skipIf(
        sys.version_info < (3, 9),
        "Our implementation for traversing zip files will silently fail to work"
        "on older python versions, also see: "
        "https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1110#note_932026766",
    )
    def test_bottom_level_embedded_apk_code_signature(self):
        apkfile = os.path.join(basedir, 'apk.embedded_1.apk')
        fdroidserver.scanner._SCANNER_TOOL.regexs['err_code_signatures'] = {
            "org/bitbucket/tickytacky/mirrormirror/MainActivity": re.compile(
                r'.*org/bitbucket/tickytacky/mirrormirror/MainActivity',
                re.IGNORECASE | re.UNICODE,
            )
        }

        self.assertEqual(
            1,
            fdroidserver.scanner.scan_binary(apkfile),
            "Did not find expected code signature '{}' in binary '{}'".format(
                fdroidserver.scanner._SCANNER_TOOL.regexs[
                    'err_code_signatures'
                ].values(),
                apkfile,
            ),
        )

    def test_top_level_signature_embedded_apk_present(self):
        apkfile = os.path.join(basedir, 'apk.embedded_1.apk')
        fdroidserver.scanner._SCANNER_TOOL.regexs['err_code_signatures'] = {
            "org/fdroid/ci/BuildConfig": re.compile(
                r'.*org/fdroid/ci/BuildConfig', re.IGNORECASE | re.UNICODE
            )
        }
        self.assertEqual(
            1,
            fdroidserver.scanner.scan_binary(apkfile),
            "Did not find expected code signature '{}' in binary '{}'".format(
                fdroidserver.scanner._SCANNER_TOOL.regexs[
                    'err_code_signatures'
                ].values(),
                apkfile,
            ),
        )


class Test_SignatureDataController(unittest.TestCase):
    def test_init(self):
        sdc = fdroidserver.scanner.SignatureDataController(
            'nnn', 'fff.yml', 'https://example.com/test.json'
        )
        self.assertEqual(sdc.name, 'nnn')
        self.assertEqual(sdc.filename, 'fff.yml')
        self.assertEqual(sdc.cache_duration, timedelta(999999))
        self.assertDictEqual(sdc.data, {})

    # check_last_updated
    def test_check_last_updated_ok(self):
        sdc = fdroidserver.scanner.SignatureDataController(
            'nnn', 'fff.yml', 'https://example.com/test.json'
        )
        sdc.data['last_updated'] = datetime.now(timezone.utc).timestamp()
        sdc.check_last_updated()

    def test_check_last_updated_exception_cache_outdated(self):
        sdc = fdroidserver.scanner.SignatureDataController(
            'nnn', 'fff.yml', 'https://example.com/test.json'
        )
        sdc.cache_duration = timedelta(days=7)
        sdc.data['last_updated'] = (
            datetime.now(timezone.utc) - timedelta(days=30)
        ).timestamp()
        with self.assertRaises(fdroidserver.scanner.SignatureDataOutdatedException):
            sdc.check_last_updated()

    def test_check_last_updated_exception_not_string(self):
        sdc = fdroidserver.scanner.SignatureDataController(
            'nnn', 'fff.yml', 'https://example.com/test.json'
        )
        sdc.data['last_updated'] = 'sepp'
        with self.assertRaises(fdroidserver.scanner.SignatureDataMalformedException):
            sdc.check_last_updated()

    def test_check_last_updated_exception_not_iso_formatted_string(self):
        sdc = fdroidserver.scanner.SignatureDataController(
            'nnn', 'fff.yml', 'https://example.com/test.json'
        )
        sdc.data['last_updated'] = '01/09/2002 10:11'
        with self.assertRaises(fdroidserver.scanner.SignatureDataMalformedException):
            sdc.check_last_updated()

    def test_check_last_updated_no_exception_missing_when_last_updated_not_set(self):
        sdc = fdroidserver.scanner.SignatureDataController(
            'nnn', 'fff.yml', 'https://example.com/test.json'
        )
        sdc.check_last_updated()

    # check_data_version
    def test_check_data_version_ok(self):
        sdc = fdroidserver.scanner.SignatureDataController(
            'nnn', 'fff.yml', 'https://example.com/test.json'
        )
        sdc.data['version'] = fdroidserver.scanner.SCANNER_CACHE_VERSION
        sdc.check_data_version()

    def test_check_data_version_exception(self):
        sdc = fdroidserver.scanner.SignatureDataController(
            'nnn', 'fff.yml', 'https://example.com/test.json'
        )
        with self.assertRaises(
            fdroidserver.scanner.SignatureDataVersionMismatchException
        ):
            sdc.check_data_version()

    def test_load_ok(self):
        sdc = fdroidserver.scanner.SignatureDataController(
            'nnn', 'fff.yml', 'https://example.com/test.json'
        )
        func_lfc = mock.Mock()
        func_vd = mock.Mock()
        func_clu = mock.Mock()
        with mock.patch(
            'fdroidserver.scanner.SignatureDataController.load_from_cache',
            func_lfc,
        ), mock.patch(
            'fdroidserver.scanner.SignatureDataController.verify_data',
            func_vd,
        ), mock.patch(
            'fdroidserver.scanner.SignatureDataController.check_last_updated',
            func_clu,
        ):
            sdc.load()
        func_lfc.assert_called_once_with()
        func_vd.assert_called_once_with()
        func_clu.assert_called_once_with()

    def test_load_initial_cache_miss(self):
        sdc = fdroidserver.scanner.SignatureDataController(
            'nnn', 'fff.yml', 'https://example.com/test.json'
        )
        func_lfc = mock.Mock(
            side_effect=fdroidserver.scanner.SignatureDataCacheMissException
        )
        func_lfd = mock.Mock()
        with mock.patch(
            'fdroidserver.scanner.SignatureDataController.load_from_cache',
            func_lfc,
        ), mock.patch(
            'fdroidserver.scanner.SignatureDataController.load_from_defaults',
            func_lfd,
        ):
            sdc.load()
        func_lfc.assert_called_once_with()
        func_lfd.assert_called_once_with()

    def test_load_cache_auto_refresh(self):
        sdc = fdroidserver.scanner.SignatureDataController(
            'nnn', 'fff.yml', 'https://example.com/test.json'
        )
        func_lfc = mock.Mock()
        func_vd = mock.Mock()
        func_clu = mock.Mock(
            side_effect=fdroidserver.scanner.SignatureDataOutdatedException()
        )
        func_fsfw = mock.Mock()
        func_wtc = mock.Mock()
        with mock.patch(
            'fdroidserver.scanner.SignatureDataController.load_from_cache',
            func_lfc,
        ), mock.patch(
            'fdroidserver.scanner.SignatureDataController.verify_data',
            func_vd,
        ), mock.patch(
            'fdroidserver.scanner.SignatureDataController.check_last_updated',
            func_clu,
        ), mock.patch(
            'fdroidserver.scanner.SignatureDataController.fetch_signatures_from_web',
            func_fsfw,
        ), mock.patch(
            'fdroidserver.scanner.SignatureDataController.write_to_cache',
            func_wtc,
        ):
            sdc.load()
        func_lfc.assert_called_once_with()
        func_vd.assert_called_once_with()
        func_clu.assert_called_once_with()
        func_fsfw.assert_called_once_with()
        func_wtc.assert_called_once_with()

    def test_load_try_web_when_no_defaults(self):
        sdc = fdroidserver.scanner.SignatureDataController(
            'nnn', 'fff.yml', 'https://example.com/test.json'
        )
        func_lfc = mock.Mock(
            side_effect=fdroidserver.scanner.SignatureDataCacheMissException()
        )
        func_lfd = mock.Mock(
            side_effect=fdroidserver.scanner.SignatureDataNoDefaultsException()
        )
        func_fsfw = mock.Mock()
        func_wtc = mock.Mock()
        with mock.patch(
            'fdroidserver.scanner.SignatureDataController.load_from_cache',
            func_lfc,
        ), mock.patch(
            'fdroidserver.scanner.SignatureDataController.load_from_defaults',
            func_lfd,
        ), mock.patch(
            'fdroidserver.scanner.SignatureDataController.fetch_signatures_from_web',
            func_fsfw,
        ), mock.patch(
            'fdroidserver.scanner.SignatureDataController.write_to_cache',
            func_wtc,
        ):
            sdc.load()
        func_lfc.assert_called_once_with()
        func_lfd.assert_called_once_with()
        func_fsfw.assert_called_once_with()
        func_wtc.assert_called_once_with()

    @unittest.skipIf(
        sys.version_info < (3, 9, 0),
        "mock_open doesn't allow easy access to written data in older python versions",
    )
    def test_write_to_cache(self):
        open_func = mock.mock_open()
        sdc = fdroidserver.scanner.SignatureDataController(
            'nnn', 'fff.yml', 'https://example.com/test.json'
        )
        sdc.data = {"mocked": "data"}

        with mock.patch("builtins.open", open_func), mock.patch(
            "fdroidserver.scanner._scanner_cachedir",
            return_value=pathlib.Path('.'),
        ):
            sdc.write_to_cache()

        open_func.assert_called_with(pathlib.Path('fff.yml'), 'w', encoding="utf-8")
        self.assertEqual(mock_open_to_str(open_func), """{\n  "mocked": "data"\n}""")


class Test_ScannerTool(unittest.TestCase):
    def setUp(self):
        fdroidserver.common.options = None
        fdroidserver.common.config = None
        os.chdir(basedir)
        self._td = mkdtemp()
        self.testdir = self._td.name
        fdroidserver.scanner.ScannerTool.refresh_allowed = True

    def tearDown(self):
        fdroidserver.common.options = None
        fdroidserver.common.config = None
        os.chdir(basedir)
        self._td.cleanup()

    def test_load(self):
        st = mock.Mock()
        st.sdcs = [mock.Mock(), mock.Mock()]
        fdroidserver.scanner.ScannerTool.load(st)
        st.sdcs[0].load.assert_called_once_with()
        st.sdcs[1].load.assert_called_once_with()

    def test_refresh_no_options_or_config(self):
        """This simulates what happens when running something like scan_source()"""
        with mock.patch('fdroidserver.scanner.ScannerTool.refresh') as refresh:
            fdroidserver.scanner.ScannerTool()
            refresh.assert_not_called()

    def test_refresh_true(self):
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.refresh_scanner = True
        with mock.patch('fdroidserver.scanner.ScannerTool.refresh') as refresh:
            fdroidserver.scanner.ScannerTool()
            refresh.assert_called_once()

    def test_refresh_false(self):
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.refresh_scanner = False
        with mock.patch('fdroidserver.scanner.ScannerTool.refresh') as refresh:
            fdroidserver.scanner.ScannerTool()
            refresh.assert_not_called()

    def test_refresh_from_config(self):
        os.chdir(self.testdir)
        pathlib.Path('config.yml').write_text('refresh_scanner: true')
        with mock.patch('fdroidserver.scanner.ScannerTool.refresh') as refresh:
            fdroidserver.scanner.ScannerTool()
            refresh.assert_called_once()

    def test_refresh_options_overrides_config(self):
        fdroidserver.common.options = mock.Mock()
        fdroidserver.common.options.refresh_scanner = True
        os.chdir(self.testdir)
        pathlib.Path('config.yml').write_text('refresh_scanner: false')
        with mock.patch('fdroidserver.scanner.ScannerTool.refresh') as refresh:
            fdroidserver.scanner.ScannerTool()
            refresh.assert_called_once()


class Test_main(unittest.TestCase):
    def setUp(self):
        self.args = ["com.example.app", "local/additional.apk", "another.apk"]
        self.exit_func = mock.Mock()
        self.read_app_args_func = mock.Mock(return_value={})
        self.scan_binary_func = mock.Mock(return_value=0)

    def test_parsing_appid(self):
        """This test verifies that app id get parsed correctly
        (doesn't test how they get processed)
        """
        self.args = ["com.example.app"]
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            TmpCwd(tmpdir),
            mock.patch("sys.exit", self.exit_func),
            mock.patch("sys.argv", ["fdroid scanner", *self.args]),
            mock.patch("fdroidserver.common.read_app_args", self.read_app_args_func),
            mock.patch("fdroidserver.scanner.scan_binary", self.scan_binary_func),
        ):
            fdroidserver.scanner.main()

            self.exit_func.assert_not_called()
            self.read_app_args_func.assert_called_once_with(
                ['com.example.app'], allow_version_codes=True
            )
            self.scan_binary_func.assert_not_called()

    def test_parsing_apkpath(self):
        """This test verifies that apk paths get parsed correctly
        (doesn't test how they get processed)
        """
        self.args = ["local.application.apk"]
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            TmpCwd(tmpdir),
            mock.patch("sys.exit", self.exit_func),
            mock.patch("sys.argv", ["fdroid scanner", *self.args]),
            mock.patch("fdroidserver.common.read_app_args", self.read_app_args_func),
            mock.patch("fdroidserver.scanner.scan_binary", self.scan_binary_func),
        ):
            pathlib.Path(self.args[0]).touch()
            fdroidserver.scanner.main()

            self.exit_func.assert_not_called()
            self.read_app_args_func.assert_not_called()
            self.scan_binary_func.assert_called_once_with('local.application.apk')
