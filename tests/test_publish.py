#!/usr/bin/env python3

#
#  command which created the keystore used in this test case:
#
#  $ for ALIAS in repokey a163ec9b d2d51ff2 dc3b169e 78688a0f; \
#        do keytool -genkey -keystore dummy-keystore.jks \
#        -alias $ALIAS -keyalg 'RSA' -keysize '2048' \
#        -validity '10000' -storepass 123456 -storetype jks \
#        -keypass 123456 -dname 'CN=test, OU=F-Droid'; done
#

import json
import os
import pathlib
import shutil
import sys
import unittest
import tempfile
from unittest import mock

from fdroidserver import publish
from fdroidserver import common
from fdroidserver import metadata
from fdroidserver import signatures
from fdroidserver.exception import FDroidException
from .testcommon import mkdtemp, VerboseFalseOptions

basedir = pathlib.Path(__file__).parent


class PublishTest(unittest.TestCase):
    '''fdroidserver/publish.py'''

    def setUp(self):
        os.chdir(basedir)
        self._td = mkdtemp()
        self.testdir = self._td.name

    def tearDown(self):
        self._td.cleanup()
        os.chdir(basedir)

    def test_key_alias(self):
        publish.config = {}
        self.assertEqual('a163ec9b', publish.key_alias('com.example.app'))
        self.assertEqual('d2d51ff2', publish.key_alias('com.example.anotherapp'))
        self.assertEqual('dc3b169e', publish.key_alias('org.test.testy'))
        self.assertEqual('78688a0f', publish.key_alias('org.org.org'))

        self.assertEqual('ee8807d2', publish.key_alias("org.schabi.newpipe"))
        self.assertEqual('b53c7e11', publish.key_alias("de.grobox.liberario"))

        publish.config = {
            'keyaliases': {'yep.app': '@org.org.org', 'com.example.app': '1a2b3c4d'}
        }
        self.assertEqual('78688a0f', publish.key_alias('yep.app'))
        self.assertEqual('1a2b3c4d', publish.key_alias('com.example.app'))

    def test_read_fingerprints_from_keystore(self):
        common.config = {}
        common.fill_config_defaults(common.config)
        publish.config = common.config
        publish.config['keystorepass'] = '123456'
        publish.config['keypass'] = '123456'
        publish.config['keystore'] = 'dummy-keystore.jks'

        expected = {
            '78688a0f': '277655a6235bc6b0ef2d824396c51ba947f5ebc738c293d887e7083ff338af82',
            'd2d51ff2': 'fa3f6a017541ee7fe797be084b1bcfbf92418a7589ef1f7fdeb46741b6d2e9c3',
            'dc3b169e': '6ae5355157a47ddcc3834a71f57f6fb5a8c2621c8e0dc739e9ddf59f865e497c',
            'a163ec9b': 'd34f678afbaa8f2fa6cc0edd6f0c2d1d2e2e9eb08bea521b24c740806016bff4',
            'repokey': 'c58460800c7b250a619c30c13b07b7359a43e5af71a4352d86c58ae18c9f6d41',
        }
        result = publish.read_fingerprints_from_keystore()
        self.maxDiff = None
        self.assertEqual(expected, result)

    def test_store_and_load_fdroid_signing_key_fingerprints(self):
        common.config = {}
        common.fill_config_defaults(common.config)
        publish.config = common.config
        publish.config['keystorepass'] = '123456'
        publish.config['keypass'] = '123456'
        publish.config['keystore'] = os.path.join(basedir, 'dummy-keystore.jks')
        publish.config['repo_keyalias'] = 'repokey'

        appids = [
            'com.example.app',
            'net.unavailable',
            'org.test.testy',
            'com.example.anotherapp',
            'org.org.org',
        ]

        os.chdir(self.testdir)
        with open('config.py', 'w') as f:
            pass

        publish.store_stats_fdroid_signing_key_fingerprints(appids, indent=2)

        self.maxDiff = None
        expected = {
            "com.example.anotherapp": {
                "signer": "fa3f6a017541ee7fe797be084b1bcfbf92418a7589ef1f7fdeb46741b6d2e9c3"
            },
            "com.example.app": {
                "signer": "d34f678afbaa8f2fa6cc0edd6f0c2d1d2e2e9eb08bea521b24c740806016bff4"
            },
            "org.org.org": {
                "signer": "277655a6235bc6b0ef2d824396c51ba947f5ebc738c293d887e7083ff338af82"
            },
            "org.test.testy": {
                "signer": "6ae5355157a47ddcc3834a71f57f6fb5a8c2621c8e0dc739e9ddf59f865e497c"
            },
        }
        self.assertEqual(expected, common.load_stats_fdroid_signing_key_fingerprints())

        with open('config.py', 'r') as f:
            self.assertEqual(
                '\nrepo_key_sha256 = "c58460800c7b250a619c30c13b07b7359a43e5af71a4352d86c58ae18c9f6d41"\n',
                f.read(),
            )

    def test_store_and_load_fdroid_signing_key_fingerprints_with_missmatch(self):
        common.config = {}
        common.fill_config_defaults(common.config)
        publish.config = common.config
        publish.config['keystorepass'] = '123456'
        publish.config['keypass'] = '123456'
        publish.config['keystore'] = os.path.join(basedir, 'dummy-keystore.jks')
        publish.config['repo_keyalias'] = 'repokey'
        publish.config['repo_key_sha256'] = 'bad bad bad bad bad bad bad bad bad bad bad bad'

        os.chdir(self.testdir)
        publish.store_stats_fdroid_signing_key_fingerprints({}, indent=2)
        with self.assertRaises(FDroidException):
            common.load_stats_fdroid_signing_key_fingerprints()

    def test_reproducible_binaries_process(self):
        common.config = {}
        common.fill_config_defaults(common.config)
        publish.config = common.config
        publish.config['keystore'] = 'keystore.jks'
        publish.config['repo_keyalias'] = 'sova'
        publish.config['keystorepass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        publish.config['keypass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        shutil.copy('keystore.jks', self.testdir)
        os.mkdir(os.path.join(self.testdir, 'repo'))
        metadata_dir = os.path.join(self.testdir, 'metadata')
        os.mkdir(metadata_dir)
        shutil.copy(os.path.join('metadata', 'com.politedroid.yml'), metadata_dir)
        with open(os.path.join(metadata_dir, 'com.politedroid.yml'), 'a') as fp:
            fp.write('\nBinaries: https://placeholder/foo%v.apk\n')
        os.mkdir(os.path.join(self.testdir, 'unsigned'))
        shutil.copy('repo/com.politedroid_6.apk', os.path.join(self.testdir, 'unsigned'))
        os.mkdir(os.path.join(self.testdir, 'unsigned', 'binaries'))
        shutil.copy('repo/com.politedroid_6.apk',
                    os.path.join(self.testdir, 'unsigned', 'binaries', 'com.politedroid_6.binary.apk'))

        os.chdir(self.testdir)
        with mock.patch.object(sys, 'argv', ['fdroid fakesubcommand']):
            publish.main()

    def test_check_for_key_collisions(self):
        from fdroidserver.metadata import App

        common.config = {}
        common.fill_config_defaults(common.config)
        publish.config = common.config

        randomappids = [
            "org.fdroid.fdroid",
            "a.b.c",
            "u.v.w.x.y.z",
            "lpzpkgqwyevnmzvrlaazhgardbyiyoybyicpmifkyrxkobljoz",
            "vuslsm.jlrevavz.qnbsenmizhur.lprwbjiujtu.ekiho",
            "w.g.g.w.p.v.f.v.gvhyz",
            "nlozuqer.ufiinmrbjqboogsjgmpfks.dywtpcpnyssjmqz",
        ]
        allapps = {}
        for appid in randomappids:
            allapps[appid] = App()
        allaliases = publish.check_for_key_collisions(allapps)
        self.assertEqual(len(randomappids), len(allaliases))

        allapps = {'tof.cv.mpp': App(), 'j6mX276h': App()}
        self.assertEqual(publish.key_alias('tof.cv.mpp'), publish.key_alias('j6mX276h'))
        self.assertRaises(SystemExit, publish.check_for_key_collisions, allapps)

    def test_create_key_if_not_existing(self):
        try:
            import jks
            import jks.util
        except ImportError:
            self.skipTest("pyjks not installed")
        common.config = {}
        common.fill_config_defaults(common.config)
        publish.config = common.config
        publish.config['keystorepass'] = '123456'
        publish.config['keypass'] = '654321'
        publish.config['keystore'] = "keystore.jks"
        publish.config['keydname'] = 'CN=Birdman, OU=Cell, O=Alcatraz, L=Alcatraz, S=California, C=US'
        os.chdir(self.testdir)
        keystore = jks.KeyStore.new("jks", [])
        keystore.save(publish.config['keystore'], publish.config['keystorepass'])

        self.assertTrue(publish.create_key_if_not_existing("newalias"))
        # The second time we try that, a new key should not be created
        self.assertFalse(publish.create_key_if_not_existing("newalias"))
        self.assertTrue(publish.create_key_if_not_existing("anotheralias"))

        keystore = jks.KeyStore.load(publish.config['keystore'], publish.config['keystorepass'])
        self.assertCountEqual(keystore.private_keys, ["newalias", "anotheralias"])
        for alias, pk in keystore.private_keys.items():
            self.assertFalse(pk.is_decrypted())
            pk.decrypt(publish.config['keypass'])
            self.assertTrue(pk.is_decrypted())
            self.assertEqual(jks.util.RSA_ENCRYPTION_OID, pk.algorithm_oid)

    def test_status_update_json(self):
        common.config = {}
        publish.config = {}
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            with mock.patch('sys.argv', ['fdroid publish', '']):
                publish.status_update_json([], [])
                with open('repo/status/publish.json') as fp:
                    data = json.load(fp)
                self.assertTrue('apksigner' in data)

                publish.config = {
                    'apksigner': 'apksigner',
                }
                publish.status_update_json([], [])
                with open('repo/status/publish.json') as fp:
                    data = json.load(fp)
                self.assertEqual(shutil.which(publish.config['apksigner']), data['apksigner'])

                publish.config = {}
                common.fill_config_defaults(publish.config)
                publish.status_update_json([], [])
                with open('repo/status/publish.json') as fp:
                    data = json.load(fp)
                self.assertEqual(publish.config.get('apksigner'), data['apksigner'])
                self.assertEqual(publish.config['jarsigner'], data['jarsigner'])
                self.assertEqual(publish.config['keytool'], data['keytool'])

    def test_sign_then_implant_signature(self):
        os.chdir(self.testdir)

        common.options = VerboseFalseOptions
        config = common.read_config()
        if 'apksigner' not in config:
            self.skipTest('SKIPPING test_sign_then_implant_signature, apksigner not installed!')
        config['repo_keyalias'] = 'sova'
        config['keystorepass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        config['keypass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        shutil.copy(basedir / 'keystore.jks', self.testdir)
        config['keystore'] = 'keystore.jks'
        config['keydname'] = 'CN=Birdman, OU=Cell, O=Alcatraz, L=Alcatraz, S=California, C=US'
        publish.config = config
        common.config = config

        app = metadata.App()
        app.id = 'org.fdroid.ci'
        versionCode = 1
        build = metadata.Build(
            {
                'versionCode': versionCode,
                'versionName': '1.0',
            }
        )
        app.Builds = [build]
        os.mkdir('metadata')
        metadata.write_metadata(os.path.join('metadata', '%s.yml' % app.id), app)

        os.mkdir('unsigned')
        testapk = basedir / 'no_targetsdk_minsdk1_unsigned.apk'
        unsigned = os.path.join('unsigned', common.get_release_filename(app, build))
        signed = os.path.join('repo', common.get_release_filename(app, build))
        shutil.copy(testapk, unsigned)

        # sign the unsigned APK
        self.assertTrue(os.path.exists(unsigned))
        self.assertFalse(os.path.exists(signed))
        with mock.patch('sys.argv', ['fdroid publish', '%s:%d' % (app.id, versionCode)]):
            publish.main()
        self.assertFalse(os.path.exists(unsigned))
        self.assertTrue(os.path.exists(signed))

        with mock.patch('sys.argv', ['fdroid signatures', signed]):
            signatures.main()
        self.assertTrue(
            os.path.exists(
                os.path.join('metadata', 'org.fdroid.ci', 'signatures', '1', 'MANIFEST.MF')
            )
        )
        os.remove(signed)

        # implant the signature into the unsigned APK
        shutil.copy(testapk, unsigned)
        self.assertTrue(os.path.exists(unsigned))
        self.assertFalse(os.path.exists(signed))
        with mock.patch('sys.argv', ['fdroid publish', '%s:%d' % (app.id, versionCode)]):
            publish.main()
        self.assertFalse(os.path.exists(unsigned))
        self.assertTrue(os.path.exists(signed))

    def test_exit_on_error(self):
        """Exits properly on errors, with and without --error-on-failed.

        `fdroid publish` runs on the signing server and does large
        batches.  In that case, it shouldn't exit after a single
        failure since it should try to complete the whole batch.  For
        CI and other use cases, there is --error-on-failed to force it
        to exit after a failure.

        """

        class Options:
            error_on_failed = True
            verbose = False

        os.chdir(self.testdir)

        common.options = Options
        config = common.read_config()
        if 'apksigner' not in config:
            self.skipTest('SKIPPING test_error_on_failed, apksigner not installed!')
        config['repo_keyalias'] = 'sova'
        config['keystorepass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        config['keypass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        shutil.copy(basedir / 'keystore.jks', self.testdir)
        config['keystore'] = 'keystore.jks'
        config[
            'keydname'
        ] = 'CN=Birdman, OU=Cell, O=Alcatraz, L=Alcatraz, S=California, C=US'
        publish.config = config
        common.config = config

        app = metadata.App()
        app.id = 'org.fdroid.ci'
        versionCode = 1
        build = metadata.Build(
            {
                'versionCode': versionCode,
                'versionName': '1.0',
            }
        )
        app.Builds = [build]
        os.mkdir('metadata')
        metadata.write_metadata(os.path.join('metadata', '%s.yml' % app.id), app)

        os.mkdir('unsigned')
        testapk = basedir / 'no_targetsdk_minsdk1_unsigned.apk'
        unsigned = os.path.join('unsigned', common.get_release_filename(app, build))
        signed = os.path.join('repo', common.get_release_filename(app, build))
        shutil.copy(testapk, unsigned)

        # sign the unsigned APK
        self.assertTrue(os.path.exists(unsigned))
        self.assertFalse(os.path.exists(signed))
        with mock.patch(
            'sys.argv', ['fdroid publish', '%s:%d' % (app.id, versionCode)]
        ):
            publish.main()
        self.assertFalse(os.path.exists(unsigned))
        self.assertTrue(os.path.exists(signed))

        with mock.patch('sys.argv', ['fdroid signatures', signed]):
            signatures.main()
        mf = os.path.join('metadata', 'org.fdroid.ci', 'signatures', '1', 'MANIFEST.MF')
        self.assertTrue(os.path.exists(mf))
        os.remove(signed)

        with open(mf, 'a') as fp:
            fp.write('appended to break signature')

        # implant the signature into the unsigned APK
        shutil.copy(testapk, unsigned)
        self.assertTrue(os.path.exists(unsigned))
        self.assertFalse(os.path.exists(signed))
        apk_id = '%s:%d' % (app.id, versionCode)

        # by default, it should complete without exiting
        with mock.patch('sys.argv', ['fdroid publish', apk_id]):
            publish.main()

        # --error-on-failed should make it exit
        with mock.patch('sys.argv', ['fdroid publish', '--error-on-failed', apk_id]):
            with self.assertRaises(SystemExit) as e:
                publish.main()
            self.assertEqual(e.exception.code, 1)
