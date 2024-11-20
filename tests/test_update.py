#!/usr/bin/env python3

import copy
import git
import glob
import hashlib
import json
import logging
import os
import random
import shutil
import string
import subprocess
import unittest
import yaml
import zipfile
import textwrap
from binascii import hexlify
from datetime import datetime
from pathlib import Path
from unittest import mock

try:
    # these were moved in androguard 4.0
    from androguard.core.apk import APK
except ImportError:
    from androguard.core.bytecodes.apk import APK

try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader

try:
    from yaml import CFullLoader as FullLoader
except ImportError:
    try:
        # FullLoader is available from PyYaml 5.1+, as we don't load user
        # controlled data here, it's okay to fall back the unsafe older
        # Loader
        from yaml import FullLoader
    except ImportError:
        from yaml import Loader as FullLoader

import fdroidserver.common
import fdroidserver.exception
import fdroidserver.metadata
import fdroidserver.update
from fdroidserver.common import CATEGORIES_CONFIG_NAME
from fdroidserver.looseversion import LooseVersion
from .testcommon import TmpCwd, mkdtemp
from PIL import PngImagePlugin


DONATION_FIELDS = ('Donate', 'Liberapay', 'OpenCollective')

logging.getLogger(PngImagePlugin.__name__).setLevel(logging.INFO)
basedir = Path(__file__).parent


class Options:
    allow_disabled_algorithms = False
    clean = False
    delete_unknown = False
    nosign = False
    pretty = True
    rename_apks = False
    verbose = False


class UpdateTest(unittest.TestCase):
    '''fdroid update'''

    def setUp(self):
        os.chdir(basedir)
        self._td = mkdtemp()
        self.testdir = self._td.name

        fdroidserver.common.config = None
        fdroidserver.common.options = None

    def tearDown(self):
        os.chdir(basedir)
        self._td.cleanup()

    def test_insert_store_metadata(self):
        os.chdir(self.testdir)

        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.update.config = config

        repo_dir = basedir / 'repo'
        os.mkdir('metadata')
        for packageName in (
            'obb.mainpatch.current',
            'org.videolan.vlc',
        ):
            shutil.copytree(
                repo_dir / packageName, os.path.join('repo', packageName)
            )
        for packageName in (
            'info.guardianproject.checkey',
            'info.guardianproject.urzip',
            'org.smssecure.smssecure',
        ):
            shutil.copytree(
                basedir / 'metadata' / packageName,
                os.path.join('metadata', packageName),
            )
        for packageName in (
            'com.nextcloud.client',
            'com.nextcloud.client.dev',
            'eu.siacs.conversations',
        ):
            shutil.copytree(
                basedir / 'source-files' / packageName,
                os.path.join(self.testdir, 'build', packageName),
            )

        testfilename = 'icon_yAfSvPRJukZzMMfUzvbYqwaD1XmHXNtiPBtuPVHW-6s=.png'
        testfile = repo_dir / 'org.videolan.vlc/en-US/icon.png'
        cpdir = os.path.join('metadata', 'org.videolan.vlc', 'en-US')
        cpfile = os.path.join(cpdir, testfilename)
        os.makedirs(cpdir, exist_ok=True)
        shutil.copy(testfile, cpfile)
        shutil.copystat(testfile, cpfile)

        apps = dict()
        for packageName in (
            'info.guardianproject.urzip',
            'org.videolan.vlc',
            'obb.mainpatch.current',
            'com.nextcloud.client',
            'com.nextcloud.client.dev',
            'eu.siacs.conversations',
        ):
            apps[packageName] = fdroidserver.metadata.App()
            apps[packageName]['id'] = packageName
            apps[packageName]['CurrentVersionCode'] = 0xCAFEBEEF

        apps['info.guardianproject.urzip']['CurrentVersionCode'] = 100

        buildnextcloudclient = fdroidserver.metadata.Build()
        buildnextcloudclient.gradle = ['generic']
        apps['com.nextcloud.client']['Builds'] = [buildnextcloudclient]

        buildnextclouddevclient = fdroidserver.metadata.Build()
        buildnextclouddevclient.gradle = ['versionDev']
        apps['com.nextcloud.client.dev']['Builds'] = [buildnextclouddevclient]

        build_conversations = fdroidserver.metadata.Build()
        build_conversations.gradle = ['free']
        apps['eu.siacs.conversations']['Builds'] = [build_conversations]

        fdroidserver.update.insert_localized_app_metadata(apps)
        fdroidserver.update.ingest_screenshots_from_repo_dir(apps)

        appdir = Path('repo/info.guardianproject.urzip/en-US')
        self.assertTrue(
            os.path.isfile(
                os.path.join(
                    appdir, 'icon_NJXNzMcyf-v9i5a1ElJi0j9X1LvllibCa48xXYPlOqQ=.png'
                )
            )
        )
        self.assertTrue(
            os.path.isfile(
                os.path.join(
                    appdir,
                    'featureGraphic_GFRT5BovZsENGpJq1HqPODGWBRPWQsx25B95Ol5w_wU=.png',
                )
            )
        )

        self.assertEqual(6, len(apps))
        for packageName, app in apps.items():
            self.assertIn('localized', app, packageName)
            self.assertIn('en-US', app['localized'])
            self.assertEqual(1, len(app['localized']))
            if packageName == 'info.guardianproject.urzip':
                self.assertEqual(7, len(app['localized']['en-US']))
                self.assertEqual('full description\n', app['localized']['en-US']['description'])
                self.assertEqual('title', app['localized']['en-US']['name'])
                self.assertEqual('short description', app['localized']['en-US']['summary'])
                self.assertEqual('video', app['localized']['en-US']['video'])
                self.assertEqual('icon_NJXNzMcyf-v9i5a1ElJi0j9X1LvllibCa48xXYPlOqQ=.png',
                                 app['localized']['en-US']['icon'])
                self.assertEqual('featureGraphic_GFRT5BovZsENGpJq1HqPODGWBRPWQsx25B95Ol5w_wU=.png',
                                 app['localized']['en-US']['featureGraphic'])
                self.assertEqual('100\n', app['localized']['en-US']['whatsNew'])
            elif packageName == 'org.videolan.vlc':
                self.assertEqual(testfilename, app['localized']['en-US']['icon'])
                self.assertEqual(9, len(app['localized']['en-US']['phoneScreenshots']))
                self.assertEqual(15, len(app['localized']['en-US']['sevenInchScreenshots']))
            elif packageName == 'obb.mainpatch.current':
                self.assertEqual('icon_WI0pkO3LsklrsTAnRr-OQSxkkoMY41lYe2-fAvXLiLg=.png',
                                 app['localized']['en-US']['icon'])
                self.assertEqual('featureGraphic_ffhLaojxbGAfu9ROe1MJgK5ux8d0OVc6b65nmvOBaTk=.png',
                                 app['localized']['en-US']['featureGraphic'])
                self.assertEqual(1, len(app['localized']['en-US']['phoneScreenshots']))
                self.assertEqual(1, len(app['localized']['en-US']['sevenInchScreenshots']))
            elif packageName == 'com.nextcloud.client':
                self.assertEqual('Nextcloud', app['localized']['en-US']['name'])
                self.assertEqual(1073, len(app['localized']['en-US']['description']))
                self.assertEqual(78, len(app['localized']['en-US']['summary']))
            elif packageName == 'com.nextcloud.client.dev':
                self.assertEqual('Nextcloud Dev', app['localized']['en-US']['name'])
                self.assertEqual(586, len(app['localized']['en-US']['description']))
                self.assertEqual(78, len(app['localized']['en-US']['summary']))
            elif packageName == 'eu.siacs.conversations':
                self.assertEqual('Conversations', app['localized']['en-US']['name'])

    def test_insert_fastlane_default_txt_changelog(self):
        """Test that Fastlane's default.txt is handled properly

        https://docs.fastlane.tools/actions/supply/#changelogs-whats-new
        """
        os.chdir(self.testdir)

        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.update.config = config

        app = fdroidserver.metadata.App()
        app.id = 'com.example.app'
        changelogs_dir = 'build/%s/metadata/en-US/changelogs' % app.id
        os.makedirs(changelogs_dir)
        with open(os.path.join(changelogs_dir, 'default.txt'), 'w') as fp:
            fp.write('default')
        with open(os.path.join(changelogs_dir, '42.txt'), 'w') as fp:
            fp.write('42')
        apps = {app.id: app}
        build = fdroidserver.metadata.Build()
        build.versionCode = 42
        app['Builds'] = [build]

        fdroidserver.update.insert_localized_app_metadata(apps)
        self.assertEqual('default', apps[app.id]['localized']['en-US']['whatsNew'])

        app.CurrentVersionCode = 1
        fdroidserver.update.insert_localized_app_metadata(apps)
        self.assertEqual('default', apps[app.id]['localized']['en-US']['whatsNew'])

        app.CurrentVersionCode = 10000
        fdroidserver.update.insert_localized_app_metadata(apps)
        self.assertEqual('default', apps[app.id]['localized']['en-US']['whatsNew'])

        app.CurrentVersionCode = 42
        fdroidserver.update.insert_localized_app_metadata(apps)
        self.assertEqual('42', apps[app.id]['localized']['en-US']['whatsNew'])

    def test_name_title_scraping(self):
        """metadata file --> fdroiddata localized files --> fastlane/triple-t in app source --> APK"""
        shutil.copytree(basedir, self.testdir, dirs_exist_ok=True)
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config
        os.chdir(self.testdir)
        fdroidserver.common.options = Options
        fdroidserver.update.options = fdroidserver.common.options
        fdroidserver.update.options.clean = True
        fdroidserver.update.options.delete_unknown = True

        apps = fdroidserver.metadata.read_metadata()
        apps['info.guardianproject.urzip']['CurrentVersionCode'] = 100
        knownapks = fdroidserver.common.KnownApks()
        apks, cachechanged = fdroidserver.update.process_apks({}, 'repo', knownapks, False)
        fdroidserver.update.insert_localized_app_metadata(apps)
        fdroidserver.update.ingest_screenshots_from_repo_dir(apps)
        fdroidserver.update.apply_info_from_latest_apk(apps, apks)
        app = apps['info.guardianproject.urzip']
        self.assertIsNone(app.Name)
        self.assertTrue('localized' in app)
        self.assertEqual('title', app['localized']['en-US']['name'])
        self.assertEqual('100\n', app['localized']['en-US']['whatsNew'])
        app = apps['org.videolan.vlc']
        self.assertIsNone(app.Name)
        self.assertTrue('localized' in app)
        self.assertFalse('name' in app['localized']['en-US'])
        app = apps['info.guardianproject.checkey']
        self.assertEqual('Checkey the app!', app.Name)
        self.assertTrue('localized' in app)
        self.assertEqual('Checkey: info on local apps', app['localized']['en-US']['name'])
        self.assertEqual('Checkey: ローカルアプリの情報', app['localized']['ja-JP']['name'])
        app = apps['org.adaway']
        self.assertIsNone(app.Name)
        self.assertFalse('localized' in app)
        app = apps['obb.main.twoversions']
        self.assertIsNone(app.Name)
        self.assertFalse('localized' in app)

    def test_insert_missing_app_names_from_apks(self):
        """en-US serves as the final, default, fallback value with index-v1"""
        testvalue = 'TESTVALUE!'
        apps = {
            'none': {},
            'name': {'Name': testvalue},
            'onlyapk': {'Name': None},
            'autoname': {'AutoName': 'autoname', 'Name': None},
            'onlylocalized': {'localized': {'en-US': {'name': testvalue}}},
            'non_en_us_localized': {'localized': {'de-AT': {'name': 'leiwand'}}},
            'apks': {},
        }
        apks = [
            {'packageName': 'none', 'name': '', 'versionCode': 1},
            {'packageName': 'name', 'name': 'fromapk', 'versionCode': 1},
            {'packageName': 'onlyapk', 'name': testvalue, 'versionCode': 1},
            {'packageName': 'autoname', 'name': testvalue, 'versionCode': 1},
            {'packageName': 'onlylocalized', 'name': 'fromapk', 'versionCode': 1},
            {'packageName': 'non_en_us_localized', 'name': testvalue, 'versionCode': 0xcafe},
            {'packageName': 'apks', 'name': 'fromapk1', 'versionCode': 1},
            {'packageName': 'apks', 'name': 'fromapk2', 'versionCode': 2},
            {'packageName': 'apks', 'name': testvalue, 'versionCode': 3},
        ]
        fdroidserver.common.options = Options
        fdroidserver.update.insert_missing_app_names_from_apks(apps, apks)
        for appid, app in apps.items():
            if appid == 'none':
                self.assertIsNone(app.get('Name'))
                self.assertIsNone(app.get('localized'))
            elif appid == 'onlyapk':
                self.assertIsNone(app.get('Name'))
                self.assertEqual(testvalue, app['localized']['en-US']['name'])
            elif appid == 'autoname':
                self.assertIsNone(app.get('Name'))
                self.assertEqual(testvalue, app['localized']['en-US']['name'])
            elif appid == 'onlylocalized':
                self.assertIsNone(app.get('Name'))
                self.assertEqual(testvalue, app['localized']['en-US']['name'])
            elif appid == 'non_en_us_localized':
                self.assertIsNone(app.get('Name'))
                self.assertEqual(testvalue, app['localized']['en-US']['name'])
            elif appid == 'name':
                self.assertEqual(testvalue, app['Name'])
                self.assertIsNone(app.get('localized'))
            elif appid == 'apks':
                self.assertIsNone(app.get('Name'))
                self.assertEqual(testvalue, app['localized']['en-US']['name'])

    def test_insert_missing_app_names_from_apks_from_repo(self):
        os.chdir(self.testdir)
        shutil.copytree(basedir, self.testdir, dirs_exist_ok=True)
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config
        fdroidserver.common.options = Options
        fdroidserver.update.options = fdroidserver.common.options
        fdroidserver.update.options.clean = True
        fdroidserver.update.options.delete_unknown = True

        apps = fdroidserver.metadata.read_metadata()
        knownapks = fdroidserver.common.KnownApks()
        apks, cachechanged = fdroidserver.update.process_apks({}, 'repo', knownapks, False)

        appid = 'info.guardianproject.checkey'
        testapps = {appid: copy.copy(apps[appid])}
        self.assertEqual('Checkey the app!', testapps[appid]['Name'])
        del testapps[appid]['Name']
        fdroidserver.update.insert_missing_app_names_from_apks(testapps, apks)
        self.assertIsNone(testapps[appid].get('Name'))

        repoapps = fdroidserver.update.prepare_apps(apps, apks, 'repo')
        fdroidserver.update.insert_missing_app_names_from_apks(repoapps, apks)
        self.assertIsNone(repoapps['com.politedroid']['Name'])
        self.assertEqual('Polite Droid',
                         repoapps['com.politedroid']['localized']['en-US']['name'])
        self.assertEqual('Duplicate Permisssions', repoapps['duplicate.permisssions']['Name'])
        self.assertEqual('Caffeine Tile', repoapps['info.zwanenburg.caffeinetile']['Name'])
        self.assertEqual('No minSdkVersion or targetSdkVersion', repoapps['no.min.target.sdk']['Name'])
        self.assertIsNone(repoapps['obb.main.oldversion'].get('Name'))
        self.assertEqual('OBB Main Old Version',
                         repoapps['obb.main.oldversion']['localized']['en-US']['name'])
        self.assertIsNone(repoapps['obb.main.twoversions'].get('Name'))
        self.assertEqual('OBB Main Two Versions',
                         repoapps['obb.main.twoversions']['localized']['en-US']['name'])
        self.assertIsNone(repoapps['souch.smsbypass'].get('Name'))
        self.assertEqual('Battery level',
                         repoapps['souch.smsbypass']['localized']['en-US']['name'])
        self.assertIsNone(repoapps['info.guardianproject.urzip'].get('Name'))
        self.assertEqual('title',
                         repoapps['info.guardianproject.urzip']['localized']['en-US']['name'])
        self.assertIsNone(repoapps['obb.mainpatch.current'].get('Name'))

        del repoapps['info.guardianproject.urzip']['localized']
        fdroidserver.update.insert_missing_app_names_from_apks(repoapps, apks)
        self.assertEqual('urzip-πÇÇπÇÇ现代汉语通用字-български-عربي1234',
                         repoapps['info.guardianproject.urzip']['localized']['en-US']['name'])

    def test_insert_triple_t_metadata(self):
        importer = basedir / 'tmp/importer'
        packageName = 'org.fdroid.ci.test.app'
        if not os.path.isdir(importer):
            logging.warning('skipping test_insert_triple_t_metadata, test_import.py must run first!')
            return
        packageDir = os.path.join(self.testdir, 'build', packageName)
        shutil.copytree(importer, packageDir)

        # always use the same commit so these tests work when ci-test-app.git is updated
        repo = git.Repo(packageDir)
        for remote in repo.remotes:
            remote.fetch()
        repo.git.reset('--hard', 'b9e5d1a0d8d6fc31d4674b2f0514fef10762ed4f')
        repo.git.clean('-fdx')

        os.mkdir(os.path.join(self.testdir, 'metadata'))
        metadata = dict()
        metadata['Description'] = 'This is just a test app'
        with open(os.path.join(self.testdir, 'metadata', packageName + '.yml'), 'w') as fp:
            yaml.dump(metadata, fp)

        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config
        os.chdir(self.testdir)

        apps = fdroidserver.metadata.read_metadata()
        fdroidserver.update.copy_triple_t_store_metadata(apps)

        # TODO ideally, this would compare the whole dict like in test_metadata.test_read_metadata()
        correctlocales = [
            'ar', 'ast_ES', 'az', 'ca', 'ca_ES', 'cs-CZ', 'cs_CZ', 'da',
            'da-DK', 'de', 'de-DE', 'el', 'en-US', 'es', 'es-ES', 'es_ES', 'et',
            'fi', 'fr', 'fr-FR', 'he_IL', 'hi-IN', 'hi_IN', 'hu', 'id', 'it',
            'it-IT', 'it_IT', 'iw-IL', 'ja', 'ja-JP', 'kn_IN', 'ko', 'ko-KR',
            'ko_KR', 'lt', 'nb', 'nb_NO', 'nl', 'nl-NL', 'no', 'pl', 'pl-PL',
            'pl_PL', 'pt', 'pt-BR', 'pt-PT', 'pt_BR', 'ro', 'ro_RO', 'ru-RU',
            'ru_RU', 'sv-SE', 'sv_SE', 'te', 'tr', 'tr-TR', 'uk', 'uk_UA', 'vi',
            'vi_VN', 'zh-CN', 'zh_CN', 'zh_TW',
        ]
        locales = sorted(apps['org.fdroid.ci.test.app']['localized'])
        self.assertEqual(correctlocales, locales)

    def test_insert_triple_t_2_metadata(self):
        packageName = 'org.piwigo.android'
        shutil.copytree(basedir / 'triple-t-2', self.testdir, dirs_exist_ok=True)
        os.chdir(self.testdir)

        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config

        apps = fdroidserver.metadata.read_metadata()
        self.assertTrue(packageName in apps)
        fdroidserver.update.copy_triple_t_store_metadata(apps)
        correctlocales = ['de-DE', 'en-US', 'fr-FR', 'kn-IN']
        app = apps[packageName]
        self.assertEqual('android@piwigo.org', app['authorEmail'])
        self.assertEqual('https://www.piwigo.org', app['authorWebSite'])
        locales = sorted(list(app['localized'].keys()))
        self.assertEqual(correctlocales, locales)
        kn_IN = app['localized']['kn-IN']
        self.assertTrue('description' in kn_IN)
        self.assertTrue('name' in kn_IN)
        self.assertTrue('summary' in kn_IN)
        en_US = app['localized']['en-US']
        self.assertTrue('whatsNew' in en_US)

        os.chdir(os.path.join('repo', packageName))
        self.assertTrue(os.path.exists(os.path.join('en-US', 'icon.png')))
        self.assertTrue(os.path.exists(os.path.join('en-US', 'featureGraphic.png')))
        self.assertTrue(os.path.exists(os.path.join('en-US', 'phoneScreenshots', '01_Login.jpg')))
        self.assertTrue(os.path.exists(os.path.join('en-US', 'sevenInchScreenshots', '01_Login.png')))
        self.assertFalse(os.path.exists(os.path.join('de-DE', 'icon.png')))
        self.assertFalse(os.path.exists(os.path.join('de-DE', 'featureGraphic.png')))
        self.assertFalse(os.path.exists(os.path.join('de-DE', 'phoneScreenshots', '01_Login.jpg')))
        self.assertFalse(os.path.exists(os.path.join('de-DE', 'sevenInchScreenshots', '01_Login.png')))

    def test_insert_triple_t_anysoftkeyboard(self):
        packages = ('com.anysoftkeyboard.languagepack.dutch', 'com.menny.android.anysoftkeyboard')
        names = ('Dutch for AnySoftKeyboard', 'AnySoftKeyboard')

        shutil.copytree(basedir / 'triple-t-anysoftkeyboard', self.testdir, dirs_exist_ok=True)
        os.chdir(self.testdir)

        for packageName, name in zip(packages, names):
            config = dict()
            fdroidserver.common.fill_config_defaults(config)
            fdroidserver.common.config = config
            fdroidserver.update.config = config
            fdroidserver.update.options = fdroidserver.common.options

            apps = fdroidserver.metadata.read_metadata()
            self.assertTrue(packageName in apps)
            fdroidserver.update.copy_triple_t_store_metadata(apps)
            app = apps[packageName]
            self.assertEqual(app['localized']['en-US']['name'], name)

    def test_insert_triple_t_multiple_metadata(self):
        namespace = 'ch.admin.bag.covidcertificate.'
        packages = ('verifier', 'wallet')
        names = dict(verifier='COVID Certificate Check', wallet='COVID Certificate')

        shutil.copytree(basedir / 'triple-t-multiple', self.testdir, dirs_exist_ok=True)
        os.chdir(self.testdir)

        for p in packages:
            packageName = namespace + p
            config = dict()
            fdroidserver.common.fill_config_defaults(config)
            fdroidserver.common.config = config
            fdroidserver.update.config = config
            fdroidserver.update.options = fdroidserver.common.options

            apps = fdroidserver.metadata.read_metadata()
            self.assertTrue(packageName in apps)
            fdroidserver.update.copy_triple_t_store_metadata(apps)
            app = apps[packageName]
            self.assertEqual(app['localized']['en-US']['name'], names[p])

    def test_insert_triple_t_flutter(self):
        packageName = 'fr.emersion.goguma'

        shutil.copytree(basedir / 'triple-t-flutter', self.testdir, dirs_exist_ok=True)
        os.chdir(self.testdir)

        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config
        fdroidserver.update.options = fdroidserver.common.options

        apps = fdroidserver.metadata.read_metadata()
        self.assertTrue(packageName in apps)
        fdroidserver.update.copy_triple_t_store_metadata(apps)
        app = apps[packageName]
        self.assertEqual(app['authorWebSite'], 'https://emersion.fr')
        self.assertEqual(app['localized']['en-US']['name'], 'Goguma')
        self.assertEqual(app['localized']['en-US']['summary'], 'An IRC client for mobile devices')

    def testBadGetsig(self):
        """getsig() should still be able to fetch the fingerprint of bad signatures"""
        # config needed to use jarsigner and keytool
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.update.config = config

        apkfile = 'urzip-badsig.apk'
        sig = fdroidserver.update.getsig(apkfile)
        self.assertEqual(sig, 'e0ecb5fc2d63088e4a07ae410a127722',
                         "python sig should be: " + str(sig))

        apkfile = 'urzip-badcert.apk'
        sig = fdroidserver.update.getsig(apkfile)
        self.assertEqual(sig, 'e0ecb5fc2d63088e4a07ae410a127722',
                         "python sig should be: " + str(sig))

    def test_getsig(self):
        # config needed to use jarsigner and keytool
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.update.config = config

        sig = fdroidserver.update.getsig('urzip-release-unsigned.apk')
        self.assertIsNone(sig)

        good_fingerprint = 'b4964fd759edaa54e65bb476d0276880'

        apkpath = 'urzip-release.apk'  # v1 only
        sig = fdroidserver.update.getsig(apkpath)
        self.assertEqual(good_fingerprint, sig,
                         'python sig was: ' + str(sig))

        apkpath = 'repo/v1.v2.sig_1020.apk'
        sig = fdroidserver.update.getsig(apkpath)
        self.assertEqual(good_fingerprint, sig,
                         'python sig was: ' + str(sig))
        # check that v1 and v2 have the same certificate
        apkobject = APK(apkpath)
        cert_encoded = apkobject.get_certificates_der_v2()[0]
        self.assertEqual(good_fingerprint, sig,
                         hashlib.md5(hexlify(cert_encoded)).hexdigest())  # nosec just used as ID for signing key

        filename = 'v2.only.sig_2.apk'
        with zipfile.ZipFile(filename) as z:
            self.assertTrue('META-INF/MANIFEST.MF' in z.namelist(), 'META-INF/MANIFEST.MF required')
            for f in z.namelist():
                # ensure there are no v1 signature files
                self.assertIsNone(fdroidserver.common.SIGNATURE_BLOCK_FILE_REGEX.match(f))
        sig = fdroidserver.update.getsig(filename)
        self.assertEqual(good_fingerprint, sig,
                         "python sig was: " + str(sig))

    def testScanApksAndObbs(self):
        os.chdir(self.testdir)
        shutil.copytree(basedir / 'repo', 'repo')
        shutil.copytree(basedir / 'metadata', 'metadata')
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        config['ndk_paths'] = dict()
        fdroidserver.common.config = config
        fdroidserver.update.config = config

        fdroidserver.common.options = Options
        fdroidserver.update.options = fdroidserver.common.options
        fdroidserver.update.options.clean = True
        fdroidserver.update.options.delete_unknown = True

        apps = fdroidserver.metadata.read_metadata()
        knownapks = fdroidserver.common.KnownApks()
        apks, cachechanged = fdroidserver.update.process_apks({}, 'repo', knownapks, False)
        self.assertEqual(len(apks), 17)
        apk = apks[1]
        self.assertEqual(apk['packageName'], 'com.politedroid')
        self.assertEqual(apk['versionCode'], 3)
        self.assertEqual(apk['minSdkVersion'], 3)
        self.assertIsNone(apk.get('targetSdkVersion'))
        self.assertFalse('maxSdkVersion' in apk)
        apk = apks[8]
        self.assertEqual(apk['packageName'], 'obb.main.oldversion')
        self.assertEqual(apk['versionCode'], 1444412523)
        self.assertEqual(apk['minSdkVersion'], 4)
        self.assertEqual(apk['targetSdkVersion'], 18)
        self.assertFalse('maxSdkVersion' in apk)

        fdroidserver.update.insert_obbs('repo', apps, apks)
        for apk in apks:
            if apk['packageName'] == 'obb.mainpatch.current':
                self.assertEqual(apk.get('obbMainFile'), 'main.1619.obb.mainpatch.current.obb')
                self.assertEqual(apk.get('obbPatchFile'), 'patch.1619.obb.mainpatch.current.obb')
            elif apk['packageName'] == 'obb.main.oldversion':
                self.assertEqual(apk.get('obbMainFile'), 'main.1434483388.obb.main.oldversion.obb')
                self.assertIsNone(apk.get('obbPatchFile'))
            elif apk['packageName'] == 'obb.main.twoversions':
                self.assertIsNone(apk.get('obbPatchFile'))
                if apk['versionCode'] == 1101613:
                    self.assertEqual(apk.get('obbMainFile'), 'main.1101613.obb.main.twoversions.obb')
                elif apk['versionCode'] == 1101615:
                    self.assertEqual(apk.get('obbMainFile'), 'main.1101615.obb.main.twoversions.obb')
                elif apk['versionCode'] == 1101617:
                    self.assertEqual(apk.get('obbMainFile'), 'main.1101615.obb.main.twoversions.obb')
                else:
                    self.assertTrue(False)
            elif apk['packageName'] == 'info.guardianproject.urzip':
                self.assertIsNone(apk.get('obbMainFile'))
                self.assertIsNone(apk.get('obbPatchFile'))

    def test_apkcache_json(self):
        """test the migration from pickle to json"""
        os.chdir(self.testdir)
        shutil.copytree(basedir / 'repo', 'repo')
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        config['ndk_paths'] = dict()
        fdroidserver.common.config = config
        fdroidserver.update.config = config

        fdroidserver.common.options = Options
        fdroidserver.update.options = fdroidserver.common.options
        fdroidserver.update.options.clean = True
        fdroidserver.update.options.delete_unknown = True

        fdroidserver.metadata.read_metadata()
        knownapks = fdroidserver.common.KnownApks()
        apkcache = fdroidserver.update.get_cache()
        self.assertEqual(2, len(apkcache))
        self.assertEqual(fdroidserver.update.METADATA_VERSION, apkcache["METADATA_VERSION"])
        self.assertEqual(fdroidserver.update.options.allow_disabled_algorithms,
                         apkcache['allow_disabled_algorithms'])
        apks, cachechanged = fdroidserver.update.process_apks(apkcache, 'repo', knownapks, False)
        fdroidserver.update.write_cache(apkcache)

        fdroidserver.update.options.clean = False
        read_from_json = fdroidserver.update.get_cache()
        self.assertEqual(19, len(read_from_json))
        for f in glob.glob('repo/*.apk'):
            self.assertTrue(os.path.basename(f) in read_from_json)

        fdroidserver.update.options.clean = True
        reset = fdroidserver.update.get_cache()
        self.assertEqual(2, len(reset))

    def test_scan_repo_files(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config

        os.chdir(self.testdir)
        os.mkdir('repo')
        filename = 'Norway_bouvet_europe_2.obf.zip'
        shutil.copy(basedir / filename, 'repo')
        knownapks = fdroidserver.common.KnownApks()
        files, fcachechanged = fdroidserver.update.scan_repo_files(dict(), 'repo', knownapks, False)
        self.assertTrue(fcachechanged)

        info = files[0]
        self.assertEqual(filename, info['apkName'])
        self.assertEqual(datetime, type(info['added']))
        self.assertEqual(os.path.getsize(os.path.join('repo', filename)), info['size'])
        self.assertEqual(
            '531190bdbc07e77d5577249949106f32dac7f62d38d66d66c3ae058be53a729d',
            info['hash'],
        )

    def test_read_added_date_from_all_apks(self):
        os.chdir(self.testdir)
        shutil.copytree(basedir / 'repo', 'repo')
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config
        fdroidserver.common.options = Options
        apps = fdroidserver.metadata.read_metadata()
        knownapks = fdroidserver.common.KnownApks()
        apks, cachechanged = fdroidserver.update.process_apks({}, 'repo', knownapks)
        fdroidserver.update.read_added_date_from_all_apks(apps, apks)

    def test_apply_info_from_latest_apk(self):
        os.chdir(self.testdir)
        shutil.copytree(basedir / 'repo', 'repo')
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config
        fdroidserver.common.options = Options
        fdroidserver.update.options = fdroidserver.common.options
        apps = fdroidserver.metadata.read_metadata()
        knownapks = fdroidserver.common.KnownApks()
        apks, cachechanged = fdroidserver.update.process_apks({}, 'repo', knownapks)
        fdroidserver.update.apply_info_from_latest_apk(apps, apks)

    def test_scan_apk(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config
        os.chdir(basedir)

        if 'apksigner' in config:
            apk_info = fdroidserver.update.scan_apk('v2.only.sig_2.apk')
            self.assertIsNone(apk_info.get('maxSdkVersion'))
            self.assertEqual(apk_info.get('versionName'), 'v2-only')
            self.assertEqual(apk_info.get('versionCode'), 2)
        else:
            print('WARNING: skipping v2-only test since apksigner cannot be found')
        apk_info = fdroidserver.update.scan_apk('repo/v1.v2.sig_1020.apk')
        self.assertIsNone(apk_info.get('maxSdkVersion'))
        self.assertEqual(apk_info.get('versionName'), 'v1+2')
        self.assertEqual(apk_info.get('versionCode'), 1020)

        apk_info = fdroidserver.update.scan_apk('repo/souch.smsbypass_9.apk')
        self.assertIsNone(apk_info.get('maxSdkVersion'))
        self.assertEqual(apk_info.get('versionName'), '0.9')

        apk_info = fdroidserver.update.scan_apk('repo/duplicate.permisssions_9999999.apk')
        self.assertEqual(apk_info.get('versionName'), '')
        self.assertEqual(apk_info['icons_src'], {'160': 'res/drawable/ic_launcher.png',
                                                 '-1': 'res/drawable/ic_launcher.png'})

        apk_info = fdroidserver.update.scan_apk('org.dyndns.fules.ck_20.apk')
        self.assertEqual(apk_info['icons_src'], {'240': 'res/drawable-hdpi-v4/icon_launcher.png',
                                                 '120': 'res/drawable-ldpi-v4/icon_launcher.png',
                                                 '160': 'res/drawable-mdpi-v4/icon_launcher.png',
                                                 '-1': 'res/drawable-mdpi-v4/icon_launcher.png'})
        self.assertEqual(apk_info['icons'], {})
        self.assertEqual(apk_info['features'], [])
        self.assertEqual(apk_info['antiFeatures'], dict())
        self.assertEqual(apk_info['versionName'], 'v1.6pre2')
        self.assertEqual(apk_info['hash'],
                         '897486e1f857c6c0ee32ccbad0e1b8cd82f6d0e65a44a23f13f852d2b63a18c8')
        self.assertEqual(apk_info['packageName'], 'org.dyndns.fules.ck')
        self.assertEqual(apk_info['versionCode'], 20)
        self.assertEqual(apk_info['size'], 132453)
        self.assertEqual(apk_info['nativecode'],
                         ['arm64-v8a', 'armeabi', 'armeabi-v7a', 'mips', 'mips64', 'x86', 'x86_64'])
        self.assertEqual(apk_info['minSdkVersion'], 7)
        self.assertEqual(apk_info['sig'], '9bf7a6a67f95688daec75eab4b1436ac')
        self.assertEqual(apk_info['hashType'], 'sha256')
        self.assertEqual(apk_info['targetSdkVersion'], 8)

        apk_info = fdroidserver.update.scan_apk('org.bitbucket.tickytacky.mirrormirror_4.apk')
        self.assertEqual(apk_info.get('versionName'), '1.0.3')
        self.assertEqual(apk_info['icons_src'], {'160': 'res/drawable-mdpi/mirror.png',
                                                 '-1': 'res/drawable-mdpi/mirror.png'})

        apk_info = fdroidserver.update.scan_apk('repo/info.zwanenburg.caffeinetile_4.apk')
        self.assertEqual(apk_info.get('versionName'), '1.3')
        self.assertEqual(apk_info['icons_src'], {})

        apk_info = fdroidserver.update.scan_apk('repo/com.politedroid_6.apk')
        self.assertEqual(apk_info.get('versionName'), '1.5')
        self.assertEqual(apk_info['icons_src'], {'120': 'res/drawable-ldpi-v4/icon.png',
                                                 '160': 'res/drawable-mdpi-v4/icon.png',
                                                 '240': 'res/drawable-hdpi-v4/icon.png',
                                                 '320': 'res/drawable-xhdpi-v4/icon.png',
                                                 '-1': 'res/drawable-mdpi-v4/icon.png'})

        apk_info = fdroidserver.update.scan_apk('SpeedoMeterApp.main_1.apk')
        self.assertEqual(apk_info.get('versionName'), '1.0')
        self.assertEqual(apk_info['icons_src'], {})

    def test_scan_apk_no_min_target(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config
        apk_info = fdroidserver.update.scan_apk('repo/no.min.target.sdk_987.apk')
        self.maxDiff = None
        expected = {
            'icons': {},
            'icons_src': {'-1': 'res/drawable/ic_launcher.png',
                          '160': 'res/drawable/ic_launcher.png'},
            'name': 'No minSdkVersion or targetSdkVersion',
            'signer': '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6',
            'hashType': 'sha256',
            'packageName': 'no.min.target.sdk',
            'features': [],
            'antiFeatures': dict(),
            'size': 14102,
            'sig': 'b4964fd759edaa54e65bb476d0276880',
            'versionName': '1.2-fake',
            'uses-permission-sdk-23': [],
            'hash': 'e2e1dc1d550df2b5bc383860139207258645b5540abeccd305ed8b2cb6459d2c',
            'versionCode': 987,
            'minSdkVersion': 3,
            'uses-permission': [
                fdroidserver.update.UsesPermission(name='android.permission.WRITE_EXTERNAL_STORAGE',
                                                   maxSdkVersion=None),
                fdroidserver.update.UsesPermission(name='android.permission.READ_PHONE_STATE',
                                                   maxSdkVersion=None),
                fdroidserver.update.UsesPermission(name='android.permission.READ_EXTERNAL_STORAGE',
                                                   maxSdkVersion=None),
            ],
        }
        if config.get('ipfs_cid'):
            expected['ipfsCIDv1'] = 'bafybeidwxseoagnew3gtlasttqovl7ciuwxaud5a5p4a5pzpbrfcfj2gaa'

        self.assertDictEqual(apk_info, expected)

    def test_scan_apk_no_sig(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config
        os.chdir(basedir)
        if os.path.basename(os.getcwd()) != 'tests':
            raise Exception('This test must be run in the "tests/" subdir')

        with self.assertRaises(fdroidserver.exception.BuildException):
            fdroidserver.update.scan_apk('urzip-release-unsigned.apk')

    def test_scan_apk_bad_zip(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config
        os.chdir(self.testdir)
        os.mkdir('repo')
        apkfile = 'repo/badzip_1.apk'
        with open(apkfile, 'w') as fp:
            fp.write('this is not a zip file')
        with self.assertRaises(fdroidserver.exception.BuildException):
            fdroidserver.update.scan_apk(apkfile)

    @unittest.skipUnless(
        os.path.exists('tests/SystemWebView-repack.apk'), "file too big for sdist"
    )
    def test_scan_apk_bad_icon_id(self):
        """Some APKs can produce an exception when extracting the icon

        This kind of parsing exception should be reported then ignored
        so that working APKs can be included in the index.  There are
        so many weird things that make it into APKs, that does not
        automatically disqualify them from inclusion. For example:

        ValueError: invalid literal for int() with base 16: '<0x801FF, type 0x07>'

        The test APK was made from:
        https://gitlab.com/fdroid/fdroidserver/-/merge_requests/1018#note_690565333
        It was then stripped down by doing:

        * mkdir SystemWebView
        * cd SystemWebView/
        * unzip ../SystemWebView.apk
        * rm -rf META-INF/ lib assets/icudtl.dat assets/stored-locales/
        * jar cf ../SystemWebView-repack.apk *
        """
        # reset the state, perhaps this should be in setUp()
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config
        with mkdtemp() as tmpdir, TmpCwd(tmpdir):
            os.mkdir('repo')
            apkfile = 'repo/SystemWebView-repack.apk'
            shutil.copy(basedir / os.path.basename(apkfile), apkfile)
            fdroidserver.update.scan_apk(apkfile)

    def test_scan_apk_bad_namespace_in_manifest(self):
        """Some APKs can produce an exception when parsing the AndroidManifest.xml

        This kind of parsing exception should be reported then ignored
        so that working APKs can be included in the index.  There are
        so many weird things that make it into APKs, that does not
        automatically disqualify them from inclusion.

        This APK has <uses-permission> elements with messed up namespaces:
        <uses-permission xmlns:n1="android" n1:name="android.permission.VIBRATE"/>

        """
        # reset the state, perhaps this should be in setUp()
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config
        with mkdtemp() as tmpdir, TmpCwd(tmpdir):
            os.mkdir('repo')
            apkfile = 'repo/org.sajeg.fallingblocks_3.apk'
            shutil.copy(basedir / os.path.basename(apkfile), apkfile)
            fdroidserver.update.scan_apk(apkfile)

    def test_process_apk(self):
        def _build_yaml_representer(dumper, data):
            '''Creates a YAML representation of a Build instance'''
            return dumper.represent_dict(data)

        os.chdir(self.testdir)
        shutil.copytree(basedir, 'tests')
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config
        os.chdir("tests")

        config['ndk_paths'] = dict()
        fdroidserver.common.config = config
        fdroidserver.update.config = config

        fdroidserver.common.options = Options
        fdroidserver.update.options = fdroidserver.common.options
        fdroidserver.update.options.clean = True
        fdroidserver.update.options.delete_unknown = True

        for icon_dir in fdroidserver.update.get_all_icon_dirs('repo'):
            if not os.path.exists(icon_dir):
                os.makedirs(icon_dir)

        knownapks = fdroidserver.common.KnownApks()
        apkList = ['../urzip.apk', '../org.dyndns.fules.ck_20.apk']

        for apkName in apkList:
            _, apk, cachechanged = fdroidserver.update.process_apk({}, apkName, 'repo', knownapks,
                                                                   False)
            # Don't care about the date added to the repo and relative apkName
            self.assertEqual(datetime, type(apk['added']))
            del apk['added']
            del apk['apkName']

            # ensure that icons have been extracted properly
            if apkName == '../urzip.apk':
                self.assertEqual(apk['icon'], 'info.guardianproject.urzip.100.png')
            if apkName == '../org.dyndns.fules.ck_20.apk':
                self.assertEqual(apk['icon'], 'org.dyndns.fules.ck.20.png')
            for density in fdroidserver.update.screen_densities:
                icon_path = os.path.join(
                    fdroidserver.update.get_icon_dir('repo', density), apk['icon']
                )
                self.assertTrue(os.path.isfile(icon_path))
                self.assertTrue(os.path.getsize(icon_path) > 1)

            savepath = os.path.join('metadata', 'apk', apk['packageName'] + '.yaml')
            # Uncomment to save APK metadata
            # with open(savepath, 'w') as f:
            #     yaml.add_representer(fdroidserver.metadata.Build, _build_yaml_representer)
            #     yaml.dump(apk, f, default_flow_style=False)

            # CFullLoader doesn't always work
            # https://github.com/yaml/pyyaml/issues/266#issuecomment-559116876
            TestLoader = FullLoader
            try:
                testyaml = '- !!python/object/new:fdroidserver.update.UsesPermission\n  - test\n  - null'
                from_yaml = yaml.load(testyaml, Loader=TestLoader)  # nosec B506
            except yaml.constructor.ConstructorError:
                from yaml import UnsafeLoader as TestLoader

            with open(savepath, 'r') as f:
                from_yaml = yaml.load(f, Loader=TestLoader)  # nosec B506
            self.maxDiff = None
            if not config.get('ipfs_cid'):
                del from_yaml['ipfsCIDv1']  # handle when ipfs_cid is not installed
            self.assertEqual(apk, from_yaml)

    def test_process_apk_signed_by_disabled_algorithms(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.update.config = config

        config['ndk_paths'] = dict()
        fdroidserver.common.config = config
        fdroidserver.update.config = config

        fdroidserver.common.options = Options
        fdroidserver.update.options = fdroidserver.common.options
        fdroidserver.update.options.clean = True
        fdroidserver.update.options.verbose = True
        fdroidserver.update.options.delete_unknown = True

        knownapks = fdroidserver.common.KnownApks()

        with mkdtemp() as tmptestsdir, TmpCwd(tmptestsdir):
            os.mkdir('repo')
            os.mkdir('archive')
            # setup the repo, create icons dirs, etc.
            fdroidserver.update.process_apks({}, 'repo', knownapks)
            fdroidserver.update.process_apks({}, 'archive', knownapks)

            disabledsigs = ['org.bitbucket.tickytacky.mirrormirror_2.apk']
            for apkName in disabledsigs:
                shutil.copy(basedir / apkName,
                            os.path.join(tmptestsdir, 'repo'))

                skip, apk, cachechanged = fdroidserver.update.process_apk({}, apkName, 'repo',
                                                                          knownapks,
                                                                          allow_disabled_algorithms=True,
                                                                          archive_bad_sig=False)
                self.assertFalse(skip)
                self.assertIsNotNone(apk)
                self.assertTrue(cachechanged)
                self.assertFalse(os.path.exists(os.path.join('archive', apkName)))
                self.assertTrue(os.path.exists(os.path.join('repo', apkName)))

                if os.path.exists('/usr/bin/apksigner') or 'apksigner' in config:
                    print('SKIPPING: apksigner installed and it allows MD5 signatures')
                    return

                javac = config['jarsigner'].replace('jarsigner', 'javac')
                v = subprocess.check_output([javac, '-version'], stderr=subprocess.STDOUT)[6:-1].decode('utf-8')
                if LooseVersion(v) < LooseVersion('1.8.0_132'):
                    print('SKIPPING: running tests with old Java (' + v + ')')
                    return

                # this test only works on systems with fully updated Java/jarsigner
                # that has MD5 listed in jdk.jar.disabledAlgorithms in java.security
                # https://blogs.oracle.com/java-platform-group/oracle-jre-will-no-longer-trust-md5-signed-code-by-default
                skip, apk, cachechanged = fdroidserver.update.process_apk({}, apkName, 'repo',
                                                                          knownapks,
                                                                          allow_disabled_algorithms=False,
                                                                          archive_bad_sig=True)
                self.assertTrue(skip)
                self.assertIsNone(apk)
                self.assertFalse(cachechanged)
                self.assertTrue(os.path.exists(os.path.join('archive', apkName)))
                self.assertFalse(os.path.exists(os.path.join('repo', apkName)))

                skip, apk, cachechanged = fdroidserver.update.process_apk({}, apkName, 'archive',
                                                                          knownapks,
                                                                          allow_disabled_algorithms=False,
                                                                          archive_bad_sig=False)
                self.assertFalse(skip)
                self.assertIsNotNone(apk)
                self.assertTrue(cachechanged)
                self.assertTrue(os.path.exists(os.path.join('archive', apkName)))
                self.assertFalse(os.path.exists(os.path.join('repo', apkName)))

                # ensure that icons have been moved to the archive as well
                for density in fdroidserver.update.screen_densities:
                    icon_path = os.path.join(fdroidserver.update.get_icon_dir('archive', density),
                                             apk['icon'])
                    self.assertTrue(os.path.isfile(icon_path))
                    self.assertTrue(os.path.getsize(icon_path) > 1)

            badsigs = ['urzip-badcert.apk', 'urzip-badsig.apk', 'urzip-release-unsigned.apk', ]
            for apkName in badsigs:
                shutil.copy(basedir / apkName,
                            os.path.join(self.testdir, 'repo'))

                skip, apk, cachechanged = fdroidserver.update.process_apk({}, apkName, 'repo',
                                                                          knownapks,
                                                                          allow_disabled_algorithms=False,
                                                                          archive_bad_sig=False)
                self.assertTrue(skip)
                self.assertIsNone(apk)
                self.assertFalse(cachechanged)

    def test_process_invalid_apk(self):
        os.chdir(basedir)
        if os.path.basename(os.getcwd()) != 'tests':
            raise Exception('This test must be run in the "tests/" subdir')

        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config
        fdroidserver.common.options = Options
        fdroidserver.update.options = fdroidserver.common.options
        fdroidserver.update.options.delete_unknown = False

        knownapks = fdroidserver.common.KnownApks()
        apk = 'fake.ota.update_1234.zip'  # this is not an APK, scanning should fail
        (skip, apk, cachechanged) = fdroidserver.update.process_apk({}, apk, 'repo', knownapks,
                                                                    False)

        self.assertTrue(skip)
        self.assertIsNone(apk)
        self.assertFalse(cachechanged)

    def test_get_apks_without_allowed_signatures(self):
        """Test when no AllowedAPKSigningKeys is specified"""
        os.chdir(self.testdir)
        shutil.copytree(basedir / 'repo', 'repo')
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.common.options = Options
        fdroidserver.update.options = fdroidserver.common.options

        app = fdroidserver.metadata.App()
        knownapks = fdroidserver.common.KnownApks()
        apks, cachechanged = fdroidserver.update.process_apks({}, 'repo', knownapks)
        apkfile = 'v1.v2.sig_1020.apk'
        self.assertIn(
            apkfile,
            os.listdir('repo'),
            f'{apkfile} was archived or otherwise removed from "repo"',
        )
        (skip, apk, cachechanged) = fdroidserver.update.process_apk(
            {}, apkfile, 'repo', knownapks, False
        )

        r = fdroidserver.update.get_apks_without_allowed_signatures(app, apk)
        self.assertIsNone(r)

    def test_get_apks_without_allowed_signatures_allowed(self):
        """Test when the APK matches the specified AllowedAPKSigningKeys"""
        os.chdir(self.testdir)
        shutil.copytree(basedir / 'repo', 'repo')
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.common.options = Options
        fdroidserver.update.options = fdroidserver.common.options

        app = fdroidserver.metadata.App(
            {
                'AllowedAPKSigningKeys': '32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6'
            }
        )
        knownapks = fdroidserver.common.KnownApks()
        apks, cachechanged = fdroidserver.update.process_apks({}, 'repo', knownapks)
        apkfile = 'v1.v2.sig_1020.apk'
        (skip, apk, cachechanged) = fdroidserver.update.process_apk(
            {}, apkfile, 'repo', knownapks, False
        )

        r = fdroidserver.update.get_apks_without_allowed_signatures(app, apk)
        self.assertIsNone(r)

    def test_get_apks_without_allowed_signatures_blocked(self):
        """Test when the APK does not match any specified AllowedAPKSigningKeys"""
        os.chdir(self.testdir)
        shutil.copytree(basedir / 'repo', 'repo')
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.common.options = Options
        fdroidserver.update.options = fdroidserver.common.options

        app = fdroidserver.metadata.App(
            {
                'AllowedAPKSigningKeys': 'fa4edeadfa4edeadfa4edeadfa4edeadfa4edeadfa4edeadfa4edeadfa4edead'
            }
        )
        knownapks = fdroidserver.common.KnownApks()
        apks, cachechanged = fdroidserver.update.process_apks({}, 'repo', knownapks)
        apkfile = 'v1.v2.sig_1020.apk'
        (skip, apk, cachechanged) = fdroidserver.update.process_apk(
            {}, apkfile, 'repo', knownapks, False
        )

        r = fdroidserver.update.get_apks_without_allowed_signatures(app, apk)
        self.assertEqual(apkfile, r)

    def test_update_with_AllowedAPKSigningKeys(self):
        """Test that APKs without allowed signatures get deleted."""
        os.chdir(self.testdir)
        os.mkdir('repo')
        testapk = os.path.join('repo', 'com.politedroid_6.apk')
        shutil.copy(basedir / testapk, testapk)
        os.mkdir('metadata')
        metadatafile = os.path.join('metadata', 'com.politedroid.yml')

        # Copy and manipulate metadata file
        shutil.copy(basedir / metadatafile, metadatafile)
        with open(metadatafile, 'a') as fp:
            fp.write(
                '\n\nAllowedAPKSigningKeys: 32a23624c201b949f085996ba5ed53d40f703aca4989476949cae891022e0ed6\n'
            )

        # Set up options
        fdroidserver.common.options = Options
        config = fdroidserver.common.read_config()
        if 'apksigner' not in config:  # TODO remove me for buildserver-bullseye
            self.skipTest('SKIPPING test_update_with_AllowedAPKSigningKeys, apksigner not installed!')
        config['repo_keyalias'] = 'sova'
        config['keystorepass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        config['keypass'] = 'r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI='
        config['keystore'] = os.path.join(basedir, 'keystore.jks')

        self.assertTrue(os.path.exists(testapk))

        # Test for non-deletion
        with mock.patch('sys.argv', ['fdroid update', '--delete-unknown']):
            fdroidserver.update.main()
        self.assertTrue(os.path.exists(testapk))

        # Copy and manipulate metadata file again
        shutil.copy(basedir / metadatafile, metadatafile)
        with open(metadatafile, 'a') as fp:
            fp.write(
                '\n\nAllowedAPKSigningKeys: fa4edeadfa4edeadfa4edeadfa4edeadfa4edeadfa4edeadfa4edeadfa4edead\n'
            )

        # Test for deletion
        with mock.patch('sys.argv', ['fdroid update', '--delete-unknown']):
            fdroidserver.update.main()
        self.assertFalse(os.path.exists(testapk))

    def test_translate_per_build_anti_features(self):
        os.chdir(self.testdir)
        shutil.copytree(basedir / 'repo', 'repo')
        shutil.copytree(basedir / 'metadata', 'metadata')
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        config['ndk_paths'] = dict()
        fdroidserver.common.config = config
        fdroidserver.update.config = config

        fdroidserver.common.options = Options
        fdroidserver.update.options = fdroidserver.common.options
        fdroidserver.update.options.clean = True
        fdroidserver.update.options.delete_unknown = True

        apps = fdroidserver.metadata.read_metadata()
        knownapks = fdroidserver.common.KnownApks()
        apks, cachechanged = fdroidserver.update.process_apks({}, 'repo', knownapks, False)
        fdroidserver.update.translate_per_build_anti_features(apps, apks)
        self.assertEqual(len(apks), 17)
        foundtest = False
        for apk in apks:
            if apk['packageName'] == 'com.politedroid' and apk['versionCode'] == 3:
                antiFeatures = apk.get('antiFeatures')
                self.assertTrue('KnownVuln' in antiFeatures)
                self.assertEqual(3, len(antiFeatures))
                foundtest = True
        self.assertTrue(foundtest)

    def test_create_metadata_from_template(self):
        os.chdir(self.testdir)
        os.mkdir('repo')
        os.mkdir('metadata')
        shutil.copy(basedir / 'urzip.apk', 'repo')

        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        config['ndk_paths'] = dict()
        fdroidserver.common.config = config
        fdroidserver.update.config = config

        fdroidserver.common.options = Options
        fdroidserver.update.options = fdroidserver.common.options
        fdroidserver.update.options.clean = True

        knownapks = fdroidserver.common.KnownApks()
        apks, cachechanged = fdroidserver.update.process_apks({}, 'repo', knownapks, False)
        self.assertEqual(1, len(apks))
        apk = apks[0]

        testfile = 'metadata/info.guardianproject.urzip.yml'
        # create empty 0 byte .yml file, run read_metadata, it should work
        open(testfile, 'a').close()
        apps = fdroidserver.metadata.read_metadata()
        self.assertEqual(1, len(apps))
        os.remove(testfile)

        # test using internal template
        apps = fdroidserver.metadata.read_metadata()
        self.assertEqual(0, len(apps))
        fdroidserver.update.create_metadata_from_template(apk)
        self.assertTrue(os.path.exists(testfile))
        apps = fdroidserver.metadata.read_metadata()
        self.assertEqual(1, len(apps))
        for app in apps.values():
            self.assertEqual('urzip', app['Name'])
            self.assertEqual(1, len(app['Categories']))
            break

        # test using external template.yml
        os.remove(testfile)
        self.assertFalse(os.path.exists(testfile))
        shutil.copy(basedir.with_name('examples') / 'template.yml', self.testdir)
        fdroidserver.update.create_metadata_from_template(apk)
        self.assertTrue(os.path.exists(testfile))
        apps = fdroidserver.metadata.read_metadata()
        self.assertEqual(1, len(apps))
        for app in apps.values():
            self.assertEqual('urzip', app['Name'])
            self.assertEqual(1, len(app['Categories']))
            self.assertEqual('Internet', app['Categories'][0])
            break
        with open(testfile) as fp:
            data = yaml.load(fp, Loader=SafeLoader)
        self.assertEqual('urzip', data['Name'])
        self.assertEqual('urzip', data['Summary'])

    def test_has_known_vulnerability(self):
        good = [
            'org.bitbucket.tickytacky.mirrormirror_1.apk',
            'org.bitbucket.tickytacky.mirrormirror_2.apk',
            'org.bitbucket.tickytacky.mirrormirror_3.apk',
            'org.bitbucket.tickytacky.mirrormirror_4.apk',
            'org.dyndns.fules.ck_20.apk',
            'urzip.apk',
            'urzip-badcert.apk',
            'urzip-badsig.apk',
            'urzip-release.apk',
            'urzip-release-unsigned.apk',
            'repo/com.politedroid_3.apk',
            'repo/com.politedroid_4.apk',
            'repo/com.politedroid_5.apk',
            'repo/com.politedroid_6.apk',
            'repo/obb.main.oldversion_1444412523.apk',
            'repo/obb.mainpatch.current_1619_another-release-key.apk',
            'repo/obb.mainpatch.current_1619.apk',
            'repo/obb.main.twoversions_1101613.apk',
            'repo/obb.main.twoversions_1101615.apk',
            'repo/obb.main.twoversions_1101617.apk',
            'repo/urzip-; Рахма́, [rɐxˈmanʲɪnəf] سيرجي_رخمانينوف 谢·.apk',
        ]
        for f in good:
            self.assertFalse(fdroidserver.update.has_known_vulnerability(f))
        with self.assertRaises(fdroidserver.exception.FDroidException):
            fdroidserver.update.has_known_vulnerability('janus.apk')

    def test_get_apk_icon_when_src_is_none(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.update.config = config

        # pylint: disable=protected-access
        icons_src = fdroidserver.update._get_apk_icons_src('urzip-release.apk', None)
        self.assertFalse(icons_src)

    def test_strip_and_copy_image(self):
        in_file = basedir / 'metadata/info.guardianproject.urzip/en-US/images/icon.png'
        out_file = os.path.join(self.testdir, 'icon.png')
        fdroidserver.update._strip_and_copy_image(in_file, out_file)
        self.assertTrue(os.path.exists(out_file))

    def test_strip_and_copy_image_bad_filename(self):
        in_file = basedir / 'corrupt-featureGraphic.png'
        out_file = os.path.join(self.testdir, 'corrupt-featureGraphic.png')
        fdroidserver.update._strip_and_copy_image(in_file, out_file)
        self.assertFalse(os.path.exists(out_file))

    def test_create_metadata_from_template_empty_keys(self):
        apk = {'packageName': 'rocks.janicerand'}
        with mkdtemp() as tmpdir, TmpCwd(tmpdir):
            os.mkdir('metadata')
            with open('template.yml', 'w') as f:
                f.write(
                    textwrap.dedent(
                        '''\
                    Disabled:
                    License:
                    AuthorName:
                    AuthorEmail:
                    AuthorWebSite:
                    WebSite:
                    SourceCode:
                    IssueTracker:
                    Translation:
                    Changelog:
                    Donate:
                    Bitcoin:
                    Litecoin:
                    Name:
                    AutoName:
                    Summary:
                    RequiresRoot:
                    RepoType:
                    Repo:
                    Binaries:
                    Builds:
                    ArchivePolicy:
                    AutoUpdateMode:
                    UpdateCheckMode:
                    UpdateCheckIgnore:
                    VercodeOperation:
                    UpdateCheckName:
                    UpdateCheckData:
                    CurrentVersion:
                    CurrentVersionCode:
                    NoSourceSince:
                    '''
                    )
                )
            fdroidserver.update.create_metadata_from_template(apk)
            with open(os.path.join('metadata', 'rocks.janicerand.yml')) as f:
                metadata_content = yaml.load(f, Loader=SafeLoader)
                self.maxDiff = None
                self.assertDictEqual(
                    metadata_content,
                    {
                        'ArchivePolicy': None,
                        'AuthorEmail': '',
                        'AuthorName': '',
                        'AuthorWebSite': '',
                        'AutoName': 'rocks.janicerand',
                        'AutoUpdateMode': '',
                        'Binaries': '',
                        'Bitcoin': '',
                        'Builds': None,
                        'Changelog': '',
                        'CurrentVersion': '',
                        'CurrentVersionCode': None,
                        'Disabled': '',
                        'Donate': '',
                        'IssueTracker': '',
                        'License': '',
                        'Litecoin': '',
                        'Name': 'rocks.janicerand',
                        'NoSourceSince': '',
                        'Repo': '',
                        'RepoType': '',
                        'RequiresRoot': None,
                        'SourceCode': '',
                        'Summary': 'rocks.janicerand',
                        'Translation': '',
                        'UpdateCheckData': '',
                        'UpdateCheckIgnore': '',
                        'UpdateCheckMode': '',
                        'UpdateCheckName': '',
                        'VercodeOperation': None,
                        'WebSite': '',
                    },
                )

    def test_insert_funding_yml_donation_links(self):
        os.chdir(self.testdir)
        os.mkdir('build')
        content = textwrap.dedent(
            """
            community_bridge: ''
            custom: [LINK1, LINK2]
            github: USERNAME
            issuehunt: USERNAME
            ko_fi: USERNAME
            liberapay: USERNAME
            open_collective: USERNAME
            otechie: USERNAME
            patreon: USERNAME
        """
        )
        app = fdroidserver.metadata.App()
        app.id = 'fake.app.id'
        apps = {app.id: app}
        os.mkdir(os.path.join('build', app.id))
        fdroidserver.update.insert_funding_yml_donation_links(apps)
        for field in DONATION_FIELDS:
            self.assertFalse(app.get(field))
        with open(os.path.join('build', app.id, 'FUNDING.yml'), 'w') as fp:
            fp.write(content)

        fdroidserver.update.insert_funding_yml_donation_links(apps)
        for field in DONATION_FIELDS:
            self.assertIsNotNone(app.get(field), field)
        self.assertEqual('LINK1', app.get('Donate'))
        self.assertEqual('USERNAME', app.get('Liberapay'))
        self.assertEqual('USERNAME', app.get('OpenCollective'))

        app['Donate'] = 'keepme'
        app['Liberapay'] = 'keepme'
        app['OpenCollective'] = 'keepme'
        fdroidserver.update.insert_funding_yml_donation_links(apps)
        for field in DONATION_FIELDS:
            self.assertEqual('keepme', app.get(field))

    def test_insert_funding_yml_donation_links_one_at_a_time(self):
        """Exercise the FUNDING.yml code one entry at a time"""
        os.chdir(self.testdir)
        os.mkdir('build')

        app = fdroidserver.metadata.App()
        app.id = 'fake.app.id'
        apps = {app.id: app}
        os.mkdir(os.path.join('build', app.id))
        fdroidserver.update.insert_funding_yml_donation_links(apps)
        for field in DONATION_FIELDS:
            self.assertIsNone(app.get(field))

        content = textwrap.dedent(
            """
            community_bridge: 'blah-de-blah'
            github: USERNAME
            issuehunt: USERNAME
            ko_fi: USERNAME
            liberapay: USERNAME
            open_collective: USERNAME
            patreon: USERNAME
        """
        )
        for line in content.split('\n'):
            if not line:
                continue
            app = fdroidserver.metadata.App()
            app.id = 'fake.app.id'
            apps = {app.id: app}
            with open(os.path.join('build', app.id, 'FUNDING.yml'), 'w') as fp:
                fp.write(line)
            data = yaml.load(line, Loader=SafeLoader)
            fdroidserver.update.insert_funding_yml_donation_links(apps)
            if 'liberapay' in data:
                self.assertEqual(data['liberapay'], app.get('Liberapay'))
            elif 'open_collective' in data:
                self.assertEqual(data['open_collective'], app.get('OpenCollective'))
            else:
                for v in data.values():
                    self.assertEqual(app.get('Donate', '').split('/')[-1], v)

    def test_insert_funding_yml_donation_links_with_corrupt_file(self):
        os.chdir(self.testdir)
        os.mkdir('build')
        app = fdroidserver.metadata.App()
        app.id = 'fake.app.id'
        apps = {app.id: app}
        os.mkdir(os.path.join('build', app.id))
        with open(os.path.join('build', app.id, 'FUNDING.yml'), 'w') as fp:
            fp.write(
                textwrap.dedent(
                    """
                opencollective: foo
                custom: []
                liberapay: :
            """
                )
            )
        fdroidserver.update.insert_funding_yml_donation_links(apps)
        for field in DONATION_FIELDS:
            self.assertIsNone(app.get(field))

    def test_sanitize_funding_yml(self):
        with open(basedir / 'funding-usernames.yaml') as fp:
            data = yaml.load(fp, Loader=SafeLoader)
        for k, entries in data.items():
            for entry in entries:
                if k in 'custom':
                    m = fdroidserver.update.sanitize_funding_yml_entry(entry)
                else:
                    m = fdroidserver.update.sanitize_funding_yml_name(entry)
                if k == 'bad':
                    self.assertIsNone(m)
                else:
                    self.assertIsNotNone(m)
        self.assertIsNone(fdroidserver.update.sanitize_funding_yml_entry('foo\nbar'))
        self.assertIsNone(fdroidserver.update.sanitize_funding_yml_entry(
            ''.join(chr(random.randint(65, 90)) for _ in range(2049))))  # nosec B311

        # not recommended but valid entries
        self.assertIsNotNone(fdroidserver.update.sanitize_funding_yml_entry(12345))
        self.assertIsNotNone(fdroidserver.update.sanitize_funding_yml_entry(5.0))
        self.assertIsNotNone(fdroidserver.update.sanitize_funding_yml_entry(' WhyIncludeWhitespace '))
        self.assertIsNotNone(fdroidserver.update.sanitize_funding_yml_entry(['first', 'second']))

    def test_set_localized_text_entry(self):
        os.chdir(self.testdir)
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.update.config = config
        fdroidserver.update.options = fdroidserver.common.options

        files = {
            'full-description.txt': 'description',
            'short-description.txt': 'summary',
            'title.txt': 'name',
            'video-url.txt': 'video',
        }

        for f, key in files.items():
            limit = config['char_limits'][key]
            with open(f, 'w') as fp:
                fp.write(''.join(random.choice(string.ascii_letters) for i in range(limit + 100)))  # nosec B311
            locale = 'ru_US'
            app = dict()
            fdroidserver.update._set_localized_text_entry(app, locale, key, f)
            self.assertEqual(limit, len(app['localized'][locale][key]))

            f = 'badlink-' + f
            os.symlink('/path/to/nowhere', f)
            app = dict()
            fdroidserver.update._set_localized_text_entry(app, locale, key, f)
            self.assertIsNone(app['localized'].get(locale, {}).get(key))

    def test_set_author_entry(self):
        os.chdir(self.testdir)
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.update.config = config
        fdroidserver.update.options = fdroidserver.common.options

        f = 'contact-website.txt'
        key = 'author'
        url = 'https://f-droid.org/'
        limit = config['char_limits']['author']
        with open(f, 'w') as fp:
            fp.write(url)
            fp.write('\n')
        app = dict()
        fdroidserver.update._set_author_entry(app, key, f)
        self.assertEqual(url, app[key])

        f = 'limits.txt'
        key = 'author'
        limit = config['char_limits']['author']
        for key in ('authorEmail', 'authorPhone', 'authorWebSite'):
            with open(f, 'w') as fp:
                fp.write(''.join(random.choice(string.ascii_letters) for i in range(limit + 100)))  # nosec B311
            app = dict()
            fdroidserver.update._set_author_entry(app, key, f)
            self.assertEqual(limit, len(app[key]))

        f = 'badlink.txt'
        os.symlink('/path/to/nowhere', f)
        app = dict()
        fdroidserver.update._set_author_entry(app, key, f)
        self.assertIsNone(app.get(key))

    def test_status_update_json(self):
        fdroidserver.common.config = {}
        fdroidserver.update.config = {}
        fdroidserver.update.options = Options
        with mkdtemp() as tmpdir:
            os.chdir(tmpdir)
            with mock.patch('sys.argv', ['fdroid update', '']):
                fdroidserver.update.status_update_json([], [])
                with open('repo/status/update.json') as fp:
                    data = json.load(fp)
                self.assertTrue('apksigner' in data)

                fdroidserver.update.config = {
                    'apksigner': 'apksigner',
                }
                fdroidserver.update.status_update_json([], [])
                with open('repo/status/update.json') as fp:
                    data = json.load(fp)
                self.assertEqual(shutil.which(fdroidserver.update.config['apksigner']), data['apksigner'])

                fdroidserver.update.config = {}
                fdroidserver.common.fill_config_defaults(fdroidserver.update.config)
                fdroidserver.update.status_update_json([], [])
                with open('repo/status/update.json') as fp:
                    data = json.load(fp)
                self.assertEqual(fdroidserver.update.config.get('apksigner'), data['apksigner'])
                self.assertEqual(fdroidserver.update.config['jarsigner'], data['jarsigner'])
                self.assertEqual(fdroidserver.update.config['keytool'], data['keytool'])

    def test_scan_metadata_androguard(self):

        def _create_apkmetadata_object(apkName):
            """Create an empty apk metadata object."""
            apk = {}
            apk['apkName'] = apkName
            apk['uses-permission'] = []
            apk['uses-permission-sdk-23'] = []
            apk['features'] = []
            apk['icons_src'] = {}
            return apk

        apkList = [
            (
                'org.dyndns.fules.ck_20.apk',
                {
                    'apkName': 'org.dyndns.fules.ck_20.apk',
                    'uses-permission': [
                        fdroidserver.update.UsesPermission(
                            name='android.permission.BIND_INPUT_METHOD',
                            maxSdkVersion=None,
                        ),
                        fdroidserver.update.UsesPermission(
                            name='android.permission.READ_EXTERNAL_STORAGE',
                            maxSdkVersion=None,
                        ),
                        fdroidserver.update.UsesPermission(
                            name='android.permission.VIBRATE', maxSdkVersion=None
                        ),
                    ],
                    'uses-permission-sdk-23': [],
                    'features': [],
                    'icons_src': {
                        '240': 'res/drawable-hdpi-v4/icon_launcher.png',
                        '120': 'res/drawable-ldpi-v4/icon_launcher.png',
                        '160': 'res/drawable-mdpi-v4/icon_launcher.png',
                        '-1': 'res/drawable-mdpi-v4/icon_launcher.png',
                    },
                    'packageName': 'org.dyndns.fules.ck',
                    'versionCode': 20,
                    'versionName': 'v1.6pre2',
                    'minSdkVersion': 7,
                    'name': 'Compass Keyboard',
                    'targetSdkVersion': 8,
                    'nativecode': [
                        'arm64-v8a',
                        'armeabi',
                        'armeabi-v7a',
                        'mips',
                        'mips64',
                        'x86',
                        'x86_64',
                    ],
                },
            )
        ]

        for apkfile, apkaapt in apkList:
            apkandroguard = _create_apkmetadata_object(apkfile)
            fdroidserver.update.scan_apk_androguard(apkandroguard, apkfile)

            self.maxDiff = None
            self.assertEqual(apkaapt, apkandroguard)

    def test_exclude_disabled_apks(self):
        os.chdir(self.testdir)
        os.mkdir('repo')
        testapk = os.path.join('repo', 'com.politedroid_6.apk')
        testapk_new = os.path.join('repo', 'Politedroid-1.5.apk')
        shutil.copy(basedir / testapk, testapk_new)

        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        config['ndk_paths'] = dict()
        fdroidserver.common.config = config
        fdroidserver.update.config = config

        fdroidserver.common.options = Options
        fdroidserver.update.options = fdroidserver.common.options
        fdroidserver.update.options.clean = True

        app = fdroidserver.metadata.App()
        app.id = 'com.politedroid'
        apps = {app.id: app}
        build = fdroidserver.metadata.Build()
        build.versionCode = 6
        build.disable = "disabled"
        app['Builds'] = [build]

        knownapks = fdroidserver.common.KnownApks()
        apks, cachechanged = fdroidserver.update.process_apks({}, 'repo', knownapks, False, apps)
        self.assertEqual([], apks)

    def test_archive_old_apks_ArchivePolicy_0(self):
        app = fdroidserver.metadata.App()
        app.id = 'test'
        app.ArchivePolicy = 0
        apps = {app.id: app}
        with self.assertLogs(level='DEBUG') as cm:
            fdroidserver.update.archive_old_apks(apps, [], [], '', '', 3)
            self.assertEqual(cm.output, [
                "DEBUG:root:Checking archiving for test - apks:0, keepversions:0, archapks:0"
            ])

    def test_archive_old_apks(self):
        app = fdroidserver.metadata.App()
        app.id = 'test'
        app.VercodeOperation = ['%c+1', '%c+2', '%c+3', '%c+4']
        apps = {app.id: app}
        with self.assertLogs(level='DEBUG') as cm:
            fdroidserver.update.archive_old_apks(apps, [], [], '', '', 3)
            self.assertEqual(cm.output, [
                "DEBUG:root:Checking archiving for test - apks:0, keepversions:12, archapks:0"
            ])

        app = fdroidserver.metadata.App()
        app.id = 'org.smssecure.smssecure'
        app.CurrentVersionCode = 135
        apps = {app.id: app}
        with self.assertLogs(level='DEBUG') as cm:
            fdroidserver.update.archive_old_apks(apps, [], [], '', '', 3)
            self.assertEqual(cm.output, [
                "DEBUG:root:Checking archiving for org.smssecure.smssecure - apks:0, keepversions:6, archapks:0"
            ])

    def test_categories_txt_is_removed_by_delete_unknown(self):
        """categories.txt used to be a part of this system, now its nothing."""
        os.chdir(self.testdir)
        Path('config.yml').write_text('repo_pubkey: ffffffffffffffffffffffffffffffffffffffff')

        categories_txt = Path('repo/categories.txt')
        categories_txt.parent.mkdir()
        categories_txt.write_text('placeholder')

        self.assertTrue(categories_txt.exists())
        with mock.patch('sys.argv', ['fdroid update', '--delete-unknown', '--nosign']):
            fdroidserver.update.main()
        self.assertFalse(categories_txt.exists())

    def test_no_blank_auto_defined_categories(self):
        """When no app has Categories, there should be no definitions in the repo."""
        os.chdir(self.testdir)
        os.mkdir('metadata')
        os.mkdir('repo')
        Path('config.yml').write_text(
            'repo_pubkey: ffffffffffffffffffffffffffffffffffffffff'
        )

        testapk = os.path.join('repo', 'com.politedroid_6.apk')
        shutil.copy(basedir / testapk, testapk)
        Path('metadata/com.politedroid.yml').write_text('Name: Polite')

        with mock.patch('sys.argv', ['fdroid update', '--delete-unknown', '--nosign']):
            fdroidserver.update.main()
        with open('repo/index-v2.json') as fp:
            index = json.load(fp)
        self.assertNotIn(CATEGORIES_CONFIG_NAME, index['repo'])

    def test_auto_defined_categories(self):
        """Repos that don't define categories in config/ should use auto-generated."""
        os.chdir(self.testdir)
        os.mkdir('metadata')
        os.mkdir('repo')
        Path('config.yml').write_text(
            'repo_pubkey: ffffffffffffffffffffffffffffffffffffffff'
        )

        testapk = os.path.join('repo', 'com.politedroid_6.apk')
        shutil.copy(basedir / testapk, testapk)
        Path('metadata/com.politedroid.yml').write_text('Categories: [Time]')

        with mock.patch('sys.argv', ['fdroid update', '--delete-unknown', '--nosign']):
            fdroidserver.update.main()
        with open('repo/index-v2.json') as fp:
            index = json.load(fp)
        self.assertEqual(
            {'Time': {'name': {'en-US': 'Time'}}},
            index['repo'][CATEGORIES_CONFIG_NAME],
        )

    def test_auto_defined_categories_two_apps(self):
        """Repos that don't define categories in config/ should use auto-generated."""
        os.chdir(self.testdir)
        os.mkdir('metadata')
        os.mkdir('repo')
        Path('config.yml').write_text(
            'repo_pubkey: ffffffffffffffffffffffffffffffffffffffff'
        )

        testapk = os.path.join('repo', 'com.politedroid_6.apk')
        shutil.copy(basedir / testapk, testapk)
        Path('metadata/com.politedroid.yml').write_text('Categories: [bar]')
        testapk = os.path.join('repo', 'souch.smsbypass_9.apk')
        shutil.copy(basedir / testapk, testapk)
        Path('metadata/souch.smsbypass.yml').write_text('Categories: [foo, bar]')

        with mock.patch('sys.argv', ['fdroid update', '--delete-unknown', '--nosign']):
            fdroidserver.update.main()
        with open('repo/index-v2.json') as fp:
            index = json.load(fp)
        self.assertEqual(
            {'bar': {'name': {'en-US': 'bar'}}, 'foo': {'name': {'en-US': 'foo'}}},
            index['repo'][CATEGORIES_CONFIG_NAME],
        )

    def test_auto_defined_categories_mix_into_config_categories(self):
        """Repos that don't define all categories in config/ also use auto-generated."""
        os.chdir(self.testdir)
        os.mkdir('config')
        Path('config/categories.yml').write_text('System: {name: System Apps}')
        os.mkdir('metadata')
        os.mkdir('repo')
        Path('config.yml').write_text(
            'repo_pubkey: ffffffffffffffffffffffffffffffffffffffff'
        )

        testapk = os.path.join('repo', 'com.politedroid_6.apk')
        shutil.copy(basedir / testapk, testapk)
        Path('metadata/com.politedroid.yml').write_text('Categories: [Time]')
        testapk = os.path.join('repo', 'souch.smsbypass_9.apk')
        shutil.copy(basedir / testapk, testapk)
        Path('metadata/souch.smsbypass.yml').write_text('Categories: [System, Time]')

        with mock.patch('sys.argv', ['fdroid update', '--delete-unknown', '--nosign']):
            fdroidserver.update.main()
        with open('repo/index-v2.json') as fp:
            index = json.load(fp)
        self.assertEqual(
            {
                'System': {'name': {'en-US': 'System Apps'}},
                'Time': {'name': {'en-US': 'Time'}},
            },
            index['repo'][CATEGORIES_CONFIG_NAME],
        )

    def test_empty_categories_not_in_index(self):
        """A category with no apps should be ignored, even if defined in config."""
        os.chdir(self.testdir)
        os.mkdir('config')
        Path('config/categories.yml').write_text('System: {name: S}\nTime: {name: T}\n')
        os.mkdir('metadata')
        os.mkdir('repo')
        Path('config.yml').write_text(
            'repo_pubkey: ffffffffffffffffffffffffffffffffffffffff'
        )

        testapk = os.path.join('repo', 'com.politedroid_6.apk')
        shutil.copy(basedir / testapk, testapk)
        Path('metadata/com.politedroid.yml').write_text('Categories: [Time]')

        with mock.patch('sys.argv', ['fdroid update', '--delete-unknown', '--nosign']):
            fdroidserver.update.main()
        with open('repo/index-v2.json') as fp:
            index = json.load(fp)
        self.assertEqual(
            {'Time': {'name': {'en-US': 'T'}}},
            index['repo'][CATEGORIES_CONFIG_NAME],
        )


class TestParseIpa(unittest.TestCase):
    def test_parse_ipa(self):
        self.maxDiff = None
        try:
            import biplist  # Fedora does not have a biplist package

            biplist  # silence the linters
        except ImportError as e:
            self.skipTest(str(e))
        ipa_path = os.path.join(basedir, 'com.fake.IpaApp_1000000000001.ipa')
        result = fdroidserver.update.parse_ipa(ipa_path, 'fake_size', 'fake_sha')
        self.assertDictEqual(
            result,
            {
                'apkName': 'com.fake.IpaApp_1000000000001.ipa',
                'hash': 'fake_sha',
                'hashType': 'sha256',
                'packageName': 'org.onionshare.OnionShare',
                'size': 'fake_size',
                'versionCode': 1000000000001,
                'versionName': '1.0.1',
                'ipa_DTPlatformVersion': '16.4',
                'ipa_MinimumOSVersion': '15.0',
                'ipa_entitlements': set(),
                'ipa_permissions': {
                    'NSCameraUsageDescription':
                        'Please allow access to your '
                        'camera, if you want to '
                        'create photos or videos for '
                        'direct sharing.',
                    'NSMicrophoneUsageDescription':
                        'Please allow access to '
                        'your microphone, if you '
                        'want to create videos '
                        'for direct sharing.',
                    'NSPhotoLibraryUsageDescription':
                        'Please allow access to '
                        'your photo library, if '
                        'you want to share '
                        'photos.',
                },
                'name': 'OnionShare',
            },
        )


class TestUpdateVersionStringToInt(unittest.TestCase):
    def test_version_string_to_int(self):
        self.assertEqual(
            fdroidserver.update.version_string_to_int("1.2.3"), 1000002000003
        )
        self.assertEqual(fdroidserver.update.version_string_to_int("0.0.0003"), 3)
        self.assertEqual(fdroidserver.update.version_string_to_int("0.0.0"), 0)
        self.assertEqual(
            fdroidserver.update.version_string_to_int("4321.321.21"), 4321000321000021
        )
        self.assertEqual(
            fdroidserver.update.version_string_to_int("18446744.073709.551615"),
            18446744073709551615,
        )

    def test_version_string_to_int_value_errors(self):
        with self.assertRaises(ValueError):
            fdroidserver.update.version_string_to_int("1.2.3a")
        with self.assertRaises(ValueError):
            fdroidserver.update.version_string_to_int("asdfasdf")
        with self.assertRaises(ValueError):
            fdroidserver.update.version_string_to_int("1.2.-3")
        with self.assertRaises(ValueError):
            fdroidserver.update.version_string_to_int("-1.2.-3")
        with self.assertRaises(ValueError):
            fdroidserver.update.version_string_to_int("0.0.0x3")


class TestScanRepoForIpas(unittest.TestCase):
    def test_scan_repo_for_ipas_no_cache(self):
        self.maxDiff = None
        with mkdtemp() as tmpdir:
            os.chdir(tmpdir)
            os.mkdir("repo")
            with open('repo/abc.Def_123.ipa', 'w') as f:
                f.write('abc')
            with open('repo/xyz.XXX_123.ipa', 'w') as f:
                f.write('xyz')

            apkcache = mock.MagicMock()
            repodir = "repo"
            knownapks = mock.MagicMock()

            def mocked_parse(p, s, c):
                # pylint: disable=unused-argument
                return {'packageName': 'abc' if 'abc' in p else 'xyz'}

            with mock.patch('fdroidserver.update.parse_ipa', mocked_parse):
                ipas, checkchanged = fdroidserver.update.scan_repo_for_ipas(
                    apkcache, repodir, knownapks
                )

            self.assertEqual(checkchanged, True)
            self.assertEqual(len(ipas), 2)
            package_names_in_ipas = [x['packageName'] for x in ipas]
            self.assertTrue('abc' in package_names_in_ipas)
            self.assertTrue('xyz' in package_names_in_ipas)

            apkcache_setter_package_name = [
                x.args[1]['packageName'] for x in apkcache.__setitem__.mock_calls
            ]
            self.assertTrue('abc' in apkcache_setter_package_name)
            self.assertTrue('xyz' in apkcache_setter_package_name)
            self.assertEqual(apkcache.__setitem__.call_count, 2)

            knownapks.recordapk.call_count = 2
            self.assertTrue(
                unittest.mock.call('abc.Def_123.ipa') in knownapks.recordapk.mock_calls
            )
            self.assertTrue(
                unittest.mock.call('xyz.XXX_123.ipa') in knownapks.recordapk.mock_calls
            )


class TestParseIosScreenShotName(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def test_parse_ios_screenshot_name_atforamt_iphone8(self):
        self.assertEqual(
            fdroidserver.update.parse_ios_screenshot_name(Path("iPhone 8+ @ iOS 16-1.png")),
            ("phoneScreenshots", "iPhone 8+", "iOS 16",),
        )

    def test_parse_ios_screenshot_name_atforamt_ipad13(self):
        self.assertEqual(
            fdroidserver.update.parse_ios_screenshot_name(Path("iPad Pro 12.9\" 2gen @ iOS 16-1.png")),
            ("tenInchScreenshots", "iPad Pro 12.9\" 2gen", "iOS 16",),
        )

    def test_parse_ios_screenshot_name_underscoreforamt_ipad(self):
        self.assertEqual(
            fdroidserver.update.parse_ios_screenshot_name(Path("1_ipadPro129_1.1.png")),
            ("tenInchScreenshots", "ipadpro129", "unknown",),
        )

    def test_parse_ios_screenshot_name_underscoreforamt_iphone(self):
        self.assertEqual(
            fdroidserver.update.parse_ios_screenshot_name(Path("1_iphone6Plus_1.1.png")),
            ("phoneScreenshots", "iphone6plus", "unknown",),
        )


class TestInsertLocalizedIosAppMetadata(unittest.TestCase):

    def test_insert_localized_ios_app_metadata(self):
        self.maxDiff = None

        self.apps_with_packages = {
            "org.fake": {}
        }

        def _mock_discover(fastlane_dir):
            self.assertEqual(
                fastlane_dir,
                Path('build/org.fake/fastlane'),
            )
            return {"fake screenshots": "fake"}

        def _mock_copy(screenshots, package_name):
            self.assertEqual(screenshots, {"fake screenshots": "fake"})
            self.assertEqual(package_name, "org.fake")

        with mock.patch('fdroidserver.update.discover_ios_screenshots', _mock_discover):
            self.set_localized_mock = mock.Mock()
            with mock.patch('fdroidserver.update.copy_ios_screenshots_to_repo', _mock_copy):
                with mock.patch("fdroidserver.update._set_localized_text_entry", self.set_localized_mock):
                    return fdroidserver.update.insert_localized_ios_app_metadata(
                        self.apps_with_packages
                    )

        self.assertListEqual(
            self.set_localized_mock.call_args_list,
            [
                mock.call({}, 'en-US', 'name', Path('build/org.fake/fastlane/metadata/en-US/name.txt')),
                mock.call({}, 'en-US', 'summary', Path('build/org.fake/fastlane/metadata/en-US/subtitle.txt')),
                mock.call({}, 'en-US', 'description', Path('build/org.fake/fastlane/metadata/en-US/description.txt')),
                mock.call({}, 'de-DE', 'name', Path('build/org.fake/fastlane/metadata/de-DE/name.txt')),
                mock.call({}, 'de-DE', 'summary', Path('build/org.fake/fastlane/metadata/de-DE/subtitle.txt')),
                mock.call({}, 'de-DE', 'description', Path('build/org.fake/fastlane/metadata/de-DE/description.txt')),
            ],
        )


class TestDiscoverIosScreenshots(unittest.TestCase):
    def test_discover_ios_screenshots(self):
        self.maxDiff = None

        with mkdtemp() as fastlane_dir:
            fastlane_dir = Path(fastlane_dir)
            (fastlane_dir / "screenshots/en-US").mkdir(parents=True)
            with open(fastlane_dir / "screenshots/en-US/iPhone 8+ @ iOS 16-1.png", 'w') as f:
                f.write("1")
            with open(fastlane_dir / "screenshots/en-US/iPad Pro 12.9\" 2gen @ iOS 16-1.png", "w") as f:
                f.write("2")
            with open(fastlane_dir / "screenshots/en-US/iPad Pro 12.9\" 2gen @ iOS 16-2.png", "w") as f:
                f.write("3")
            (fastlane_dir / "screenshots/de-DE").mkdir(parents=True)
            with open(fastlane_dir / "screenshots/de-DE/1_ipadPro129_1.1.png", "w") as f:
                f.write("4")

            screenshots = fdroidserver.update.discover_ios_screenshots(fastlane_dir)

            self.assertDictEqual(
                screenshots,
                {
                    "en-US": {
                        "phoneScreenshots": [
                            fastlane_dir / "screenshots/en-US/iPhone 8+ @ iOS 16-1.png",
                        ],
                        "tenInchScreenshots": [
                            fastlane_dir / "screenshots/en-US/iPad Pro 12.9\" 2gen @ iOS 16-1.png",
                            fastlane_dir / "screenshots/en-US/iPad Pro 12.9\" 2gen @ iOS 16-2.png",
                        ],
                    },
                    "de-DE": {
                        "tenInchScreenshots": [
                            fastlane_dir / "screenshots/de-DE/1_ipadPro129_1.1.png",
                        ],
                    },
                },
            )


class TestCopyIosScreenshotsToRepo(unittest.TestCase):
    def setUp(self):
        self._td = mkdtemp()
        os.chdir(self._td.name)

    def tearDown(self):
        os.chdir(basedir)
        self._td.cleanup()

    def test_copy_ios_screenshots_to_repo(self):
        self.maxDiff = None

        screenshot_dir_en = Path("build/org.fake/fastlane/screenshots/en-US")
        s1 = screenshot_dir_en / "iPhone 8+ @ iOS 16-1.png"
        s2 = screenshot_dir_en / "iPad Pro 12.9\" 2gen @ iOS 16-1.png"
        s3 = screenshot_dir_en / "iPad Pro 12.9\" 2gen @ iOS 16-2.png"
        screenshot_dir_de = Path("build/org.fake/fastlane/screenshots/de-DE")
        s4 = screenshot_dir_de / "1_ipadPro129_1.1.png"

        cmock = mock.Mock()
        with mock.patch("fdroidserver.update._strip_and_copy_image", cmock):
            fdroidserver.update.copy_ios_screenshots_to_repo(
                {
                    "en-US": {
                        "phoneScreenshots": [s1],
                        "tenInchScreenshots": [s2, s3],
                    },
                    "de-DE": {
                        "tenInchScreenshots": [s4],
                    },
                },
                "org.fake",
            )

        self.assertListEqual(
            cmock.call_args_list,
            [
                mock.call(
                    'build/org.fake/fastlane/screenshots/en-US/iPhone 8+ @ iOS 16-1.png',
                    'repo/org.fake/en-US/phoneScreenshots/iPhone_8+_@_iOS_16-1.png',
                ),
                mock.call(
                    'build/org.fake/fastlane/screenshots/en-US/iPad Pro 12.9" 2gen @ iOS 16-1.png',
                    'repo/org.fake/en-US/tenInchScreenshots/iPad_Pro_12.9"_2gen_@_iOS_16-1.png',
                ),
                mock.call(
                    'build/org.fake/fastlane/screenshots/en-US/iPad Pro 12.9" 2gen @ iOS 16-2.png',
                    'repo/org.fake/en-US/tenInchScreenshots/iPad_Pro_12.9"_2gen_@_iOS_16-2.png',
                ),
                mock.call(
                    'build/org.fake/fastlane/screenshots/de-DE/1_ipadPro129_1.1.png',
                    'repo/org.fake/de-DE/tenInchScreenshots/1_ipadPro129_1.1.png',
                ),
            ],
        )


class TestGetIpaIcon(unittest.TestCase):
    def test_get_ipa_icon(self):
        self.maxDiff = None

        with mkdtemp() as tmpdir:
            tmpdir = Path(tmpdir)
            (tmpdir / 'OnionBrowser.xcodeproj').mkdir()
            with open(tmpdir / 'OnionBrowser.xcodeproj/project.pbxproj', "w") as f:
                f.write("")
            icondir = tmpdir / "fake_icon.appiconset"
            icondir.mkdir()
            with open(icondir / "Contents.json", "w", encoding="utf-8") as f:
                f.write("""
                    {"images": [
                        {"scale": "2x", "size": "128x128", "filename": "nope"},
                        {"scale": "1x", "size": "512x512", "filename": "nope"},
                        {"scale": "1x", "size": "16x16", "filename": "nope"},
                        {"scale": "1x", "size": "32x32", "filename": "yep"}
                    ]}
                """)

            pfp = mock.Mock(return_value="fake_icon")
            with mock.patch("fdroidserver.update._parse_from_pbxproj", pfp):
                p = fdroidserver.update._get_ipa_icon(tmpdir)
                self.assertEqual(str(icondir / "yep"), p)


class TestParseFromPbxproj(unittest.TestCase):
    def test_parse_from_pbxproj(self):
        self.maxDiff = None

        with mkdtemp() as tmpdir:
            with open(Path(tmpdir) / "asdf.pbxproj", 'w', encoding="utf-8") as f:
                f.write("""
                    230jfaod=flc'
                    ASSETCATALOG_COMPILER_APPICON_NAME = MyIcon;
                    cm opa1c p[m
                """)
            v = fdroidserver.update._parse_from_pbxproj(
                Path(tmpdir) / "asdf.pbxproj",
                "ASSETCATALOG_COMPILER_APPICON_NAME"
            )
            self.assertEqual(v, "MyIcon")
