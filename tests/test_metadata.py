#!/usr/bin/env python3

import copy
import io
import os
import random
import ruamel.yaml
import shutil
import unittest
import tempfile
import textwrap
from collections import OrderedDict
from pathlib import Path
from unittest import mock

import fdroidserver
from fdroidserver import metadata
from fdroidserver.exception import MetaDataException
from fdroidserver.common import DEFAULT_LOCALE
from .testcommon import TmpCwd, mkdtemp


basedir = Path(__file__).parent


def _get_mock_mf(s):
    mf = io.StringIO(s)
    mf.name = 'mock_filename.yaml'
    return mf


class MetadataTest(unittest.TestCase):
    '''fdroidserver/metadata.py'''

    def setUp(self):
        os.chdir(basedir)
        self._td = mkdtemp()
        self.testdir = self._td.name
        fdroidserver.metadata.warnings_action = 'error'

    def tearDown(self):
        # auto-generated dirs by functions, not tests, so they are not always cleaned up
        self._td.cleanup()
        try:
            os.rmdir("srclibs")
        except OSError:
            pass
        try:
            os.rmdir("tmp")
        except OSError:
            pass

    def test_fieldtypes_key_exist(self):
        for k in fdroidserver.metadata.fieldtypes:
            self.assertIn(k, fdroidserver.metadata.yaml_app_fields)

    def test_build_flagtypes_key_exist(self):
        for k in fdroidserver.metadata.flagtypes:
            self.assertIn(k, fdroidserver.metadata.build_flags)

    def test_FieldValidator_BitcoinAddress(self):
        validator = None
        for vali in fdroidserver.metadata.valuetypes:
            if vali.name == 'Bitcoin address':
                validator = vali
                break
        self.assertIsNotNone(validator, "could not find 'Bitcoin address' validator")

        # some valid addresses (P2PKH, P2SH, Bech32)
        self.assertIsNone(
            validator.check('1BrrrrErsrWetrTrnrrrrm4GFg7xJaNVN2', 'fake.app.id')
        )
        self.assertIsNone(
            validator.check('3JrrrrWrEZr3rNrrvrecrnyirrnqRhWNLy', 'fake.app.id')
        )
        self.assertIsNone(
            validator.check('bc1qar0srrr7xrkvr5lr43lrdnwrre5rgtrzrf5rrq', 'fake.app.id')
        )

        # some invalid addresses
        self.assertRaises(
            fdroidserver.exception.MetaDataException,
            validator.check,
            '21BvMrSYsrWrtrrlL5A10mlGFr7rrarrN2',
            'fake.app.id',
        )
        self.assertRaises(
            fdroidserver.exception.MetaDataException,
            validator.check,
            '5Hrgr3ur5rGLrfKrrrrrrHSrqJrroGrrzrQrrrrrrLNrsrDrrrA',
            'fake.app.id',
        )
        self.assertRaises(
            fdroidserver.exception.MetaDataException,
            validator.check,
            '92rr46rUrgTrrromrVrirW6r1rrrdrerrdbJrrrhrCsYrrrrrrc',
            'fake.app.id',
        )
        self.assertRaises(
            fdroidserver.exception.MetaDataException,
            validator.check,
            'K1BvMrSYsrWrtrrrn5Au4m4GFr7rrarrN2',
            'fake.app.id',
        )
        self.assertRaises(
            fdroidserver.exception.MetaDataException,
            validator.check,
            'L1BvMrSYsrWrtrrrn5Au4m4GFr7rrarrN2',
            'fake.app.id',
        )
        self.assertRaises(
            fdroidserver.exception.MetaDataException,
            validator.check,
            'tb1qw5r8drrejxrrg4y5rrrrrraryrrrrwrkxrjrsx',
            'fake.app.id',
        )

    def test_FieldValidator_LitecoinAddress(self):
        validator = None
        for vali in fdroidserver.metadata.valuetypes:
            if vali.name == 'Litecoin address':
                validator = vali
                break
        self.assertIsNotNone(validator, "could not find 'Litecoin address' validator")

        # some valid addresses (L, M, 3, segwit)
        self.assertIsNone(
            validator.check('LgeGrrrrJAxyXprrPrrBrrX5Qrrrrrrrrd', 'fake.app.id')
        )
        self.assertIsNone(
            validator.check('MrrrrrrrJAxyXpanPtrrRAX5QHxvUJo8id', 'fake.app.id')
        )
        self.assertIsNone(validator.check('3rereVr9rAryrranrrrrrAXrrHx', 'fake.app.id'))
        self.assertIsNone(
            validator.check(
                'ltc1q7euacwhn6ef99vcfa57mute92q572aqsc4c2j5', 'fake.app.id'
            )
        )

        # some invalid addresses (various special use/testnet addresses, invalid chars)
        self.assertRaises(
            fdroidserver.exception.MetaDataException,
            validator.check,
            '21BvMrSYsrWrtrrrn5Au4l4GFr7rrarrN2',
            'fake.app.id',
        )
        self.assertRaises(
            fdroidserver.exception.MetaDataException,
            validator.check,
            '5Hrgr3ur5rGLrfKrrrrrr1SrqJrroGrrzrQrrrrrrLNrsrDrrrA',
            'fake.app.id',
        )
        self.assertRaises(
            fdroidserver.exception.MetaDataException,
            validator.check,
            '92rr46rUrgTrrromrVrirW6r1rrrdrerrdbJrrrhrCsYrrrrrrc',
            'fake.app.id',
        )
        self.assertRaises(
            fdroidserver.exception.MetaDataException,
            validator.check,
            'K1BvMrSYsrWrtrrrn5Au4m4GFr7rrarrN2',
            'fake.app.id',
        )
        self.assertRaises(
            fdroidserver.exception.MetaDataException,
            validator.check,
            'L0000rSYsrWrtrrrn5Au4m4GFr7rrarrN2',
            'fake.app.id',
        )
        self.assertRaises(
            fdroidserver.exception.MetaDataException,
            validator.check,
            'tb1qw5r8drrejxrrg4y5rrrrrraryrrrrwrkxrjrsx',
            'fake.app.id',
        )

    def test_valid_funding_yml_regex(self):
        """Check the regex can find all the cases"""
        with (basedir / 'funding-usernames.yaml').open() as fp:
            yaml = ruamel.yaml.YAML(typ='safe')
            data = yaml.load(fp)

        for k, entries in data.items():
            for entry in entries:
                m = fdroidserver.metadata.VALID_USERNAME_REGEX.match(entry)
                if k == 'custom':
                    pass
                elif k == 'bad':
                    self.assertIsNone(
                        m, 'this is an invalid %s username: {%s}' % (k, entry)
                    )
                else:
                    self.assertIsNotNone(
                        m, 'this is a valid %s username: {%s}' % (k, entry)
                    )

    @mock.patch('git.Repo', mock.Mock())
    @mock.patch('logging.error')
    def test_read_metadata(self, logging_error):
        """Read specified metadata files included in tests/, compare to stored output"""

        self.maxDiff = None

        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.metadata.warnings_action = None

        yaml = ruamel.yaml.YAML(typ='safe')
        apps = fdroidserver.metadata.read_metadata()
        for appid in (
            'app.with.special.build.params',
            'org.smssecure.smssecure',
            'org.adaway',
            'org.videolan.vlc',
            'com.politedroid',
        ):
            savepath = Path('metadata/dump') / (appid + '.yaml')
            frommeta = dict(apps[appid])
            self.assertTrue(appid in apps)
            with savepath.open('r') as f:
                from_yaml = yaml.load(f)
            self.assertEqual(frommeta, from_yaml)
            # comment above assert and uncomment below to update test
            # files when new metadata fields are added
            # with savepath.open('w') as fp:
            #     yaml.default_flow_style = False
            #     yaml.register_class(metadata.Build)
            #     yaml.dump(frommeta, fp)

        # errors are printed when .yml overrides localized
        logging_error.assert_called()
        self.assertEqual(3, len(logging_error.call_args_list))

    @mock.patch('git.Repo', mock.Mock())
    def test_metadata_overrides_dot_fdroid_yml(self):
        """Fields in metadata files should override anything in .fdroid.yml."""
        app = metadata.parse_metadata('metadata/info.guardianproject.urzip.yml')
        self.assertEqual(app['Summary'], '一个实用工具，获取已安装在您的设备上的应用的有关信息')

    def test_dot_fdroid_yml_works_without_git(self):
        """Parsing should work if .fdroid.yml is present and it is not a git repo."""
        os.chdir(self.testdir)
        yml = Path('metadata/test.yml')
        yml.parent.mkdir()
        with yml.open('w') as fp:
            fp.write('Repo: https://example.com/not/git/or/anything')
        fdroid_yml = Path('build/test/.fdroid.yml')
        fdroid_yml.parent.mkdir(parents=True)
        with fdroid_yml.open('w') as fp:
            fp.write('OpenCollective: test')
        metadata.parse_metadata(yml)  # should not throw an exception

    @mock.patch('git.Repo', mock.Mock())
    @mock.patch('logging.error')
    def test_rewrite_yaml_fakeotaupdate(self, logging_error):
        with tempfile.TemporaryDirectory() as testdir:
            testdir = Path(testdir)
            fdroidserver.common.config = {'accepted_formats': ['yml']}
            fdroidserver.metadata.warnings_action = None

            # rewrite metadata
            allapps = fdroidserver.metadata.read_metadata()
            for appid, app in allapps.items():
                if appid == 'fake.ota.update':
                    fdroidserver.metadata.write_metadata(
                        testdir / (appid + '.yml'), app
                    )

            # assert rewrite result
            self.maxDiff = None
            file_name = 'fake.ota.update.yml'
            self.assertEqual(
                (testdir / file_name).read_text(encoding='utf-8'),
                (Path('metadata-rewrite-yml') / file_name).read_text(encoding='utf-8'),
            )

        # errors are printed when .yml overrides localized
        logging_error.assert_called()
        self.assertEqual(3, len(logging_error.call_args_list))

    @mock.patch('git.Repo', mock.Mock())
    def test_rewrite_yaml_fdroidclient(self):
        with tempfile.TemporaryDirectory() as testdir:
            testdir = Path(testdir)
            fdroidserver.common.config = {'accepted_formats': ['yml']}

            # rewrite metadata
            allapps = fdroidserver.metadata.read_metadata()
            for appid, app in allapps.items():
                if appid == 'org.fdroid.fdroid':
                    fdroidserver.metadata.write_metadata(
                        testdir / (appid + '.yml'), app
                    )

            # assert rewrite result
            self.maxDiff = None
            file_name = 'org.fdroid.fdroid.yml'
            self.assertEqual(
                (testdir / file_name).read_text(encoding='utf-8'),
                (Path('metadata-rewrite-yml') / file_name).read_text(encoding='utf-8'),
            )

    @mock.patch('git.Repo', mock.Mock())
    def test_rewrite_yaml_special_build_params(self):
        """Test rewriting a plain YAML metadata file without localized files."""
        os.chdir(self.testdir)
        os.mkdir('metadata')
        appid = 'app.with.special.build.params'
        file_name = Path('metadata/%s.yml' % appid)
        shutil.copy(basedir / file_name, file_name)

        # rewrite metadata
        allapps = fdroidserver.metadata.read_metadata({appid: -1})
        for appid, app in allapps.items():
            metadata.write_metadata(file_name, app)

        # assert rewrite result
        self.maxDiff = None
        self.assertEqual(
            file_name.read_text(),
            (basedir / 'metadata-rewrite-yml' / file_name.name).read_text(),
        )

    def test_normalize_type_string(self):
        """TYPE_STRING currently has some quirky behavior."""
        self.assertEqual('123456', metadata._normalize_type_string(123456))
        self.assertEqual('1.0', metadata._normalize_type_string(1.0))
        self.assertEqual('0', metadata._normalize_type_string(0))
        self.assertEqual('0.0', metadata._normalize_type_string(0.0))
        self.assertEqual('0.1', metadata._normalize_type_string(0.1))
        self.assertEqual('[]', metadata._normalize_type_string(list()))
        self.assertEqual('{}', metadata._normalize_type_string(dict()))
        self.assertEqual('false', metadata._normalize_type_string(False))
        self.assertEqual('true', metadata._normalize_type_string(True))

    def test_normalize_type_string_sha256(self):
        """SHA-256 values are TYPE_STRING, which YAML can parse as decimal ints."""
        yaml = ruamel.yaml.YAML(typ='safe')
        for v in range(1, 1000):
            s = '%064d' % (v * (10**51))
            self.assertEqual(s, metadata._normalize_type_string(yaml.load(s)))

    def test_normalize_type_stringmap_none(self):
        self.assertEqual(dict(), metadata._normalize_type_stringmap('key', None))

    def test_normalize_type_stringmap_empty_list(self):
        self.assertEqual(dict(), metadata._normalize_type_stringmap('AntiFeatures', []))

    def test_normalize_type_stringmap_simple_list_format(self):
        self.assertEqual(
            {'Ads': {}, 'Tracking': {}},
            metadata._normalize_type_stringmap('AntiFeatures', ['Ads', 'Tracking']),
        )

    def test_normalize_type_int(self):
        """TYPE_INT should be an int whenever possible."""
        self.assertEqual(0, metadata._normalize_type_int('key', 0))
        self.assertEqual(1, metadata._normalize_type_int('key', 1))
        self.assertEqual(-5, metadata._normalize_type_int('key', -5))
        self.assertEqual(0, metadata._normalize_type_int('key', '0'))
        self.assertEqual(1, metadata._normalize_type_int('key', '1'))
        self.assertEqual(-5, metadata._normalize_type_int('key', '-5'))
        self.assertEqual(
            12345678901234567890,
            metadata._normalize_type_int('key', 12345678901234567890),
        )

    def test_normalize_type_int_fails(self):
        with self.assertRaises(MetaDataException):
            metadata._normalize_type_int('key', '1a')
        with self.assertRaises(MetaDataException):
            metadata._normalize_type_int('key', 1.1)
        with self.assertRaises(MetaDataException):
            metadata._normalize_type_int('key', True)

    def test_normalize_type_list(self):
        """TYPE_LIST is always a list of strings, no matter what YAML thinks."""
        k = 'placeholder'
        yaml = ruamel.yaml.YAML(typ='safe')
        self.assertEqual(['1.0'], metadata._normalize_type_list(k, 1.0))
        self.assertEqual(['1234567890'], metadata._normalize_type_list(k, 1234567890))
        self.assertEqual(['false'], metadata._normalize_type_list(k, False))
        self.assertEqual(['true'], metadata._normalize_type_list(k, True))
        self.assertEqual(['foo'], metadata._normalize_type_list(k, 'foo'))
        self.assertEqual([], metadata._normalize_type_list(k, list()))
        self.assertEqual([], metadata._normalize_type_list(k, tuple()))
        self.assertEqual([], metadata._normalize_type_list(k, set()))
        self.assertEqual(['0', '1', '2'], metadata._normalize_type_list(k, {0, 1, 2}))
        self.assertEqual(
            ['a', 'b', 'c', '0', '0.0'],
            metadata._normalize_type_list(k, yaml.load('[a, b, c, 0, 0.0]')),
        )
        self.assertEqual(
            ['1', '1.0', 's', 'true', '{}'],
            metadata._normalize_type_list(k, yaml.load('[1, 1.0, s, true, {}]')),
        )
        self.assertEqual(
            ['1', '1.0', 's', 'true', '{}'],
            metadata._normalize_type_list(k, (1, 1.0, 's', True, dict())),
        )

    def test_normalize_type_list_fails(self):
        with self.assertRaises(MetaDataException):
            metadata._normalize_type_list('placeholder', dict())

    def test_post_parse_yaml_metadata(self):
        yamldata = dict()
        metadata.post_parse_yaml_metadata(yamldata)

        yamldata[
            'AllowedAPKSigningKeys'
        ] = 'c03dac71394d6c26766f1b04d3e31cfcac5d03b55d8aa40cc9b9fa6b74354c66'
        metadata.post_parse_yaml_metadata(yamldata)

    def test_post_parse_yaml_metadata_ArchivePolicy_int(self):
        for i in range(20):
            yamldata = {'ArchivePolicy': i}
            metadata.post_parse_yaml_metadata(yamldata)
            self.assertEqual(i, yamldata['ArchivePolicy'])

    def test_post_parse_yaml_metadata_ArchivePolicy_string(self):
        for i in range(20):
            yamldata = {'ArchivePolicy': '%d' % i}
            metadata.post_parse_yaml_metadata(yamldata)
            self.assertEqual(i, yamldata['ArchivePolicy'])

    def test_post_parse_yaml_metadata_ArchivePolicy_versions(self):
        """Test that the old format still works."""
        for i in range(20):
            yamldata = {'ArchivePolicy': '%d versions' % i}
            metadata.post_parse_yaml_metadata(yamldata)
            self.assertEqual(i, yamldata['ArchivePolicy'])

    def test_post_parse_yaml_metadata_fails(self):
        yamldata = {'AllowedAPKSigningKeys': {'bad': 'dict-placement'}}
        with self.assertRaises(MetaDataException):
            metadata.post_parse_yaml_metadata(yamldata)

    def test_post_parse_yaml_metadata_0padding_sha256(self):
        """SHA-256 values are strings, but YAML 1.2 will read some as decimal ints."""
        v = '0027293472934293872934729834729834729834729834792837487293847926'
        yaml = ruamel.yaml.YAML(typ='safe')
        yamldata = yaml.load('AllowedAPKSigningKeys: ' + v)
        metadata.post_parse_yaml_metadata(yamldata)
        self.assertEqual(yamldata['AllowedAPKSigningKeys'], [v])

    def test_post_parse_yaml_metadata_builds(self):
        yamldata = OrderedDict()
        builds = []
        yamldata['Builds'] = builds
        build = OrderedDict()
        builds.append(build)

        build['versionCode'] = 1.1
        self.assertRaises(
            fdroidserver.exception.MetaDataException,
            fdroidserver.metadata.post_parse_yaml_metadata,
            yamldata,
        )

        build['versionCode'] = '1a'
        self.assertRaises(
            fdroidserver.exception.MetaDataException,
            fdroidserver.metadata.post_parse_yaml_metadata,
            yamldata,
        )

        build['versionCode'] = 1
        build['versionName'] = 1
        fdroidserver.metadata.post_parse_yaml_metadata(yamldata)
        self.assertNotEqual(1, yamldata['Builds'][0]['versionName'])
        self.assertEqual('1', yamldata['Builds'][0]['versionName'])
        self.assertEqual(1, yamldata['Builds'][0]['versionCode'])

        build['versionName'] = 1.0
        fdroidserver.metadata.post_parse_yaml_metadata(yamldata)
        self.assertNotEqual(1.0, yamldata['Builds'][0]['versionName'])
        self.assertEqual('1.0', yamldata['Builds'][0]['versionName'])

        build['commit'] = 1.0
        fdroidserver.metadata.post_parse_yaml_metadata(yamldata)
        self.assertNotEqual(1.0, yamldata['Builds'][0]['commit'])
        self.assertEqual('1.0', yamldata['Builds'][0]['commit'])

        teststr = '98234fab134b'
        build['commit'] = teststr
        fdroidserver.metadata.post_parse_yaml_metadata(yamldata)
        self.assertEqual(teststr, yamldata['Builds'][0]['commit'])

        testcommitid = 1234567890
        build['commit'] = testcommitid
        fdroidserver.metadata.post_parse_yaml_metadata(yamldata)
        self.assertNotEqual(testcommitid, yamldata['Builds'][0]['commit'])
        self.assertEqual('1234567890', yamldata['Builds'][0]['commit'])

    def test_read_metadata_sort_by_time(self):
        with tempfile.TemporaryDirectory() as testdir, TmpCwd(testdir):
            testdir = Path(testdir)
            metadatadir = testdir / 'metadata'
            metadatadir.mkdir()

            randomlist = []
            randomapps = list((basedir / 'metadata').glob('*.yml'))
            random.shuffle(randomapps)
            i = 1
            for f in randomapps:
                shutil.copy(f, metadatadir)
                new = metadatadir / f.name
                stat = new.stat()
                os.utime(new, (stat.st_ctime, stat.st_mtime + i))
                # prepend new item so newest is always first
                randomlist = [f.stem] + randomlist
                i += 1
            allapps = fdroidserver.metadata.read_metadata(sort_by_time=True)
            allappids = []
            for appid, app in allapps.items():
                allappids.append(appid)
            self.assertEqual(randomlist, allappids)

    def test_parse_yaml_metadata_0size_file(self):
        self.assertEqual(dict(), metadata.parse_yaml_metadata(_get_mock_mf('')))

    def test_parse_yaml_metadata_empty_dict_file(self):
        self.assertEqual(dict(), metadata.parse_yaml_metadata(_get_mock_mf('{}')))

    def test_parse_yaml_metadata_empty_string_file(self):
        self.assertEqual(dict(), metadata.parse_yaml_metadata(_get_mock_mf('""')))

    def test_parse_yaml_metadata_fail_on_root_list(self):
        with self.assertRaises(MetaDataException):
            metadata.parse_yaml_metadata(_get_mock_mf('-'))
        with self.assertRaises(MetaDataException):
            metadata.parse_yaml_metadata(_get_mock_mf('[]'))
        with self.assertRaises(MetaDataException):
            metadata.parse_yaml_metadata(_get_mock_mf('- AutoName: fake'))

    def test_parse_yaml_metadata_type_list_str(self):
        v = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        mf = _get_mock_mf('AllowedAPKSigningKeys: "%s"' % v)
        self.assertEqual(
            v,
            metadata.parse_yaml_metadata(mf)['AllowedAPKSigningKeys'][0],
        )

    def test_parse_yaml_metadata_type_list_build_str(self):
        mf = _get_mock_mf('Builds: [{versionCode: 1, rm: s}]')
        self.assertEqual(
            metadata.parse_yaml_metadata(mf),
            {'Builds': [{'rm': ['s'], 'versionCode': 1}]},
        )

    def test_parse_yaml_metadata_app_type_list_fails(self):
        mf = _get_mock_mf('AllowedAPKSigningKeys: {t: f}')
        with self.assertRaises(MetaDataException):
            metadata.parse_yaml_metadata(mf)

    def test_parse_yaml_metadata_build_type_list_fails(self):
        mf = _get_mock_mf('Builds: [{versionCode: 1, rm: {bad: dict-placement}}]')
        with self.assertRaises(MetaDataException):
            metadata.parse_yaml_metadata(mf)

    def test_parse_yaml_metadata_unknown_app_field(self):
        mf = io.StringIO(
            textwrap.dedent(
                """\
                AutoName: F-Droid
                RepoType: git
                Builds: []
                bad: value"""
            )
        )
        mf.name = 'mock_filename.yaml'
        with self.assertRaises(MetaDataException):
            fdroidserver.metadata.parse_yaml_metadata(mf)

    def test_parse_yaml_metadata_unknown_build_flag(self):
        mf = io.StringIO(
            textwrap.dedent(
                """\
                AutoName: F-Droid
                RepoType: git
                Builds:
                - bad: value"""
            )
        )
        mf.name = 'mock_filename.yaml'
        with self.assertRaises(MetaDataException):
            fdroidserver.metadata.parse_yaml_metadata(mf)

    @mock.patch('logging.warning')
    @mock.patch('logging.error')
    def test_parse_yaml_metadata_continue_on_warning(self, _error, _warning):
        """When errors are disabled, parsing should provide something that can work.

        When errors are disabled, then it should try to give data that
        lets something happen.  A zero-length file is valid for
        operation, it just declares a Application ID as "known" and
        nothing else.  This example gives a list as the base in the
        .yml file, which is unparsable, so it gives a warning message
        and carries on with a blank dict.

        """
        fdroidserver.metadata.warnings_action = None
        mf = _get_mock_mf('[AntiFeatures: Tracking]')
        self.assertEqual(fdroidserver.metadata.parse_yaml_metadata(mf), dict())
        _warning.assert_called_once()
        _error.assert_called_once()

    def test_parse_localized_antifeatures(self):
        """Unit test based on reading files included in the test repo."""
        app = dict()
        app['id'] = 'app.with.special.build.params'
        metadata.parse_localized_antifeatures(app)
        self.maxDiff = None
        self.assertEqual(
            app,
            {
                'AntiFeatures': {
                    'Ads': {'en-US': 'please no'},
                    'NoSourceSince': {'en-US': 'no activity\n'},
                },
                'Builds': [
                    {
                        'versionCode': 50,
                        'antifeatures': {
                            'Ads': {
                                'en-US': 'includes ad lib\n',
                                'zh-CN': '包括广告图书馆\n',
                            },
                            'Tracking': {'en-US': 'standard suspects\n'},
                        },
                    },
                    {
                        'versionCode': 49,
                        'antifeatures': {
                            'Tracking': {'zh-CN': 'Text from zh-CN/49_Tracking.txt'},
                        },
                    },
                ],
                'id': app['id'],
            },
        )

    def test_parse_localized_antifeatures_passthrough(self):
        """Test app values are cleanly passed through if no localized files."""
        before = {
            'id': 'placeholder',
            'AntiFeatures': {'NonFreeDep': {}},
            'Builds': [{'versionCode': 999, 'antifeatures': {'zero': {}, 'one': {}}}],
        }
        after = copy.deepcopy(before)
        with tempfile.TemporaryDirectory() as testdir:
            os.chdir(testdir)
            os.mkdir('metadata')
            os.mkdir(os.path.join('metadata', after['id']))
            metadata.parse_localized_antifeatures(after)
        self.assertEqual(before, after)

    def test_parse_metadata_antifeatures_NoSourceSince(self):
        """Test that NoSourceSince gets added as an Anti-Feature."""
        os.chdir(self.testdir)
        yml = Path('metadata/test.yml')
        yml.parent.mkdir()
        with yml.open('w') as fp:
            fp.write('AntiFeatures: Ads\nNoSourceSince: gone\n')
        app = metadata.parse_metadata(yml)
        self.assertEqual(
            app['AntiFeatures'], {'Ads': {}, 'NoSourceSince': {DEFAULT_LOCALE: 'gone'}}
        )

    @mock.patch('logging.error')
    def test_yml_overrides_localized_antifeatures(self, logging_error):
        """Definitions in .yml files should override the localized versions."""
        app = metadata.parse_metadata('metadata/app.with.special.build.params.yml')

        self.assertEqual(app['AntiFeatures'], {'UpstreamNonFree': {}})

        self.assertEqual(49, app['Builds'][-3]['versionCode'])
        self.assertEqual(
            app['Builds'][-3]['antifeatures'],
            {'Tracking': {DEFAULT_LOCALE: 'Uses the Facebook SDK.'}},
        )

        self.assertEqual(50, app['Builds'][-2]['versionCode'])
        self.assertEqual(
            app['Builds'][-2]['antifeatures'],
            {
                'Ads': {
                    'en-US': 'includes ad lib\n',
                    'zh-CN': '包括广告图书馆\n',
                },
                'Tracking': {'en-US': 'standard suspects\n'},
            },
        )
        # errors are printed when .yml overrides localized
        logging_error.assert_called()
        self.assertEqual(3, len(logging_error.call_args_list))

    def test_parse_yaml_srclib_corrupt_file(self):
        with tempfile.TemporaryDirectory() as testdir:
            testdir = Path(testdir)
            srclibfile = testdir / 'srclib/mock.yml'
            srclibfile.parent.mkdir()
            with srclibfile.open('w') as fp:
                fp.write(
                    textwrap.dedent(
                        """
                        - RepoType: git
                        - Repo: https://github.com/realm/realm-js.git
                        """
                    )
                )
            with self.assertRaises(MetaDataException):
                fdroidserver.metadata.parse_yaml_srclib(srclibfile)

    def test_write_yaml_with_placeholder_values(self):
        mf = io.StringIO()

        app = fdroidserver.metadata.App()
        app.Categories = ['None']
        app.SourceCode = "https://gitlab.com/fdroid/fdroidclient.git"
        app.IssueTracker = "https://gitlab.com/fdroid/fdroidclient/issues"
        app.RepoType = 'git'
        app.Repo = 'https://gitlab.com/fdroid/fdroidclient.git'
        app.AutoUpdateMode = 'None'
        app.UpdateCheckMode = 'Tags'
        build = fdroidserver.metadata.Build()
        build.versionName = 'Unknown'  # taken from fdroidserver/import.py
        build.versionCode = 0  # taken from fdroidserver/import.py
        build.disable = 'Generated by import.py ...'
        build.commit = 'Unknown'
        build.gradle = ['yes']
        app['Builds'] = [build]

        fdroidserver.metadata.write_yaml(mf, app)

        mf.seek(0)
        self.assertEqual(
            mf.read(),
            textwrap.dedent(
                """\
                Categories:
                  - None
                License: Unknown
                SourceCode: https://gitlab.com/fdroid/fdroidclient.git
                IssueTracker: https://gitlab.com/fdroid/fdroidclient/issues

                RepoType: git
                Repo: https://gitlab.com/fdroid/fdroidclient.git

                Builds:
                  - versionName: Unknown
                    versionCode: 0
                    disable: Generated by import.py ...
                    commit: Unknown
                    gradle:
                      - yes

                AutoUpdateMode: None
                UpdateCheckMode: Tags
                """
            ),
        )

    def test_parse_yaml_metadata_prebuild_list(self):
        mf = io.StringIO(
            textwrap.dedent(
                """\
                AutoName: F-Droid
                RepoType: git
                Builds:
                  - versionCode: 1
                    versionName: v0.1.0
                    sudo:
                      - apt-get update
                      - apt-get install -y whatever
                      - sed -i -e 's/<that attr="bad"/<that attr="good"/' ~/.whatever/config.xml
                    init:
                      - bash generate_some_file.sh
                      - sed -i -e 'g/what/ever/' /some/file
                    prebuild:
                      - npm something
                      - echo 'important setting' >> /a/file
                    build:
                      - ./gradlew someSpecialTask
                      - sed -i 'd/that wrong config/' gradle.properties
                      - ./gradlew compile
                """
            )
        )
        mf.name = 'mock_filename.yaml'
        mf.seek(0)
        result = fdroidserver.metadata.parse_yaml_metadata(mf)
        self.maxDiff = None
        self.assertDictEqual(
            result,
            {
                'AutoName': 'F-Droid',
                'RepoType': 'git',
                'Builds': [
                    {
                        'versionCode': 1,
                        'versionName': 'v0.1.0',
                        'sudo': [
                            "apt-get update",
                            "apt-get install -y whatever",
                            "sed -i -e 's/<that attr=\"bad\"/<that attr=\"good\"/' ~/.whatever/config.xml",
                        ],
                        'init': [
                            "bash generate_some_file.sh",
                            "sed -i -e 'g/what/ever/' /some/file",
                        ],
                        'prebuild': [
                            "npm something",
                            "echo 'important setting' >> /a/file",
                        ],
                        'build': [
                            "./gradlew someSpecialTask",
                            "sed -i 'd/that wrong config/' gradle.properties",
                            "./gradlew compile",
                        ],
                    }
                ],
            },
        )

    def test_parse_yaml_metadata_prebuild_strings(self):
        mf = io.StringIO(
            textwrap.dedent(
                """\
                AutoName: F-Droid
                RepoType: git
                Builds:
                  - versionCode: 1
                    versionName: v0.1.0
                    sudo: |-
                      apt-get update && apt-get install -y whatever && sed -i -e 's/<that attr="bad"/<that attr="good"/' ~/.whatever/config.xml
                    init: bash generate_some_file.sh && sed -i -e 'g/what/ever/' /some/file
                    prebuild: npm something && echo 'important setting' >> /a/file
                    build: |-
                      ./gradlew someSpecialTask && sed -i 'd/that wrong config/' gradle.properties && ./gradlew compile
                """
            )
        )
        mf.name = 'mock_filename.yaml'
        mf.seek(0)
        result = fdroidserver.metadata.parse_yaml_metadata(mf)
        self.maxDiff = None
        self.assertDictEqual(
            result,
            {
                'AutoName': 'F-Droid',
                'RepoType': 'git',
                'Builds': [
                    {
                        'versionCode': 1,
                        'versionName': 'v0.1.0',
                        'sudo': [
                            "apt-get update && "
                            "apt-get install -y whatever && "
                            "sed -i -e 's/<that attr=\"bad\"/<that attr=\"good\"/' ~/.whatever/config.xml"
                        ],
                        'init': [
                            "bash generate_some_file.sh && "
                            "sed -i -e 'g/what/ever/' /some/file"
                        ],
                        'prebuild': [
                            "npm something && echo 'important setting' >> /a/file"
                        ],
                        'build': [
                            "./gradlew someSpecialTask && "
                            "sed -i 'd/that wrong config/' gradle.properties && "
                            "./gradlew compile"
                        ],
                    }
                ],
            },
        )

    def test_parse_yaml_metadata_prebuild_string(self):
        mf = io.StringIO(
            textwrap.dedent(
                """\
                AutoName: F-Droid
                RepoType: git
                Builds:
                  - versionCode: 1
                    versionName: v0.1.0
                    prebuild: |-
                      a && b && sed -i 's,a,b,'
                """
            )
        )
        mf.name = 'mock_filename.yaml'
        mf.seek(0)
        result = fdroidserver.metadata.parse_yaml_metadata(mf)
        self.assertDictEqual(
            result,
            {
                'AutoName': 'F-Droid',
                'RepoType': 'git',
                'Builds': [
                    {
                        'versionCode': 1,
                        'versionName': 'v0.1.0',
                        'prebuild': ["a && b && sed -i 's,a,b,'"],
                    }
                ],
            },
        )

    def test_parse_yaml_provides_should_be_ignored(self):
        mf = io.StringIO(
            textwrap.dedent(
                """\
                Provides: this.is.deprecated
                AutoName: F-Droid
                RepoType: git
                Builds:
                  - versionCode: 1
                    versionName: v0.1.0
                    prebuild: |-
                      a && b && sed -i 's,a,b,'
                """
            )
        )
        mf.name = 'mock_filename.yaml'
        mf.seek(0)
        result = fdroidserver.metadata.parse_yaml_metadata(mf)
        self.assertNotIn('Provides', result)
        self.assertNotIn('provides', result)

    def test_parse_yaml_app_antifeatures_dict(self):
        nonfreenet = 'free it!'
        tracking = 'so many'
        mf = io.StringIO(
            textwrap.dedent(
                f"""
                AntiFeatures:
                  Tracking: {tracking}
                  NonFreeNet: {nonfreenet}
                """
            )
        )
        self.assertEqual(
            metadata.parse_yaml_metadata(mf),
            {
                'AntiFeatures': {
                    'NonFreeNet': {DEFAULT_LOCALE: nonfreenet},
                    'Tracking': {DEFAULT_LOCALE: tracking},
                }
            },
        )

    def test_parse_yaml_metadata_build_antifeatures_old_style(self):
        mf = _get_mock_mf(
            textwrap.dedent(
                """
                AntiFeatures:
                  - Ads
                Builds:
                  - versionCode: 123
                    antifeatures:
                      - KnownVuln
                      - UpstreamNonFree
                      - NonFreeAssets
                """
            )
        )
        self.assertEqual(
            metadata.parse_yaml_metadata(mf),
            {
                'AntiFeatures': {'Ads': {}},
                'Builds': [
                    {
                        'antifeatures': {
                            'KnownVuln': {},
                            'NonFreeAssets': {},
                            'UpstreamNonFree': {},
                        },
                        'versionCode': 123,
                    }
                ],
            },
        )

    def test_parse_yaml_metadata_antifeatures_sort(self):
        """All data should end up sorted, to minimize diffs in the index files."""
        self.assertEqual(
            metadata.parse_yaml_metadata(
                _get_mock_mf(
                    textwrap.dedent(
                        """
                Builds:
                  - versionCode: 123
                    antifeatures:
                      KnownVuln:
                        es: 2nd
                        az: zero
                        en-US: first
                      UpstreamNonFree:
                      NonFreeAssets:
                AntiFeatures:
                  NonFreeDep:
                  Ads:
                    sw: 2nd
                    zh-CN: 3rd
                    de: 1st
                """
                    )
                )
            ),
            {
                'AntiFeatures': {
                    'Ads': {'de': '1st', 'sw': '2nd', 'zh-CN': '3rd'},
                    'NonFreeDep': {},
                },
                'Builds': [
                    {
                        'antifeatures': {
                            'KnownVuln': {'az': 'zero', 'en-US': 'first', 'es': '2nd'},
                            'NonFreeAssets': {},
                            'UpstreamNonFree': {},
                        },
                        'versionCode': 123,
                    }
                ],
            },
        )

    def test_parse_yaml_app_antifeatures_str(self):
        self.assertEqual(
            metadata.parse_yaml_metadata(io.StringIO('AntiFeatures: Tracking')),
            {'AntiFeatures': {'Tracking': {}}},
        )

    def test_parse_yaml_app_antifeatures_bool(self):
        self.assertEqual(
            metadata.parse_yaml_metadata(io.StringIO('AntiFeatures: true')),
            {'AntiFeatures': {'true': {}}},
        )

    def test_parse_yaml_app_antifeatures_float_nan(self):
        self.assertEqual(
            metadata.parse_yaml_metadata(io.StringIO('AntiFeatures: .nan')),
            {'AntiFeatures': {'.nan': {}}},
        )

    def test_parse_yaml_app_antifeatures_float_inf(self):
        self.assertEqual(
            metadata.parse_yaml_metadata(io.StringIO('AntiFeatures: .inf')),
            {'AntiFeatures': {'.inf': {}}},
        )

    def test_parse_yaml_app_antifeatures_float_negative_inf(self):
        self.assertEqual(
            metadata.parse_yaml_metadata(io.StringIO('AntiFeatures: -.inf')),
            {'AntiFeatures': {'-.inf': {}}},
        )

    def test_parse_yaml_app_antifeatures_int(self):
        self.assertEqual(
            metadata.parse_yaml_metadata(io.StringIO('AntiFeatures: 1')),
            {'AntiFeatures': {'1': {}}},
        )

    def test_parse_yaml_app_antifeatures_float(self):
        self.assertEqual(
            metadata.parse_yaml_metadata(io.StringIO('AntiFeatures: 1.0')),
            {'AntiFeatures': {'1.0': {}}},
        )

    def test_parse_yaml_app_antifeatures_list_float(self):
        self.assertEqual(
            metadata.parse_yaml_metadata(io.StringIO('AntiFeatures:\n  - 1.0\n')),
            {'AntiFeatures': {'1.0': {}}},
        )

    def test_parse_yaml_app_antifeatures_dict_float(self):
        mf = io.StringIO('AntiFeatures:\n  0.0: too early\n')
        self.assertEqual(
            metadata.parse_yaml_metadata(mf),
            {'AntiFeatures': {'0.0': {'en-US': 'too early'}}},
        )

    def test_parse_yaml_app_antifeatures_dict_float_fail_value(self):
        mf = io.StringIO('AntiFeatures:\n  NoSourceSince: 1.0\n')
        self.assertEqual(
            metadata.parse_yaml_metadata(mf),
            {'AntiFeatures': {'NoSourceSince': {'en-US': '1.0'}}},
        )

    def test_parse_yaml_metadata_type_stringmap_old_list(self):
        mf = _get_mock_mf(
            textwrap.dedent(
                """
                    AntiFeatures:
                      - Ads
                      - Tracking
                """
            )
        )
        self.assertEqual(
            {'AntiFeatures': {'Ads': {}, 'Tracking': {}}},
            metadata.parse_yaml_metadata(mf),
        )

    def test_parse_yaml_app_antifeatures_dict_no_value(self):
        mf = io.StringIO(
            textwrap.dedent(
                """\
                AntiFeatures:
                  Tracking:
                  NonFreeNet:
                """
            )
        )
        self.assertEqual(
            metadata.parse_yaml_metadata(mf),
            {'AntiFeatures': {'NonFreeNet': {}, 'Tracking': {}}},
        )

    def test_parse_yaml_metadata_type_stringmap_transitional(self):
        """Support a transitional format, where users just append a text"""
        ads = 'Has ad lib in it.'
        tracking = 'opt-out reports with ACRA'
        mf = _get_mock_mf(
            textwrap.dedent(
                f"""
                    AntiFeatures:
                      - Ads: {ads}
                      - Tracking: {tracking}
                """
            )
        )
        self.assertEqual(
            metadata.parse_yaml_metadata(mf),
            {
                'AntiFeatures': {
                    'Ads': {DEFAULT_LOCALE: ads},
                    'Tracking': {DEFAULT_LOCALE: tracking},
                }
            },
        )

    def test_parse_yaml_app_antifeatures_dict_mixed_values(self):
        ads = 'true'
        tracking = 'many'
        nonfreenet = '1'
        mf = io.StringIO(
            textwrap.dedent(
                f"""
                AntiFeatures:
                  Ads: {ads}
                  Tracking: {tracking}
                  NonFreeNet: {nonfreenet}
                """
            )
        )
        self.assertEqual(
            metadata.parse_yaml_metadata(mf),
            {
                'AntiFeatures': {
                    'Ads': {DEFAULT_LOCALE: ads},
                    'NonFreeNet': {DEFAULT_LOCALE: nonfreenet},
                    'Tracking': {DEFAULT_LOCALE: tracking},
                }
            },
        )

    def test_parse_yaml_app_antifeatures_stringmap_full(self):
        ads = 'watching'
        tracking = 'many'
        nonfreenet = 'pipes'
        nonfreenet_zh = '非免费网络'
        self.maxDiff = None
        mf = io.StringIO(
            textwrap.dedent(
                f"""
                AntiFeatures:
                  Ads:
                    {DEFAULT_LOCALE}: {ads}
                  Tracking:
                    {DEFAULT_LOCALE}: {tracking}
                  NonFreeNet:
                    {DEFAULT_LOCALE}: {nonfreenet}
                    zh-CN: {nonfreenet_zh}
                """
            )
        )
        self.assertEqual(
            metadata.parse_yaml_metadata(mf),
            {
                'AntiFeatures': {
                    'Ads': {DEFAULT_LOCALE: ads},
                    'NonFreeNet': {DEFAULT_LOCALE: nonfreenet, 'zh-CN': nonfreenet_zh},
                    'Tracking': {DEFAULT_LOCALE: tracking},
                }
            },
        )

    def test_parse_yaml_build_type_int_fail(self):
        mf = io.StringIO('Builds: [{versionCode: 1a}]')
        with self.assertRaises(MetaDataException):
            fdroidserver.metadata.parse_yaml_metadata(mf)

    def test_parse_yaml_int_strict_typing_fails(self):
        """Things that cannot be preserved when parsing as YAML."""
        mf = io.StringIO('Builds: [{versionCode: 1, rm: 0xf}]')
        self.assertEqual(
            {'Builds': [{'rm': ['15'], 'versionCode': 1}]},  # 15 != 0xf
            fdroidserver.metadata.parse_yaml_metadata(mf),
        )
        mf = io.StringIO('Builds: [{versionCode: 1, rm: 0x010}]')
        self.assertEqual(
            {'Builds': [{'rm': ['16'], 'versionCode': 1}]},  # 16 != 0x010
            fdroidserver.metadata.parse_yaml_metadata(mf),
        )
        mf = io.StringIO('Builds: [{versionCode: 1, rm: 0o015}]')
        self.assertEqual(
            {'Builds': [{'rm': ['13'], 'versionCode': 1}]},  # 13 != 0o015
            fdroidserver.metadata.parse_yaml_metadata(mf),
        )
        mf = io.StringIO('Builds: [{versionCode: 1, rm: 10_000}]')
        self.assertEqual(
            {'Builds': [{'rm': ['10000'], 'versionCode': 1}]},  # 10000 != 10_000
            fdroidserver.metadata.parse_yaml_metadata(mf),
        )

    def test_write_yaml_1_line_scripts_as_string(self):
        mf = io.StringIO()
        app = fdroidserver.metadata.App()
        app.Categories = ['None']
        app['Builds'] = []
        build = fdroidserver.metadata.Build()
        build.versionCode = 102030
        build.versionName = 'v1.2.3'
        build.sudo = ["chmod +rwx /opt"]
        build.init = ["sed -i -e 'g/what/ever/' /some/file"]
        build.prebuild = ["sed -i 'd/that wrong config/' gradle.properties"]
        build.build = ["./gradlew compile"]
        app['Builds'].append(build)
        fdroidserver.metadata.write_yaml(mf, app)
        mf.seek(0)
        self.assertEqual(
            mf.read(),
            textwrap.dedent(
                """\
                Categories:
                  - None
                License: Unknown

                Builds:
                  - versionName: v1.2.3
                    versionCode: 102030
                    sudo: chmod +rwx /opt
                    init: sed -i -e 'g/what/ever/' /some/file
                    prebuild: sed -i 'd/that wrong config/' gradle.properties
                    build: ./gradlew compile

                AutoUpdateMode: None
                UpdateCheckMode: None
                """
            ),
        )

    def test_write_yaml_1_line_scripts_as_list(self):
        mf = io.StringIO()
        app = fdroidserver.metadata.App()
        app.Categories = ['None']
        app['Builds'] = []
        build = fdroidserver.metadata.Build()
        build.versionCode = 102030
        build.versionName = 'v1.2.3'
        build.sudo = ["chmod +rwx /opt"]
        build.init = ["sed -i -e 'g/what/ever/' /some/file"]
        build.prebuild = ["sed -i 'd/that wrong config/' gradle.properties"]
        build.build = ["./gradlew compile"]
        app['Builds'].append(build)
        fdroidserver.metadata.write_yaml(mf, app)
        mf.seek(0)
        self.assertEqual(
            mf.read(),
            textwrap.dedent(
                """\
                Categories:
                  - None
                License: Unknown

                Builds:
                  - versionName: v1.2.3
                    versionCode: 102030
                    sudo: chmod +rwx /opt
                    init: sed -i -e 'g/what/ever/' /some/file
                    prebuild: sed -i 'd/that wrong config/' gradle.properties
                    build: ./gradlew compile

                AutoUpdateMode: None
                UpdateCheckMode: None
                """
            ),
        )

    def test_write_yaml_multiline_scripts_from_list(self):
        mf = io.StringIO()
        app = fdroidserver.metadata.App()
        app.Categories = ['None']
        app['Builds'] = []
        build = fdroidserver.metadata.Build()
        build.versionCode = 102030
        build.versionName = 'v1.2.3'
        build.sudo = [
            "apt-get update",
            "apt-get install -y whatever",
            "sed -i -e 's/<that attr=\"bad\"/<that attr=\"good\"/' ~/.whatever/config.xml",
        ]
        build.init = [
            "bash generate_some_file.sh",
            "sed -i -e 'g/what/ever/' /some/file",
        ]
        build.prebuild = ["npm something", "echo 'important setting' >> /a/file"]
        build.build = [
            "./gradlew someSpecialTask",
            "sed -i 'd/that wrong config/' gradle.properties",
            "./gradlew compile",
        ]
        app['Builds'].append(build)
        fdroidserver.metadata.write_yaml(mf, app)
        mf.seek(0)
        self.assertEqual(
            mf.read(),
            textwrap.dedent(
                """\
            Categories:
              - None
            License: Unknown

            Builds:
              - versionName: v1.2.3
                versionCode: 102030
                sudo:
                  - apt-get update
                  - apt-get install -y whatever
                  - sed -i -e 's/<that attr="bad"/<that attr="good"/' ~/.whatever/config.xml
                init:
                  - bash generate_some_file.sh
                  - sed -i -e 'g/what/ever/' /some/file
                prebuild:
                  - npm something
                  - echo 'important setting' >> /a/file
                build:
                  - ./gradlew someSpecialTask
                  - sed -i 'd/that wrong config/' gradle.properties
                  - ./gradlew compile

            AutoUpdateMode: None
            UpdateCheckMode: None
            """
            ),
        )

    def test_write_yaml_multiline_scripts_from_string(self):
        mf = io.StringIO()
        app = fdroidserver.metadata.App()
        app.Categories = ['None']
        app['Builds'] = []
        build = fdroidserver.metadata.Build()
        build.versionCode = 102030
        build.versionName = 'v1.2.3'
        build.sudo = [
            "apt-get update",
            "apt-get install -y whatever",
            "sed -i -e 's/<that attr=\"bad\"/<that attr=\"good\"/' ~/.whatever/config.xml",
        ]
        build.init = [
            "bash generate_some_file.sh",
            "sed -i -e 'g/what/ever/' /some/file",
        ]
        build.prebuild = ["npm something", "echo 'important setting' >> /a/file"]
        build.build = [
            "./gradlew someSpecialTask",
            "sed -i 'd/that wrong config/' gradle.properties",
            "./gradlew compile",
        ]
        app['Builds'].append(build)
        fdroidserver.metadata.write_yaml(mf, app)
        mf.seek(0)
        self.assertEqual(
            mf.read(),
            textwrap.dedent(
                """\
            Categories:
              - None
            License: Unknown

            Builds:
              - versionName: v1.2.3
                versionCode: 102030
                sudo:
                  - apt-get update
                  - apt-get install -y whatever
                  - sed -i -e 's/<that attr="bad"/<that attr="good"/' ~/.whatever/config.xml
                init:
                  - bash generate_some_file.sh
                  - sed -i -e 'g/what/ever/' /some/file
                prebuild:
                  - npm something
                  - echo 'important setting' >> /a/file
                build:
                  - ./gradlew someSpecialTask
                  - sed -i 'd/that wrong config/' gradle.properties
                  - ./gradlew compile

            AutoUpdateMode: None
            UpdateCheckMode: None
            """
            ),
        )

    def test_write_yaml_build_antifeatures(self):
        mf = io.StringIO()
        app = metadata.App(
            {
                'License': 'Apache-2.0',
                'Builds': [
                    metadata.Build(
                        {
                            'versionCode': 102030,
                            'versionName': 'v1.2.3',
                            'gradle': ['yes'],
                            'antifeatures': {
                                'a': {},
                                'b': {'de': 'Probe', 'en-US': 'test'},
                            },
                        }
                    ),
                ],
                'id': 'placeholder',
            }
        )
        metadata.write_yaml(mf, app)
        mf.seek(0)
        self.assertEqual(
            mf.read(),
            textwrap.dedent(
                """\
                License: Apache-2.0

                Builds:
                  - versionName: v1.2.3
                    versionCode: 102030
                    gradle:
                      - yes
                    antifeatures:
                      a: {}
                      b:
                        de: Probe
                        en-US: test
                """
            ),
        )

    def test_write_yaml_build_antifeatures_old_style(self):
        mf = io.StringIO()
        app = metadata.App(
            {
                'License': 'Apache-2.0',
                'Builds': [
                    metadata.Build(
                        {
                            'versionCode': 102030,
                            'versionName': 'v1.2.3',
                            'gradle': ['yes'],
                            'antifeatures': {'b': {}, 'a': {}},
                        }
                    ),
                ],
                'id': 'placeholder',
            }
        )
        metadata.write_yaml(mf, app)
        mf.seek(0)
        self.assertEqual(
            mf.read(),
            textwrap.dedent(
                """\
                License: Apache-2.0

                Builds:
                  - versionName: v1.2.3
                    versionCode: 102030
                    gradle:
                      - yes
                    antifeatures:
                      - a
                      - b
                """
            ),
        )

    def test_write_yaml_make_sure_provides_does_not_get_written(self):
        mf = io.StringIO()
        app = fdroidserver.metadata.App()
        app.Categories = ['None']
        app.Provides = 'this.is.deprecated'
        app['Builds'] = []
        build = fdroidserver.metadata.Build()
        build.versionCode = 102030
        build.versionName = 'v1.2.3'
        build.gradle = ['yes']
        app['Builds'].append(build)
        fdroidserver.metadata.write_yaml(mf, app)
        mf.seek(0)
        self.assertEqual(
            mf.read(),
            textwrap.dedent(
                """\
                Categories:
                  - None
                License: Unknown

                Builds:
                  - versionName: v1.2.3
                    versionCode: 102030
                    gradle:
                      - yes

                AutoUpdateMode: None
                UpdateCheckMode: None
                """
            ),
        )

    def test_parse_yaml_srclib_unknown_key(self):
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with Path('test.yml').open('w', encoding='utf-8') as f:
                f.write(
                    textwrap.dedent(
                        '''\
                        RepoType: git
                        Repo: https://example.com/test.git
                        Evil: I should not be here.
                        '''
                    )
                )
            with self.assertRaisesRegex(
                MetaDataException,
                "Invalid srclib metadata: unknown key 'Evil' in 'test.yml'",
            ):
                fdroidserver.metadata.parse_yaml_srclib(Path('test.yml'))

    def test_parse_yaml_srclib_does_not_exists(self):
        with self.assertRaisesRegex(
            MetaDataException,
            "Invalid scrlib metadata: "
            r"'non(/|\\)existent-test-srclib.yml' "
            "does not exist",
        ):
            fdroidserver.metadata.parse_yaml_srclib(
                Path('non/existent-test-srclib.yml')
            )

    def test_parse_yaml_srclib_simple(self):
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with Path('simple.yml').open('w', encoding='utf-8') as f:
                f.write(
                    textwrap.dedent(
                        '''\
                    # this should be simple
                    RepoType: git
                    Repo: https://git.host/repo.git
                    '''
                    )
                )
            srclib = fdroidserver.metadata.parse_yaml_srclib(Path('simple.yml'))
            self.assertDictEqual(
                {
                    'Repo': 'https://git.host/repo.git',
                    'RepoType': 'git',
                    'Subdir': None,
                    'Prepare': None,
                },
                srclib,
            )

    def test_parse_yaml_srclib_simple_with_blanks(self):
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with Path('simple.yml').open('w', encoding='utf-8') as f:
                f.write(
                    textwrap.dedent(
                        '''\
                    # this should be simple

                    RepoType: git

                    Repo: https://git.host/repo.git

                    Subdir:

                    Prepare:
                    '''
                    )
                )
            srclib = fdroidserver.metadata.parse_yaml_srclib(Path('simple.yml'))
            self.assertDictEqual(
                {
                    'Repo': 'https://git.host/repo.git',
                    'RepoType': 'git',
                    'Subdir': [''],
                    'Prepare': [],
                },
                srclib,
            )

    def test_parse_yaml_srclib_Changelog_cketti(self):
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            with Path('Changelog-cketti.yml').open('w', encoding='utf-8') as f:
                f.write(
                    textwrap.dedent(
                        '''\
                    RepoType: git
                    Repo: https://github.com/cketti/ckChangeLog

                    Subdir: library,ckChangeLog/src/main
                    Prepare: "[ -f project.properties ] || echo 'source.dir=java' > ant.properties && echo -e 'android.library=true\\\\ntarget=android-19' > project.properties"
                    '''
                    )
                )
            srclib = fdroidserver.metadata.parse_yaml_srclib(
                Path('Changelog-cketti.yml')
            )
            self.assertDictEqual(
                srclib,
                {
                    'Repo': 'https://github.com/cketti/ckChangeLog',
                    'RepoType': 'git',
                    'Subdir': ['library', 'ckChangeLog/src/main'],
                    'Prepare': [
                        "[ -f project.properties ] || echo 'source.dir=java' > "
                        "ant.properties && echo -e "
                        "'android.library=true\\ntarget=android-19' > project.properties"
                    ],
                },
            )

    def test_read_srclibs_yml_subdir_list(self):
        fdroidserver.metadata.srclibs = None
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            Path('srclibs').mkdir()
            with Path('srclibs/with-list.yml').open('w', encoding='utf-8') as f:
                f.write(
                    textwrap.dedent(
                        '''\
                    # this should be simple
                    RepoType: git
                    Repo: https://git.host/repo.git

                    Subdir:
                     - This is your last chance.
                     - After this, there is no turning back.
                     - You take the blue pill—the story ends,
                     - you wake up in your bed
                     - and believe whatever you want to believe.
                     - You take the red pill—you stay in Wonderland
                     - and I show you how deep the rabbit-hole goes.
                    Prepare:
                        There is a difference between knowing the path
                        and walking the path.
                    '''
                    )
                )
            fdroidserver.metadata.read_srclibs()
        self.maxDiff = None
        self.assertDictEqual(
            fdroidserver.metadata.srclibs,
            {
                'with-list': {
                    'RepoType': 'git',
                    'Repo': 'https://git.host/repo.git',
                    'Subdir': [
                        'This is your last chance.',
                        'After this, there is no turning back.',
                        'You take the blue pill—the story ends,',
                        'you wake up in your bed',
                        'and believe whatever you want to believe.',
                        'You take the red pill—you stay in Wonderland',
                        'and I show you how deep the rabbit-hole goes.',
                    ],
                    'Prepare': [
                        'There is a difference between knowing the path '
                        'and walking the path.'
                    ],
                }
            },
        )

    def test_read_srclibs_yml_prepare_list(self):
        fdroidserver.metadata.srclibs = None
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            Path('srclibs').mkdir()
            with Path('srclibs/with-list.yml').open('w', encoding='utf-8') as f:
                f.write(
                    textwrap.dedent(
                        '''\
                    # this should be simple
                    RepoType: git
                    Repo: https://git.host/repo.git

                    Subdir:
                    Prepare:
                     - Many
                     - invalid
                     - commands
                     - here.
                    '''
                    )
                )
            fdroidserver.metadata.read_srclibs()
        self.maxDiff = None
        self.assertDictEqual(
            fdroidserver.metadata.srclibs,
            {
                'with-list': {
                    'RepoType': 'git',
                    'Repo': 'https://git.host/repo.git',
                    'Subdir': [''],
                    'Prepare': [
                        'Many',
                        'invalid',
                        'commands',
                        'here.',
                    ],
                }
            },
        )

    def test_read_srclibs(self):
        fdroidserver.metadata.srclibs = None
        with tempfile.TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            Path('srclibs').mkdir()
            with Path('srclibs/simple.yml').open('w', encoding='utf-8') as f:
                f.write(
                    textwrap.dedent(
                        '''\
                    RepoType: git
                    Repo: https://git.host/repo.git
                    '''
                    )
                )
            with Path('srclibs/simple-wb.yml').open('w', encoding='utf-8') as f:
                f.write(
                    textwrap.dedent(
                        '''\
                    # this should be simple
                    RepoType: git
                    Repo: https://git.host/repo.git

                    Subdir:
                    Prepare:
                    '''
                    )
                )
            fdroidserver.metadata.read_srclibs()
        self.assertDictEqual(
            fdroidserver.metadata.srclibs,
            {
                'simple-wb': {
                    'RepoType': 'git',
                    'Repo': 'https://git.host/repo.git',
                    'Subdir': [''],
                    'Prepare': [],
                },
                'simple': {
                    'RepoType': 'git',
                    'Repo': 'https://git.host/repo.git',
                    'Subdir': None,
                    'Prepare': None,
                },
            },
        )

    def test_build_ndk_path(self):
        with tempfile.TemporaryDirectory(prefix='android-sdk-') as sdk_path:
            config = {'ndk_paths': {}, 'sdk_path': sdk_path}
            fdroidserver.common.config = config

            build = fdroidserver.metadata.Build()
            build.ndk = 'r10e'
            self.assertEqual('', build.ndk_path())

            correct = '/fake/path/ndk/r21b'
            config['ndk_paths'] = {'r21b': correct}
            self.assertEqual('', build.ndk_path())
            config['ndk_paths'] = {'r10e': correct}
            self.assertEqual(correct, build.ndk_path())

            r10e = '/fake/path/ndk/r10e'
            r22b = '/fake/path/ndk/r22e'
            config['ndk_paths'] = {'r10e': r10e, 'r22b': r22b}
            self.assertEqual(r10e, build.ndk_path())

            build.ndk = ['r10e', 'r22b']
            self.assertEqual(r10e, build.ndk_path())

            build.ndk = ['r22b', 'r10e']
            self.assertEqual(r22b, build.ndk_path())

    def test_build_ndk_path_only_accepts_str(self):
        """Paths in the config must be strings, never pathlib.Path instances"""
        config = {'ndk_paths': {'r24': Path('r24')}}
        fdroidserver.common.config = config
        build = fdroidserver.metadata.Build()
        build.ndk = 'r24'
        with self.assertRaises(TypeError):
            build.ndk_path()

    def test_del_duplicated_NoSourceSince(self):
        app = {
            'AntiFeatures': {'Ads': {}, 'NoSourceSince': {DEFAULT_LOCALE: '1.0'}},
            'NoSourceSince': '1.0',
        }
        metadata._del_duplicated_NoSourceSince(app)
        self.assertEqual(app, {'AntiFeatures': {'Ads': {}}, 'NoSourceSince': '1.0'})

    def test_check_manually_extended_NoSourceSince(self):
        app = {
            'AntiFeatures': {'NoSourceSince': {DEFAULT_LOCALE: '1.0', 'de': '1,0'}},
            'NoSourceSince': '1.0',
        }
        metadata._del_duplicated_NoSourceSince(app)
        self.assertEqual(
            app,
            {
                'AntiFeatures': {'NoSourceSince': {DEFAULT_LOCALE: '1.0', 'de': '1,0'}},
                'NoSourceSince': '1.0',
            },
        )

    def test_make_sure_nosourcesince_does_not_get_written(self):
        appid = 'com.politedroid'
        app = metadata.read_metadata({appid: -1})[appid]
        builds = app['Builds']
        app['Builds'] = [copy.deepcopy(builds[0])]
        mf = io.StringIO()
        metadata.write_yaml(mf, app)
        mf.seek(0)
        self.maxDiff = None
        self.assertEqual(
            mf.read(),
            textwrap.dedent(
                """\
                AntiFeatures:
                  - NonFreeNet
                Categories:
                  - Multimedia
                  - Security
                  - Time
                License: GPL-3.0-only
                SourceCode: https://github.com/miguelvps/PoliteDroid
                IssueTracker: https://github.com/miguelvps/PoliteDroid/issues

                AutoName: Polite Droid
                Summary: Calendar tool
                Description: Activates silent mode during calendar events.

                RepoType: git
                Repo: https://github.com/miguelvps/PoliteDroid.git

                Builds:
                  - versionName: '1.2'
                    versionCode: 3
                    commit: 6a548e4b19
                    target: android-10
                    antifeatures:
                      - KnownVuln
                      - NonFreeAssets
                      - UpstreamNonFree

                ArchivePolicy: 4
                AutoUpdateMode: Version v%v
                UpdateCheckMode: Tags
                CurrentVersion: '1.5'
                CurrentVersionCode: 6

                NoSourceSince: '1.5'
                """
            ),
        )

    def test_app_to_yaml_smokecheck(self):
        self.assertTrue(
            isinstance(metadata._app_to_yaml(dict()), ruamel.yaml.comments.CommentedMap)
        )

    def test_app_to_yaml_build_list_empty(self):
        app = metadata.App({'Builds': [metadata.Build({'rm': []})]})
        self.assertEqual(dict(), metadata._app_to_yaml(app)['Builds'][0])

    def test_app_to_yaml_build_list_one(self):
        app = metadata.App({'Builds': [metadata.Build({'rm': ['one']})]})
        self.assertEqual({'rm': ['one']}, metadata._app_to_yaml(app)['Builds'][0])

    def test_app_to_yaml_build_list_two(self):
        app = metadata.App({'Builds': [metadata.Build({'rm': ['1', '2']})]})
        self.assertEqual({'rm': ['1', '2']}, metadata._app_to_yaml(app)['Builds'][0])

    def test_app_to_yaml_build_list(self):
        app = metadata.App({'Builds': [metadata.Build({'rm': ['b2', 'NO1']})]})
        self.assertEqual({'rm': ['b2', 'NO1']}, metadata._app_to_yaml(app)['Builds'][0])

    def test_app_to_yaml_AllowedAPKSigningKeys_two(self):
        cm = metadata._app_to_yaml(metadata.App({'AllowedAPKSigningKeys': ['b', 'A']}))
        self.assertEqual(['b', 'a'], cm['AllowedAPKSigningKeys'])

    def test_app_to_yaml_AllowedAPKSigningKeys_one(self):
        cm = metadata._app_to_yaml(metadata.App({'AllowedAPKSigningKeys': ['One']}))
        self.assertEqual('one', cm['AllowedAPKSigningKeys'])

    def test_app_to_yaml_int_hex(self):
        cm = metadata._app_to_yaml(metadata.App({'CurrentVersionCode': 0xFF}))
        self.assertEqual(255, cm['CurrentVersionCode'])

    def test_app_to_yaml_int_underscore(self):
        cm = metadata._app_to_yaml(metadata.App({'CurrentVersionCode': 1_2_3}))
        self.assertEqual(123, cm['CurrentVersionCode'])

    def test_app_to_yaml_int_0(self):
        """Document that 0 values fail to make it through."""
        # TODO it should be possible to use `CurrentVersionCode: 0`
        cm = metadata._app_to_yaml(metadata.App({'CurrentVersionCode': 0}))
        self.assertFalse('CurrentVersionCode' in cm)

    def test_format_multiline(self):
        self.assertEqual(metadata._format_multiline('description'), 'description')

    def test_format_multiline_empty(self):
        self.assertEqual(metadata._format_multiline(''), '')

    def test_format_multiline_newline_char(self):
        self.assertEqual(metadata._format_multiline('one\\ntwo'), 'one\\ntwo')

    def test_format_multiline_newlines(self):
        self.assertEqual(
            metadata._format_multiline(
                textwrap.dedent(
                    """
                    one
                    two
                    three
                    """
                )
            ),
            '\none\ntwo\nthree\n',
        )

    def test_format_list_empty(self):
        self.assertEqual(metadata._format_list(['', None]), list())

    def test_format_list_one_empty(self):
        self.assertEqual(metadata._format_list(['foo', None]), ['foo'])

    def test_format_list_two(self):
        self.assertEqual(metadata._format_list(['2', '1']), ['2', '1'])

    def test_format_list_newline(self):
        self.assertEqual(metadata._format_list(['one\ntwo']), ['one\ntwo'])

    def test_format_list_newline_char(self):
        self.assertEqual(metadata._format_list(['one\\ntwo']), ['one\\ntwo'])

    def test_format_script_empty(self):
        self.assertEqual(metadata._format_script(['', None]), list())

    def test_format_script_newline(self):
        self.assertEqual(metadata._format_script(['one\ntwo']), 'one\ntwo')

    def test_format_script_newline_char(self):
        self.assertEqual(metadata._format_script(['one\\ntwo']), 'one\\ntwo')

    def test_format_stringmap_empty(self):
        self.assertEqual(
            metadata._format_stringmap('🔥', 'test', dict()),
            list(),
        )

    def test_format_stringmap_one_list(self):
        self.assertEqual(
            metadata._format_stringmap('🔥', 'test', {'Tracking': {}, 'Ads': {}}),
            ['Ads', 'Tracking'],
        )

    def test_format_stringmap_one_list_empty_desc(self):
        self.assertEqual(
            metadata._format_stringmap('🔥', 'test', {'NonFree': {}, 'Ads': {'en': ''}}),
            ['Ads', 'NonFree'],
        )

    def test_format_stringmap_three_list(self):
        self.assertEqual(
            metadata._format_stringmap('🔥', 'test', {'B': {}, 'A': {}, 'C': {}}),
            ['A', 'B', 'C'],
        )

    def test_format_stringmap_two_dict(self):
        self.assertEqual(
            metadata._format_stringmap('🔥', 'test', {'1': {'uz': 'a'}, '2': {}}),
            {'1': {'uz': 'a'}, '2': {}},
        )

    def test_format_stringmap_three_locales(self):
        self.assertEqual(
            metadata._format_stringmap(
                '🔥', 'test', {'AF': {'uz': 'a', 'ko': 'b', 'zh': 'c'}}
            ),
            {'AF': {'ko': 'b', 'uz': 'a', 'zh': 'c'}},
        )

    def test_format_stringmap_move_build_antifeatures_to_filesystem(self):
        os.chdir(self.testdir)
        appid = 'a'
        yml = Path('metadata/a.yml')
        yml.parent.mkdir()
        self.assertEqual(
            metadata._format_stringmap(
                appid, 'antifeatures', {'AF': {'uz': 'a', 'ko': 'b', 'zh': 'c'}}
            ),
            {'AF': {'ko': 'b', 'uz': 'a', 'zh': 'c'}},
        )

    def test_format_stringmap_app_antifeatures_conflict(self):
        """Raise an error if a YAML Anti-Feature conflicts with a localized file."""
        os.chdir(self.testdir)
        appid = 'a'
        field = 'AntiFeatures'
        locale = 'ko'
        yml = Path('metadata/a.yml')
        antifeatures_ko = yml.parent / appid / locale / field.lower()
        antifeatures_ko.mkdir(parents=True)
        afname = 'Anti-🔥'
        (antifeatures_ko / (afname + '.txt')).write_text('SOMETHING ELSE')
        with self.assertRaises(MetaDataException):
            metadata._format_stringmap(
                appid, field, {afname: {'uz': 'a', locale: 'b', 'zh': 'c'}}
            )

    def test_format_stringmap_app_antifeatures_conflict_same_contents(self):
        """Raise an error if a YAML Anti-Feature conflicts with a localized file."""
        os.chdir(self.testdir)
        appid = 'a'
        field = 'AntiFeatures'
        locale = 'ko'
        yml = Path('metadata/a.yml')
        antifeatures_ko = yml.parent / appid / locale / field.lower()
        antifeatures_ko.mkdir(parents=True)
        afname = 'Anti-🔥'
        (antifeatures_ko / (afname + '.txt')).write_text('b')
        metadata._format_stringmap(
            appid, field, {afname: {'uz': 'a', locale: 'b', 'zh': 'c'}}
        )

    def test_format_stringmap_build_antifeatures_conflict(self):
        """Raise an error if a YAML Anti-Feature conflicts with a localized file."""
        os.chdir(self.testdir)
        appid = 'a'
        field = 'antifeatures'
        locale = 'ko'
        versionCode = 123
        yml = Path('metadata/a.yml')
        antifeatures_ko = yml.parent / appid / locale / field.lower()
        antifeatures_ko.mkdir(parents=True)
        afname = 'Anti-🔥'
        with (antifeatures_ko / ('%d_%s.txt' % (versionCode, afname))).open('w') as fp:
            fp.write('SOMETHING ELSE')
        with self.assertRaises(MetaDataException):
            metadata._format_stringmap(
                appid, field, {afname: {'uz': 'a', locale: 'b', 'zh': 'c'}}, versionCode
            )

    def test_app_to_yaml_one_category(self):
        """Categories does not get simplified to string when outputting YAML."""
        self.assertEqual(
            metadata._app_to_yaml({'Categories': ['one']}),
            {'Categories': ['one']},
        )

    def test_app_to_yaml_categories(self):
        """Sort case-insensitive before outputting YAML."""
        self.assertEqual(
            metadata._app_to_yaml({'Categories': ['c', 'a', 'B']}),
            {'Categories': ['a', 'B', 'c']},
        )

    def test_builds_to_yaml_gradle_yes(self):
        app = {'Builds': [{'versionCode': 0, 'gradle': ['yes']}]}
        self.assertEqual(
            metadata._builds_to_yaml(app), [{'versionCode': 0, 'gradle': ['yes']}]
        )

    def test_builds_to_yaml_gradle_off(self):
        app = {'Builds': [{'versionCode': 0, 'gradle': ['off']}]}
        self.assertEqual(
            metadata._builds_to_yaml(app), [{'versionCode': 0, 'gradle': ['off']}]
        )

    def test_builds_to_yaml_gradle_true(self):
        app = {'Builds': [{'versionCode': 0, 'gradle': ['true']}]}
        self.assertEqual(
            metadata._builds_to_yaml(app), [{'versionCode': 0, 'gradle': ['true']}]
        )

    def test_builds_to_yaml_gradle_false(self):
        app = {'Builds': [{'versionCode': 0, 'gradle': ['false']}]}
        self.assertEqual(
            metadata._builds_to_yaml(app), [{'versionCode': 0, 'gradle': ['false']}]
        )

    def test_builds_to_yaml_stripped(self):
        self.assertEqual(
            metadata._builds_to_yaml(
                {
                    'Builds': [
                        metadata.Build({'versionCode': 0, 'rm': [None], 'init': ['']})
                    ]
                }
            ),
            [{'versionCode': 0}],
        )

    def test_builds_to_yaml(self):
        """Include one of each flag type with a valid value."""
        app = {
            'Builds': [
                metadata.Build(
                    {
                        'versionCode': 0,
                        'gradle': ['free'],
                        'rm': ['0', '2'],
                        'submodules': True,
                        'timeout': 0,
                        'init': ['false', 'two'],
                    }
                )
            ]
        }
        # check that metadata.Build() inited flag values
        self.assertEqual(app['Builds'][0]['scanignore'], list())
        # then unchanged values should be removed by _builds_to_yaml
        self.assertEqual(
            metadata._builds_to_yaml(app),
            [
                {
                    'versionCode': 0,
                    'gradle': ['free'],
                    'rm': ['0', '2'],
                    'submodules': True,
                    'timeout': 0,
                    'init': ['false', 'two'],
                }
            ],
        )


class PostMetadataParseTest(unittest.TestCase):
    """Test the functions that post process the YAML input.

    The following series of "post_metadata_parse" tests map out the
    current state of automatic type conversion in the YAML post
    processing.  They are not necessary a statement of how things
    should be, but more to surface the details of it functions.

    """

    def setUp(self):
        fdroidserver.metadata.warnings_action = 'error'

    def _post_metadata_parse_app_int(self, from_yaml, expected):
        app = {'ArchivePolicy': from_yaml}
        metadata.post_parse_yaml_metadata(app)
        return {'ArchivePolicy': expected}, app

    def _post_metadata_parse_app_list(self, from_yaml, expected):
        app = {'AllowedAPKSigningKeys': from_yaml}
        metadata.post_parse_yaml_metadata(app)
        return {'AllowedAPKSigningKeys': expected}, app

    def _post_metadata_parse_app_string(self, from_yaml, expected):
        app = {'Repo': from_yaml}
        metadata.post_parse_yaml_metadata(app)
        return {'Repo': expected}, app

    def _post_metadata_parse_build_bool(self, from_yaml, expected):
        tested_key = 'submodules'
        app = {'Builds': [{'versionCode': 1, tested_key: from_yaml}]}
        post = copy.deepcopy(app)
        metadata.post_parse_yaml_metadata(post)
        del app['Builds'][0]['versionCode']
        del post['Builds'][0]['versionCode']
        for build in post['Builds']:
            for k in list(build):
                if k != tested_key:
                    del build[k]
        app['Builds'][0][tested_key] = expected
        return app, post

    def _post_metadata_parse_build_int(self, from_yaml, expected):
        tested_key = 'versionCode'
        app = {'Builds': [{'versionCode': from_yaml}]}
        post = copy.deepcopy(app)
        metadata.post_parse_yaml_metadata(post)
        for build in post['Builds']:
            for k in list(build):
                if k != tested_key:
                    del build[k]
        app['Builds'][0][tested_key] = expected
        return app, post

    def _post_metadata_parse_build_list(self, from_yaml, expected):
        tested_key = 'rm'
        app = {'Builds': [{'versionCode': 1, tested_key: from_yaml}]}
        post = copy.deepcopy(app)
        metadata.post_parse_yaml_metadata(post)
        del app['Builds'][0]['versionCode']
        del post['Builds'][0]['versionCode']
        for build in post['Builds']:
            for k in list(build):
                if k != tested_key:
                    del build[k]
        app['Builds'][0][tested_key] = expected
        return app, post

    def _post_metadata_parse_build_script(self, from_yaml, expected):
        tested_key = 'build'
        app = {'Builds': [{'versionCode': 1, tested_key: from_yaml}]}
        post = copy.deepcopy(app)
        metadata.post_parse_yaml_metadata(post)
        del app['Builds'][0]['versionCode']
        del post['Builds'][0]['versionCode']
        for build in post['Builds']:
            for k in list(build):
                if k != tested_key:
                    del build[k]
        app['Builds'][0][tested_key] = expected
        return app, post

    def _post_metadata_parse_build_string(self, from_yaml, expected):
        tested_key = 'commit'
        app = {'Builds': [{'versionCode': 1, tested_key: from_yaml}]}
        post = copy.deepcopy(app)
        metadata.post_parse_yaml_metadata(post)
        del app['Builds'][0]['versionCode']
        del post['Builds'][0]['versionCode']
        for build in post['Builds']:
            for k in list(build):
                if k != tested_key:
                    del build[k]
        app['Builds'][0][tested_key] = expected
        return app, post

    def test_post_metadata_parse_none(self):
        """Run None aka YAML null or blank through the various field and flag types."""
        self.assertEqual(*self._post_metadata_parse_app_int(None, None))
        self.assertEqual(*self._post_metadata_parse_app_list(None, None))
        self.assertEqual(*self._post_metadata_parse_app_string(None, None))
        self.assertEqual(*self._post_metadata_parse_build_bool(None, None))
        self.assertEqual(*self._post_metadata_parse_build_int(None, None))
        self.assertEqual(*self._post_metadata_parse_build_list(None, None))
        self.assertEqual(*self._post_metadata_parse_build_script(None, None))
        self.assertEqual(*self._post_metadata_parse_build_string(None, None))

    def test_post_metadata_parse_int(self):
        """Run the int 123456 through the various field and flag types."""
        self.assertEqual(*self._post_metadata_parse_app_int(123456, 123456))
        self.assertEqual(*self._post_metadata_parse_app_list(123456, ['123456']))
        self.assertEqual(*self._post_metadata_parse_app_string(123456, '123456'))
        self.assertEqual(*self._post_metadata_parse_build_bool(123456, True))
        self.assertEqual(*self._post_metadata_parse_build_int(123456, 123456))
        self.assertEqual(*self._post_metadata_parse_build_list(123456, ['123456']))
        self.assertEqual(*self._post_metadata_parse_build_script(123456, ['123456']))
        self.assertEqual(*self._post_metadata_parse_build_string(123456, '123456'))

    def test_post_metadata_parse_sha256(self):
        """Run a SHA-256 that YAML calls an int through the various types.

        The current f-droid.org signer set has SHA-256 values with a
        maximum of two leading zeros, but this will handle more.

        """
        yaml = ruamel.yaml.YAML(typ='safe', pure=True)
        str_sha256 = '0000000000000498456908409534729834729834729834792837487293847926'
        sha256 = yaml.load('a: ' + str_sha256)['a']
        self.assertEqual(*self._post_metadata_parse_app_int(sha256, int(str_sha256)))
        self.assertEqual(*self._post_metadata_parse_app_list(sha256, [str_sha256]))
        self.assertEqual(*self._post_metadata_parse_app_string(sha256, str_sha256))
        self.assertEqual(*self._post_metadata_parse_build_bool(sha256, True))
        self.assertEqual(*self._post_metadata_parse_build_int(sha256, sha256))
        self.assertEqual(*self._post_metadata_parse_build_list(sha256, [str_sha256]))
        self.assertEqual(*self._post_metadata_parse_build_script(sha256, [str_sha256]))
        self.assertEqual(*self._post_metadata_parse_build_string(sha256, str_sha256))

    def test_post_metadata_parse_int_0(self):
        """Run the int 0 through the various field and flag types."""
        self.assertEqual(*self._post_metadata_parse_app_int(0, 0))
        self.assertEqual(*self._post_metadata_parse_app_list(0, ['0']))
        self.assertEqual(*self._post_metadata_parse_app_string(0, '0'))
        self.assertEqual(*self._post_metadata_parse_build_bool(0, False))
        self.assertEqual(*self._post_metadata_parse_build_int(0, 0))
        self.assertEqual(*self._post_metadata_parse_build_list(0, ['0']))
        self.assertEqual(*self._post_metadata_parse_build_script(0, ['0']))
        self.assertEqual(*self._post_metadata_parse_build_string(0, '0'))

    def test_post_metadata_parse_float_0_0(self):
        """Run the float 0.0 through the various field and flag types."""
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_app_int(0.0, MetaDataException)
        self.assertEqual(*self._post_metadata_parse_app_list(0.0, ['0.0']))
        self.assertEqual(*self._post_metadata_parse_app_string(0.0, '0.0'))
        self.assertEqual(*self._post_metadata_parse_build_bool(0.0, False))
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_build_int(0.0, MetaDataException)
        self.assertEqual(*self._post_metadata_parse_build_list(0.0, ['0.0']))
        self.assertEqual(*self._post_metadata_parse_build_script(0.0, ['0.0']))
        self.assertEqual(*self._post_metadata_parse_build_string(0.0, '0.0'))

    def test_post_metadata_parse_float_0_1(self):
        """Run the float 0.1 through the various field and flag types."""
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_app_int(0.1, MetaDataException)
        self.assertEqual(*self._post_metadata_parse_app_list(0.1, ['0.1']))
        self.assertEqual(*self._post_metadata_parse_app_string(0.1, '0.1'))
        self.assertEqual(*self._post_metadata_parse_build_bool(0.1, True))
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_build_int(0.1, MetaDataException)
        self.assertEqual(*self._post_metadata_parse_build_list(0.1, ['0.1']))
        self.assertEqual(*self._post_metadata_parse_build_script(0.1, ['0.1']))
        self.assertEqual(*self._post_metadata_parse_build_string(0.1, '0.1'))

    def test_post_metadata_parse_float_1_0(self):
        """Run the float 1.0 through the various field and flag types."""
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_app_int(1.0, MetaDataException)
        self.assertEqual(*self._post_metadata_parse_app_list(1.0, ['1.0']))
        self.assertEqual(*self._post_metadata_parse_app_string(1.0, '1.0'))
        self.assertEqual(*self._post_metadata_parse_build_bool(1.0, True))
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_build_int(1.0, MetaDataException)
        self.assertEqual(*self._post_metadata_parse_build_list(1.0, ['1.0']))
        self.assertEqual(*self._post_metadata_parse_build_script(1.0, ['1.0']))
        self.assertEqual(*self._post_metadata_parse_build_string(1.0, '1.0'))

    def test_post_metadata_parse_empty_list(self):
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_app_int(list(), MetaDataException)
        self.assertEqual(*self._post_metadata_parse_app_list(list(), list()))
        self.assertEqual(*self._post_metadata_parse_app_string(list(), list()))
        self.assertEqual(*self._post_metadata_parse_build_bool(list(), False))
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_build_int(list(), MetaDataException)
        self.assertEqual(*self._post_metadata_parse_build_list(list(), list()))
        self.assertEqual(*self._post_metadata_parse_build_script(list(), list()))
        self.assertEqual(*self._post_metadata_parse_build_string(list(), list()))

    def test_post_metadata_parse_set_of_1(self):
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_app_int({1}, MetaDataException)
        self.assertEqual(*self._post_metadata_parse_app_list({1}, ['1']))
        self.assertEqual(*self._post_metadata_parse_app_string({1}, '{1}'))
        self.assertEqual(*self._post_metadata_parse_build_bool({1}, True))
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_build_int({1}, MetaDataException)
        self.assertEqual(*self._post_metadata_parse_build_list({1}, ['1']))
        self.assertEqual(*self._post_metadata_parse_build_script({1}, ['1']))
        self.assertEqual(*self._post_metadata_parse_build_string({1}, '{1}'))

    def test_post_metadata_parse_empty_dict(self):
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_app_int(dict(), MetaDataException)
        self.assertEqual(*self._post_metadata_parse_app_list(dict(), dict()))
        self.assertEqual(*self._post_metadata_parse_app_string(dict(), dict()))
        self.assertEqual(*self._post_metadata_parse_build_bool(dict(), False))
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_build_int(dict(), MetaDataException)
        self.assertEqual(*self._post_metadata_parse_build_list(dict(), dict()))
        self.assertEqual(*self._post_metadata_parse_build_script(dict(), dict()))
        self.assertEqual(*self._post_metadata_parse_build_string(dict(), dict()))

    def test_post_metadata_parse_list_int_string(self):
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_app_int([1, 'a'], MetaDataException)
        self.assertEqual(*self._post_metadata_parse_app_list([1, 'a'], ['1', 'a']))
        self.assertEqual(*self._post_metadata_parse_app_string([1, 'a'], "[1, 'a']"))
        self.assertEqual(*self._post_metadata_parse_build_bool([1, 'a'], True))
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_build_int([1, 'a'], MetaDataException)
        self.assertEqual(*self._post_metadata_parse_build_list([1, 'a'], ['1', 'a']))
        self.assertEqual(*self._post_metadata_parse_build_script([1, 'a'], ['1', 'a']))
        self.assertEqual(*self._post_metadata_parse_build_string([1, 'a'], "[1, 'a']"))

    def test_post_metadata_parse_dict_int_string(self):
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_app_int({'k': 1}, MetaDataException)
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_app_list({'k': 1}, MetaDataException)
        self.assertEqual(*self._post_metadata_parse_app_string({'k': 1}, "{'k': 1}"))
        self.assertEqual(*self._post_metadata_parse_build_bool({'k': 1}, True))
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_build_int({'k': 1}, MetaDataException)
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_build_list({'k': 1}, MetaDataException)
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_build_script({'k': 1}, MetaDataException)
        self.assertEqual(*self._post_metadata_parse_build_string({'k': 1}, "{'k': 1}"))

    def test_post_metadata_parse_false(self):
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_app_int(False, MetaDataException)
        self.assertEqual(*self._post_metadata_parse_app_list(False, ['false']))
        self.assertEqual(*self._post_metadata_parse_app_string(False, 'false'))
        self.assertEqual(*self._post_metadata_parse_build_bool(False, False))
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_build_int(False, MetaDataException)
        self.assertEqual(*self._post_metadata_parse_build_list(False, ['false']))
        self.assertEqual(*self._post_metadata_parse_build_script(False, ['false']))
        self.assertEqual(*self._post_metadata_parse_build_string(False, 'false'))

    def test_post_metadata_parse_true(self):
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_app_int(True, MetaDataException)
        self.assertEqual(*self._post_metadata_parse_app_list(True, ['true']))
        self.assertEqual(*self._post_metadata_parse_app_string(True, 'true'))
        self.assertEqual(*self._post_metadata_parse_build_bool(True, True))
        with self.assertRaises(MetaDataException):
            self._post_metadata_parse_build_int(True, MetaDataException)
        self.assertEqual(*self._post_metadata_parse_build_list(True, ['true']))
        self.assertEqual(*self._post_metadata_parse_build_script(True, ['true']))
        self.assertEqual(*self._post_metadata_parse_build_string(True, 'true'))
