#!/usr/bin/env python3

import logging
import os
import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

import fdroidserver.common
import fdroidserver.lint
import fdroidserver.metadata
from fdroidserver._yaml import config_dump

from .shared_test_code import mkdtemp

basedir = Path(__file__).parent


class SetUpTearDownMixin:
    """A base class with no test in it for shared setUp and tearDown."""

    def setUp(self):
        os.chdir(basedir)
        fdroidserver.common.config = None
        fdroidserver.lint.CATEGORIES_KEYS = None
        self._td = mkdtemp()
        self.testdir = self._td.name

    def tearDown(self):
        self._td.cleanup()


class LintTest(SetUpTearDownMixin, unittest.TestCase):
    '''fdroidserver/lint.py'''

    def test_check_for_unsupported_metadata_files(self):
        self.assertTrue(fdroidserver.lint.check_for_unsupported_metadata_files())

        with tempfile.TemporaryDirectory() as testdir:
            testdir = Path(testdir)
            self.assertFalse(
                fdroidserver.lint.check_for_unsupported_metadata_files(testdir)
            )
            shutil.copytree(
                basedir / 'metadata',
                testdir / 'metadata',
                ignore=shutil.ignore_patterns('apk', 'dump', '*.json'),
            )
            self.assertFalse(
                fdroidserver.lint.check_for_unsupported_metadata_files(testdir)
            )
            (testdir / 'metadata/org.adaway.json').write_text('placeholder')
            self.assertTrue(
                fdroidserver.lint.check_for_unsupported_metadata_files(testdir)
            )

    def test_forbidden_html_tags(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config

        app = {
            'Name': 'Bad App',
            'Summary': 'We pwn you',
            'Description': 'This way: <style><img src="</style><img src=x onerror=alert(1)//">',
        }

        anywarns = False
        for warn in fdroidserver.lint.check_regexes(app):
            anywarns = True
            logging.debug(warn)
        self.assertTrue(anywarns)

    def test_source_urls(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config

        app = {
            'Name': 'My App',
            'Summary': 'just a placeholder',
            'Description': 'This app does all sorts of useful stuff',
        }
        good_urls = [
            'https://github.com/Matteljay/mastermindy-android',
            'https://gitlab.com/origin/master',
            'https://gitlab.com/group/subgroup/masterthing',
            'https://raw.githubusercontent.com/Seva-coder/Finder/HEAD/ChangeLog.txt',
            'https://github.com/scoutant/blokish/blob/HEAD/README.md#changelog',
            'https://git.ieval.ro/?p=fonbot.git;a=blob;f=Changes;hb=HEAD',
            'https://htmlpreview.github.io/?https://github.com/YasuakiHonda/Maxima-on-Android-AS/blob/HEAD/app/src/main/assets/About_MoA/index.html',
            '',
        ]

        anywarns = False
        for url in good_urls:
            app['SourceCode'] = url
            for warn in fdroidserver.lint.check_regexes(app):
                anywarns = True
                logging.debug(warn)
        self.assertFalse(anywarns)

        bad_urls = [
            'github.com/my/proj',
            'http://github.com/not/secure',
            'https://github.com/foo/bar.git',
            'https://gitlab.com/group/subgroup/project.git',
            'http://htmlpreview.github.io/?https://github.com/my/project/blob/HEAD/index.html',
            'http://fdroid.gitlab.io/fdroid-website',
        ]
        logging.debug('bad urls:')
        for url in bad_urls:
            anywarns = False
            app['SourceCode'] = url
            for warn in fdroidserver.lint.check_regexes(app):
                anywarns = True
                logging.debug(warn)
            self.assertTrue(anywarns, url + " does not fail lint!")

    def test_check_repo_git_good(self):
        app = {'RepoType': 'git'}
        good_git_urls = [
            'https://github.com/Matteljay/mastermindy-android',
            'https://gitlab.com/origin/master.git',
            'https://gitlab.com/group/subgroup/masterthing',
            'https://git.ieval.ro/?p=fonbot.git;a=blob;f=Changes;hb=HEAD',
        ]

        anywarns = False
        for url in good_git_urls:
            app['Repo'] = url
            for warn in fdroidserver.lint.check_repo(app):
                anywarns = True
                logging.debug(warn)
        self.assertFalse(anywarns)

    def test_check_repo_git_bad(self):
        app = {'RepoType': 'git'}
        bad_urls = ['github.com/my/proj', 'http://github.com/not/secure']
        for url in bad_urls:
            anywarns = False
            app['Repo'] = url
            for warn in fdroidserver.lint.check_repo(app):
                anywarns = True
            self.assertTrue(anywarns, url + " does not fail lint!")

    def test_check_repo_srclib_good(self):
        os.chdir(self.testdir)
        testname = 'wireguard-tools'
        testfile = Path(f'srclibs/{testname}.yml')
        testfile.parent.mkdir()
        testfile.write_text('test')
        app = {'RepoType': 'srclib', 'Repo': testname}
        anywarns = False
        for warn in fdroidserver.lint.check_repo(app):
            anywarns = True
            logging.debug(warn)
        self.assertFalse(anywarns)

    def test_check_repo_srclib_file_missing(self):
        os.chdir(self.testdir)
        app = {'RepoType': 'srclib', 'Repo': 'nosrclibsymlfile'}
        for warn in fdroidserver.lint.check_repo(app):
            anywarns = True
        self.assertTrue(anywarns)

    def test_check_repo_srclib_bad(self):
        bad_urls = ['github.com/my/proj', 'https://github.com/not/secure']
        for url in bad_urls:
            anywarns = False
            app = {'RepoType': 'srclib', 'Repo': url}
            for warn in fdroidserver.lint.check_repo(app):
                anywarns = True
                logging.debug(warn)
            self.assertTrue(anywarns, f"{url} does not fail lint!")

    def test_check_regexes_binaries(self):
        app = fdroidserver.metadata.App()
        app.Binaries = 'https://example.com/%v.apk'
        for warn in fdroidserver.lint.check_regexes(app):
            self.fail()

    def test_check_regexes_binaries_http(self):
        app = fdroidserver.metadata.App()
        app.Binaries = 'http://example.com/%v.apk'
        for warn in fdroidserver.lint.check_regexes(app):
            self.assertIn('https://', warn)
            anywarns = True
        self.assertTrue(anywarns)

    def test_check_regexes_binaries_shortener(self):
        app = fdroidserver.metadata.App()
        app.Binaries = 'https://bit.ly/%v.apk'
        for warn in fdroidserver.lint.check_regexes(app):
            self.assertIn('bit.ly', warn)
            anywarns = True
        self.assertTrue(anywarns)

    def test_check_regexes_binaries_both(self):
        app = fdroidserver.metadata.App()
        app.Binaries = 'http://bit.ly/%v.apk'
        warns = list(fdroidserver.lint.check_regexes(app))
        for warn in warns:
            self.assertIn('bit.ly', warn)
        self.assertEqual(2, len(warns))

    def test_check_regexes_binary(self):
        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.binary = 'https://example.com/%v.apk'
        app['Builds'] = [build]
        for warn in fdroidserver.lint.check_builds(app):
            self.fail()

    def test_check_regexes_binary_http(self):
        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.binary = 'http://example.com/%v.apk'
        build.versionCode = 123
        app['Builds'] = [build]
        for warn in fdroidserver.lint.check_builds(app):
            self.assertIn('https://', warn)
            anywarns = True
        self.assertTrue(anywarns)

    def test_check_regexes_binary_shortener(self):
        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.binary = 'https://bit.ly/%v.apk'
        build.versionCode = 123
        app['Builds'] = [build]
        for warn in fdroidserver.lint.check_builds(app):
            self.assertIn('bit.ly', warn)
            anywarns = True
        self.assertTrue(anywarns)

    def test_check_regexes_binary_both(self):
        app = fdroidserver.metadata.App()
        build = fdroidserver.metadata.Build()
        build.binary = 'http://bit.ly/%v.apk'
        build.versionCode = 123
        app['Builds'] = [build]
        warns = list(fdroidserver.lint.check_builds(app))
        for warn in warns:
            self.assertIn('bit.ly', warn)
        self.assertEqual(2, len(warns))

    def test_check_app_field_types(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config

        app = fdroidserver.metadata.App()
        app.id = 'fake.app'
        app.Name = 'Bad App'
        app.Summary = 'We pwn you'
        app.Description = 'These are some back'

        fields = {
            'Categories': {
                'good': [
                    ['Sports & Health'],
                    ['Multimedia', 'Graphics'],
                ],
                'bad': [
                    'Science & Education',
                    'Multimedia,Graphics',
                ],
            },
            'WebSite': {
                'good': [
                    'https://homepage.com',
                ],
                'bad': [
                    [],
                    [
                        'nope',
                    ],
                    29,
                ],
            },
        }

        for field, values in fields.items():
            for bad in values['bad']:
                anywarns = False
                app[field] = bad
                for warn in fdroidserver.lint.check_app_field_types(app):
                    anywarns = True
                    logging.debug(warn)
                self.assertTrue(anywarns)

            for good in values['good']:
                anywarns = False
                app[field] = good
                for warn in fdroidserver.lint.check_app_field_types(app):
                    anywarns = True
                    logging.debug(warn)
                self.assertFalse(anywarns)

    def test_check_vercode_operation(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config

        app = fdroidserver.metadata.App()
        app.Name = 'Bad App'
        app.Summary = 'We pwn you'
        app.Description = 'These are some back'

        good_fields = [
            '6%c',
            '%c - 1',
            '%c + 10',
            '%c*10',
            '%c*10 + 3',
            '%c*10 + 8',
            '%c + 2 ',
            '%c + 3',
            '%c + 7',
        ]
        bad_fields = [
            'open("/etc/passwd")',
            '%C + 1',
            '%%c * 123',
            '123 + %%',
            '%c % 7',
        ]

        anywarns = False
        for good in good_fields:
            app.VercodeOperation = [good]
            for warn in fdroidserver.lint.check_vercode_operation(app):
                anywarns = True
                logging.debug(warn)
            self.assertFalse(anywarns)

        for bad in bad_fields:
            anywarns = False
            app.VercodeOperation = [bad]
            for warn in fdroidserver.lint.check_vercode_operation(app):
                anywarns = True
                logging.debug(warn)
            self.assertTrue(anywarns)

    def test_check_license_tag_no_custom_pass(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config

        app = fdroidserver.metadata.App()
        app.License = "GPL-3.0-or-later"

        anywarns = False
        for warn in fdroidserver.lint.check_license_tag(app):
            anywarns = True
            logging.debug(warn)
        self.assertFalse(anywarns)

    def test_check_license_tag_no_custom_fail(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config

        app = fdroidserver.metadata.App()
        app.License = "Adobe-2006"

        anywarns = False
        for warn in fdroidserver.lint.check_license_tag(app):
            anywarns = True
            logging.debug(warn)
        self.assertTrue(anywarns)

    def test_check_license_tag_with_custom_pass(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        config['lint_licenses'] = ['fancy-license', 'GPL-3.0-or-later']

        app = fdroidserver.metadata.App()
        app.License = "fancy-license"

        anywarns = False
        for warn in fdroidserver.lint.check_license_tag(app):
            anywarns = True
            logging.debug(warn)
        self.assertFalse(anywarns)

    def test_check_license_tag_with_custom_fail(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        config['lint_licenses'] = ['fancy-license', 'GPL-3.0-or-later']

        app = fdroidserver.metadata.App()
        app.License = "Apache-2.0"

        anywarns = False
        for warn in fdroidserver.lint.check_license_tag(app):
            anywarns = True
            logging.debug(warn)
        self.assertTrue(anywarns)

    def test_check_license_tag_with_custom_empty(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        config['lint_licenses'] = []

        app = fdroidserver.metadata.App()
        app.License = "Apache-2.0"

        anywarns = False
        for warn in fdroidserver.lint.check_license_tag(app):
            anywarns = True
            logging.debug(warn)
        self.assertTrue(anywarns)

    def test_check_license_tag_disabled(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        config['lint_licenses'] = None

        app = fdroidserver.metadata.App()
        app.License = "Apache-2.0"

        anywarns = False
        for warn in fdroidserver.lint.check_license_tag(app):
            anywarns = True
            logging.debug(warn)
        self.assertFalse(anywarns)

    def test_check_categories_in_config(self):
        fdroidserver.common.config = {
            fdroidserver.common.CATEGORIES_CONFIG_NAME: ['InConfig']
        }
        fdroidserver.lint.load_categories_config()
        app = fdroidserver.metadata.App({'Categories': ['InConfig']})
        self.assertEqual(0, len(list(fdroidserver.lint.check_categories(app))))

    def test_check_categories_not_in_config(self):
        fdroidserver.common.config = dict()
        fdroidserver.lint.load_categories_config()
        app = fdroidserver.metadata.App({'Categories': ['NotInConfig']})
        self.assertEqual(1, len(list(fdroidserver.lint.check_categories(app))))

    def test_check_categories_empty_is_error(self):
        fdroidserver.common.config = {fdroidserver.common.CATEGORIES_CONFIG_NAME: []}
        fdroidserver.lint.load_categories_config()
        app = fdroidserver.metadata.App({'Categories': ['something']})
        self.assertEqual(1, len(list(fdroidserver.lint.check_categories(app))))

    def test_check_categories_old_hardcoded_not_defined(self):
        fdroidserver.common.config = {
            fdroidserver.common.CATEGORIES_CONFIG_NAME: ['foo', 'bar']
        }
        fdroidserver.lint.load_categories_config()
        app = fdroidserver.metadata.App({'Categories': ['Writing']})
        self.assertEqual(1, len(list(fdroidserver.lint.check_categories(app))))

    def test_check_categories_from_config_yml(self):
        """In config.yml, categories is a list."""
        os.chdir(self.testdir)
        fdroidserver.common.write_config_file('categories: [foo, bar]\n')
        fdroidserver.common.read_config()
        fdroidserver.lint.load_categories_config()
        self.assertEqual(fdroidserver.lint.CATEGORIES_KEYS, ['foo', 'bar'])
        app = fdroidserver.metadata.App({'Categories': ['bar']})
        self.assertEqual(0, len(list(fdroidserver.lint.check_categories(app))))

    def test_check_categories_from_config_categories_yml(self):
        """In config/categories.yml, categories is a localized STRINGMAP dict."""
        os.chdir(self.testdir)
        os.mkdir('config')
        Path('config/categories.yml').write_text('{foo: {name: foo}, bar: {name: bar}}')
        fdroidserver.common.read_config()
        fdroidserver.lint.load_categories_config()
        self.assertEqual(fdroidserver.lint.CATEGORIES_KEYS, ['foo', 'bar'])
        app = fdroidserver.metadata.App({'Categories': ['bar']})
        self.assertEqual(0, len(list(fdroidserver.lint.check_categories(app))))

    def test_lint_config_basic_mirrors_yml(self):
        os.chdir(self.testdir)
        with Path('mirrors.yml').open('w') as fp:
            config_dump([{'url': 'https://example.com/fdroid/repo'}], fp)
        self.assertTrue(fdroidserver.lint.lint_config('mirrors.yml'))

    def test_lint_config_mirrors_yml_kenya_countryCode(self):
        os.chdir(self.testdir)
        with Path('mirrors.yml').open('w') as fp:
            config_dump(
                [{'url': 'https://foo.com/fdroid/repo', 'countryCode': 'KE'}], fp
            )
        self.assertTrue(fdroidserver.lint.lint_config('mirrors.yml'))

    def test_lint_config_mirrors_yml_invalid_countryCode(self):
        """WV is "indeterminately reserved" so it should never be used."""
        os.chdir(self.testdir)
        with Path('mirrors.yml').open('w') as fp:
            config_dump(
                [{'url': 'https://foo.com/fdroid/repo', 'countryCode': 'WV'}], fp
            )
        self.assertFalse(fdroidserver.lint.lint_config('mirrors.yml'))

    def test_lint_config_mirrors_yml_alpha3_countryCode(self):
        """Only ISO 3166-1 alpha 2 are supported"""
        os.chdir(self.testdir)
        with Path('mirrors.yml').open('w') as fp:
            config_dump(
                [{'url': 'https://de.com/fdroid/repo', 'countryCode': 'DEU'}], fp
            )
        self.assertFalse(fdroidserver.lint.lint_config('mirrors.yml'))

    def test_lint_config_mirrors_yml_one_invalid_countryCode(self):
        """WV is "indeterminately reserved" so it should never be used."""
        os.chdir(self.testdir)
        with Path('mirrors.yml').open('w') as fp:
            config_dump(
                [
                    {'url': 'https://bar.com/fdroid/repo', 'countryCode': 'BA'},
                    {'url': 'https://foo.com/fdroid/repo', 'countryCode': 'FO'},
                    {'url': 'https://wv.com/fdroid/repo', 'countryCode': 'WV'},
                ],
                fp,
            )
        self.assertFalse(fdroidserver.lint.lint_config('mirrors.yml'))

    def test_lint_config_bad_mirrors_yml_dict(self):
        os.chdir(self.testdir)
        Path('mirrors.yml').write_text('baz: [foo, bar]\n')
        with self.assertRaises(TypeError):
            fdroidserver.lint.lint_config('mirrors.yml')

    def test_lint_config_bad_mirrors_yml_float(self):
        os.chdir(self.testdir)
        Path('mirrors.yml').write_text('1.0\n')
        with self.assertRaises(TypeError):
            fdroidserver.lint.lint_config('mirrors.yml')

    def test_lint_config_bad_mirrors_yml_int(self):
        os.chdir(self.testdir)
        Path('mirrors.yml').write_text('1\n')
        with self.assertRaises(TypeError):
            fdroidserver.lint.lint_config('mirrors.yml')

    def test_lint_config_bad_mirrors_yml_str(self):
        os.chdir(self.testdir)
        Path('mirrors.yml').write_text('foo\n')
        with self.assertRaises(TypeError):
            fdroidserver.lint.lint_config('mirrors.yml')

    def test_lint_invalid_config_keys(self):
        os.chdir(self.testdir)
        os.mkdir('config')
        config_yml = fdroidserver.common.CONFIG_FILE
        with open(f'config/{config_yml}', 'w', encoding='utf-8') as fp:
            fp.write('repo:\n  invalid_key: test\n')
        self.assertFalse(fdroidserver.lint.lint_config(f'config/{config_yml}'))

    def test_lint_invalid_localized_config_keys(self):
        os.chdir(self.testdir)
        Path('config/en').mkdir(parents=True)
        Path('config/en/antiFeatures.yml').write_text('NonFreeNet:\n  icon: test.png\n')
        self.assertFalse(fdroidserver.lint.lint_config('config/en/antiFeatures.yml'))

    def test_check_certificate_pinned_binaries_empty(self):
        fdroidserver.common.config = {}
        app = fdroidserver.metadata.App()
        app.AllowedAPKSigningKeys = [
            'a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc'
        ]
        self.assertEqual(
            [],
            list(fdroidserver.lint.check_certificate_pinned_binaries(app)),
            "when the config is empty, any signing key should be allowed",
        )

    def test_lint_known_debug_keys_no_match(self):
        fdroidserver.common.config = {
            "apk_signing_key_block_list": "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc"
        }
        app = fdroidserver.metadata.App()
        app.AllowedAPKSigningKeys = [
            '2fd4fd5f54babba4bcb21237809bb653361d0d2583c80964ec89b28a26e9539e'
        ]
        self.assertEqual(
            [],
            list(fdroidserver.lint.check_certificate_pinned_binaries(app)),
            "A signing key that does not match one in the config should be allowed",
        )

    def test_lint_known_debug_keys(self):
        fdroidserver.common.config = {
            'apk_signing_key_block_list': 'a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc'
        }
        app = fdroidserver.metadata.App()
        app.AllowedAPKSigningKeys = [
            'a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc'
        ]
        for warn in fdroidserver.lint.check_certificate_pinned_binaries(app):
            anywarns = True
            logging.debug(warn)
        self.assertTrue(anywarns)


class LintAntiFeaturesTest(unittest.TestCase):
    def setUp(self):
        os.chdir(basedir)
        fdroidserver.common.config = dict()
        fdroidserver.lint.ANTIFEATURES_KEYS = None
        fdroidserver.lint.load_antiFeatures_config()

    def test_check_antiFeatures_empty(self):
        app = fdroidserver.metadata.App()
        self.assertEqual([], list(fdroidserver.lint.check_antiFeatures(app)))

    def test_check_antiFeatures_empty_AntiFeatures(self):
        app = fdroidserver.metadata.App()
        app['AntiFeatures'] = []
        self.assertEqual([], list(fdroidserver.lint.check_antiFeatures(app)))

    def test_check_antiFeatures(self):
        app = fdroidserver.metadata.App()
        app['AntiFeatures'] = ['Ads', 'Tracking']
        self.assertEqual([], list(fdroidserver.lint.check_antiFeatures(app)))

    def test_check_antiFeatures_fails_one(self):
        app = fdroidserver.metadata.App()
        app['AntiFeatures'] = ['Ad']
        self.assertEqual(1, len(list(fdroidserver.lint.check_antiFeatures(app))))

    def test_check_antiFeatures_fails_many(self):
        app = fdroidserver.metadata.App()
        app['AntiFeatures'] = ['Adss', 'Tracker', 'NoSourceSince', 'FAKE', 'NonFree']
        self.assertEqual(4, len(list(fdroidserver.lint.check_antiFeatures(app))))

    def test_check_antiFeatures_build_empty(self):
        app = fdroidserver.metadata.App()
        app['Builds'] = [{'antifeatures': []}]
        self.assertEqual([], list(fdroidserver.lint.check_antiFeatures(app)))

    def test_check_antiFeatures_build(self):
        app = fdroidserver.metadata.App()
        app['Builds'] = [{'antifeatures': ['Tracking']}]
        self.assertEqual(0, len(list(fdroidserver.lint.check_antiFeatures(app))))

    def test_check_antiFeatures_build_fail(self):
        app = fdroidserver.metadata.App()
        app['Builds'] = [{'antifeatures': ['Ads', 'Tracker']}]
        self.assertEqual(1, len(list(fdroidserver.lint.check_antiFeatures(app))))


class ConfigYmlTest(SetUpTearDownMixin, unittest.TestCase):
    """Test data formats used in config.yml.

    lint.py uses print() and not logging so hacks are used to control
    the output when running in the test runner.

    """

    def setUp(self):
        super().setUp()
        self.config_yml = Path(self.testdir) / fdroidserver.common.CONFIG_FILE

    def test_config_yml_int(self):
        self.config_yml.write_text('repo_maxage: 1\n')
        self.assertTrue(fdroidserver.lint.lint_config(self.config_yml))

    @mock.patch('builtins.print', mock.Mock())  # hide error message
    def test_config_yml_int_bad(self):
        self.config_yml.write_text('repo_maxage: "1"\n')
        self.assertFalse(fdroidserver.lint.lint_config(self.config_yml))

    def test_config_yml_str(self):
        self.config_yml.write_text('sdk_path: /opt/android-sdk\n')
        self.assertTrue(fdroidserver.lint.lint_config(self.config_yml))

    def test_config_yml_str_list(self):
        self.config_yml.write_text('serverwebroot: [server1, server2]\n')
        self.assertTrue(fdroidserver.lint.lint_config(self.config_yml))

    def test_config_yml_str_list_of_dicts(self):
        self.config_yml.write_text(
            textwrap.dedent(
                """\
                serverwebroot:
                  - url: 'me@b.az:/srv/fdroid'
                    index_only: true
                """
            )
        )
        self.assertTrue(fdroidserver.lint.lint_config(self.config_yml))

    def test_config_yml_str_list_of_dicts_env(self):
        """serverwebroot can be str, list of str, or list of dicts."""
        self.config_yml.write_text('serverwebroot: {env: ANDROID_HOME}\n')
        self.assertTrue(fdroidserver.lint.lint_config(self.config_yml))

    def test_config_yml_str_env(self):
        self.config_yml.write_text('sdk_path: {env: ANDROID_HOME}\n')
        self.assertTrue(fdroidserver.lint.lint_config(self.config_yml))

    @mock.patch('builtins.print', mock.Mock())  # hide error message
    def test_config_yml_str_bad(self):
        self.config_yml.write_text('sdk_path: 1.0\n')
        self.assertFalse(fdroidserver.lint.lint_config(self.config_yml))

    def test_config_yml_bool(self):
        self.config_yml.write_text("deploy_process_logs: true\n")
        self.assertTrue(fdroidserver.lint.lint_config(self.config_yml))

    @mock.patch('builtins.print', mock.Mock())  # hide error message
    def test_config_yml_bool_bad(self):
        self.config_yml.write_text('deploy_process_logs: 2342fe23\n')
        self.assertFalse(fdroidserver.lint.lint_config(self.config_yml))

    def test_config_yml_dict(self):
        self.config_yml.write_text("keyaliases: {com.example: '@com.foo'}\n")
        self.assertTrue(fdroidserver.lint.lint_config(self.config_yml))

    @mock.patch('builtins.print', mock.Mock())  # hide error message
    def test_config_yml_dict_bad(self):
        self.config_yml.write_text('keyaliases: 2342fe23\n')
        self.assertFalse(fdroidserver.lint.lint_config(self.config_yml))

    @mock.patch('builtins.print', mock.Mock())  # hide error message
    def test_config_yml_bad_key_name(self):
        self.config_yml.write_text('keyalias: 2342fe23\n')
        self.assertFalse(fdroidserver.lint.lint_config(self.config_yml))

    @mock.patch('builtins.print', mock.Mock())  # hide error message
    def test_config_yml_bad_value_for_all_keys(self):
        """Check all config keys with a bad value."""
        for key in fdroidserver.lint.check_config_keys:
            if key in fdroidserver.lint.bool_keys:
                value = 'foobar'
            else:
                value = 'false'
            self.config_yml.write_text(f'{key}: {value}\n')
            self.assertFalse(
                fdroidserver.lint.lint_config(self.config_yml),
                f'{key} should fail on value of "{value}"',
            )

    def test_config_yml_keyaliases(self):
        self.config_yml.write_text(
            textwrap.dedent(
                """\
                keyaliases:
                  com.example: myalias
                  com.foo: '@com.example'
                """
            )
        )
        self.assertTrue(fdroidserver.lint.lint_config(self.config_yml))

    @mock.patch('builtins.print', mock.Mock())  # hide error message
    def test_config_yml_keyaliases_bad_str(self):
        """The keyaliases: value is a dict not a str."""
        self.config_yml.write_text("keyaliases: '@com.example'\n")
        self.assertFalse(fdroidserver.lint.lint_config(self.config_yml))

    @mock.patch('builtins.print', mock.Mock())  # hide error message
    def test_config_yml_keyaliases_bad_list(self):
        """The keyaliases: value is a dict not a list."""
        self.config_yml.write_text(
            textwrap.dedent(
                """\
                keyaliases:
                  - com.example: myalias
                """
            )
        )
        self.assertFalse(fdroidserver.lint.lint_config(self.config_yml))


class HttpUrlShorteners(unittest.TestCase):
    def _exec_checks(self, text):
        for check, msg in fdroidserver.lint.http_url_shorteners:
            if check.match(text):
                yield f'{text} {check} {msg}'

    def test_avoid_domain_confusion(self):
        good_urls = [
            'https://github.com/Matteljay/mastermindy-android',
            'https://gitlab.com/origin/master.git',
            'https://gitlab.com/group/subgroup/masterthing',
            'https://git.ieval.ro/?p=fonbot.git;a=blob;f=Changes;hb=HEAD',
            'https://silkevicious.codeberg.page/fediphoto-lineage.html',
            'https://mental-math.codeberg.page/',
            'http://imshyam.me/mintube/',
            'http://trikita.co/',
        ]

        for url in good_urls:
            anywarns = False
            for warn in self._exec_checks(url):
                anywarns = True
            self.assertFalse(anywarns, f"{url} should be valid.")

    def test_warn_on_shorteners(self):
        bad_urls = [
            'https://sub.tr.im/test',
            'https://tr.im/misproyectos',
        ]

        for url in bad_urls:
            anywarns = False
            for warn in self._exec_checks(url):
                anywarns = True
            self.assertTrue(anywarns, f"Should warn on {url}")
