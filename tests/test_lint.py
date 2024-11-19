#!/usr/bin/env python3

import logging
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import ruamel.yaml

from .testcommon import mkdtemp

import fdroidserver.common
import fdroidserver.lint
import fdroidserver.metadata

basedir = Path(__file__).parent


class LintTest(unittest.TestCase):
    '''fdroidserver/lint.py'''

    def setUp(self):
        os.chdir(basedir)
        fdroidserver.common.config = None
        fdroidserver.lint.config = None
        fdroidserver.lint.CATEGORIES_KEYS = None
        self._td = mkdtemp()
        self.testdir = self._td.name

    def tearDown(self):
        self._td.cleanup()

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
        fdroidserver.lint.config = config

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
        fdroidserver.lint.config = config

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
            'https://raw.githubusercontent.com/Seva-coder/Finder/master/ChangeLog.txt',
            'https://github.com/scoutant/blokish/blob/master/README.md#changelog',
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

    def test_check_app_field_types(self):
        config = dict()
        fdroidserver.common.fill_config_defaults(config)
        fdroidserver.common.config = config
        fdroidserver.lint.config = config

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
        fdroidserver.lint.config = config

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
        fdroidserver.lint.config = config

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
        fdroidserver.lint.config = config

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
        fdroidserver.lint.config = config
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
        fdroidserver.lint.config = config
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
        fdroidserver.lint.config = config
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
        fdroidserver.lint.config = config
        config['lint_licenses'] = None

        app = fdroidserver.metadata.App()
        app.License = "Apache-2.0"

        anywarns = False
        for warn in fdroidserver.lint.check_license_tag(app):
            anywarns = True
            logging.debug(warn)
        self.assertFalse(anywarns)

    def test_check_categories_in_config(self):
        fdroidserver.lint.config = {
            fdroidserver.common.CATEGORIES_CONFIG_NAME: ['InConfig']
        }
        fdroidserver.lint.load_categories_config()
        app = fdroidserver.metadata.App({'Categories': ['InConfig']})
        self.assertEqual(0, len(list(fdroidserver.lint.check_categories(app))))

    def test_check_categories_not_in_config(self):
        fdroidserver.lint.config = dict()
        fdroidserver.lint.load_categories_config()
        app = fdroidserver.metadata.App({'Categories': ['NotInConfig']})
        self.assertEqual(1, len(list(fdroidserver.lint.check_categories(app))))

    def test_check_categories_empty_is_error(self):
        fdroidserver.lint.config = {fdroidserver.common.CATEGORIES_CONFIG_NAME: []}
        fdroidserver.lint.load_categories_config()
        app = fdroidserver.metadata.App({'Categories': ['something']})
        self.assertEqual(1, len(list(fdroidserver.lint.check_categories(app))))

    def test_check_categories_old_hardcoded_not_defined(self):
        fdroidserver.lint.config = {
            fdroidserver.common.CATEGORIES_CONFIG_NAME: ['foo', 'bar']
        }
        fdroidserver.lint.load_categories_config()
        app = fdroidserver.metadata.App({'Categories': ['Writing']})
        self.assertEqual(1, len(list(fdroidserver.lint.check_categories(app))))

    def test_check_categories_from_config_yml(self):
        """In config.yml, categories is a list."""
        os.chdir(self.testdir)
        Path('config.yml').write_text('categories: [foo, bar]')
        fdroidserver.lint.config = fdroidserver.common.read_config()
        fdroidserver.lint.load_categories_config()
        self.assertEqual(fdroidserver.lint.CATEGORIES_KEYS, ['foo', 'bar'])
        app = fdroidserver.metadata.App({'Categories': ['bar']})
        self.assertEqual(0, len(list(fdroidserver.lint.check_categories(app))))

    def test_check_categories_from_config_categories_yml(self):
        """In config/categories.yml, categories is a localized STRINGMAP dict."""
        os.chdir(self.testdir)
        os.mkdir('config')
        Path('config/categories.yml').write_text('{foo: {name: foo}, bar: {name: bar}}')
        fdroidserver.lint.config = fdroidserver.common.read_config()
        fdroidserver.lint.load_categories_config()
        self.assertEqual(fdroidserver.lint.CATEGORIES_KEYS, ['foo', 'bar'])
        app = fdroidserver.metadata.App({'Categories': ['bar']})
        self.assertEqual(0, len(list(fdroidserver.lint.check_categories(app))))

    def test_lint_config_basic_mirrors_yml(self):
        os.chdir(self.testdir)
        yaml = ruamel.yaml.YAML(typ='safe')
        with Path('mirrors.yml').open('w') as fp:
            yaml.dump([{'url': 'https://example.com/fdroid/repo'}], fp)
        self.assertTrue(fdroidserver.lint.lint_config('mirrors.yml'))

    def test_lint_config_mirrors_yml_kenya_countryCode(self):
        os.chdir(self.testdir)
        yaml = ruamel.yaml.YAML(typ='safe')
        with Path('mirrors.yml').open('w') as fp:
            yaml.dump([{'url': 'https://foo.com/fdroid/repo', 'countryCode': 'KE'}], fp)
        self.assertTrue(fdroidserver.lint.lint_config('mirrors.yml'))

    def test_lint_config_mirrors_yml_invalid_countryCode(self):
        """WV is "indeterminately reserved" so it should never be used."""
        os.chdir(self.testdir)
        yaml = ruamel.yaml.YAML(typ='safe')
        with Path('mirrors.yml').open('w') as fp:
            yaml.dump([{'url': 'https://foo.com/fdroid/repo', 'countryCode': 'WV'}], fp)
        self.assertFalse(fdroidserver.lint.lint_config('mirrors.yml'))

    def test_lint_config_mirrors_yml_alpha3_countryCode(self):
        """Only ISO 3166-1 alpha 2 are supported"""
        os.chdir(self.testdir)
        yaml = ruamel.yaml.YAML(typ='safe')
        with Path('mirrors.yml').open('w') as fp:
            yaml.dump([{'url': 'https://de.com/fdroid/repo', 'countryCode': 'DEU'}], fp)
        self.assertFalse(fdroidserver.lint.lint_config('mirrors.yml'))

    def test_lint_config_mirrors_yml_one_invalid_countryCode(self):
        """WV is "indeterminately reserved" so it should never be used."""
        os.chdir(self.testdir)
        yaml = ruamel.yaml.YAML(typ='safe')
        with Path('mirrors.yml').open('w') as fp:
            yaml.dump(
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
        Path('config').mkdir()
        Path('config/config.yml').write_text('repo:\n  invalid_key: test')
        self.assertFalse(fdroidserver.lint.lint_config('config/config.yml'))

    def test_lint_invalid_localized_config_keys(self):
        os.chdir(self.testdir)
        Path('config/en').mkdir(parents=True)
        Path('config/en/antiFeatures.yml').write_text('NonFreeNet:\n  icon: test.png')
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
        app['AntiFeatures'] = ['Ads', 'UpstreamNonFree']
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
