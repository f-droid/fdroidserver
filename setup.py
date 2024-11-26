#!/usr/bin/env python3

import re
import subprocess
import sys

from setuptools import Command, setup
from setuptools.command.install import install


class VersionCheckCommand(Command):
    """Make sure git tag and version match before uploading."""

    user_options = []

    def initialize_options(self):
        """Abstract method that is required to be overwritten."""

    def finalize_options(self):
        """Abstract method that is required to be overwritten."""

    def run(self):
        version = self.distribution.get_version()
        version_git = (
            subprocess.check_output(['git', 'describe', '--tags', '--always'])
            .rstrip()
            .decode('utf-8')
        )
        if version != version_git:
            print(
                'ERROR: Release version mismatch! setup.py (%s) does not match git (%s)'
                % (version, version_git)
            )
            sys.exit(1)
        print('Upload using: twine upload --sign dist/fdroidserver-%s.tar.gz' % version)


class InstallWithCompile(install):
    def run(self):
        from babel.messages.frontend import compile_catalog

        compiler = compile_catalog(self.distribution)
        option_dict = self.distribution.get_option_dict('compile_catalog')
        compiler.domain = [option_dict['domain'][1]]
        compiler.directory = option_dict['directory'][1]
        compiler.run()
        super().run()


def get_data_files():
    data_files = []
    with open('MANIFEST.in') as fp:
        data = fp.read()

    data_files.append(
        ('share/doc/fdroidserver/examples', re.findall(r'include (examples/.*)', data))
    )
    data_files.append(
        ('share/doc/fdroidserver/examples', ['buildserver/config.buildserver.yml'])
    )

    for d in re.findall(r'include (locale/.*)/fdroidserver\.po', data):
        data_files.append(('share/' + d, [d + '/fdroidserver.mo']))

    return data_files


with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='fdroidserver',
    version='2.3.2',
    description='F-Droid Server Tools',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='The F-Droid Project',
    author_email='team@f-droid.org',
    url='https://f-droid.org',
    license='AGPL-3.0',
    packages=['fdroidserver', 'fdroidserver.asynchronousfilereader'],
    entry_points={'console_scripts': ['fdroid=fdroidserver.__main__:main']},
    data_files=get_data_files(),
    python_requires='>=3.9',
    cmdclass={
        'versioncheck': VersionCheckCommand,
        'install': InstallWithCompile,
    },
    setup_requires=[
        'babel',
    ],
    install_requires=[
        'platformdirs',
        'androguard >= 3.3.5',
        'asn1crypto',
        # TODO use biplist on all platforms once IPA support is stable
        'biplist ; sys_platform=="darwin"',
        'clint',
        'defusedxml',
        'GitPython',
        'oscrypto',
        'paramiko',
        'Pillow',
        'apache-libcloud >= 0.14.1',
        'puremagic',
        'pycountry ; sys_platform=="darwin"',
        'python-vagrant',
        'PyYAML',
        'qrcode',
        'ruamel.yaml >= 0.15, < 0.17.22',
        'requests >= 2.5.2, != 2.11.0, != 2.12.2, != 2.18.0',
        'sdkmanager >= 0.6.4',
        'yamllint',
        'tomli >= 1.1.0; python_version < "3.11"',
    ],
    # Some requires are only needed for very limited cases:
    # * biplist is only used for parsing Apple .ipa files
    # * pycountry is only for linting config/mirrors.yml
    extras_require={
        'optional': ['biplist', 'pycountry'],
        'test': ['pyjks', 'html5print'],
        'docs': [
            'sphinx',
            'numpydoc',
            'pydata_sphinx_theme',
            'pydocstyle',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Operating System :: POSIX',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Unix',
        'Topic :: Utilities',
    ],
)
