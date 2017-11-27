#!/usr/bin/env python3

from setuptools import setup
import os
import re
import shutil
import sys


def get_data_files():
    # workaround issue on OSX or --user installs, where sys.prefix is not an installable location
    if os.access(sys.prefix, os.W_OK | os.X_OK):
        data_prefix = sys.prefix
    else:
        data_prefix = '.'

    data_files = []
    with open('MANIFEST.in') as fp:
        data = fp.read()

    data_files.append((data_prefix + '/share/doc/fdroidserver/examples',
                       ['buildserver/config.buildserver.py', ]
                       + re.findall(r'include (examples/.*)', data)))

    for f in re.findall(r'include (locale/[a-z][a-z][a-zA-Z_]*/LC_MESSAGES/fdroidserver.mo)', data):
        d = os.path.join(data_prefix, 'share', os.path.dirname(f))
        data_files.append((d, [f, ]))
    return data_files


# PyPI accepts reST not Markdown
if os.path.exists('README.md'):
    if shutil.which('pandoc'):
        print('Using reST README')
        import subprocess
        subprocess.check_call(['pandoc', '--from=markdown', '--to=rst', 'README.md',
                               '--output=README.rst'], universal_newlines=True)
        with open('README.rst') as fp:
            readme = fp.read()
    else:
        print('Using Markdown README')
        with open('README.md') as fp:
            readme = fp.read()
else:
    readme = ''

setup(name='fdroidserver',
      version='0.9',
      description='F-Droid Server Tools',
      long_description=readme,
      author='The F-Droid Project',
      author_email='team@f-droid.org',
      url='https://f-droid.org',
      license='AGPL-3.0',
      packages=['fdroidserver', 'fdroidserver.asynchronousfilereader'],
      scripts=['fdroid', 'fd-commit', 'makebuildserver'],
      data_files=get_data_files(),
      python_requires='>=3.4',
      install_requires=[
          'clint',
          'GitPython',
          'mwclient',
          'paramiko',
          'Pillow',
          'apache-libcloud >= 0.14.1',
          'pyasn1',
          'pyasn1-modules',
          'python-vagrant',
          'PyYAML',
          'ruamel.yaml >= 0.13',
          'requests >= 2.5.2, != 2.11.0, != 2.12.2, != 2.18.0',
          'docker-py >= 1.9, < 2.0',
      ],
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
