#!/usr/bin/env python3

from setuptools import setup
import os
import sys

# workaround issue on OSX or --user installs, where sys.prefix is not an installable location
if os.access(sys.prefix, os.W_OK | os.X_OK):
    data_prefix = sys.prefix
else:
    data_prefix = '.'

setup(name='fdroidserver',
      version='0.8',
      description='F-Droid Server Tools',
      long_description=open('README.md').read(),
      author='The F-Droid Project',
      author_email='team@f-droid.org',
      url='https://f-droid.org',
      license='AGPL-3.0',
      packages=['fdroidserver', 'fdroidserver.asynchronousfilereader'],
      scripts=['fdroid', 'fd-commit', 'makebuildserver'],
      data_files=[
          (data_prefix + '/share/doc/fdroidserver/examples',
              ['buildserver/config.buildserver.py',
               'examples/config.py',
               'examples/fdroid-icon.png',
               'examples/makebuildserver.config.py',
               'examples/opensc-fdroid.cfg',
               'examples/public-read-only-s3-bucket-policy.json',
               'examples/template.yml']),
      ],
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
