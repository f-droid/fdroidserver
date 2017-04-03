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
      version='0.7.0',
      description='F-Droid Server Tools',
      long_description=open('README.md').read(),
      author='The F-Droid Project',
      author_email='team@f-droid.org',
      url='https://f-droid.org',
      packages=['fdroidserver', 'fdroidserver.asynchronousfilereader'],
      scripts=['fdroid', 'fd-commit'],
      data_files=[
          (data_prefix + '/share/doc/fdroidserver/examples',
              ['buildserver/config.buildserver.py',
                  'examples/config.py',
                  'examples/makebuildserver.config.py',
                  'examples/opensc-fdroid.cfg',
                  'examples/fdroid-icon.png']),
      ],
      install_requires=[
          'clint',
          'GitPython',
          'mwclient',
          'paramiko',
          'Pillow',
          'apache-libcloud >= 0.14.1',
          'pyasn1',
          'pyasn1-modules',
          'PyYAML',
          'requests < 2.11',
          'docker-py == 1.9.0',
      ],
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
          'Operating System :: POSIX',
          'Topic :: Utilities',
      ],
      )
