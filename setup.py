#!/usr/bin/env python2

from setuptools import setup
import sys

setup(name='fdroidserver',
      version='0.3.0',
      description='F-Droid Server Tools',
      long_description=open('README').read(),
      author='The F-Droid Project',
      author_email='team@f-droid.org',
      url='https://f-droid.org',
      packages=['fdroidserver'],
      scripts=['fdroid', 'fd-commit'],
      data_files=[
          (sys.prefix + '/share/doc/fdroidserver/examples',
              ['buildserver/config.buildserver.py',
                  'examples/config.py',
                  'examples/makebs.config.py',
                  'examples/opensc-fdroid.cfg',
                  'examples/fdroid-icon.png']),
      ],
      install_requires=[
          'mwclient',
          'paramiko',
          'Pillow',
          'python-magic',
          'apache-libcloud >= 0.14.1',
          'pyasn1',
          'pyasn1-modules',
      ],
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
          'Operating System :: POSIX',
          'Topic :: Utilities',
      ],
      )
