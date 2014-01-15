#!/usr/bin/env python2

from setuptools import setup

setup(name='FDroidServer',
      version='0.1',
      description='F-Droid Server Tools',
      long_description=open('README').read(),
      author='The F-Droid Project',
      author_email='team@f-droid.org',
      url='https://f-droid.org',
      packages=['fdroidserver'],
      scripts=['fdroid', 'fd-commit'],
      data_files=[
        ('share/doc/fdroidserver/examples',
         [ 'config.buildserver.py',
             'sampleconfigs/config.sample.py',
             'sampleconfigs/makebs.config.sample.py',
          'fdroid-icon.png']),
        ],
      install_requires=[
        'python-magic',
        'PIL',
        ],
      classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: POSIX',
        'Topic :: Utilities',
        ],
      )
