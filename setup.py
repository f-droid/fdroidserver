#!/usr/bin/env python2

from setuptools import setup

setup(name='FDroidServer',
      version='0.1',
      description='F-Droid Server Tools',
      long_description=open('README').read(),
      author='The F-Droid Project',
      author_email='admin@f-droid.org',
      url='http://f-droid.org',
      packages=['fdroidserver'],
      scripts=['fdroid'],
      data_files=[
        ('share/doc/fdroidserver/examples',
         ['config.buildserver.py', 'config.sample.py', 'makebs.config.sample.py',
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
