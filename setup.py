#!/usr/bin/python

from distutils.core import setup

setup(name='FDroidServer',
      version='0.1',
      description='F-Droid Server Tools',
      author='The F-Droid Project',
      author_email='admin@f-droid.org',
      url='http://f-droid.org',
      packages=['fdroidserver'],
      scripts=['fdroid'],
      data_files = [('', ['COPYING', 'config.sample.py']),
                    ('docs', ['docs/*.texi'])
                   ]
     )
