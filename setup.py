#!/usr/bin/env python2

from setuptools import setup
import os
import subprocess
import sys

if not os.path.exists('fdroidserver/getsig/getsig.class'):
    subprocess.check_output('cd fdroidserver/getsig && javac getsig.java',
                            shell=True)

setup(name='fdroidserver',
      version='0.2.1',
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
        ('fdroidserver/getsig', ['fdroidserver/getsig/getsig.class'])
        ],
      install_requires=[
        'mwclient',
        'paramiko',
        'Pillow',
        'python-magic',
        'apache-libcloud >= 0.14.1',
        ],
      classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: POSIX',
        'Topic :: Utilities',
        ],
      )
