#!/usr/bin/env python3

import os
import sys

sys.path.insert(1, os.path.join(os.getcwd(), '..', 'fdroidserver'))
import common

config = common.get_default_config()

testtext = '''
This is a block of text that has been wrapped to fit nicely in PEP8 style:

GnuPrivacyGuard extends the gpgcli command line tool to bring an integrated
privacy engine to your Android. It gives you command line access to the entire
GnuPG suite of encryption software. It also serves as the test bed for
complete Android integration for all of GnuPG's crypto services, including
OpenPGP, symmetric encryption, and more.

GPG is GNU’s tool for end-to-end secure communication and encrypted data
storage. This trusted protocol is the free software alternative to PGP. This
app is built upon GnuPG 2.1, the new modularized version of GnuPG that now
supports S/MIME.

GPG aims to provide an integrated experience, so clicking on PGP files should
"just work". You can also share files to GPG to encrypt them. GPG will also
respond when you click on a PGP fingerprint URL (one that starts with
openpgp4fpr:).

Before using GPG, be sure to launch the app and let it finish its installation
process. Once it has completed, then you're ready to use it. The easiest way
to get started with GPG is to install [[jackpal.androidterm]]. GPG will
automatically configure Android Terminal Emulator as long as you have the
"Allow PATH extensions" settings enabled.
'''

archive_description = """
The repository of older versions of applications from the main demo repository.
"""


print('\n\n\n----------------------------------------------------')
print(common.clean_description(testtext))
print('\n\n\n----------------------------------------------------')
print(common.clean_description(archive_description))
print('\n\n\n----------------------------------------------------')
print(common.clean_description(config['repo_description']))
