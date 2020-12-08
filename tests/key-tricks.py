#!/usr/bin/env python3

import os
import fdroidserver
import shutil
import sys
from fdroidserver import common, nightly

if os.getenv('CI') is None:
    print('ERROR: This can overwrite SSH keys, so it should only be run in CI')
    sys.exit(1)

os.chdir(os.path.dirname(__file__))
config = fdroidserver.common.read_config(common.options)
nightly.PASSWORD = config['keystorepass']
nightly.KEY_ALIAS = config['repo_keyalias']

privkey = nightly._ssh_key_from_debug_keystore('keystore.jks')
print('privkey', privkey)
ssh_private_key_file = os.path.join(os.getenv('HOME'), '.ssh', 'id_rsa')
if os.path.exists(ssh_private_key_file):
    print('ERROR:', ssh_private_key_file, 'exists!')
    sys.exit(1)
shutil.move(privkey, ssh_private_key_file)
shutil.move(privkey + '.pub', ssh_private_key_file + '.pub')
