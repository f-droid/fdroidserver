#!/usr/bin/env python3
#
# an fdroid plugin for exporting a repo's keystore in standard PEM format

import os
from argparse import ArgumentParser
from fdroidserver import common
from fdroidserver.common import FDroidPopen
from fdroidserver.exception import BuildException

fdroid_summary = 'export the keystore in standard PEM format'


def main():
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    options = parser.parse_args()
    config = common.read_config(options)
    env_vars = {'LC_ALL': 'C.UTF-8',
                'FDROID_KEY_STORE_PASS': config['keystorepass'],
                'FDROID_KEY_PASS': config['keypass']}
    destkeystore = config['keystore'].replace('.jks', '.p12').replace('/', '_')
    exportkeystore = config['keystore'].replace('.jks', '.pem').replace('/', '_')
    if os.path.exists(destkeystore) or os.path.exists(exportkeystore):
        raise BuildException('%s exists!' % exportkeystore)
    p = FDroidPopen([config['keytool'], '-importkeystore',
                     '-srckeystore', config['keystore'],
                     '-srcalias', config['repo_keyalias'],
                     '-srcstorepass:env', 'FDROID_KEY_STORE_PASS',
                     '-srckeypass:env', 'FDROID_KEY_PASS',
                     '-destkeystore', destkeystore,
                     '-deststoretype', 'PKCS12',
                     '-deststorepass:env', 'FDROID_KEY_STORE_PASS',
                     '-destkeypass:env', 'FDROID_KEY_PASS'],
                    envs=env_vars)
    if p.returncode != 0:
        raise BuildException("Failed to convert to PKCS12!", p.output)
    p = FDroidPopen(['openssl', 'pkcs12', '-in', destkeystore,
                     '-passin', 'env:FDROID_KEY_STORE_PASS', '-nokeys',
                     '-out', exportkeystore,
                     '-passout', 'env:FDROID_KEY_STORE_PASS'],
                    envs=env_vars)
    if p.returncode != 0:
        raise BuildException("Failed to convert to PEM!", p.output)


if __name__ == "__main__":
    main()
