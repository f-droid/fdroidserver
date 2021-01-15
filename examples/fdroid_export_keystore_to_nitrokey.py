#!/usr/bin/env python3
#
# an fdroid plugin for exporting a repo's keystore in standard PEM format

import os
from argparse import ArgumentParser
from fdroidserver import common
from fdroidserver.common import FDroidPopen
from fdroidserver.exception import BuildException

fdroid_summary = "export the repo's keystore file to a NitroKey HSM"


def run(cmd, error):
    envs = {'LC_ALL': 'C.UTF-8',
            'PIN': config['smartcard_pin'],
            'FDROID_KEY_STORE_PASS': config['keystorepass'],
            'FDROID_KEY_PASS': config['keypass']}
    p = FDroidPopen(cmd, envs=envs)
    if p.returncode != 0:
        raise BuildException(error, p.output)


def main():
    global config
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    options = parser.parse_args()
    config = common.read_config(options)
    destkeystore = config['keystore'].replace('.jks', '.p12').replace('/', '_')
    exportkeystore = config['keystore'].replace('.jks', '.pem').replace('/', '_')
    if os.path.exists(destkeystore) or os.path.exists(exportkeystore):
        raise BuildException('%s exists!' % exportkeystore)
    run([config['keytool'], '-importkeystore',
         '-srckeystore', config['keystore'],
         '-srcalias', config['repo_keyalias'],
         '-srcstorepass:env', 'FDROID_KEY_STORE_PASS',
         '-srckeypass:env', 'FDROID_KEY_PASS',
         '-destkeystore', destkeystore,
         '-deststorepass:env', 'FDROID_KEY_STORE_PASS',
         '-deststoretype', 'PKCS12'],
        'Failed to convert to PKCS12!')
#    run(['openssl', 'pkcs12', '-in', destkeystore,
#         '-passin', 'env:FDROID_KEY_STORE_PASS', '-nokeys',
#         '-out', exportkeystore,
#         '-passout', 'env:FDROID_KEY_STORE_PASS'],
#        'Failed to convert to PEM!')
    run(['pkcs15-init', '--delete-objects', 'privkey,pubkey',
         '--id', '3', '--store-private-key', destkeystore,
         '--format', 'pkcs12', '--auth-id', '3',
         '--verify-pin', '--pin', 'env:PIN'],
        '')
    run(['pkcs15-init', '--delete-objects', 'privkey,pubkey',
         '--id', '2', '--store-private-key', destkeystore,
         '--format', 'pkcs12', '--auth-id', '3',
         '--verify-pin', '--pin', 'env:PIN'],
        '')


if __name__ == "__main__":
    main()
