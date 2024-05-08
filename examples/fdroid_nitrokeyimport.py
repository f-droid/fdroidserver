#!/usr/bin/env python3

from argparse import ArgumentParser
from fdroidserver import common
from fdroidserver.common import FDroidPopen
from fdroidserver.exception import BuildException

fdroid_summary = 'import the local keystore into a SmartCard HSM'


def main():
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    common.parse_args(parser)
    config = common.read_config()
    env_vars = {
        'LC_ALL': 'C.UTF-8',
        'FDROID_KEY_STORE_PASS': config['keystorepass'],
        'FDROID_KEY_PASS': config['keypass'],
        'SMARTCARD_PIN': str(config['smartcard_pin']),
    }
    p = FDroidPopen([config['keytool'], '-importkeystore',
                     '-srcalias', config['repo_keyalias'],
                     '-srckeystore', config['keystore'],
                     '-srcstorepass:env', 'FDROID_KEY_STORE_PASS',
                     '-srckeypass:env', 'FDROID_KEY_PASS',
                     '-destalias', config['repo_keyalias'],
                     '-destkeystore', 'NONE',
                     '-deststoretype', 'PKCS11',
                     '-providerName', 'SunPKCS11-OpenSC',
                     '-providerClass', 'sun.security.pkcs11.SunPKCS11',
                     '-providerArg', 'opensc-fdroid.cfg',
                     '-deststorepass:env', 'SMARTCARD_PIN',
                     '-J-Djava.security.debug=sunpkcs11'],
                    envs=env_vars)
    if p.returncode != 0:
        raise BuildException("Failed to import into HSM!", p.output)


if __name__ == "__main__":
    main()
