#!/usr/bin/env python3
#
# an fdroid plugin for setting up srclibs
#
# The 'fdroid build' gitlab-ci job uses --on-server, which does not
# set up the srclibs.  This plugin does the missing setup.

import glob
import os
from argparse import ArgumentParser
from fdroidserver import _, common, scanner


fdroid_summary = 'Run scanner.scan_binary on APKs'


def main():
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument("APK", nargs='*', help=_("Path to a signed or unsigned APK."))
    options = common.parse_args(parser)
    common.read_config()
    if options.APK:
        apks = options.APK
    else:
        apks = glob.glob(os.path.join('unsigned', '*.apk'))

    errors = 0
    for apk in apks:
        print('Scanning', apk, '...')
        if scanner.scan_binary(apk):
            print("ERROR: Found blocklisted packages in:", apk)
            errors += 1
    exit(errors)


if __name__ == "__main__":
    main()
