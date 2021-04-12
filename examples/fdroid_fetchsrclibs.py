#!/usr/bin/env python3
#
# an fdroid plugin for setting up srclibs
#
# The 'fdroid build' gitlab-ci job uses --on-server, which does not
# set up the srclibs.  This plugin does the missing setup.

import argparse
import os
import pprint
from fdroidserver import _, common, metadata

fdroid_summary = 'prepare the srclibs for `fdroid build --on-server`'


def main():
    parser = argparse.ArgumentParser(usage="%(prog)s [options] [APPID[:VERCODE] [APPID[:VERCODE] ...]]")
    common.setup_global_opts(parser)
    parser.add_argument("appid", nargs='*', help=_("applicationId with optional versionCode in the form APPID[:VERCODE]"))
    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    common.options = options
    pkgs = common.read_pkg_args(options.appid, True)
    allapps = metadata.read_metadata(pkgs)
    apps = common.read_app_args(options.appid, allapps, True)
    common.read_config(options)
    srclib_dir = os.path.join('build', 'srclib')
    os.makedirs(srclib_dir, exist_ok=True)
    srclibpaths = []
    for appid, app in apps.items():
        vcs, _ignored = common.setup_vcs(app)
        vcs.gotorevision('HEAD', refresh=False)
        for build in app.get('Builds', []):
            for lib in build.srclibs:
                srclibpaths.append(common.getsrclib(lib, srclib_dir, prepare=False, build=build))
    print('Set up srclibs:')
    pprint.pprint(srclibpaths)


if __name__ == "__main__":
    main()
