#!/usr/bin/env python3
#
# an fdroid plugin for resetting app VCSs to the latest version for the metadata

import argparse
import logging

from fdroidserver import _, common, metadata

from fdserver.exeption import VCSException

fdroid_summary = 'reset app VCSs to the latest version'


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

    for appid, app in apps.items():
        if "Builds" in app and len(app["Builds"]) > 0:
            logging.info(_("Cleaning up '{appid}' VCS").format(appid=appid))
            try:
                vcs, build_dir = common.setup_vcs(app)
                vcs.gotorevision(app["Builds"][-1].commit)

            except VCSException:
                pass


if __name__ == "__main__":
    main()
