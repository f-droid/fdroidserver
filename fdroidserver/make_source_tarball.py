#!/usr/bin/env python3
#
# make_source_tarball.py - part of the F-Droid server tools
# Copyright (C) 2024-2025, Michael Pöhn <michael@poehn.at>
# Copyright (C) 2024-2025, Hans-Christoph Steiner <hans@eds.org>
# Copyright (C) 2018, Areeb Jamal
# Copyright (C) 2013-2014, Daniel Martí <mvdan@mvdan.cc>
# Copyright (C) 2010-2015, Ciaran Gultnieks <ciaran@ciarang.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Make a source tarball from a single app's checked out source code.

This assumes that the app's source code is already checked out into the
repo, and that it is in a clean state.  It makes a src.tar.gz in the
repo's tmp/ directory.

"""

import argparse
import logging
import os
import pathlib
import sys
import tarfile
import traceback

from fdroidserver import common, metadata


def make_source_tarball(app, build, output_dir=pathlib.Path('unsigned')):
    if not output_dir.exists():
        output_dir.mkdir()
    build_dir = common.get_build_dir(app)
    # Build the source tarball right before we build the release...
    logging.info("Creating source tarball...")
    tarname = common.get_src_tarball_name(app.id, build.versionCode)
    tarball = tarfile.open(os.path.join(output_dir, tarname), "w:gz")

    def tarexc(t):
        return (
            None
            if any(t.name.endswith(s) for s in ['.svn', '.git', '.hg', '.bzr'])
            else t
        )

    tarball.add(build_dir, tarname, filter=tarexc)
    tarball.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    common.setup_global_opts(parser)
    parser.add_argument(
        "APPID:VERCODE",
        help="Application ID with Version Code in the form APPID:VERCODE",
    )
    options = common.parse_args(parser)

    try:
        appid, versionCode = common.split_pkg_arg(options.APPID_VERCODE)
        make_source_tarball(metadata.get_single_build(appid, versionCode))
    except Exception as e:
        if options.verbose:
            traceback.print_exc()
        else:
            print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
