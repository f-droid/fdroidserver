#!/usr/bin/env python3
#
# Copyright (C) 2017, Michael Poehn <michael.poehn@fsfe.org>
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
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from argparse import ArgumentParser

import re
import os
import sys
import logging

from . import _
from . import common
from . import net
from .exception import FDroidException


def extract_signature(apkpath):

    if not os.path.exists(apkpath):
        raise FDroidException("file APK does not exists '{}'".format(apkpath))
    if not common.verify_apk_signature(apkpath):
        raise FDroidException("no valid signature in '{}'".format(apkpath))
    logging.debug('signature okay: %s', apkpath)

    appid, vercode, _ignored = common.get_apk_id(apkpath)
    sigdir = common.metadata_get_sigdir(appid, vercode)
    if not os.path.exists(sigdir):
        os.makedirs(sigdir)
    common.apk_extract_signatures(apkpath, sigdir)

    return sigdir


def extract(options):

    # Create tmp dir if missing…
    tmp_dir = 'tmp'
    if not os.path.exists(tmp_dir):
        os.mkdir(tmp_dir)

    if not options.APK or len(options.APK) <= 0:
        logging.critical(_('no APK supplied'))
        sys.exit(1)

    # iterate over supplied APKs downlaod and extract them…
    httpre = re.compile(r'https?:\/\/')
    for apk in options.APK:
        try:
            if os.path.isfile(apk):
                sigdir = extract_signature(apk)
                logging.info(_("Fetched signatures for '{apkfilename}' -> '{sigdir}'")
                             .format(apkfilename=apk, sigdir=sigdir))
            elif httpre.match(apk):
                if apk.startswith('https') or options.no_check_https:
                    try:
                        tmp_apk = os.path.join(tmp_dir, 'signed.apk')
                        net.download_file(apk, tmp_apk)
                        sigdir = extract_signature(tmp_apk)
                        logging.info(_("Fetched signatures for '{apkfilename}' -> '{sigdir}'")
                                     .format(apkfilename=apk, sigdir=sigdir))
                    finally:
                        if tmp_apk and os.path.exists(tmp_apk):
                            os.remove(tmp_apk)
                else:
                    logging.warning(_('refuse downloading via insecure HTTP connection '
                                      '(use HTTPS or specify --no-https-check): {apkfilename}')
                                    .format(apkfilename=apk))
        except FDroidException as e:
            logging.warning(_("Failed fetching signatures for '{apkfilename}': {error}")
                            .format(apkfilename=apk, error=e))
            if e.detail:
                logging.debug(e.detail)


def main():
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument(
        "APK", nargs='*', help=_("signed APK, either a file-path or HTTPS URL.")
    )
    parser.add_argument("--no-check-https", action="store_true", default=False)
    options = parser.parse_args()

    # Read config.py...
    common.read_config(options)

    extract(options)
