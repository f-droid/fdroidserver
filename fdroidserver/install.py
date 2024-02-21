#!/usr/bin/env python3
#
# install.py - part of the FDroid server tools
# Copyright (C) 2013, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
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

import sys
import os
import glob
import logging

from argparse import ArgumentParser
from pathlib import Path
from urllib.parse import urlencode, urlparse, urlunparse

from . import _
from . import common, index, net
from .common import SdkToolsPopen
from .exception import FDroidException

config = None


DEFAULT_IPFS_GATEWAYS = ("https://gateway.ipfs.io/ipfs/",)


def download_apk(appid='org.fdroid.fdroid'):
    """Download an APK from F-Droid via the first mirror that works."""
    url = urlunparse(
        urlparse(common.FDROIDORG_MIRRORS[0]['url'])._replace(
            query=urlencode({'fingerprint': common.FDROIDORG_FINGERPRINT})
        )
    )

    data, _ignored = index.download_repo_index_v2(url)
    app = data.get('packages', dict()).get(appid)
    preferred_version = None
    for version in app['versions'].values():
        if not preferred_version:
            # if all else fails, use the first one
            preferred_version = version
        if not version.get('releaseChannels'):
            # prefer APK in default release channel
            preferred_version = version
            break
        print('skipping', version)

    mirrors = common.append_filename_to_mirrors(
        preferred_version['file']['name'][1:], common.FDROIDORG_MIRRORS
    )
    ipfsCIDv1 = preferred_version['file'].get('ipfsCIDv1')
    if ipfsCIDv1:
        for gateway in DEFAULT_IPFS_GATEWAYS:
            mirrors.append({'url': os.path.join(gateway, ipfsCIDv1)})
    f = net.download_using_mirrors(mirrors)
    if f and os.path.exists(f):
        versionCode = preferred_version['manifest']['versionCode']
        f = Path(f)
        return str(f.rename(f.with_stem(f'{appid}_{versionCode}')).resolve())


def devices():
    p = SdkToolsPopen(['adb', "devices"])
    if p.returncode != 0:
        raise FDroidException("An error occured when finding devices: %s" % p.output)
    lines = [line for line in p.output.splitlines() if not line.startswith('* ')]
    if len(lines) < 3:
        return []
    lines = lines[1:-1]
    return [line.split()[0] for line in lines]


def main():
    global config

    # Parse command line...
    parser = ArgumentParser(
        usage="%(prog)s [options] [APPID[:VERCODE] [APPID[:VERCODE] ...]]"
    )
    common.setup_global_opts(parser)
    parser.add_argument(
        "appid",
        nargs='*',
        help=_("application ID with optional versionCode in the form APPID[:VERCODE]"),
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        default=False,
        help=_("Install all signed applications available"),
    )
    options = common.parse_args(parser)

    common.set_console_logging(options.verbose)

    if not options.appid and not options.all:
        parser.error(
            _("option %s: If you really want to install all the signed apps, use --all")
            % "all"
        )

    config = common.read_config()

    output_dir = 'repo'
    if not os.path.isdir(output_dir):
        logging.info(_("No signed output directory - nothing to do"))
        sys.exit(0)

    if options.appid:
        vercodes = common.read_pkg_args(options.appid, True)
        common.get_metadata_files(vercodes)  # only check appids
        apks = {appid: None for appid in vercodes}

        # Get the signed APK with the highest vercode
        for apkfile in sorted(glob.glob(os.path.join(output_dir, '*.apk'))):
            try:
                appid, vercode = common.publishednameinfo(apkfile)
            except FDroidException:
                continue
            if appid not in apks:
                continue
            if vercodes[appid] and vercode not in vercodes[appid]:
                continue
            apks[appid] = apkfile

        for appid, apk in apks.items():
            if not apk:
                raise FDroidException(_("No signed APK available for %s") % appid)

    else:
        apks = {
            common.publishednameinfo(apkfile)[0]: apkfile
            for apkfile in sorted(glob.glob(os.path.join(output_dir, '*.apk')))
        }

    for appid, apk in apks.items():
        # Get device list each time to avoid device not found errors
        devs = devices()
        if not devs:
            raise FDroidException(_("No attached devices found"))
        logging.info(_("Installing %s...") % apk)
        for dev in devs:
            logging.info(
                _("Installing '{apkfilename}' on {dev}...").format(
                    apkfilename=apk, dev=dev
                )
            )
            p = SdkToolsPopen(['adb', "-s", dev, "install", apk])
            fail = ""
            for line in p.output.splitlines():
                if line.startswith("Failure"):
                    fail = line[9:-1]
            if not fail:
                continue

            if fail == "INSTALL_FAILED_ALREADY_EXISTS":
                logging.warning(
                    _('"{apkfilename}" is already installed on {dev}.').format(
                        apkfilename=apk, dev=dev
                    )
                )
            else:
                raise FDroidException(
                    _("Failed to install '{apkfilename}' on {dev}: {error}").format(
                        apkfilename=apk, dev=dev, error=fail
                    )
                )

    logging.info('\n' + _('Finished'))


if __name__ == "__main__":
    main()
