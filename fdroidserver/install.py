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
import locale
import logging
import termios
import tty

import defusedxml.ElementTree as XMLElementTree

from argparse import ArgumentParser, BooleanOptionalAction
from pathlib import Path
from urllib.parse import urlencode, urlparse, urlunparse

from . import _
from . import common, github, index, net
from .exception import FDroidException


DEFAULT_IPFS_GATEWAYS = ("https://gateway.ipfs.io/ipfs/",)
MAVEN_CENTRAL_MIRRORS = [
    {
        "url": "https://repo1.maven.org/maven2/",
        "dnsA": ["199.232.16.209"],
        "worksWithoutSNI": True,
    },
    {
        "url": "https://repo.maven.apache.org/maven2/",
        "dnsA": ["199.232.16.215"],
        "worksWithoutSNI": True,
    },
    {
        "url": "https://maven-central-asia.storage-download.googleapis.com/maven2/",
    },
    {
        "url": "https://maven-central-eu.storage-download.googleapis.com/maven2/",
    },
    {
        "url": "https://maven-central.storage-download.googleapis.com/maven2/",
    },
]


# pylint: disable=unused-argument
def download_apk(appid='org.fdroid.fdroid', privacy_mode=False):
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


def download_fdroid_apk(privacy_mode=False):  # pylint: disable=unused-argument
    """Directly download the current F-Droid APK and verify it.

    This downloads the "download button" link, which is the version
    that is best tested for new installs.

    """
    mirror = common.FDROIDORG_MIRRORS[0]
    mirror['url'] = urlunparse(urlparse(mirror['url'])._replace(path='F-Droid.apk'))
    return net.download_using_mirrors([mirror])


def download_fdroid_apk_from_github(privacy_mode=False):
    """Download F-Droid.apk from F-Droid's GitHub Releases."""
    if common.config and not privacy_mode:
        token = common.config.get('github_token')
    else:
        token = None
    gh = github.GithubApi(token, 'https://github.com/f-droid/fdroidclient')
    latest_apk = gh.get_latest_apk()
    filename = os.path.basename(latest_apk)
    return net.download_file(latest_apk, os.path.join(common.get_cachedir(), filename))


def download_fdroid_apk_from_ipns(privacy_mode=False):
    """Download the F-Droid APK from an IPNS repo."""
    cid = 'k51qzi5uqu5dl4hbcksbdmplanu9n4hivnqsupqe6vzve1pdbeh418ssptldd3'
    mirrors = [
        {"url": f"https://ipfs.io/ipns/{cid}/F-Droid.apk"},
    ]
    if not privacy_mode:
        mirrors.append({"url": f"https://{cid}.ipns.dweb.link/F-Droid.apk"})
    return net.download_using_mirrors(mirrors)


def download_fdroid_apk_from_maven(privacy_mode=False):
    """Download F-Droid.apk from Maven Central and official mirrors."""
    path = 'org/fdroid/fdroid/F-Droid'
    if privacy_mode:
        mirrors = MAVEN_CENTRAL_MIRRORS[:2]  # skip the Google servers
    else:
        mirrors = MAVEN_CENTRAL_MIRRORS
    metadata = net.download_using_mirrors(
        common.append_filename_to_mirrors(
            os.path.join(path, 'maven-metadata.xml'), mirrors
        )
    )
    version = XMLElementTree.parse(metadata).getroot().findall('*.//latest')[0].text
    mirrors = common.append_filename_to_mirrors(
        os.path.join(path, version, f'F-Droid-{version}.apk'), mirrors
    )
    return net.download_using_mirrors(mirrors)


def install_fdroid_apk(privacy_mode=False):
    """Download and install F-Droid.apk using all tricks we can muster.

    By default, this first tries to fetch the official install APK
    which is offered when someone clicks the "download" button on
    https://f-droid.org/.  Then it will try all the mirrors and
    methods until it gets something successful, or runs out of
    options.

    There is privacy_mode which tries to download from mirrors first,
    so that this downloads from a mirror that has many different kinds
    of files available, thereby breaking the clear link to F-Droid.

    Returns
    -------
    None for success or the error message.

    """
    country_code = locale.getlocale()[0].split('_')[-1]
    if privacy_mode is None and country_code in ('CN', 'HK', 'IR', 'TM'):
        logging.warning(
            _('Privacy mode was enabled based on your locale ({country_code}).').format(
                country_code=country_code
            )
        )
        privacy_mode = True

    if privacy_mode or not (common.config and common.config.get('jarsigner')):
        download_methods = [
            download_fdroid_apk_from_maven,
            download_fdroid_apk_from_ipns,
            download_fdroid_apk_from_github,
        ]
    else:
        download_methods = [
            download_apk,
            download_fdroid_apk_from_maven,
            download_fdroid_apk_from_github,
            download_fdroid_apk_from_ipns,
            download_fdroid_apk,
        ]
    for method in download_methods:
        try:
            f = method(privacy_mode=privacy_mode)
            break
        except Exception as e:
            logging.info(e)
    else:
        return _('F-Droid.apk could not be downloaded from any known source!')

    fingerprint = common.apk_signer_fingerprint(f)
    if fingerprint.upper() != common.FDROIDORG_FINGERPRINT:
        return _('{path} has the wrong fingerprint ({fingerprint})!').format(
            path=f, fingerprint=fingerprint
        )
    install_apk(f)


def install_apk(f):
    if common.config and common.config.get('apksigner'):
        # TODO this should always verify, but that requires APK sig verification in Python #94
        logging.info(_('Verifying package {path} with apksigner.').format(path=f))
        common.verify_apk_signature(f)
    if common.config and common.config.get('adb'):
        if devices():
            install_apks_to_devices([f])
            os.remove(f)
        else:
            os.remove(f)
            return _('No devices found for `adb install`! Please plug one in.')


def devices():
    """Get the list of device serials for use with adb commands."""
    p = common.SdkToolsPopen(['adb', "devices"])
    if p.returncode != 0:
        raise FDroidException("An error occured when finding devices: %s" % p.output)
    serials = list()
    for line in p.output.splitlines():
        columns = line.strip().split("\t", maxsplit=1)
        if len(columns) == 2:
            serial, status = columns
            if status == 'device':
                serials.append(serial)
            else:
                d = {'serial': serial, 'status': status}
                logging.warning(_('adb reports {serial} is "{status}"!'.format(**d)))
    return serials


def install_apks_to_devices(apks):
    """Install the list of APKs to all Android devices reported by `adb devices`."""
    for apk in apks:
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
            p = common.SdkToolsPopen(['adb', "-s", dev, "install", apk])
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


def read_char():
    """Read input from the terminal prompt one char at a time."""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch


def strtobool(val):
    """Convert a localized string representation of truth to True or False."""
    return val.lower() in ('', 'y', 'yes', _('yes'), _('true'))  # '' is pressing Enter


def prompt_user(yes, msg):
    """Prompt user for yes/no, supporting Enter and Esc as accepted answers."""
    run_install = yes
    if yes is None and sys.stdout.isatty():
        print(msg, end=' ', flush=True)
        answer = ''
        while True:
            in_char = read_char()
            if in_char == '\r':  # Enter key
                break
            if not in_char.isprintable():
                sys.exit(1)
            print(in_char, end='', flush=True)
            answer += in_char
        run_install = strtobool(answer)
        print()
    return run_install


def main():
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
    parser.add_argument(
        "-p",
        "--privacy-mode",
        action=BooleanOptionalAction,
        default=None,
        help=_("Download F-Droid.apk using mirrors that leak less to the network"),
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        default=None,
        help=_("Automatic yes to all prompts."),
    )
    parser.add_argument(
        "-n",
        "--no",
        action="store_false",
        dest='yes',
        help=_("Automatic no to all prompts."),
    )
    options = common.parse_args(parser)

    common.set_console_logging(options.verbose, options.color)
    logging.captureWarnings(True)  # for SNIMissingWarning

    common.get_config()

    if not options.appid and not options.all:
        run_install = prompt_user(
            options.yes,
            _('Would you like to download and install F-Droid.apk via adb? (YES/no)'),
        )
        if run_install:
            sys.exit(install_fdroid_apk(options.privacy_mode))
        sys.exit(1)

    output_dir = 'repo'
    if (options.appid or options.all) and not os.path.isdir(output_dir):
        logging.error(_("No signed output directory - nothing to do"))
        run_install = prompt_user(
            options.yes,
            _('Would you like to download the app(s) from f-droid.org? (YES/no)'),
        )
        if run_install:
            for appid in options.appid:
                f = download_apk(appid)
                install_apk(f)
            sys.exit(install_fdroid_apk(options.privacy_mode))
        sys.exit(1)

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
        install_apks_to_devices(apks.values())

    elif options.all:
        apks = {
            common.publishednameinfo(apkfile)[0]: apkfile
            for apkfile in sorted(glob.glob(os.path.join(output_dir, '*.apk')))
        }
        install_apks_to_devices(apks.values())

    logging.info('\n' + _('Finished'))


if __name__ == "__main__":
    main()
