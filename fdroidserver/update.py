#!/usr/bin/env python3
#
# update.py - part of the FDroid server tools
# Copyright (C) 2016, Blue Jay Wireless
# Copyright (C) 2014-2016, Hans-Christoph Steiner <hans@eds.org>
# Copyright (C) 2010-2015, Ciaran Gultnieks <ciaran@ciarang.com>
# Copyright (C) 2013-2014, Daniel Martí <mvdan@mvdan.cc>
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

import argparse
import sys
import os
import shutil
import glob
import logging
import re
import socket
import warnings
import zipfile
import hashlib
import json
import time
import yaml
import copy
from datetime import datetime
from argparse import ArgumentParser
from pathlib import Path

try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader

import collections
from binascii import hexlify

from . import _
from . import common
from . import index
from . import metadata
from .exception import BuildException, FDroidException

from PIL import Image, PngImagePlugin

if hasattr(Image, 'DecompressionBombWarning'):
    warnings.simplefilter('error', Image.DecompressionBombWarning)
Image.MAX_IMAGE_PIXELS = 0xffffff  # 4096x4096

METADATA_VERSION = 20001

# less than the valid range of versionCode, i.e. Java's Integer.MIN_VALUE
UNSET_VERSION_CODE = -0x100000000

APK_NAME_PAT = re.compile(r".*\Wname='([a-zA-Z0-9._]*)'.*")
APK_VERCODE_PAT = re.compile(".*versionCode='([0-9]*)'.*")
APK_VERNAME_PAT = re.compile(".*versionName='([^']*)'.*")
APK_LABEL_ICON_PAT = re.compile(r".*\s+label='(.*)'\s+icon='(.*?)'")
APK_SDK_VERSION_PAT = re.compile(".*'([0-9]*)'.*")
APK_PERMISSION_PAT = re.compile(r".*name='([^']*)'(?:.*maxSdkVersion='([^']*)')?.*")
APK_FEATURE_PAT = re.compile(".*name='([^']*)'.*")

screen_densities = ['65534', '640', '480', '320', '240', '160', '120']
# resolutions must end with 'dpi'
screen_resolutions = {
    "xxxhdpi": '640',
    "xxhdpi": '480',
    "xhdpi": '320',
    "hdpi": '240',
    "mdpi": '160',
    "ldpi": '120',
    "tvdpi": '213',
    "undefineddpi": '-1',
    "anydpi": '65534',
    "nodpi": '65535'
}

all_screen_densities = ['0'] + screen_densities

UsesPermission = collections.namedtuple('UsesPermission', ['name', 'maxSdkVersion'])
UsesPermissionSdk23 = collections.namedtuple('UsesPermissionSdk23', ['name', 'maxSdkVersion'])

ALLOWED_EXTENSIONS = ('png', 'jpg', 'jpeg')
GRAPHIC_NAMES = ('featureGraphic', 'icon', 'promoGraphic', 'tvBanner')
SCREENSHOT_DIRS = ('phoneScreenshots', 'sevenInchScreenshots',
                   'tenInchScreenshots', 'tvScreenshots', 'wearScreenshots')

BLANK_PNG_INFO = PngImagePlugin.PngInfo()


def dpi_to_px(density):
    return (int(density) * 48) / 160


def px_to_dpi(px):
    return (int(px) * 160) / 48


def get_icon_dir(repodir, density):
    if density == '0' or density == '65534':
        return os.path.join(repodir, "icons")
    else:
        return os.path.join(repodir, "icons-%s" % density)


def get_icon_dirs(repodir):
    for density in screen_densities:
        yield get_icon_dir(repodir, density)


def get_all_icon_dirs(repodir):
    for density in all_screen_densities:
        yield get_icon_dir(repodir, density)


def disabled_algorithms_allowed():
    return ((options is not None and options.allow_disabled_algorithms)
            or (config is not None and config['allow_disabled_algorithms'])
            or common.default_config['allow_disabled_algorithms'])


def status_update_json(apps, apks):
    """Output a JSON file with metadata about this `fdroid update` run.

    Parameters
    ----------
    apps
      fully populated list of all applications
    apks
      all to be published apks

    """
    logging.debug(_('Outputting JSON'))
    output = common.setup_status_output(start_timestamp)
    output['antiFeatures'] = dict()
    output['disabled'] = []
    output['archivePolicy0'] = []
    output['failedBuilds'] = dict()
    output['noPackages'] = []
    output['needsUpdate'] = []
    output['noUpdateCheck'] = []
    output['apksigner'] = shutil.which(config.get('apksigner', ''))
    output['jarsigner'] = shutil.which(config.get('jarsigner', ''))
    output['keytool'] = shutil.which(config.get('keytool', ''))

    for appid in apps:
        app = apps[appid]
        for af in app.get('AntiFeatures', []):
            antiFeatures = output['antiFeatures']  # JSON camelCase
            if af not in antiFeatures:
                antiFeatures[af] = dict()
            if 'apps' not in antiFeatures[af]:
                antiFeatures[af]['apps'] = set()
            antiFeatures[af]['apps'].add(appid)

        apklist = []
        gotcurrentver = False
        for apk in apks:
            if apk['packageName'] == appid:
                if str(apk['versionCode']) == app.get('CurrentVersionCode'):
                    gotcurrentver = True
                apklist.append(apk)
        validapks = 0
        if app.get('Disabled'):
            output['disabled'].append(appid)
        elif app.get("ArchivePolicy") and int(app["ArchivePolicy"][:-9]) == 0:
            output['archivePolicy0'].append(appid)
        else:
            for build in app.get('Builds', []):
                if not build.get('disable'):
                    builtit = False
                    for apk in apklist:
                        if apk['versionCode'] == int(build.versionCode):
                            builtit = True
                            validapks += 1
                            break
                    if not builtit:
                        failedBuilds = output['failedBuilds']
                        if appid not in failedBuilds:
                            failedBuilds[appid] = []
                        failedBuilds[appid].append(build.versionCode)
            if validapks == 0:
                output['noPackages'].append(appid)
            if not gotcurrentver:
                output['needsUpdate'].append(appid)
            if app.get('UpdateCheckMode') == 'None':
                output['noUpdateCheck'].append(appid)
    common.write_status_json(output, options.pretty)


def delete_disabled_builds(apps, apkcache, repodirs):
    """Delete disabled build outputs.

    Parameters
    ----------
    apps
      list of all applications, as per metadata.read_metadata
    apkcache
      current apk cache information
    repodirs
      the repo directories to process
    """
    for appid, app in apps.items():
        for build in app.get('Builds', []):
            if not build.disable:
                continue
            apkfilename = common.get_release_filename(app, build)
            iconfilename = "%s.%s.png" % (
                appid,
                build.versionCode)
            for repodir in repodirs:
                files = [
                    os.path.join(repodir, apkfilename),
                    os.path.join(repodir, apkfilename + '.asc'),
                    os.path.join(repodir, apkfilename[:-4] + "_src.tar.gz"),
                ]
                for density in all_screen_densities:
                    repo_dir = get_icon_dir(repodir, density)
                    files.append(os.path.join(repo_dir, iconfilename))

                for f in files:
                    if os.path.exists(f):
                        logging.info("Deleting disabled build output " + f)
                        os.remove(f)
            if apkfilename in apkcache:
                del apkcache[apkfilename]


def resize_icon(iconpath, density):

    if not os.path.isfile(iconpath):
        return

    fp = None
    try:
        fp = open(iconpath, 'rb')
        im = Image.open(fp)
        size = dpi_to_px(density)

        if any(length > size for length in im.size):
            oldsize = im.size
            im.thumbnail((size, size), Image.ANTIALIAS)
            logging.debug("%s was too large at %s - new size is %s" % (
                iconpath, oldsize, im.size))
            im.save(iconpath, "PNG", optimize=True,
                    pnginfo=BLANK_PNG_INFO, icc_profile=None)

    except Exception as e:
        logging.error(_("Failed resizing {path}: {error}".format(path=iconpath, error=e)))

    finally:
        if fp:
            fp.close()


def resize_all_icons(repodirs):
    """Resize all icons that exceed the max size.

    Parameters
    ----------
    repodirs
      the repo directories to process
    """
    for repodir in repodirs:
        for density in screen_densities:
            icon_dir = get_icon_dir(repodir, density)
            icon_glob = os.path.join(icon_dir, '*.png')
            for iconpath in glob.glob(icon_glob):
                resize_icon(iconpath, density)


def getsig(apkpath):
    """Get the unique ID for the signing certificate of an APK.

    This uses a strange algorithm that was devised at the very
    beginning of F-Droid.  Since it is only used for checking
    signature compatibility, it does not matter much that it uses MD5.

    To get the same MD5 has that fdroidclient gets, we encode the .RSA
    certificate in a specific format and pass it hex-encoded to the
    md5 digest algorithm.  This is not the same as the standard X.509
    certificate fingerprint.

    Parameters
    ----------
    apkpath
      path to the apk

    Returns
    -------
    A string containing the md5 of the signature of the apk or None
    if an error occurred.

    """
    cert_encoded = common.get_first_signer_certificate(apkpath)
    if not cert_encoded:
        return None
    return hashlib.md5(hexlify(cert_encoded)).hexdigest()  # nosec just used as ID for signing key


def get_cache_file():
    return os.path.join('tmp', 'apkcache.json')


def get_cache():
    """Get the cached dict of the APK index.

    Gather information about all the apk files in the repo directory,
    using cached data if possible. Some of the index operations take a
    long time, like calculating the SHA-256 and verifying the APK
    signature.

    The cache is invalidated if the metadata version is different, or
    the 'allow_disabled_algorithms' config/option is different.  In
    those cases, there is no easy way to know what has changed from
    the cache, so just rerun the whole thing.

    Returns
    -------
    apkcache

    """
    apkcachefile = get_cache_file()
    ada = disabled_algorithms_allowed()
    if options is not None and not options.clean and os.path.exists(apkcachefile):
        with open(apkcachefile) as fp:
            apkcache = json.load(fp, object_pairs_hook=collections.OrderedDict)
        if apkcache.get("METADATA_VERSION") != METADATA_VERSION \
           or apkcache.get('allow_disabled_algorithms') != ada:
            apkcache = collections.OrderedDict()
    else:
        apkcache = collections.OrderedDict()

    apkcache["METADATA_VERSION"] = METADATA_VERSION
    apkcache['allow_disabled_algorithms'] = ada

    for k, v in apkcache.items():
        if not isinstance(v, dict):
            continue
        if 'antiFeatures' in v:
            v['antiFeatures'] = set(v['antiFeatures'])
        if 'added' in v:
            v['added'] = datetime.fromtimestamp(v['added'])

    return apkcache


def write_cache(apkcache):
    class Encoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, set):
                return list(obj)
            elif isinstance(obj, datetime):
                return obj.timestamp()
            return super().default(obj)

    apkcachefile = get_cache_file()
    cache_path = os.path.dirname(apkcachefile)
    if not os.path.exists(cache_path):
        os.makedirs(cache_path)
    for k, v in apkcache.items():
        if isinstance(k, bytes):
            print('BYTES: ' + str(k) + ' ' + str(v))
    with open(apkcachefile, 'w') as fp:
        json.dump(apkcache, fp, cls=Encoder, indent=2)


def get_icon_bytes(apkzip, iconsrc):
    """ZIP has no official encoding, UTF-* and CP437 are defacto."""
    try:
        return apkzip.read(iconsrc)
    except KeyError:
        return apkzip.read(iconsrc.encode('utf-8').decode('cp437'))


def has_known_vulnerability(filename):
    """Check for known vulnerabilities in the APK.

    Checks OpenSSL .so files in the APK to see if they are a known vulnerable
    version.  Google also enforces this:
    https://support.google.com/faqs/answer/6376725?hl=en

    Checks whether there are more than one classes.dex or AndroidManifest.xml
    files, which is invalid and an essential part of the "Master Key" attack.
    http://www.saurik.com/id/17

    Janus is similar to Master Key but is perhaps easier to scan for.
    https://www.guardsquare.com/en/blog/new-android-vulnerability-allows-attackers-modify-apps-without-affecting-their-signatures
    """
    found_vuln = False

    # statically load this pattern
    if not hasattr(has_known_vulnerability, "pattern"):
        has_known_vulnerability.pattern = re.compile(b'.*OpenSSL ([01][0-9a-z.-]+)')

    with open(filename.encode(), 'rb') as fp:
        first4 = fp.read(4)
    if first4 != b'\x50\x4b\x03\x04':
        raise FDroidException(_('{path} has bad file signature "{pattern}", possible Janus exploit!')
                              .format(path=filename, pattern=first4.decode().replace('\n', ' ')) + '\n'
                              + 'https://www.guardsquare.com/en/blog/new-android-vulnerability-allows-attackers-modify-apps-without-affecting-their-signatures')

    files_in_apk = set()
    with zipfile.ZipFile(filename) as zf:
        for name in zf.namelist():
            if name.endswith('.so') and ('libcrypto' in name or 'libssl' in name):
                lib = zf.open(name)
                while True:
                    chunk = lib.read(4096)
                    if chunk == b'':
                        break
                    m = has_known_vulnerability.pattern.search(chunk)
                    if m:
                        version = m.group(1).decode('ascii')
                        if (version.startswith('1.0.1') and len(version) > 5 and version[5] >= 'r') \
                           or (version.startswith('1.0.2') and len(version) > 5 and version[5] >= 'f') \
                           or re.match(r'[1-9]\.[1-9]\.[0-9].*', version):
                            logging.debug(_('"{path}" contains recent {name} ({version})')
                                          .format(path=filename, name=name, version=version))
                        else:
                            logging.warning(_('"{path}" contains outdated {name} ({version})')
                                            .format(path=filename, name=name, version=version))
                            found_vuln = True
                        break
            elif name == 'AndroidManifest.xml' or name == 'classes.dex' or name.endswith('.so'):
                if name in files_in_apk:
                    logging.warning(_('{apkfilename} has multiple {name} files, looks like Master Key exploit!')
                                    .format(apkfilename=filename, name=name))
                    found_vuln = True
                files_in_apk.add(name)
    return found_vuln


def insert_obbs(repodir, apps, apks):
    """Scan the .obb files in a given repo directory and adds them to the relevant APK instances.

    OBB files have versionCodes like APK
    files, and they are loosely associated.  If there is an OBB file
    present, then any APK with the same or higher versionCode will use
    that OBB file.  There are two OBB types: main and patch, each APK
    can only have only have one of each.

    https://developer.android.com/google/play/expansion-files.html

    Parameters
    ----------
    repodir
      repo directory to scan
    apps
      list of current, valid apps
    apks
      current information on all APKs
    """
    def obbWarnDelete(f, msg):
        logging.warning(msg + ' ' + f)
        if options.delete_unknown:
            logging.error(_("Deleting unknown file: {path}").format(path=f))
            os.remove(f)

    obbs = []
    java_Integer_MIN_VALUE = -pow(2, 31)
    currentPackageNames = apps.keys()
    for f in glob.glob(os.path.join(repodir, '*.obb')):
        obbfile = os.path.basename(f)
        # obbfile looks like: [main|patch].<expansion-version>.<package-name>.obb
        chunks = obbfile.split('.')
        if chunks[0] != 'main' and chunks[0] != 'patch':
            obbWarnDelete(f, _('OBB filename must start with "main." or "patch.":'))
            continue
        if not re.match(r'^-?[0-9]+$', chunks[1]):
            obbWarnDelete(f, _('The OBB version code must come after "{name}.":')
                          .format(name=chunks[0]))
            continue
        versionCode = int(chunks[1])
        packagename = ".".join(chunks[2:-1])

        highestVersionCode = java_Integer_MIN_VALUE
        if packagename not in currentPackageNames:
            obbWarnDelete(f, _("OBB's packagename does not match a supported APK:"))
            continue
        for apk in apks:
            if packagename == apk['packageName'] and apk['versionCode'] > highestVersionCode:
                highestVersionCode = apk['versionCode']
        if versionCode > highestVersionCode:
            obbWarnDelete(f, _('OBB file has newer versionCode({integer}) than any APK:')
                          .format(integer=str(versionCode)))
            continue
        obbsha256 = common.sha256sum(f)
        obbs.append((packagename, versionCode, obbfile, obbsha256))

    for apk in apks:
        for (packagename, versionCode, obbfile, obbsha256) in sorted(obbs, reverse=True):
            if versionCode <= apk['versionCode'] and packagename == apk['packageName']:
                if obbfile.startswith('main.') and 'obbMainFile' not in apk:
                    apk['obbMainFile'] = obbfile
                    apk['obbMainFileSha256'] = obbsha256
                elif obbfile.startswith('patch.') and 'obbPatchFile' not in apk:
                    apk['obbPatchFile'] = obbfile
                    apk['obbPatchFileSha256'] = obbsha256
            if 'obbMainFile' in apk and 'obbPatchFile' in apk:
                break


def translate_per_build_anti_features(apps, apks):
    """Grab the anti-features list from the build metadata.

    For most Anti-Features, they are really most applicable per-APK,
    not for an app.  An app can fix a vulnerability, add/remove
    tracking, etc.  This reads the 'antifeatures' list from the Build
    entries in the fdroiddata metadata file, then transforms it into
    the 'antiFeatures' list of unique items for the index.

    The field key is all lower case in the metadata file to match the
    rest of the Build fields.  It is 'antiFeatures' camel case in the
    implementation, index, and fdroidclient since it is translated
    from the build 'antifeatures' field, not directly included.

    """
    antiFeatures = dict()
    for packageName, app in apps.items():
        d = dict()
        for build in app.get('Builds', []):
            afl = build.get('antifeatures')
            if afl:
                d[int(build.versionCode)] = afl
        if len(d) > 0:
            antiFeatures[packageName] = d

    for apk in apks:
        d = antiFeatures.get(apk['packageName'])
        if d:
            afl = d.get(apk['versionCode'])
            if afl:
                apk['antiFeatures'].update(afl)


def _get_localized_dict(app, locale):
    """Get the dict to add localized store metadata to."""
    if 'localized' not in app:
        app['localized'] = collections.OrderedDict()
    if locale not in app['localized']:
        app['localized'][locale] = collections.OrderedDict()
    return app['localized'][locale]


def _set_localized_text_entry(app, locale, key, f):
    """Read a fastlane/triple-t metadata file and add an entry to the app.

    This reads more than the limit, in case there is leading or
    trailing whitespace to be stripped

    """
    try:
        limit = config['char_limits'][key]
        localized = _get_localized_dict(app, locale)
        with open(f, errors='replace') as fp:
            text = fp.read(limit * 2)
            if len(text) > 0:
                if key in ('name', 'summary', 'video'):  # hardcoded as a single line
                    localized[key] = text.strip('\n')[:limit]
                else:
                    localized[key] = text[:limit]
    except Exception as e:
        logging.error(_('{path}: {error}').format(path=f, error=str(e)))


def _set_author_entry(app, key, f):
    """Read a fastlane/triple-t author file and add the entry to the app.

    This reads more than the limit, in case there is leading or
    trailing whitespace to be stripped

    """
    try:
        limit = config['char_limits']['author']
        with open(f, errors='replace') as fp:
            text = fp.read(limit * 2)
            if len(text) > 0:
                app[key] = text.strip()[:limit]
    except Exception as e:
        logging.error(_('{path}: {error}').format(path=f, error=str(e)))


def _strip_and_copy_image(in_file, outpath):
    """Remove any metadata from image and copy it to new path.

    Sadly, image metadata like EXIF can be used to exploit devices.
    It is not used at all in the F-Droid ecosystem, so its much safer
    just to remove it entirely.

    This uses size+mtime to check for a new file since this process
    actually modifies the resulting file to strip out the EXIF.

    outpath can be path to either a file or dir.  The dir that outpath
    refers to must exist before calling this.

    Potential source of Python code to strip JPEGs without dependencies:
    http://www.fetidcascade.com/public/minimal_exif_writer.py
    """
    logging.debug('copying ' + in_file + ' ' + outpath)

    if not os.path.exists(in_file):
        if os.path.islink(in_file):
            logging.warning(_("Broken symlink: {path}").format(path=in_file))
        else:
            logging.warning(_("File disappeared while processing it: {path}").format(path=in_file))
        return

    if os.path.isdir(outpath):
        out_file = os.path.join(outpath, os.path.basename(in_file))
    else:
        out_file = outpath

    if os.path.exists(out_file):
        in_stat = os.stat(in_file)
        out_stat = os.stat(out_file)
        if in_stat.st_size == out_stat.st_size \
           and in_stat.st_mtime == out_stat.st_mtime:
            return

    extension = common.get_extension(in_file)[1]
    if extension == 'png':
        try:
            with open(in_file, 'rb') as fp:
                in_image = Image.open(fp)
                in_image.save(out_file, "PNG", optimize=True,
                              pnginfo=BLANK_PNG_INFO, icc_profile=None)
        except Exception as e:
            logging.error(_("Failed copying {path}: {error}".format(path=in_file, error=e)))
            return
    elif extension == 'jpg' or extension == 'jpeg':
        try:
            with open(in_file, 'rb') as fp:
                in_image = Image.open(fp)
                data = list(in_image.getdata())
                out_image = Image.new(in_image.mode, in_image.size)
            out_image.putdata(data)
            out_image.save(out_file, "JPEG", optimize=True)
        except Exception as e:
            logging.error(_("Failed copying {path}: {error}".format(path=in_file, error=e)))
            return
    else:
        raise FDroidException(_('Unsupported file type "{extension}" for repo graphic')
                              .format(extension=extension))
    stat_result = os.stat(in_file)
    os.utime(out_file, times=(stat_result.st_atime, stat_result.st_mtime))


def _get_base_hash_extension(f):
    """Split a graphic/screenshot filename into base, sha256, and extension."""
    base, extension = common.get_extension(f)
    sha256_index = base.find('_')
    if sha256_index > 0:
        return base[:sha256_index], base[sha256_index + 1:], extension
    return base, None, extension


def sanitize_funding_yml_entry(entry):
    """FUNDING.yml comes from upstream repos, entries must be sanitized."""
    if type(entry) not in (bytes, int, float, list, str):
        return
    if isinstance(entry, bytes):
        entry = entry.decode()
    elif isinstance(entry, list):
        if entry:
            entry = entry[0]
        else:
            return
    try:
        entry = str(entry)
    except (TypeError, ValueError):
        return
    if len(entry) > 2048:
        logging.warning(_('Ignoring FUNDING.yml entry longer than 2048: %s') % entry[:2048])
        return
    if '\n' in entry:
        return
    return entry.strip()


def sanitize_funding_yml_name(name):
    """Sanitize usernames that come from FUNDING.yml."""
    entry = sanitize_funding_yml_entry(name)
    if entry:
        m = metadata.VALID_USERNAME_REGEX.match(entry)
        if m:
            return m.group()
    return


def insert_funding_yml_donation_links(apps):
    """Include donation links from FUNDING.yml in app's source repo.

    GitHub made a standard file format for declaring donation
    links. This parses that format from upstream repos to include in
    metadata here.  GitHub supports mostly proprietary services, so
    this logic adds proprietary services only as Donate: links.

    FUNDING.yml can be either in the root of the project, or in the
    ".github" subdir.

    https://help.github.com/en/articles/displaying-a-sponsor-button-in-your-repository#about-funding-files

    """
    if not os.path.isdir('build'):
        return  # nothing to do
    for packageName, app in apps.items():
        sourcedir = os.path.join('build', packageName)
        if not os.path.isdir(sourcedir):
            continue
        for f in ([os.path.join(sourcedir, 'FUNDING.yml'), ]
                  + glob.glob(os.path.join(sourcedir, '.github', 'FUNDING.yml'))):
            if not os.path.isfile(f):
                continue
            data = None
            try:
                with open(f) as fp:
                    data = yaml.load(fp, Loader=SafeLoader)
            except yaml.YAMLError as e:
                logging.error(_('Found bad funding file "{path}" for "{name}":')
                              .format(path=f, name=packageName))
                logging.error(e)
            if not data or type(data) != dict:
                continue
            if not app.get('Liberapay') and 'liberapay' in data:
                s = sanitize_funding_yml_name(data['liberapay'])
                if s:
                    app['Liberapay'] = s
            if not app.get('OpenCollective') and 'open_collective' in data:
                s = sanitize_funding_yml_name(data['open_collective'])
                if s:
                    app['OpenCollective'] = s
            if not app.get('Donate'):
                if 'liberapay' in data:
                    del(data['liberapay'])
                if 'open_collective' in data:
                    del(data['open_collective'])
                # this tuple provides a preference ordering
                for k in ('custom', 'github', 'patreon', 'community_bridge', 'ko_fi', 'issuehunt'):
                    v = data.get(k)
                    if not v:
                        continue
                    if k == 'custom':
                        s = sanitize_funding_yml_entry(v)
                        if s:
                            app['Donate'] = s
                            break
                    elif k == 'community_bridge':
                        s = sanitize_funding_yml_name(v)
                        if s:
                            app['Donate'] = 'https://funding.communitybridge.org/projects/' + s
                            break
                    elif k == 'github':
                        s = sanitize_funding_yml_name(v)
                        if s:
                            app['Donate'] = 'https://github.com/sponsors/' + s
                            break
                    elif k == 'issuehunt':
                        s = sanitize_funding_yml_name(v)
                        if s:
                            app['Donate'] = 'https://issuehunt.io/r/' + s
                            break
                    elif k == 'ko_fi':
                        s = sanitize_funding_yml_name(v)
                        if s:
                            app['Donate'] = 'https://ko-fi.com/' + s
                            break
                    elif k == 'patreon':
                        s = sanitize_funding_yml_name(v)
                        if s:
                            app['Donate'] = 'https://patreon.com/' + s
                            break


def copy_triple_t_store_metadata(apps):
    """Include store metadata from the app's source repo.

    The Triple-T Gradle Play Publisher is a plugin that has a standard
    file layout for all of the metadata and graphics that the Google
    Play Store accepts.  Since F-Droid has the git repo, it can just
    pluck those files directly.  This method reads any text files into
    the app dict, then copies any graphics into the fdroid repo
    directory structure.

    This needs to be run before insert_localized_app_metadata() so that
    the graphics files that are copied into the fdroid repo get
    properly indexed.

    https://github.com/Triple-T/gradle-play-publisher/blob/1.2.2/README.md#uploading-images
    https://github.com/Triple-T/gradle-play-publisher/blob/1.2.2/README.md#play-store-metadata
    https://github.com/Triple-T/gradle-play-publisher/blob/2.1.0/README.md#publishing-listings

    """
    if not os.path.isdir('build'):
        return  # nothing to do

    tt_graphic_names = ('feature-graphic', 'icon', 'promo-graphic', 'tv-banner')
    tt_screenshot_dirs = ('phone-screenshots', 'tablet-screenshots',
                          'large-tablet-screenshots', 'tv-screenshots', 'wear-screenshots')
    setting_gradle_pattern = re.compile(r"""\s*include\s+["']:([^"']+)["'](?:,[\n\s]*["']:([^"']+)["'])*""")

    for packageName, app in apps.items():
        builds = app.get('Builds', [])
        gradle_subdirs = set()
        if builds and builds[-1].subdir:
            for flavor in builds[-1].gradle:
                if flavor not in ('yes', 'no', True, False):
                    p = os.path.join('build', packageName, builds[-1].subdir, 'src', flavor, 'play')
                    if os.path.exists(p):
                        gradle_subdirs.add(p)
            if not gradle_subdirs:
                gradle_subdirs.update(glob.glob(os.path.join('build', packageName, builds[-1].subdir, 'src', '*', 'play')))
            if not gradle_subdirs:
                gradle_subdirs.update(glob.glob(os.path.join('build', packageName, builds[-1].subdir, '*', 'src', '*', 'play')))
        if not gradle_subdirs:
            sg_list = sorted(glob.glob(os.path.join('build', packageName, 'settings.gradle*')))
            if sg_list:
                settings_gradle = sg_list[0]
                with open(settings_gradle, encoding='utf-8') as fp:
                    data = fp.read()
                for matches in setting_gradle_pattern.findall(data):
                    for m in matches:
                        if m:
                            gradle_path = m.replace(':', '/')
                            p = os.path.join('build', packageName, gradle_path, 'src', 'main', 'play')
                            if os.path.exists(p):
                                gradle_subdirs.add(p)
                            flavors = builds[-1].gradle if builds else []
                            for flavor in flavors:
                                if flavor not in ('yes', 'no', True, False):
                                    p = os.path.join('build', packageName, gradle_path, 'src', flavor, 'play')
                                    if os.path.exists(p):
                                        gradle_subdirs.add(p)
        if not gradle_subdirs:
            gradle_subdirs.update(glob.glob(os.path.join('build', packageName, '*', 'src', '*', 'play')))

        for d in sorted(gradle_subdirs):
            logging.debug('Triple-T Gradle Play Publisher: ' + d)
            for root, dirs, files in os.walk(d):
                segments = root.split('/')
                if segments[-2] == 'listings' or segments[-2] == 'release-notes':
                    locale = segments[-1]
                else:
                    locale = segments[-2]

                for f in files:
                    if f == 'fulldescription' or f == 'full-description.txt':
                        _set_localized_text_entry(app, locale, 'description',
                                                  os.path.join(root, f))
                    elif f == 'shortdescription' or f == 'short-description.txt':
                        _set_localized_text_entry(app, locale, 'summary',
                                                  os.path.join(root, f))
                    elif f == 'title' or f == 'title.txt':
                        _set_localized_text_entry(app, locale, 'name',
                                                  os.path.join(root, f))
                    elif f == 'video' or f == 'video-url.txt':
                        _set_localized_text_entry(app, locale, 'video',
                                                  os.path.join(root, f))
                    elif f == 'whatsnew':
                        _set_localized_text_entry(app, segments[-1], 'whatsNew',
                                                  os.path.join(root, f))
                    elif f == 'default.txt' and segments[-2] == 'release-notes':
                        _set_localized_text_entry(app, locale, 'whatsNew',
                                                  os.path.join(root, f))
                    elif f == 'contactEmail' or f == 'contact-email.txt':
                        _set_author_entry(app, 'authorEmail', os.path.join(root, f))
                    elif f == 'contactPhone' or f == 'contact-phone.txt':
                        _set_author_entry(app, 'authorPhone', os.path.join(root, f))
                    elif f == 'contactWebsite' or f == 'contact-website.txt':
                        _set_author_entry(app, 'authorWebSite', os.path.join(root, f))
                    else:
                        base, extension = common.get_extension(f)
                        dirname = os.path.basename(root)
                        if extension in ALLOWED_EXTENSIONS \
                           and (dirname in GRAPHIC_NAMES or dirname in tt_graphic_names
                                or dirname in SCREENSHOT_DIRS or dirname in tt_screenshot_dirs):
                            repofilename = os.path.basename(f)
                            if segments[-2] == 'listing':
                                locale = segments[-3]
                            elif segments[-4] == 'listings':  # v2.x
                                locale = segments[-3]
                                if dirname in tt_graphic_names:
                                    repofilename = GRAPHIC_NAMES[tt_graphic_names.index(dirname)]
                                    repofilename += '.' + extension
                                    dirname = ''
                                else:
                                    dirname = SCREENSHOT_DIRS[tt_screenshot_dirs.index(dirname)]
                            else:
                                locale = segments[-2]
                            destdir = os.path.join('repo', packageName, locale, dirname)
                            os.makedirs(destdir, mode=0o755, exist_ok=True)
                            sourcefile = os.path.join(root, f)
                            destfile = os.path.join(destdir, repofilename)
                            _strip_and_copy_image(sourcefile, destfile)


def insert_localized_app_metadata(apps):
    """Scan standard locations for graphics and localized text.

    Scans for localized description files, changelogs, store graphics, and
    screenshots and adds them to the app metadata. Each app's source repo root
    checked out at /build/<packageName> is scanned at the following standard
    locations for these files...

    metadata/<locale>/
    fastlane/metadata/android/<locale>/
    src/<buildFlavor>/fastlane/metadata/android/<locale>/

    ...as well as the /metadata/<packageName>/<locale> directory.

    If it finds them, they will be added to the dict of all packages, with the
    versions in the /metadata/ folder taking precedence over the what
    is in the app's source repo.

    The <locale> is the locale of the files supplied in that directory, using
    the IETF RFC5646 format (e.g. en, en-US, ast, etc).

    For each <locale> directory, this script searches for the following files
    in the directory structure as supplied by fastlane. See
    https://github.com/fastlane/fastlane/blob/2.28.7/supply/README.md#images-and-screenshots

    See also our documentation page:
    https://f-droid.org/en/docs/All_About_Descriptions_Graphics_and_Screenshots/#in-the-apps-build-metadata-in-an-fdroiddata-collection
    """
    sourcedirs = glob.glob(os.path.join('build', '[A-Za-z]*', 'src', '[A-Za-z]*', 'fastlane', 'metadata', 'android', '[a-z][a-z]*'))
    sourcedirs += glob.glob(os.path.join('build', '[A-Za-z]*', 'fastlane', 'metadata', 'android', '[a-z][a-z]*'))
    sourcedirs += glob.glob(os.path.join('build', '[A-Za-z]*', 'metadata', '[a-z][a-z]*'))
    sourcedirs += glob.glob(os.path.join('metadata', '[A-Za-z]*', '[a-z][a-z]*'))

    for srcd in sorted(sourcedirs):
        if not os.path.isdir(srcd):
            continue
        for root, dirs, files in os.walk(srcd):
            segments = root.split('/')
            packageName = segments[1]
            if packageName not in apps:
                logging.debug(packageName + ' does not have app metadata, skipping l18n scan.')
                continue
            locale = segments[-1]
            destdir = os.path.join('repo', packageName, locale)

            # flavours specified in build receipt
            build_flavours = ""
            if (
                apps[packageName]
                and len(apps[packageName].get('Builds', [])) > 0
                and 'gradle' in apps[packageName]['Builds'][-1]
            ):
                build_flavours = apps[packageName]['Builds'][-1]['gradle']

            if len(segments) >= 5 and segments[4] == "fastlane" and segments[3] not in build_flavours:
                logging.debug("ignoring due to wrong flavour")
                continue

            for f in files:
                if f in ('description.txt', 'full_description.txt'):
                    _set_localized_text_entry(apps[packageName], locale, 'description',
                                              os.path.join(root, f))
                    continue
                elif f in ('summary.txt', 'short_description.txt'):
                    _set_localized_text_entry(apps[packageName], locale, 'summary',
                                              os.path.join(root, f))
                    continue
                elif f in ('name.txt', 'title.txt'):
                    _set_localized_text_entry(apps[packageName], locale, 'name',
                                              os.path.join(root, f))
                    continue
                elif f == 'video.txt':
                    _set_localized_text_entry(apps[packageName], locale, 'video',
                                              os.path.join(root, f))
                    continue
                elif f == str(apps[packageName]['CurrentVersionCode']) + '.txt':
                    locale = segments[-2]
                    _set_localized_text_entry(apps[packageName], locale, 'whatsNew',
                                              os.path.join(root, f))
                    continue

                base, extension = common.get_extension(f)
                if locale == 'images':
                    locale = segments[-2]
                    destdir = os.path.join('repo', packageName, locale)
                if base in GRAPHIC_NAMES and extension in ALLOWED_EXTENSIONS:
                    os.makedirs(destdir, mode=0o755, exist_ok=True)
                    _strip_and_copy_image(os.path.join(root, f), destdir)
            for d in dirs:
                if d in SCREENSHOT_DIRS:
                    if locale == 'images':
                        locale = segments[-2]
                        destdir = os.path.join('repo', packageName, locale)
                    for f in glob.glob(os.path.join(root, d, '*.*')):
                        _ignored, extension = common.get_extension(f)
                        if extension in ALLOWED_EXTENSIONS:
                            screenshotdestdir = os.path.join(destdir, d)
                            os.makedirs(screenshotdestdir, mode=0o755, exist_ok=True)
                            _strip_and_copy_image(f, screenshotdestdir)

    repodirs = sorted(glob.glob(os.path.join('repo', '[A-Za-z]*', '[a-z][a-z]*')))
    for d in repodirs:
        if not os.path.isdir(d):
            continue
        for f in sorted(glob.glob(os.path.join(d, '*.*')) + glob.glob(os.path.join(d, '*Screenshots', '*.*'))):
            if not os.path.isfile(f):
                continue
            segments = f.split('/')
            packageName = segments[1]
            locale = segments[2]
            screenshotdir = segments[3]
            filename = os.path.basename(f)
            base, sha256, extension = _get_base_hash_extension(filename)

            if packageName not in apps:
                logging.warning(_('Found "{path}" graphic without metadata for app "{name}"!')
                                .format(path=filename, name=packageName))
                continue
            graphics = _get_localized_dict(apps[packageName], locale)

            if extension not in ALLOWED_EXTENSIONS:
                logging.warning(_('Only PNG and JPEG are supported for graphics, found: {path}').format(path=f))
            elif base in GRAPHIC_NAMES:
                # there can only be zero or one of these per locale
                basename = base + '.' + extension
                basepath = os.path.join(os.path.dirname(f), basename)
                if sha256:
                    if not os.path.samefile(f, basepath):
                        os.unlink(f)
                else:
                    sha256 = common.sha256base64(f)
                    filename = base + '_' + sha256 + '.' + extension
                    index_file = os.path.join(os.path.dirname(f), filename)
                    if not os.path.exists(index_file):
                        os.link(f, index_file, follow_symlinks=False)
                    graphics[base] = filename
            elif screenshotdir in SCREENSHOT_DIRS:
                # there can any number of these per locale
                logging.debug(_('adding to {name}: {path}').format(name=screenshotdir, path=f))
                if screenshotdir not in graphics:
                    graphics[screenshotdir] = []
                graphics[screenshotdir].append(filename)
            else:
                logging.warning(_('Unsupported graphics file found: {path}').format(path=f))


def scan_repo_files(apkcache, repodir, knownapks, use_date_from_file=False):
    """Scan a repo for all files with an extension except APK/OBB.

    Parameters
    ----------
    apkcache
      current cached info about all repo files
    repodir
      repo directory to scan
    knownapks
      list of all known files, as per metadata.read_metadata
    use_date_from_file
      use date from file (instead of current date) for newly added files
    """
    cachechanged = False
    repo_files = []
    repodir = repodir.encode()
    for name in os.listdir(repodir):
        file_extension = common.get_file_extension(name)
        if file_extension == 'apk' or file_extension == 'obb':
            continue
        filename = os.path.join(repodir, name)
        name_utf8 = name.decode()
        if filename.endswith(b'_src.tar.gz'):
            logging.debug(_('skipping source tarball: {path}')
                          .format(path=filename.decode()))
            continue
        if not common.is_repo_file(filename):
            continue
        stat = os.stat(filename)
        if stat.st_size == 0:
            raise FDroidException(_('{path} is zero size!')
                                  .format(path=filename))

        shasum = common.sha256sum(filename)
        usecache = False
        if name_utf8 in apkcache:
            repo_file = apkcache[name_utf8]
            if repo_file.get('hash') == shasum:
                logging.debug(_("Reading {apkfilename} from cache")
                              .format(apkfilename=name_utf8))
                usecache = True
            else:
                logging.debug(_("Ignoring stale cache data for {apkfilename}")
                              .format(apkfilename=name_utf8))

        if not usecache:
            logging.debug(_("Processing {apkfilename}").format(apkfilename=name_utf8))
            repo_file = collections.OrderedDict()
            repo_file['name'] = os.path.splitext(name_utf8)[0]
            # TODO rename apkname globally to something more generic
            repo_file['apkName'] = name_utf8
            repo_file['hash'] = shasum
            repo_file['hashType'] = 'sha256'
            repo_file['versionCode'] = 0
            repo_file['versionName'] = shasum[0:7]
            # the static ID is the SHA256 unless it is set in the metadata
            repo_file['packageName'] = shasum

            m = common.STANDARD_FILE_NAME_REGEX.match(name_utf8)
            if m:
                repo_file['packageName'] = m.group(1)
                repo_file['versionCode'] = int(m.group(2))
            srcfilename = name + b'_src.tar.gz'
            if os.path.exists(os.path.join(repodir, srcfilename)):
                repo_file['srcname'] = srcfilename.decode()
            repo_file['size'] = stat.st_size

            apkcache[name_utf8] = repo_file
            cachechanged = True

        if use_date_from_file:
            timestamp = stat.st_ctime
            default_date_param = time.gmtime(time.mktime(datetime.fromtimestamp(timestamp).timetuple()))
        else:
            default_date_param = None

        # Record in knownapks, getting the added date at the same time..
        added = knownapks.recordapk(repo_file['apkName'], repo_file['packageName'],
                                    default_date=default_date_param)
        if added:
            repo_file['added'] = added

        repo_files.append(repo_file)

    return repo_files, cachechanged


def scan_apk(apk_file, require_signature=True):
    """Scan an APK file and returns dictionary with metadata of the APK.

    Attention: This does *not* verify that the APK signature is correct.

    Parameters
    ----------
    apk_file
      The (ideally absolute) path to the APK file
    require_signature
      Raise an exception is there is no valid signature. Default to True.

    Raises
    ------
    BuildException

    Returns
    -------
    A dict containing APK metadata
    """
    apk = {
        'hash': common.sha256sum(apk_file),
        'hashType': 'sha256',
        'uses-permission': [],
        'uses-permission-sdk-23': [],
        'features': [],
        'icons_src': {},
        'icons': {},
        'antiFeatures': set(),
    }

    scan_apk_androguard(apk, apk_file)

    if not common.is_valid_package_name(apk['packageName']):
        raise BuildException(_("{appid} from {path} is not a valid Java Package Name!")
                             .format(appid=apk['packageName'], path=apk_file))
    elif not common.is_strict_application_id(apk['packageName']):
        logging.warning(_("{appid} from {path} is not a valid Android application ID!")
                        .format(appid=apk['packageName'], path=apk_file))

    # Get the signature, or rather the signing key fingerprints
    logging.debug('Getting signature of {0}'.format(os.path.basename(apk_file)))
    apk['sig'] = getsig(apk_file)
    if require_signature:
        if not apk['sig']:
            raise BuildException(_("Failed to get APK signing key fingerprint"))
        apk['signer'] = common.apk_signer_fingerprint(
            os.path.join(os.getcwd(), apk_file)
        )
        if not apk.get('signer'):
            raise BuildException(_("Failed to get APK signing key fingerprint"))

    # Get size of the APK
    apk['size'] = os.path.getsize(apk_file)

    if 'minSdkVersion' not in apk:
        logging.warning(_("No minimum SDK version found in {0}, using default (3).").format(apk_file))
        apk['minSdkVersion'] = 3  # aapt defaults to 3 as the min

    # Check for known vulnerabilities
    if has_known_vulnerability(apk_file):
        apk['antiFeatures'].add('KnownVuln')

    return apk


def _get_apk_icons_src(apkfile, icon_name):
    """Extract the paths to the app icon in all available densities.

    The folder name is normally generated by the Android Tools, but
    there is nothing that prevents people from using whatever DPI
    names they make up.  Android will just ignore them, so we should
    too.

    """
    icons_src = dict()
    density_re = re.compile(r'^res/(.*)/{}\.png$'.format(icon_name))
    with zipfile.ZipFile(apkfile) as zf:
        for filename in zf.namelist():
            m = density_re.match(filename)
            if m:
                folder = m.group(1).split('-')
                try:
                    density = screen_resolutions[folder[1]]
                except Exception:
                    density = '160'
                icons_src[density] = m.group(0)
    if icons_src.get('-1') is None and '160' in icons_src:
        icons_src['-1'] = icons_src['160']
    return icons_src


def _sanitize_sdk_version(value):
    """Sanitize the raw values from androguard to handle bad values.

    minSdkVersion/targetSdkVersion/maxSdkVersion must be integers, but
    that doesn't stop devs from doing strange things like setting them
    using Android XML strings. This method makes the Androguard output
    match the output from `aapt dump badging`: bad values are ignored.

    https://gitlab.com/souch/SMSbypass/blob/v0.9/app/src/main/AndroidManifest.xml#L29
    https://gitlab.com/souch/SMSbypass/blob/v0.9/app/src/main/res/values/strings.xml#L27

    """
    try:
        sdk_version = int(value)
        if sdk_version > 0:
            return sdk_version
    except (TypeError, ValueError):
        pass
    return None


def scan_apk_androguard(apk, apkfile):
    try:
        from androguard.core.bytecodes.apk import APK
        apkobject = APK(apkfile)
        if apkobject.is_valid_APK():
            arsc = apkobject.get_android_resources()
        else:
            if options.delete_unknown:
                if os.path.exists(apkfile):
                    logging.error(_("Failed to get APK information, deleting {path}")
                                  .format(path=apkfile))
                    os.remove(apkfile)
                else:
                    logging.error(_("Could not find {path} to remove it")
                                  .format(path=apkfile))
            else:
                logging.error(_("Failed to get APK information, skipping {path}")
                              .format(path=apkfile))
            raise BuildException(_("Invalid APK"))
    except (FileNotFoundError, zipfile.BadZipFile) as e:
        logging.error(_("Could not open APK {path} for analysis: ").format(path=apkfile)
                      + str(e))
        raise BuildException(_("Invalid APK"))

    apk['packageName'] = apkobject.get_package()

    xml = apkobject.get_android_manifest_xml()
    androidmanifest_xml = apkobject.xml['AndroidManifest.xml']
    if len(xml.nsmap) > 0:
        # one of them surely will be the Android one, or its corrupt
        xmlns = common.XMLNS_ANDROID
    else:
        # strange but sometimes the namespace is blank.  This seems to
        # only happen with the Bromite/Chromium APKs
        xmlns = '{}'

    vcstr = androidmanifest_xml.get(xmlns + 'versionCode')

    if vcstr.startswith('0x'):
        apk['versionCode'] = int(vcstr, 16)
    else:
        apk['versionCode'] = int(vcstr)
    apk['name'] = apkobject.get_app_name()

    apk['versionName'] = common.ensure_final_value(apk['packageName'], arsc,
                                                   androidmanifest_xml.get(xmlns + 'versionName'))

    minSdkVersion = _sanitize_sdk_version(apkobject.get_min_sdk_version())
    if minSdkVersion is not None:
        apk['minSdkVersion'] = minSdkVersion

    targetSdkVersion = _sanitize_sdk_version(apkobject.get_target_sdk_version())
    if targetSdkVersion is not None:
        apk['targetSdkVersion'] = targetSdkVersion

    maxSdkVersion = _sanitize_sdk_version(apkobject.get_max_sdk_version())
    if maxSdkVersion is not None:
        apk['maxSdkVersion'] = maxSdkVersion

    icon_id_str = apkobject.get_element("application", "icon")
    if icon_id_str:
        try:
            icon_id = int(icon_id_str.replace("@", "0x"), 16)
            resource_id = arsc.get_id(apk['packageName'], icon_id)
            if resource_id:
                icon_name = arsc.get_id(apk['packageName'], icon_id)[1]
            else:
                # don't use 'anydpi' aka 0xFFFE aka 65534 since it is XML
                icon_name = os.path.splitext(os.path.basename(apkobject.get_app_icon(max_dpi=65534 - 1)))[0]
            apk['icons_src'] = _get_apk_icons_src(apkfile, icon_name)
        except Exception as e:
            logging.error("Cannot fetch icon from %s: %s" % (apkfile, str(e)))

    arch_re = re.compile("^lib/(.*)/.*$")
    arch = set([arch_re.match(file).group(1) for file in apkobject.get_files() if arch_re.match(file)])
    if len(arch) >= 1:
        apk['nativecode'] = []
        apk['nativecode'].extend(sorted(list(arch)))

    for item in xml.findall('uses-permission'):
        name = str(item.attrib[xmlns + 'name'])
        maxSdkVersion = item.attrib.get(xmlns + 'maxSdkVersion')
        maxSdkVersion = int(maxSdkVersion) if maxSdkVersion else None
        permission = UsesPermission(
            name,
            maxSdkVersion
        )
        apk['uses-permission'].append(permission)
    for name, maxSdkVersion in apkobject.get_uses_implied_permission_list():
        permission = UsesPermission(
            name,
            maxSdkVersion
        )
        apk['uses-permission'].append(permission)

    for item in xml.findall('uses-permission-sdk-23'):
        name = str(item.attrib[xmlns + 'name'])
        maxSdkVersion = item.attrib.get(xmlns + 'maxSdkVersion')
        maxSdkVersion = int(maxSdkVersion) if maxSdkVersion else None
        permission_sdk_23 = UsesPermissionSdk23(
            name,
            maxSdkVersion
        )
        apk['uses-permission-sdk-23'].append(permission_sdk_23)

    for item in xml.findall('uses-feature'):
        key = xmlns + 'name'
        if key not in item.attrib:
            continue
        feature = str(item.attrib[key])
        if feature != "android.hardware.screen.portrait" \
                and feature != "android.hardware.screen.landscape":
            if feature.startswith("android.feature."):
                feature = feature[16:]
        required = item.attrib.get(xmlns + 'required')
        if required is None or required == 'true':
            apk['features'].append(feature)


def process_apk(apkcache, apkfilename, repodir, knownapks, use_date_from_apk=False,
                allow_disabled_algorithms=False, archive_bad_sig=False):
    """Process the apk with the given filename in the given repo directory.

    This also extracts the icons.

    Parameters
    ----------
    apkcache
      current apk cache information
    apkfilename
      the filename of the apk to scan
    repodir
      repo directory to scan
    knownapks
      known apks info
    use_date_from_apk
      use date from APK (instead of current date) for newly added APKs
    allow_disabled_algorithms
      allow APKs with valid signatures that include
      disabled algorithms in the signature (e.g. MD5)
    archive_bad_sig
      move APKs with a bad signature to the archive

    Returns
    -------
    (skip, apk, cachechanged) where skip is a boolean indicating whether to skip this apk,
      apk is the scanned apk information, and cachechanged is True if the apkcache got changed.
    """
    apk = {}
    apkfile = os.path.join(repodir, apkfilename)

    cachechanged = False
    usecache = False
    if apkfilename in apkcache:
        apk = apkcache[apkfilename]
        if apk.get('hash') == common.sha256sum(apkfile):
            logging.debug(_("Reading {apkfilename} from cache")
                          .format(apkfilename=apkfilename))
            usecache = True
        else:
            logging.debug(_("Ignoring stale cache data for {apkfilename}")
                          .format(apkfilename=apkfilename))

    if not usecache:
        logging.debug(_("Processing {apkfilename}").format(apkfilename=apkfilename))

        try:
            apk = scan_apk(apkfile)
        except BuildException:
            logging.warning(_("Skipping '{apkfilename}' with invalid signature!")
                            .format(apkfilename=apkfilename))
            return True, None, False

        # Check for debuggable apks...
        if common.is_apk_and_debuggable(apkfile):
            logging.warning('{0} is set to android:debuggable="true"'.format(apkfile))

        if options.rename_apks:
            n = apk['packageName'] + '_' + str(apk['versionCode']) + '.apk'
            std_short_name = os.path.join(repodir, n)
            if apkfile != std_short_name:
                if os.path.exists(std_short_name):
                    std_long_name = std_short_name.replace('.apk', '_' + apk['sig'][:7] + '.apk')
                    if apkfile != std_long_name:
                        if os.path.exists(std_long_name):
                            dupdir = os.path.join('duplicates', repodir)
                            if not os.path.isdir(dupdir):
                                os.makedirs(dupdir, exist_ok=True)
                            dupfile = os.path.join('duplicates', std_long_name)
                            logging.warning('Moving duplicate ' + std_long_name + ' to ' + dupfile)
                            os.rename(apkfile, dupfile)
                            return True, None, False
                        else:
                            os.rename(apkfile, std_long_name)
                    apkfile = std_long_name
                else:
                    os.rename(apkfile, std_short_name)
                    apkfile = std_short_name
                apkfilename = apkfile[len(repodir) + 1:]

        apk['apkName'] = apkfilename
        srcfilename = apkfilename[:-4] + "_src.tar.gz"
        if os.path.exists(os.path.join(repodir, srcfilename)):
            apk['srcname'] = srcfilename

        # verify the jar signature is correct, allow deprecated
        # algorithms only if the APK is in the archive.
        skipapk = False
        if not common.verify_apk_signature(apkfile):
            if repodir == 'archive' or allow_disabled_algorithms:
                if common.verify_old_apk_signature(apkfile):
                    apk['antiFeatures'].update(['KnownVuln', 'DisabledAlgorithm'])
                else:
                    skipapk = True
            else:
                skipapk = True

        if skipapk:
            if archive_bad_sig:
                logging.warning(_('Archiving {apkfilename} with invalid signature!')
                                .format(apkfilename=apkfilename))
                move_apk_between_sections(repodir, 'archive', apk)
            else:
                logging.warning(_('Skipping {apkfilename} with invalid signature!')
                                .format(apkfilename=apkfilename))
            return True, None, False

        apkzip = zipfile.ZipFile(apkfile, 'r')

        manifest = apkzip.getinfo('AndroidManifest.xml')
        # 1980-0-0 means zeroed out, any other invalid date should trigger a warning
        if (1980, 0, 0) != manifest.date_time[0:3]:
            try:
                common.check_system_clock(datetime(*manifest.date_time), apkfilename)
            except ValueError as e:
                logging.warning(_("{apkfilename}'s AndroidManifest.xml has a bad date: ")
                                .format(apkfilename=apkfile) + str(e))

        # extract icons from APK zip file
        iconfilename = "%s.%s.png" % (apk['packageName'], apk['versionCode'])
        try:
            empty_densities = extract_apk_icons(iconfilename, apk, apkzip, repodir)
        finally:
            apkzip.close()  # ensure that APK zip file gets closed

        # resize existing icons for densities missing in the APK
        fill_missing_icon_densities(empty_densities, iconfilename, apk, repodir)

        if use_date_from_apk and manifest.date_time[1] != 0:
            default_date_param = datetime(*manifest.date_time)
        else:
            default_date_param = None

        # Record in known apks, getting the added date at the same time..
        added = knownapks.recordapk(apk['apkName'], apk['packageName'],
                                    default_date=default_date_param)
        if added:
            apk['added'] = added

        apkcache[apkfilename] = apk
        cachechanged = True

    return False, apk, cachechanged


def process_apks(apkcache, repodir, knownapks, use_date_from_apk=False):
    """Process the apks in the given repo directory.

    This also extracts the icons.

    Parameters
    ----------
    apkcache
      current apk cache information
    repodir
      repo directory to scan
    knownapks
     b known apks info
    use_date_from_apk
      use date from APK (instead of current date) for newly added APKs

    Returns
    -------
    (apks, cachechanged) where apks is a list of apk information,
      and cachechanged is True if the apkcache got changed.
    """
    cachechanged = False

    for icon_dir in get_all_icon_dirs(repodir):
        if os.path.exists(icon_dir):
            if options is not None and options.clean:
                shutil.rmtree(icon_dir)
                os.makedirs(icon_dir)
        else:
            os.makedirs(icon_dir)

    apks = []
    for apkfile in sorted(glob.glob(os.path.join(repodir, '*.apk'))):
        apkfilename = apkfile[len(repodir) + 1:]
        ada = disabled_algorithms_allowed()
        (skip, apk, cachethis) = process_apk(apkcache, apkfilename, repodir, knownapks,
                                             use_date_from_apk, ada, True)
        if skip:
            continue
        apks.append(apk)
        cachechanged = cachechanged or cachethis

    return apks, cachechanged


def extract_apk_icons(icon_filename, apk, apkzip, repo_dir):
    """Extract PNG icons from an APK with the supported pixel densities.

    Extracts icons from the given APK zip in various densities, saves
    them into given repo directory and stores their names in the APK
    metadata dictionary.  If the icon is an XML icon, then this tries
    to find PNG icon that can replace it.

    Parameters
    ----------
    icon_filename
      A string representing the icon's file name
    apk
      A populated dictionary containing APK metadata.
      Needs to have 'icons_src' key
    apkzip
      An opened zipfile.ZipFile of the APK file
    repo_dir
      The directory of the APK's repository

    Returns
    -------
    A list of icon densities that are missing

    """
    res_name_re = re.compile(r'res/(drawable|mipmap)-(x*[hlm]dpi|anydpi).*/(.*)_[0-9]+dp.(png|xml)')
    pngs = dict()
    for f in apkzip.namelist():
        m = res_name_re.match(f)
        if m and m.group(4) == 'png':
            density = screen_resolutions[m.group(2)]
            pngs[m.group(3) + '/' + density] = m.group(0)
    empty_densities = []
    for density in screen_densities:
        if density not in apk['icons_src']:
            empty_densities.append(density)
            continue
        icon_src = apk['icons_src'][density]
        icon_dir = get_icon_dir(repo_dir, density)
        icon_dest = os.path.join(icon_dir, icon_filename)

        # Extract the icon files per density
        if icon_src.endswith('.xml'):
            m = res_name_re.match(icon_src)
            if m:
                name = pngs.get(m.group(3) + '/' + str(density))
                if name:
                    icon_src = name
            if icon_src.endswith('.xml'):
                empty_densities.append(density)
                continue
        try:
            with open(icon_dest, 'wb') as f:
                f.write(get_icon_bytes(apkzip, icon_src))
            apk['icons'][density] = icon_filename
        except (zipfile.BadZipFile, ValueError, KeyError) as e:
            logging.warning("Error retrieving icon file: %s %s", icon_dest, e)
            del apk['icons_src'][density]
            empty_densities.append(density)

    # '-1' here is a remnant of the parsing of aapt output, meaning "no DPI specified"
    if '-1' in apk['icons_src'] and not apk['icons_src']['-1'].endswith('.xml'):
        icon_src = apk['icons_src']['-1']
        icon_path = os.path.join(get_icon_dir(repo_dir, '0'), icon_filename)
        with open(icon_path, 'wb') as f:
            f.write(get_icon_bytes(apkzip, icon_src))
        im = None
        try:
            im = Image.open(icon_path)
            dpi = px_to_dpi(im.size[0])
            for density in screen_densities:
                if density in apk['icons']:
                    break
                if density == screen_densities[-1] or dpi >= int(density):
                    apk['icons'][density] = icon_filename
                    shutil.move(icon_path,
                                os.path.join(get_icon_dir(repo_dir, density), icon_filename))
                    empty_densities.remove(density)
                    break
        except Exception as e:
            logging.warning(_("Failed reading {path}: {error}")
                            .format(path=icon_path, error=e))
        finally:
            if im and hasattr(im, 'close'):
                im.close()

    if apk['icons']:
        apk['icon'] = icon_filename

    return empty_densities


def fill_missing_icon_densities(empty_densities, icon_filename, apk, repo_dir):
    """Resize existing PNG icons for densities missing in the APK to ensure all densities are available.

    Parameters
    ----------
    empty_densities: A list of icon densities that are missing
    icon_filename: A string representing the icon's file name
    apk: A populated dictionary containing APK metadata. Needs to have 'icons' key
    repo_dir: The directory of the APK's repository

    """
    # First try resizing down to not lose quality
    last_density = None
    for density in screen_densities:
        if density == '65534':  # not possible to generate 'anydpi' from other densities
            continue
        if density not in empty_densities:
            last_density = density
            continue
        if last_density is None:
            continue
        logging.debug("Density %s not available, resizing down from %s", density, last_density)

        last_icon_path = os.path.join(get_icon_dir(repo_dir, last_density), icon_filename)
        icon_path = os.path.join(get_icon_dir(repo_dir, density), icon_filename)
        fp = None
        try:
            fp = open(last_icon_path, 'rb')
            im = Image.open(fp)

            size = dpi_to_px(density)

            im.thumbnail((size, size), Image.ANTIALIAS)
            im.save(icon_path, "PNG", optimize=True,
                    pnginfo=BLANK_PNG_INFO, icc_profile=None)
            empty_densities.remove(density)
        except Exception as e:
            logging.warning("Invalid image file at %s: %s", last_icon_path, e)
        finally:
            if fp:
                fp.close()

    # Then just copy from the highest resolution available
    last_density = None
    for density in reversed(screen_densities):
        if density not in empty_densities:
            last_density = density
            continue

        if last_density is None:
            continue

        shutil.copyfile(
            os.path.join(get_icon_dir(repo_dir, last_density), icon_filename),
            os.path.join(get_icon_dir(repo_dir, density), icon_filename)
        )
        empty_densities.remove(density)

    for density in screen_densities:
        icon_dir = get_icon_dir(repo_dir, density)
        icon_dest = os.path.join(icon_dir, icon_filename)
        resize_icon(icon_dest, density)

    # Copy from icons-mdpi to icons since mdpi is the baseline density
    baseline = os.path.join(get_icon_dir(repo_dir, '160'), icon_filename)
    if os.path.isfile(baseline):
        apk['icons']['0'] = icon_filename
        shutil.copyfile(baseline, os.path.join(get_icon_dir(repo_dir, '0'), icon_filename))


def apply_info_from_latest_apk(apps, apks):
    """No summary.

    Some information from the apks needs to be applied up to the application level.

    When doing this, we use the info from the most recent version's apk.
    We deal with figuring out when the app was added and last updated at the same time.
    """
    for appid, app in apps.items():
        bestver = UNSET_VERSION_CODE
        for apk in apks:
            if apk['packageName'] == appid:
                if apk['versionCode'] > bestver:
                    bestver = apk['versionCode']
                    bestapk = apk

                if app.get('NoSourceSince'):
                    apk['antiFeatures'].add('NoSourceSince')

        if not app['added']:
            logging.debug("Don't know when " + appid + " was added")
        if not app['lastUpdated']:
            logging.debug("Don't know when " + appid + " was last updated")

        if bestver == UNSET_VERSION_CODE:
            app['icon'] = None
            logging.debug("Application " + appid + " has no packages")
        else:
            app.icon = bestapk['icon'] if 'icon' in bestapk else None
            if app.get('CurrentVersionCode') is None:
                app['CurrentVersionCode'] = str(bestver)


def make_categories_txt(repodir, categories):
    """Write a category list in the repo to allow quick access."""
    catdata = ''
    for cat in sorted(categories):
        catdata += cat + '\n'
    with open(os.path.join(repodir, 'categories.txt'), 'w') as f:
        f.write(catdata)


def archive_old_apks(apps, apks, archapks, repodir, archivedir, defaultkeepversions):
    def filter_apk_list_sorted(apk_list):
        apkList = []
        currentVersionApk = None
        for apk in apk_list:
            if apk['packageName'] == appid:
                if app.get('CurrentVersionCode') is not None:
                    if apk['versionCode'] == common.version_code_string_to_int(app['CurrentVersionCode']):
                        currentVersionApk = apk
                        continue
                apkList.append(apk)

        # Sort the apk list by version code. First is highest/newest.
        sorted_list = sorted(apkList, key=lambda apk: apk['versionCode'], reverse=True)
        if currentVersionApk:
            # Insert apk which corresponds to currentVersion at the front
            sorted_list.insert(0, currentVersionApk)
        return sorted_list

    for appid, app in apps.items():

        if app.get('ArchivePolicy'):
            keepversions = int(app['ArchivePolicy'][:-9])
        else:
            keepversions = defaultkeepversions

        logging.debug(_("Checking archiving for {appid} - apks:{integer}, keepversions:{keep}, archapks:{arch}")
                      .format(appid=appid, integer=len(apks), keep=keepversions, arch=len(archapks)))

        all_app_apks = filter_apk_list_sorted(apks + archapks)

        # determine which apks to keep in repo
        keep = []
        for apk in all_app_apks:
            if len(keep) == keepversions:
                break
            if 'antiFeatures' not in apk:
                keep.append(apk)
            elif 'DisabledAlgorithm' not in apk['antiFeatures'] or disabled_algorithms_allowed():
                keep.append(apk)

        # actually move apks to the target section
        for apk in all_app_apks:
            if apk in apks and apk not in keep:
                apks.remove(apk)
                archapks.append(apk)
                move_apk_between_sections(repodir, archivedir, apk)
            elif apk in archapks and apk in keep:
                archapks.remove(apk)
                apks.append(apk)
                move_apk_between_sections(archivedir, repodir, apk)


def move_apk_between_sections(from_dir, to_dir, apk):
    """Move an APK from repo to archive or vice versa."""
    def _move_file(from_dir, to_dir, filename, ignore_missing):
        from_path = os.path.join(from_dir, filename)
        if ignore_missing and not os.path.exists(from_path):
            return
        to_path = os.path.join(to_dir, filename)
        if not os.path.exists(to_dir):
            os.mkdir(to_dir)
        shutil.move(from_path, to_path)

    if from_dir == to_dir:
        return

    logging.info("Moving %s from %s to %s" % (apk['apkName'], from_dir, to_dir))
    _move_file(from_dir, to_dir, apk['apkName'], False)
    _move_file(from_dir, to_dir, apk['apkName'] + '.asc', True)
    _move_file(from_dir, to_dir, apk['apkName'][:-4] + '.log.gz', True)
    for density in all_screen_densities:
        from_icon_dir = get_icon_dir(from_dir, density)
        to_icon_dir = get_icon_dir(to_dir, density)
        if density not in apk.get('icons', []):
            continue
        _move_file(from_icon_dir, to_icon_dir, apk['icons'][density], True)
    if 'srcname' in apk:
        _move_file(from_dir, to_dir, apk['srcname'], False)


def add_apks_to_per_app_repos(repodir, apks):
    apks_per_app = dict()
    for apk in apks:
        apk['per_app_dir'] = os.path.join(apk['packageName'], 'fdroid')
        apk['per_app_repo'] = os.path.join(apk['per_app_dir'], 'repo')
        apk['per_app_icons'] = os.path.join(apk['per_app_repo'], 'icons')
        apks_per_app[apk['packageName']] = apk

        if not os.path.exists(apk['per_app_icons']):
            logging.info(_('Adding new repo for only {name}').format(name=apk['packageName']))
            os.makedirs(apk['per_app_icons'])

        apkpath = os.path.join(repodir, apk['apkName'])
        shutil.copy(apkpath, apk['per_app_repo'])
        apksigpath = apkpath + '.sig'
        if os.path.exists(apksigpath):
            shutil.copy(apksigpath, apk['per_app_repo'])
        apkascpath = apkpath + '.asc'
        if os.path.exists(apkascpath):
            shutil.copy(apkascpath, apk['per_app_repo'])


def create_metadata_from_template(apk):
    """Create a new metadata file using internal or external template.

    Generate warnings for apk's with no metadata (or create skeleton
    metadata files, if requested on the command line).  Though the
    template file is YAML, this uses neither pyyaml nor ruamel.yaml
    since those impose things on the metadata file made from the
    template: field sort order, empty field value, formatting, etc.
    """
    if os.path.exists('template.yml'):
        with open('template.yml') as f:
            metatxt = f.read()
        if 'name' in apk and apk['name'] != '':
            metatxt = re.sub(r'''^(((Auto)?Name|Summary):)[ '"\.]*$''',
                             r'\1 ' + apk['name'],
                             metatxt,
                             flags=re.IGNORECASE | re.MULTILINE)
        else:
            logging.warning(_('{appid} does not have a name! Using application ID instead.')
                            .format(appid=apk['packageName']))
            metatxt = re.sub(r'^(((Auto)?Name|Summary):).*$',
                             r'\1 ' + apk['packageName'],
                             metatxt,
                             flags=re.IGNORECASE | re.MULTILINE)
        # make sure unset string values will be interpreted as blank strings
        str_fields = [x for x in metadata.yaml_app_fields if metadata.fieldtype(x) == metadata.TYPE_STRING]
        metatxt = re.sub(r'^(' + '|'.join(str_fields) + '):\\s*$',
                         r"\1: ''", metatxt,
                         flags=re.MULTILINE)
        with open(os.path.join('metadata', apk['packageName'] + '.yml'), 'w') as f:
            f.write(metatxt)
    else:
        app = dict()
        app['Categories'] = [os.path.basename(os.getcwd())]
        # include some blanks as part of the template
        app['AuthorName'] = ''
        app['Summary'] = ''
        app['WebSite'] = ''
        app['IssueTracker'] = ''
        app['SourceCode'] = ''
        app['CurrentVersionCode'] = 2147483647  # Java's Integer.MAX_VALUE
        if 'name' in apk and apk['name'] != '':
            app['Name'] = apk['name']
        else:
            logging.warning(_('{appid} does not have a name! Using application ID instead.')
                            .format(appid=apk['packageName']))
            app['Name'] = apk['packageName']
        with open(os.path.join('metadata', apk['packageName'] + '.yml'), 'w') as f:
            yaml.dump(app, f, default_flow_style=False)
    logging.info(_("Generated skeleton metadata for {appid}").format(appid=apk['packageName']))


def read_added_date_from_all_apks(apps, apks):
    """No summary.

    Added dates come from the stats/known_apks.txt file but are
    read when scanning apks and thus need to be applied form apk
    level to app level for _all_ apps and not only from non-archived
    ones

    TODO: read the added dates directly from known_apks.txt instead of
          going through apks that way it also works for for repos that
          don't keep an archive of apks.
    """
    for appid, app in apps.items():
        for apk in apks:
            if apk['packageName'] == appid:
                if 'added' in apk:
                    if not app.get('added') or apk['added'] < app['added']:
                        app['added'] = apk['added']
                    if not app.get('lastUpdated') or apk['added'] > app['lastUpdated']:
                        app['lastUpdated'] = apk['added']


def insert_missing_app_names_from_apks(apps, apks):
    """Use app name from APK if it is not set in the metadata.

    Name -> localized -> from APK

    The name from the APK is set as the default name for the app if
    there is no other default set, e.g. app['Name'] or
    app['localized']['en-US']['name'].  The en-US locale is defined in
    the F-Droid ecosystem as the locale of last resort, as in the one
    that should always be present.  en-US is used since it is the
    locale of the source strings.

    This should only be used for index v0 and v1.  Later versions of
    the index should be sorted by Application ID, since it is
    guaranteed to always be there.  Before, the index was stored by
    the app name (aka <application android:label="">) to save the
    website from having to sort the entries.  That is no longer
    relevant since the website switched from Wordpress to Jekyll.

    """
    for appid, app in apps.items():
        if app.get('Name') is not None:
            continue
        if app.get('localized', {}).get('en-US', {}).get('name') is not None:
            continue

        bestver = UNSET_VERSION_CODE
        for apk in apks:
            if apk['packageName'] == appid:
                if apk.get('name') and apk['versionCode'] > bestver:
                    bestver = apk['versionCode']
                    bestapk = apk

        if bestver != UNSET_VERSION_CODE:
            if 'localized' not in app:
                app['localized'] = {}
            if 'en-US' not in app['localized']:
                app['localized']['en-US'] = {}
            app['localized']['en-US']['name'] = bestapk.get('name')


def get_apps_with_packages(apps, apks):
    """Return a deepcopy of that subset apps that actually has any associated packages. Skips disabled apps."""
    appsWithPackages = collections.OrderedDict()
    for packageName in apps:
        app = apps[packageName]
        if app['Disabled']:
            continue

        # only include apps with packages
        for apk in apks:
            if apk['packageName'] == packageName:
                newapp = copy.copy(app)
                appsWithPackages[packageName] = newapp
                break
    return appsWithPackages


def get_apks_without_allowed_signatures(app, apk):
    """Check the APK or package has been signed by one of the allowed signing certificates.

    The fingerprint of the signing certificate is the standard X.509
    SHA-256 fingerprint as a hex string.  It can be fetched from an
    APK using:

    apksigner verify --print-certs my.apk | grep SHA-256

    Parameters
    ----------
    app
      The app which declares the AllowedSigningKey
    apk
      The APK to check
    """
    if not app or not apk:
        return
    allowed_signer_keys = app.get('AllowedAPKSigningKeys', [])
    if not allowed_signer_keys:
        return
    if apk['signer'] not in allowed_signer_keys:
        return apk['apkName']


def prepare_apps(apps, apks, repodir):
    """Encapsulate all necessary preparation steps before we can build an index out of apps and apks.

    Parameters
    ----------
    apps
      All apps as read from metadata
    apks
      list of apks that belong into repo, this gets modified in place
    repodir
      the target repository directory, metadata files will be copied here

    Returns
    -------
    the relevant subset of apps (as a deepcopy)
    """
    apps_with_packages = get_apps_with_packages(apps, apks)
    apply_info_from_latest_apk(apps_with_packages, apks)
    insert_funding_yml_donation_links(apps)
    # This is only currently done for /repo because doing it for the archive
    # will take a lot of time and bloat the archive mirrors and index
    if repodir == 'repo':
        copy_triple_t_store_metadata(apps_with_packages)
    insert_obbs(repodir, apps_with_packages, apks)
    translate_per_build_anti_features(apps_with_packages, apks)
    if repodir == 'repo':
        insert_localized_app_metadata(apps_with_packages)
    insert_missing_app_names_from_apks(apps_with_packages, apks)
    return apps_with_packages


config = None
options = None
start_timestamp = time.gmtime()


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument("--create-key", action="store_true", default=False,
                        help=_("Add a repo signing key to an unsigned repo"))
    parser.add_argument("-c", "--create-metadata", action="store_true", default=False,
                        help=_("Add skeleton metadata files for APKs that are missing them"))
    parser.add_argument("--delete-unknown", action="store_true", default=False,
                        help=_("Delete APKs and/or OBBs without metadata from the repo"))
    parser.add_argument("-I", "--icons", action="store_true", default=False,
                        help=_("Resize all the icons exceeding the max pixel size and exit"))
    parser.add_argument("-w", "--wiki", default=False, action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--pretty", action="store_true", default=False,
                        help=_("Produce human-readable XML/JSON for index files"))
    parser.add_argument("--clean", action="store_true", default=False,
                        help=_("Clean update - don't uses caches, reprocess all APKs"))
    parser.add_argument("--nosign", action="store_true", default=False,
                        help=_("When configured for signed indexes, create only unsigned indexes at this stage"))
    parser.add_argument("--use-date-from-apk", action="store_true", default=False,
                        help=_("Use date from APK instead of current time for newly added APKs"))
    parser.add_argument("--rename-apks", action="store_true", default=False,
                        help=_("Rename APK files that do not match package.name_123.apk"))
    parser.add_argument("--allow-disabled-algorithms", action="store_true", default=False,
                        help=_("Include APKs that are signed with disabled algorithms like MD5"))
    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    metadata.warnings_action = options.W

    config = common.read_config(options)

    common.use_androguard()
    if not (('jarsigner' in config or 'apksigner' in config)
            and 'keytool' in config):
        raise FDroidException(_('Java JDK not found! Install in standard location or set java_paths!'))

    repodirs = ['repo']
    if config['archive_older'] != 0:
        repodirs.append('archive')
        if not os.path.exists('archive'):
            os.mkdir('archive')

    if options.icons:
        resize_all_icons(repodirs)
        sys.exit(0)

    if options.rename_apks:
        options.clean = True

    # check that icons exist now, rather than fail at the end of `fdroid update`
    for k in ['repo_icon', 'archive_icon']:
        if k in config:
            if not os.path.exists(config[k]):
                logging.warning(_('{name} "{section}/icons/{path}" does not exist! Check "config.yml".')
                                .format(name=k, section=k.split('_')[0], path=config[k]))

    # if the user asks to create a keystore, do it now, reusing whatever it can
    if options.create_key:
        if os.path.exists(config['keystore']):
            logging.critical(_("Cowardily refusing to overwrite existing signing key setup!"))
            logging.critical("\t'" + config['keystore'] + "'")
            sys.exit(1)

        if 'repo_keyalias' not in config:
            config['repo_keyalias'] = socket.getfqdn()
            common.write_to_config(config, 'repo_keyalias', config['repo_keyalias'])
        if 'keydname' not in config:
            config['keydname'] = 'CN=' + config['repo_keyalias'] + ', OU=F-Droid'
            common.write_to_config(config, 'keydname', config['keydname'])
        if 'keystore' not in config:
            config['keystore'] = common.default_config['keystore']
            common.write_to_config(config, 'keystore', config['keystore'])

        password = common.genpassword()
        if 'keystorepass' not in config:
            config['keystorepass'] = password
            common.write_to_config(config, 'keystorepass', config['keystorepass'])
        if 'keypass' not in config and not config['keystore'] == "NONE":
            config['keypass'] = password
            common.write_to_config(config, 'keypass', config['keypass'])
        common.genkeystore(config)

    # Get all apps...
    apps = metadata.read_metadata()

    # Generate a list of categories...
    categories = set()
    for app in apps.values():
        categories.update(app.Categories)

    # Read known apks data (will be updated and written back when we've finished)
    knownapks = common.KnownApks()

    # Get APK cache
    apkcache = get_cache()

    # Delete builds for disabled apps
    delete_disabled_builds(apps, apkcache, repodirs)

    # Scan all apks in the main repo
    apks, cachechanged = process_apks(apkcache, repodirs[0], knownapks, options.use_date_from_apk)

    files, fcachechanged = scan_repo_files(apkcache, repodirs[0], knownapks,
                                           options.use_date_from_apk)
    cachechanged = cachechanged or fcachechanged
    apks += files
    appid_has_apks = set()
    appid_has_repo_files = set()
    for apk in apks:
        to_remove = get_apks_without_allowed_signatures(apps.get(apk['packageName']), apk)
        if to_remove:
            apks.remove(apk)
            logging.warning(
                _('"{path}" is signed by a key that is not allowed:').format(
                    path=to_remove
                )
                + '\n'
                + apk['signer']
            )
            if options.delete_unknown:
                for d in repodirs:
                    path = Path(d) / to_remove
                    if path.exists():
                        logging.warning(_('Removing {path}"').format(path=path))
                        path.unlink()

        if apk['apkName'].endswith('.apk'):
            appid_has_apks.add(apk['packageName'])
        else:
            appid_has_repo_files.add(apk['packageName'])
        if apk['packageName'] not in apps:
            if options.create_metadata:
                create_metadata_from_template(apk)
                apps = metadata.read_metadata()
            else:
                msg = _("{apkfilename} ({appid}) has no metadata!") \
                    .format(apkfilename=apk['apkName'], appid=apk['packageName'])
                if options.delete_unknown:
                    logging.warning(msg + '\n\t' + _("deleting: repo/{apkfilename}")
                                    .format(apkfilename=apk['apkName']))
                    rmf = os.path.join(repodirs[0], apk['apkName'])
                    if not os.path.exists(rmf):
                        logging.error(_("Could not find {path} to remove it").format(path=rmf))
                    else:
                        os.remove(rmf)
                else:
                    logging.warning(msg + '\n\t' + _('Use `fdroid update -c` to create it.'))

    mismatch_errors = ''
    for appid in appid_has_apks:
        if appid in appid_has_repo_files:
            appid_files = ', '.join(glob.glob(os.path.join('repo', appid + '_[0-9]*.*')))
            mismatch_errors += (_('{appid} has both APKs and files: {files}')
                                .format(appid=appid, files=appid_files)) + '\n'
    if mismatch_errors:
        raise FDroidException(mismatch_errors)

    # Scan the archive repo for apks as well
    if len(repodirs) > 1:
        archapks, cc = process_apks(apkcache, repodirs[1], knownapks, options.use_date_from_apk)
        if cc:
            cachechanged = True
    else:
        archapks = []

    if cachechanged:
        write_cache(apkcache)

    # The added date currently comes from the oldest apk which might be in the archive.
    # So we need this populated at app level before continuing with only processing /repo
    # or /archive
    read_added_date_from_all_apks(apps, apks + archapks)

    if len(repodirs) > 1:
        archive_old_apks(apps, apks, archapks, repodirs[0], repodirs[1], config['archive_older'])
        archived_apps = prepare_apps(apps, archapks, repodirs[1])
        index.make(archived_apps, archapks, repodirs[1], True)

    repoapps = prepare_apps(apps, apks, repodirs[0])

    # APKs are placed into multiple repos based on the app package, providing
    # per-app subscription feeds for nightly builds and things like it
    if config['per_app_repos']:
        add_apks_to_per_app_repos(repodirs[0], apks)
        for appid, app in apps.items():
            repodir = os.path.join(appid, 'fdroid', 'repo')
            appdict = dict()
            appdict[appid] = app
            if os.path.isdir(repodir):
                index.make(appdict, apks, repodir, False)
            else:
                logging.info(_('Skipping index generation for {appid}').format(appid=appid))
        return

    # Make the index for the main repo...
    index.make(repoapps, apks, repodirs[0], False)
    make_categories_txt(repodirs[0], categories)

    git_remote = config.get('binary_transparency_remote')
    if git_remote or os.path.isdir(os.path.join('binary_transparency', '.git')):
        from . import btlog
        btlog.make_binary_transparency_log(repodirs)

    if config['update_stats']:
        # Update known apks info...
        knownapks.writeifchanged()

    status_update_json(apps, apks + archapks)

    logging.info(_("Finished"))


if __name__ == "__main__":
    main()
