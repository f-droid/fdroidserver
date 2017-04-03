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

import sys
import os
import shutil
import glob
import json
import re
import socket
import zipfile
import hashlib
import pickle
import platform
from datetime import datetime, timedelta
from argparse import ArgumentParser

import collections
from binascii import hexlify

from PIL import Image
import logging

from . import common
from . import index
from . import metadata
from .common import SdkToolsPopen

METADATA_VERSION = 18

# less than the valid range of versionCode, i.e. Java's Integer.MIN_VALUE
UNSET_VERSION_CODE = -0x100000000

APK_NAME_PAT = re.compile(".*name='([a-zA-Z0-9._]*)'.*")
APK_VERCODE_PAT = re.compile(".*versionCode='([0-9]*)'.*")
APK_VERNAME_PAT = re.compile(".*versionName='([^']*)'.*")
APK_LABEL_PAT = re.compile(".*label='(.*?)'(\n| [a-z]*?=).*")
APK_ICON_PAT = re.compile(".*application-icon-([0-9]+):'([^']+?)'.*")
APK_ICON_PAT_NODPI = re.compile(".*icon='([^']+?)'.*")
APK_SDK_VERSION_PAT = re.compile(".*'([0-9]*)'.*")
APK_PERMISSION_PAT = \
    re.compile(".*(name='(?P<name>.*?)')(.*maxSdkVersion='(?P<maxSdkVersion>.*?)')?.*")
APK_FEATURE_PAT = re.compile(".*name='([^']*)'.*")

screen_densities = ['640', '480', '320', '240', '160', '120']

all_screen_densities = ['0'] + screen_densities

UsesPermission = collections.namedtuple('UsesPermission', ['name', 'maxSdkVersion'])
UsesPermissionSdk23 = collections.namedtuple('UsesPermissionSdk23', ['name', 'maxSdkVersion'])


def dpi_to_px(density):
    return (int(density) * 48) / 160


def px_to_dpi(px):
    return (int(px) * 160) / 48


def get_icon_dir(repodir, density):
    if density == '0':
        return os.path.join(repodir, "icons")
    return os.path.join(repodir, "icons-%s" % density)


def get_icon_dirs(repodir):
    for density in screen_densities:
        yield get_icon_dir(repodir, density)


def get_all_icon_dirs(repodir):
    for density in all_screen_densities:
        yield get_icon_dir(repodir, density)


def update_wiki(apps, sortedids, apks):
    """Update the wiki

    :param apps: fully populated list of all applications
    :param apks: all apks, except...
    """
    logging.info("Updating wiki")
    wikicat = 'Apps'
    wikiredircat = 'App Redirects'
    import mwclient
    site = mwclient.Site((config['wiki_protocol'], config['wiki_server']),
                         path=config['wiki_path'])
    site.login(config['wiki_user'], config['wiki_password'])
    generated_pages = {}
    generated_redirects = {}

    for appid in sortedids:
        app = metadata.App(apps[appid])

        wikidata = ''
        if app.Disabled:
            wikidata += '{{Disabled|' + app.Disabled + '}}\n'
        if app.AntiFeatures:
            for af in app.AntiFeatures:
                wikidata += '{{AntiFeature|' + af + '}}\n'
        if app.RequiresRoot:
            requiresroot = 'Yes'
        else:
            requiresroot = 'No'
        wikidata += '{{App|id=%s|name=%s|added=%s|lastupdated=%s|source=%s|tracker=%s|web=%s|changelog=%s|donate=%s|flattr=%s|bitcoin=%s|litecoin=%s|license=%s|root=%s|author=%s|email=%s}}\n' % (
            appid,
            app.Name,
            app.added.strftime('%Y-%m-%d') if app.added else '',
            app.lastUpdated.strftime('%Y-%m-%d') if app.lastUpdated else '',
            app.SourceCode,
            app.IssueTracker,
            app.WebSite,
            app.Changelog,
            app.Donate,
            app.FlattrID,
            app.Bitcoin,
            app.Litecoin,
            app.License,
            requiresroot,
            app.AuthorName,
            app.AuthorEmail)

        if app.Provides:
            wikidata += "This app provides: %s" % ', '.join(app.Summary.split(','))

        wikidata += app.Summary
        wikidata += " - [https://f-droid.org/repository/browse/?fdid=" + appid + " view in repository]\n\n"

        wikidata += "=Description=\n"
        wikidata += metadata.description_wiki(app.Description) + "\n"

        wikidata += "=Maintainer Notes=\n"
        if app.MaintainerNotes:
            wikidata += metadata.description_wiki(app.MaintainerNotes) + "\n"
        wikidata += "\nMetadata: [https://gitlab.com/fdroid/fdroiddata/blob/master/metadata/{0}.txt current] [https://gitlab.com/fdroid/fdroiddata/commits/master/metadata/{0}.txt history]\n".format(appid)

        # Get a list of all packages for this application...
        apklist = []
        gotcurrentver = False
        cantupdate = False
        buildfails = False
        for apk in apks:
            if apk['packageName'] == appid:
                if str(apk['versionCode']) == app.CurrentVersionCode:
                    gotcurrentver = True
                apklist.append(apk)
        # Include ones we can't build, as a special case...
        for build in app.builds:
            if build.disable:
                if build.versionCode == app.CurrentVersionCode:
                    cantupdate = True
                # TODO: Nasty: vercode is a string in the build, and an int elsewhere
                apklist.append({'versionCode': int(build.versionCode),
                                'versionName': build.versionName,
                                'buildproblem': "The build for this version was manually disabled. Reason: {0}".format(build.disable),
                                })
            else:
                builtit = False
                for apk in apklist:
                    if apk['versionCode'] == int(build.versionCode):
                        builtit = True
                        break
                if not builtit:
                    buildfails = True
                    apklist.append({'versionCode': int(build.versionCode),
                                    'versionName': build.versionName,
                                    'buildproblem': "The build for this version appears to have failed. Check the [[{0}/lastbuild_{1}|build log]].".format(appid, build.versionCode),
                                    })
        if app.CurrentVersionCode == '0':
            cantupdate = True
        # Sort with most recent first...
        apklist = sorted(apklist, key=lambda apk: apk['versionCode'], reverse=True)

        wikidata += "=Versions=\n"
        if len(apklist) == 0:
            wikidata += "We currently have no versions of this app available."
        elif not gotcurrentver:
            wikidata += "We don't have the current version of this app."
        else:
            wikidata += "We have the current version of this app."
        wikidata += " (Check mode: " + app.UpdateCheckMode + ") "
        wikidata += " (Auto-update mode: " + app.AutoUpdateMode + ")\n\n"
        if len(app.NoSourceSince) > 0:
            wikidata += "This application has partially or entirely been missing source code since version " + app.NoSourceSince + ".\n\n"
        if len(app.CurrentVersion) > 0:
            wikidata += "The current (recommended) version is " + app.CurrentVersion
            wikidata += " (version code " + app.CurrentVersionCode + ").\n\n"
        validapks = 0
        for apk in apklist:
            wikidata += "==" + apk['versionName'] + "==\n"

            if 'buildproblem' in apk:
                wikidata += "We can't build this version: " + apk['buildproblem'] + "\n\n"
            else:
                validapks += 1
                wikidata += "This version is built and signed by "
                if 'srcname' in apk:
                    wikidata += "F-Droid, and guaranteed to correspond to the source tarball published with it.\n\n"
                else:
                    wikidata += "the original developer.\n\n"
            wikidata += "Version code: " + str(apk['versionCode']) + '\n'

        wikidata += '\n[[Category:' + wikicat + ']]\n'
        if len(app.NoSourceSince) > 0:
            wikidata += '\n[[Category:Apps missing source code]]\n'
        if validapks == 0 and not app.Disabled:
            wikidata += '\n[[Category:Apps with no packages]]\n'
        if cantupdate and not app.Disabled:
            wikidata += "\n[[Category:Apps we cannot update]]\n"
        if buildfails and not app.Disabled:
            wikidata += "\n[[Category:Apps with failing builds]]\n"
        elif not gotcurrentver and not cantupdate and not app.Disabled and app.UpdateCheckMode != "Static":
            wikidata += '\n[[Category:Apps to Update]]\n'
        if app.Disabled:
            wikidata += '\n[[Category:Apps that are disabled]]\n'
        if app.UpdateCheckMode == 'None' and not app.Disabled:
            wikidata += '\n[[Category:Apps with no update check]]\n'
        for appcat in app.Categories:
            wikidata += '\n[[Category:{0}]]\n'.format(appcat)

        # We can't have underscores in the page name, even if they're in
        # the package ID, because MediaWiki messes with them...
        pagename = appid.replace('_', ' ')

        # Drop a trailing newline, because mediawiki is going to drop it anyway
        # and it we don't we'll think the page has changed when it hasn't...
        if wikidata.endswith('\n'):
            wikidata = wikidata[:-1]

        generated_pages[pagename] = wikidata

        # Make a redirect from the name to the ID too, unless there's
        # already an existing page with the name and it isn't a redirect.
        noclobber = False
        apppagename = app.Name.replace('_', ' ')
        apppagename = apppagename.replace('{', '')
        apppagename = apppagename.replace('}', ' ')
        apppagename = apppagename.replace(':', ' ')
        apppagename = apppagename.replace('[', ' ')
        apppagename = apppagename.replace(']', ' ')
        # Drop double spaces caused mostly by replacing ':' above
        apppagename = apppagename.replace('  ', ' ')
        for expagename in site.allpages(prefix=apppagename,
                                        filterredir='nonredirects',
                                        generator=False):
            if expagename == apppagename:
                noclobber = True
        # Another reason not to make the redirect page is if the app name
        # is the same as it's ID, because that will overwrite the real page
        # with an redirect to itself! (Although it seems like an odd
        # scenario this happens a lot, e.g. where there is metadata but no
        # builds or binaries to extract a name from.
        if apppagename == pagename:
            noclobber = True
        if not noclobber:
            generated_redirects[apppagename] = "#REDIRECT [[" + pagename + "]]\n[[Category:" + wikiredircat + "]]"

    for tcat, genp in [(wikicat, generated_pages),
                       (wikiredircat, generated_redirects)]:
        catpages = site.Pages['Category:' + tcat]
        existingpages = []
        for page in catpages:
            existingpages.append(page.name)
            if page.name in genp:
                pagetxt = page.edit()
                if pagetxt != genp[page.name]:
                    logging.debug("Updating modified page " + page.name)
                    page.save(genp[page.name], summary='Auto-updated')
                else:
                    logging.debug("Page " + page.name + " is unchanged")
            else:
                logging.warn("Deleting page " + page.name)
                page.delete('No longer published')
        for pagename, text in genp.items():
            logging.debug("Checking " + pagename)
            if pagename not in existingpages:
                logging.debug("Creating page " + pagename)
                try:
                    newpage = site.Pages[pagename]
                    newpage.save(text, summary='Auto-created')
                except Exception as e:
                    logging.error("...FAILED to create page '{0}': {1}".format(pagename, e))

    # Purge server cache to ensure counts are up to date
    site.pages['Repository Maintenance'].purge()


def delete_disabled_builds(apps, apkcache, repodirs):
    """Delete disabled build outputs.

    :param apps: list of all applications, as per metadata.read_metadata
    :param apkcache: current apk cache information
    :param repodirs: the repo directories to process
    """
    for appid, app in apps.items():
        for build in app['builds']:
            if not build.disable:
                continue
            apkfilename = appid + '_' + str(build.versionCode) + '.apk'
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
            im.save(iconpath, "PNG")

    except Exception as e:
        logging.error("Failed resizing {0} - {1}".format(iconpath, e))

    finally:
        if fp:
            fp.close()


def resize_all_icons(repodirs):
    """Resize all icons that exceed the max size

    :param repodirs: the repo directories to process
    """
    for repodir in repodirs:
        for density in screen_densities:
            icon_dir = get_icon_dir(repodir, density)
            icon_glob = os.path.join(icon_dir, '*.png')
            for iconpath in glob.glob(icon_glob):
                resize_icon(iconpath, density)


def getsig(apkpath):
    """ Get the signing certificate of an apk. To get the same md5 has that
    Android gets, we encode the .RSA certificate in a specific format and pass
    it hex-encoded to the md5 digest algorithm.

    :param apkpath: path to the apk
    :returns: A string containing the md5 of the signature of the apk or None
              if an error occurred.
    """

    # verify the jar signature is correct
    if not common.verify_apk_signature(apkpath):
        return None

    with zipfile.ZipFile(apkpath, 'r') as apk:
        certs = [n for n in apk.namelist() if common.CERT_PATH_REGEX.match(n)]

        if len(certs) < 1:
            logging.error("Found no signing certificates on %s" % apkpath)
            return None
        if len(certs) > 1:
            logging.error("Found multiple signing certificates on %s" % apkpath)
            return None

        cert = apk.read(certs[0])

    cert_encoded = common.get_certificate(cert)

    return hashlib.md5(hexlify(cert_encoded)).hexdigest()


def get_cache_file():
    return os.path.join('tmp', 'apkcache')


def get_cache():
    """
    Gather information about all the apk files in the repo directory,
    using cached data if possible.
    :return: apkcache
    """
    apkcachefile = get_cache_file()
    if not options.clean and os.path.exists(apkcachefile):
        with open(apkcachefile, 'rb') as cf:
            apkcache = pickle.load(cf, encoding='utf-8')
        if apkcache.get("METADATA_VERSION") != METADATA_VERSION:
            apkcache = {}
    else:
        apkcache = {}

    return apkcache


def write_cache(apkcache):
    apkcachefile = get_cache_file()
    cache_path = os.path.dirname(apkcachefile)
    if not os.path.exists(cache_path):
        os.makedirs(cache_path)
    apkcache["METADATA_VERSION"] = METADATA_VERSION
    with open(apkcachefile, 'wb') as cf:
        pickle.dump(apkcache, cf)


def get_icon_bytes(apkzip, iconsrc):
    '''ZIP has no official encoding, UTF-* and CP437 are defacto'''
    try:
        return apkzip.read(iconsrc)
    except KeyError:
        return apkzip.read(iconsrc.encode('utf-8').decode('cp437'))


def sha256sum(filename):
    '''Calculate the sha256 of the given file'''
    sha = hashlib.sha256()
    with open(filename, 'rb') as f:
        while True:
            t = f.read(16384)
            if len(t) == 0:
                break
            sha.update(t)
    return sha.hexdigest()


def has_old_openssl(filename):
    '''checks for known vulnerable openssl versions in the APK'''

    # statically load this pattern
    if not hasattr(has_old_openssl, "pattern"):
        has_old_openssl.pattern = re.compile(b'.*OpenSSL ([01][0-9a-z.-]+)')

    with zipfile.ZipFile(filename) as zf:
        for name in zf.namelist():
            if name.endswith('libcrypto.so') or name.endswith('libssl.so'):
                lib = zf.open(name)
                while True:
                    chunk = lib.read(4096)
                    if chunk == b'':
                        break
                    m = has_old_openssl.pattern.search(chunk)
                    if m:
                        version = m.group(1).decode('ascii')
                        if version.startswith('1.0.1') and version[5] >= 'r' \
                           or version.startswith('1.0.2') and version[5] >= 'f':
                            logging.debug('"%s" contains recent %s (%s)', filename, name, version)
                        else:
                            logging.warning('"%s" contains outdated %s (%s)', filename, name, version)
                            return True
                        break
    return False


def insert_obbs(repodir, apps, apks):
    """Scans the .obb files in a given repo directory and adds them to the
    relevant APK instances.  OBB files have versionCodes like APK
    files, and they are loosely associated.  If there is an OBB file
    present, then any APK with the same or higher versionCode will use
    that OBB file.  There are two OBB types: main and patch, each APK
    can only have only have one of each.

    https://developer.android.com/google/play/expansion-files.html

    :param repodir: repo directory to scan
    :param apps: list of current, valid apps
    :param apks: current information on all APKs

    """

    def obbWarnDelete(f, msg):
        logging.warning(msg + f)
        if options.delete_unknown:
            logging.error("Deleting unknown file: " + f)
            os.remove(f)

    obbs = []
    java_Integer_MIN_VALUE = -pow(2, 31)
    currentPackageNames = apps.keys()
    for f in glob.glob(os.path.join(repodir, '*.obb')):
        obbfile = os.path.basename(f)
        # obbfile looks like: [main|patch].<expansion-version>.<package-name>.obb
        chunks = obbfile.split('.')
        if chunks[0] != 'main' and chunks[0] != 'patch':
            obbWarnDelete(f, 'OBB filename must start with "main." or "patch.": ')
            continue
        if not re.match(r'^-?[0-9]+$', chunks[1]):
            obbWarnDelete('The OBB version code must come after "' + chunks[0] + '.": ')
            continue
        versionCode = int(chunks[1])
        packagename = ".".join(chunks[2:-1])

        highestVersionCode = java_Integer_MIN_VALUE
        if packagename not in currentPackageNames:
            obbWarnDelete(f, "OBB's packagename does not match a supported APK: ")
            continue
        for apk in apks:
            if packagename == apk['packageName'] and apk['versionCode'] > highestVersionCode:
                highestVersionCode = apk['versionCode']
        if versionCode > highestVersionCode:
            obbWarnDelete(f, 'OBB file has newer versionCode(' + str(versionCode)
                          + ') than any APK: ')
            continue
        obbsha256 = sha256sum(f)
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


def insert_graphics(repodir, apps):
    """Scans for screenshot PNG files in statically defined screenshots
    directory and adds them to the app metadata.  The screenshots and
    graphic must be PNG or JPEG files ending with ".png", ".jpg", or ".jpeg"
    and must be in the following layout:

    repo/packageName/locale/featureGraphic.png
    repo/packageName/locale/phoneScreenshots/1.png
    repo/packageName/locale/phoneScreenshots/2.png

    Where "packageName" is the app's packageName and "locale" is the locale
    of the graphics, e.g. what language they are in, using the IETF RFC5646
    format (en-US, fr-CA, es-MX, etc).  This is following this pattern:
    https://github.com/fastlane/fastlane/blob/1.109.0/supply/README.md#images-and-screenshots

    This will also scan the metadata/ folder and the apps' source repos
    for standard locations of graphic and screenshot files.  If it finds
    them, it will copy them into the repo.

    :param repodir: repo directory to scan

    """

    allowed_extensions = ('png', 'jpg', 'jpeg')
    graphicnames = ('featureGraphic', 'icon', 'promoGraphic', 'tvBanner')
    screenshotdirs = ('phoneScreenshots', 'sevenInchScreenshots',
                      'tenInchScreenshots', 'tvScreenshots', 'wearScreenshots')

    sourcedirs = glob.glob(os.path.join('build', '[A-Za-z]*', 'fastlane', 'metadata', 'android', '[a-z][a-z][A-Z-.@]*'))
    sourcedirs += glob.glob(os.path.join('metadata', '[A-Za-z]*', '[a-z][a-z][A-Z-.@]*'))

    for d in sorted(sourcedirs):
        if not os.path.isdir(d):
            continue
        for root, dirs, files in os.walk(d):
            segments = root.split('/')
            destdir = os.path.join('repo', segments[1], segments[-1])  # repo/packageName/locale
            for f in files:
                base, extension = common.get_extension(f)
                if base in graphicnames and extension in allowed_extensions:
                    os.makedirs(destdir, mode=0o755, exist_ok=True)
                    logging.debug('copying ' + os.path.join(root, f) + ' ' + destdir)
                    shutil.copy(os.path.join(root, f), destdir)
            for d in dirs:
                if d in screenshotdirs:
                    for f in glob.glob(os.path.join(root, d, '*.*')):
                        _, extension = common.get_extension(f)
                        if extension in allowed_extensions:
                            screenshotdestdir = os.path.join(destdir, d)
                            os.makedirs(screenshotdestdir, mode=0o755, exist_ok=True)
                            logging.debug('copying ' + f + ' ' + screenshotdestdir)
                            shutil.copy(f, screenshotdestdir)

    repofiles = sorted(glob.glob(os.path.join('repo', '[A-Za-z]*', '[a-z][a-z][A-Z-.@]*')))
    for d in repofiles:
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
            base, extension = common.get_extension(filename)

            if packageName not in apps:
                logging.warning('Found "%s" graphic without metadata for app "%s"!'
                                % (filename, packageName))
                continue
            if 'localized' not in apps[packageName]:
                apps[packageName]['localized'] = collections.OrderedDict()
            if locale not in apps[packageName]['localized']:
                apps[packageName]['localized'][locale] = collections.OrderedDict()
            graphics = apps[packageName]['localized'][locale]

            if extension not in allowed_extensions:
                logging.warning('Only PNG and JPEG are supported for graphics, found: ' + f)
            elif base in graphicnames:
                # there can only be zero or one of these per locale
                graphics[base] = filename
            elif screenshotdir in screenshotdirs:
                # there can any number of these per locale
                logging.debug('adding ' + base + ':' + f)
                if screenshotdir not in graphics:
                    graphics[screenshotdir] = []
                graphics[screenshotdir].append(filename)
            else:
                logging.warning('Unsupported graphics file found: ' + f)


def scan_repo_files(apkcache, repodir, knownapks, use_date_from_file=False):
    """Scan a repo for all files with an extension except APK/OBB

    :param apkcache: current cached info about all repo files
    :param repodir: repo directory to scan
    :param knownapks: list of all known files, as per metadata.read_metadata
    :param use_date_from_file: use date from file (instead of current date)
                               for newly added files
    """

    cachechanged = False
    repo_files = []
    for name in os.listdir(repodir):
        file_extension = common.get_file_extension(name)
        if file_extension == 'apk' or file_extension == 'obb':
            continue
        filename = os.path.join(repodir, name)
        if filename.endswith('_src.tar.gz'):
            logging.debug('skipping source tarball: ' + filename)
            continue
        if not common.is_repo_file(filename):
            continue
        stat = os.stat(filename)
        if stat.st_size == 0:
            logging.error(filename + ' is zero size!')
            sys.exit(1)

        shasum = sha256sum(filename)
        usecache = False
        if name in apkcache:
            repo_file = apkcache[name]
            # added time is cached as tuple but used here as datetime instance
            if 'added' in repo_file:
                a = repo_file['added']
                if isinstance(a, datetime):
                    repo_file['added'] = a
                else:
                    repo_file['added'] = datetime(*a[:6])
            if repo_file['hash'] == shasum:
                logging.debug("Reading " + name + " from cache")
                usecache = True
            else:
                logging.debug("Ignoring stale cache data for " + name)

        if not usecache:
            logging.debug("Processing " + name)
            repo_file = {}
            # TODO rename apkname globally to something more generic
            repo_file['name'] = name
            repo_file['apkName'] = name
            repo_file['hash'] = shasum
            repo_file['hashType'] = 'sha256'
            repo_file['versionCode'] = 0
            repo_file['versionName'] = shasum
            # the static ID is the SHA256 unless it is set in the metadata
            repo_file['packageName'] = shasum
            n = name.split('_')
            if len(n) == 2:
                packageName = n[0]
                versionCode = n[1].split('.')[0]
                if re.match(r'^-?[0-9]+$', versionCode) \
                   and common.is_valid_package_name(name.split('_')[0]):
                    repo_file['packageName'] = packageName
                    repo_file['versionCode'] = int(versionCode)
            srcfilename = name + "_src.tar.gz"
            if os.path.exists(os.path.join(repodir, srcfilename)):
                repo_file['srcname'] = srcfilename
            repo_file['size'] = stat.st_size

            apkcache[name] = repo_file
            cachechanged = True

        if use_date_from_file:
            timestamp = stat.st_ctime
            default_date_param = datetime.fromtimestamp(timestamp).utctimetuple()
        else:
            default_date_param = None

        # Record in knownapks, getting the added date at the same time..
        added = knownapks.recordapk(repo_file['apkName'], repo_file['packageName'],
                                    default_date=default_date_param)
        if added:
            repo_file['added'] = added

        repo_files.append(repo_file)

    return repo_files, cachechanged


def scan_apk(apkcache, apkfilename, repodir, knownapks, use_date_from_apk):
    """Scan the apk with the given filename in the given repo directory.

    This also extracts the icons.

    :param apkcache: current apk cache information
    :param apkfilename: the filename of the apk to scan
    :param repodir: repo directory to scan
    :param knownapks: known apks info
    :param use_date_from_apk: use date from APK (instead of current date)
                              for newly added APKs
    :returns: (skip, apk, cachechanged) where skip is a boolean indicating whether to skip this apk,
     apk is the scanned apk information, and cachechanged is True if the apkcache got changed.
    """

    if ' ' in apkfilename:
        logging.critical("Spaces in filenames are not allowed.")
        sys.exit(1)

    apkfile = os.path.join(repodir, apkfilename)
    shasum = sha256sum(apkfile)

    cachechanged = False
    usecache = False
    if apkfilename in apkcache:
        apk = apkcache[apkfilename]
        if apk['hash'] == shasum:
            logging.debug("Reading " + apkfilename + " from cache")
            usecache = True
        else:
            logging.debug("Ignoring stale cache data for " + apkfilename)

    if not usecache:
        logging.debug("Processing " + apkfilename)
        apk = {}
        apk['apkName'] = apkfilename
        apk['hash'] = shasum
        apk['hashType'] = 'sha256'
        srcfilename = apkfilename[:-4] + "_src.tar.gz"
        if os.path.exists(os.path.join(repodir, srcfilename)):
            apk['srcname'] = srcfilename
        apk['size'] = os.path.getsize(apkfile)
        apk['uses-permission'] = set()
        apk['uses-permission-sdk-23'] = set()
        apk['features'] = set()
        apk['icons_src'] = {}
        apk['icons'] = {}
        apk['antiFeatures'] = set()
        if has_old_openssl(apkfile):
            apk['antiFeatures'].add('KnownVuln')
        p = SdkToolsPopen(['aapt', 'dump', 'badging', apkfile], output=False)
        if p.returncode != 0:
            if options.delete_unknown:
                if os.path.exists(apkfile):
                    logging.error("Failed to get apk information, deleting " + apkfile)
                    os.remove(apkfile)
                else:
                    logging.error("Could not find {0} to remove it".format(apkfile))
            else:
                logging.error("Failed to get apk information, skipping " + apkfile)
            return True
        for line in p.output.splitlines():
            if line.startswith("package:"):
                try:
                    apk['packageName'] = re.match(APK_NAME_PAT, line).group(1)
                    apk['versionCode'] = int(re.match(APK_VERCODE_PAT, line).group(1))
                    apk['versionName'] = re.match(APK_VERNAME_PAT, line).group(1)
                except Exception as e:
                    logging.error("Package matching failed: " + str(e))
                    logging.info("Line was: " + line)
                    sys.exit(1)
            elif line.startswith("application:"):
                apk['name'] = re.match(APK_LABEL_PAT, line).group(1)
                # Keep path to non-dpi icon in case we need it
                match = re.match(APK_ICON_PAT_NODPI, line)
                if match:
                    apk['icons_src']['-1'] = match.group(1)
            elif line.startswith("launchable-activity:"):
                # Only use launchable-activity as fallback to application
                if not apk['name']:
                    apk['name'] = re.match(APK_LABEL_PAT, line).group(1)
                if '-1' not in apk['icons_src']:
                    match = re.match(APK_ICON_PAT_NODPI, line)
                    if match:
                        apk['icons_src']['-1'] = match.group(1)
            elif line.startswith("application-icon-"):
                match = re.match(APK_ICON_PAT, line)
                if match:
                    density = match.group(1)
                    path = match.group(2)
                    apk['icons_src'][density] = path
            elif line.startswith("sdkVersion:"):
                m = re.match(APK_SDK_VERSION_PAT, line)
                if m is None:
                    logging.error(line.replace('sdkVersion:', '')
                                  + ' is not a valid minSdkVersion!')
                else:
                    apk['minSdkVersion'] = m.group(1)
                    # if target not set, default to min
                    if 'targetSdkVersion' not in apk:
                        apk['targetSdkVersion'] = m.group(1)
            elif line.startswith("targetSdkVersion:"):
                m = re.match(APK_SDK_VERSION_PAT, line)
                if m is None:
                    logging.error(line.replace('targetSdkVersion:', '')
                                  + ' is not a valid targetSdkVersion!')
                else:
                    apk['targetSdkVersion'] = m.group(1)
            elif line.startswith("maxSdkVersion:"):
                apk['maxSdkVersion'] = re.match(APK_SDK_VERSION_PAT, line).group(1)
            elif line.startswith("native-code:"):
                apk['nativecode'] = []
                for arch in line[13:].split(' '):
                    apk['nativecode'].append(arch[1:-1])
            elif line.startswith('uses-permission:'):
                perm_match = re.match(APK_PERMISSION_PAT, line).groupdict()
                if perm_match['maxSdkVersion']:
                    perm_match['maxSdkVersion'] = int(perm_match['maxSdkVersion'])
                permission = UsesPermission(
                    perm_match['name'],
                    perm_match['maxSdkVersion']
                )

                apk['uses-permission'].add(permission)
            elif line.startswith('uses-permission-sdk-23:'):
                perm_match = re.match(APK_PERMISSION_PAT, line).groupdict()
                if perm_match['maxSdkVersion']:
                    perm_match['maxSdkVersion'] = int(perm_match['maxSdkVersion'])
                permission_sdk_23 = UsesPermissionSdk23(
                    perm_match['name'],
                    perm_match['maxSdkVersion']
                )

                apk['uses-permission-sdk-23'].add(permission_sdk_23)

            elif line.startswith('uses-feature:'):
                feature = re.match(APK_FEATURE_PAT, line).group(1)
                # Filter out this, it's only added with the latest SDK tools and
                # causes problems for lots of apps.
                if feature != "android.hardware.screen.portrait" \
                        and feature != "android.hardware.screen.landscape":
                    if feature.startswith("android.feature."):
                        feature = feature[16:]
                    apk['features'].add(feature)

        if 'minSdkVersion' not in apk:
            logging.warn("No SDK version information found in {0}".format(apkfile))
            apk['minSdkVersion'] = 1

        # Check for debuggable apks...
        if common.isApkAndDebuggable(apkfile, config):
            logging.warning('{0} is set to android:debuggable="true"'.format(apkfile))

        # Get the signature (or md5 of, to be precise)...
        logging.debug('Getting signature of {0}'.format(apkfile))
        apk['sig'] = getsig(os.path.join(os.getcwd(), apkfile))
        if not apk['sig']:
            logging.critical("Failed to get apk signature")
            sys.exit(1)

        apkzip = zipfile.ZipFile(apkfile, 'r')

        # if an APK has files newer than the system time, suggest updating
        # the system clock.  This is useful for offline systems, used for
        # signing, which do not have another source of clock sync info. It
        # has to be more than 24 hours newer because ZIP/APK files do not
        # store timezone info
        manifest = apkzip.getinfo('AndroidManifest.xml')
        if manifest.date_time[1] == 0:  # month can't be zero
            logging.debug('AndroidManifest.xml has no date')
        else:
            dt_obj = datetime(*manifest.date_time)
            checkdt = dt_obj - timedelta(1)
            if datetime.today() < checkdt:
                logging.warn('System clock is older than manifest in: '
                             + apkfilename
                             + '\nSet clock to that time using:\n'
                             + 'sudo date -s "' + str(dt_obj) + '"')

        iconfilename = "%s.%s.png" % (
            apk['packageName'],
            apk['versionCode'])

        # Extract the icon file...
        empty_densities = []
        for density in screen_densities:
            if density not in apk['icons_src']:
                empty_densities.append(density)
                continue
            iconsrc = apk['icons_src'][density]
            icon_dir = get_icon_dir(repodir, density)
            icondest = os.path.join(icon_dir, iconfilename)

            try:
                with open(icondest, 'wb') as f:
                    f.write(get_icon_bytes(apkzip, iconsrc))
                apk['icons'][density] = iconfilename

            except Exception as e:
                logging.warn("Error retrieving icon file: %s" % (e))
                del apk['icons'][density]
                del apk['icons_src'][density]
                empty_densities.append(density)

        if '-1' in apk['icons_src']:
            iconsrc = apk['icons_src']['-1']
            iconpath = os.path.join(
                get_icon_dir(repodir, '0'), iconfilename)
            with open(iconpath, 'wb') as f:
                f.write(get_icon_bytes(apkzip, iconsrc))
            try:
                im = Image.open(iconpath)
                dpi = px_to_dpi(im.size[0])
                for density in screen_densities:
                    if density in apk['icons']:
                        break
                    if density == screen_densities[-1] or dpi >= int(density):
                        apk['icons'][density] = iconfilename
                        shutil.move(iconpath,
                                    os.path.join(get_icon_dir(repodir, density), iconfilename))
                        empty_densities.remove(density)
                        break
            except Exception as e:
                logging.warn("Failed reading {0} - {1}".format(iconpath, e))

        if apk['icons']:
            apk['icon'] = iconfilename

        apkzip.close()

        # First try resizing down to not lose quality
        last_density = None
        for density in screen_densities:
            if density not in empty_densities:
                last_density = density
                continue
            if last_density is None:
                continue
            logging.debug("Density %s not available, resizing down from %s"
                          % (density, last_density))

            last_iconpath = os.path.join(
                get_icon_dir(repodir, last_density), iconfilename)
            iconpath = os.path.join(
                get_icon_dir(repodir, density), iconfilename)
            fp = None
            try:
                fp = open(last_iconpath, 'rb')
                im = Image.open(fp)

                size = dpi_to_px(density)

                im.thumbnail((size, size), Image.ANTIALIAS)
                im.save(iconpath, "PNG")
                empty_densities.remove(density)
            except Exception as e:
                logging.warning("Invalid image file at %s: %s" % (last_iconpath, e))
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
            logging.debug("Density %s not available, copying from lower density %s"
                          % (density, last_density))

            shutil.copyfile(
                os.path.join(get_icon_dir(repodir, last_density), iconfilename),
                os.path.join(get_icon_dir(repodir, density), iconfilename))

            empty_densities.remove(density)

        for density in screen_densities:
            icon_dir = get_icon_dir(repodir, density)
            icondest = os.path.join(icon_dir, iconfilename)
            resize_icon(icondest, density)

        # Copy from icons-mdpi to icons since mdpi is the baseline density
        baseline = os.path.join(get_icon_dir(repodir, '160'), iconfilename)
        if os.path.isfile(baseline):
            apk['icons']['0'] = iconfilename
            shutil.copyfile(baseline,
                            os.path.join(get_icon_dir(repodir, '0'), iconfilename))

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


def scan_apks(apkcache, repodir, knownapks, use_date_from_apk=False):
    """Scan the apks in the given repo directory.

    This also extracts the icons.

    :param apkcache: current apk cache information
    :param repodir: repo directory to scan
    :param knownapks: known apks info
    :param use_date_from_apk: use date from APK (instead of current date)
                              for newly added APKs
    :returns: (apks, cachechanged) where apks is a list of apk information,
              and cachechanged is True if the apkcache got changed.
    """

    cachechanged = False

    for icon_dir in get_all_icon_dirs(repodir):
        if os.path.exists(icon_dir):
            if options.clean:
                shutil.rmtree(icon_dir)
                os.makedirs(icon_dir)
        else:
            os.makedirs(icon_dir)

    apks = []
    for apkfile in glob.glob(os.path.join(repodir, '*.apk')):
        apkfilename = apkfile[len(repodir) + 1:]
        (skip, apk, cachechanged) = scan_apk(apkcache, apkfilename, repodir, knownapks, use_date_from_apk)
        if skip:
            continue
        apks.append(apk)

    return apks, cachechanged


def apply_info_from_latest_apk(apps, apks):
    """
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

                if 'added' in apk:
                    if not app.added or apk['added'] < app.added:
                        app.added = apk['added']
                    if not app.lastUpdated or apk['added'] > app.lastUpdated:
                        app.lastUpdated = apk['added']

        if not app.added:
            logging.debug("Don't know when " + appid + " was added")
        if not app.lastUpdated:
            logging.debug("Don't know when " + appid + " was last updated")

        if bestver == UNSET_VERSION_CODE:

            if app.Name is None:
                app.Name = app.AutoName or appid
            app.icon = None
            logging.debug("Application " + appid + " has no packages")
        else:
            if app.Name is None:
                app.Name = bestapk['name']
            app.icon = bestapk['icon'] if 'icon' in bestapk else None
            if app.CurrentVersionCode is None:
                app.CurrentVersionCode = str(bestver)


def make_categories_txt(repodir, categories):
    '''Write a category list in the repo to allow quick access'''
    catdata = ''
    for cat in sorted(categories):
        catdata += cat + '\n'
    with open(os.path.join(repodir, 'categories.txt'), 'w', encoding='utf8') as f:
        f.write(catdata)


def archive_old_apks(apps, apks, archapks, repodir, archivedir, defaultkeepversions):

    for appid, app in apps.items():

        if app.ArchivePolicy:
            keepversions = int(app.ArchivePolicy[:-9])
        else:
            keepversions = defaultkeepversions

        def filter_apk_list_sorted(apk_list):
            res = []
            for apk in apk_list:
                if apk['packageName'] == appid:
                    res.append(apk)

            # Sort the apk list by version code. First is highest/newest.
            return sorted(res, key=lambda apk: apk['versionCode'], reverse=True)

        def move_file(from_dir, to_dir, filename, ignore_missing):
            from_path = os.path.join(from_dir, filename)
            if ignore_missing and not os.path.exists(from_path):
                return
            to_path = os.path.join(to_dir, filename)
            shutil.move(from_path, to_path)

        logging.debug("Checking archiving for {0} - apks:{1}, keepversions:{2}, archapks:{3}"
                      .format(appid, len(apks), keepversions, len(archapks)))

        if len(apks) > keepversions:
            apklist = filter_apk_list_sorted(apks)
            # Move back the ones we don't want.
            for apk in apklist[keepversions:]:
                logging.info("Moving " + apk['apkName'] + " to archive")
                move_file(repodir, archivedir, apk['apkName'], False)
                move_file(repodir, archivedir, apk['apkName'] + '.asc', True)
                for density in all_screen_densities:
                    repo_icon_dir = get_icon_dir(repodir, density)
                    archive_icon_dir = get_icon_dir(archivedir, density)
                    if density not in apk['icons']:
                        continue
                    move_file(repo_icon_dir, archive_icon_dir, apk['icons'][density], True)
                if 'srcname' in apk:
                    move_file(repodir, archivedir, apk['srcname'], False)
                archapks.append(apk)
                apks.remove(apk)
        elif len(apks) < keepversions and len(archapks) > 0:
            required = keepversions - len(apks)
            archapklist = filter_apk_list_sorted(archapks)
            # Move forward the ones we want again.
            for apk in archapklist[:required]:
                logging.info("Moving " + apk['apkName'] + " from archive")
                move_file(archivedir, repodir, apk['apkName'], False)
                move_file(archivedir, repodir, apk['apkName'] + '.asc', True)
                for density in all_screen_densities:
                    repo_icon_dir = get_icon_dir(repodir, density)
                    archive_icon_dir = get_icon_dir(archivedir, density)
                    if density not in apk['icons']:
                        continue
                    move_file(archive_icon_dir, repo_icon_dir, apk['icons'][density], True)
                if 'srcname' in apk:
                    move_file(archivedir, repodir, apk['srcname'], False)
                archapks.remove(apk)
                apks.append(apk)


def add_apks_to_per_app_repos(repodir, apks):
    apks_per_app = dict()
    for apk in apks:
        apk['per_app_dir'] = os.path.join(apk['packageName'], 'fdroid')
        apk['per_app_repo'] = os.path.join(apk['per_app_dir'], 'repo')
        apk['per_app_icons'] = os.path.join(apk['per_app_repo'], 'icons')
        apks_per_app[apk['packageName']] = apk

        if not os.path.exists(apk['per_app_icons']):
            logging.info('Adding new repo for only ' + apk['packageName'])
            os.makedirs(apk['per_app_icons'])

        apkpath = os.path.join(repodir, apk['apkName'])
        shutil.copy(apkpath, apk['per_app_repo'])
        apksigpath = apkpath + '.sig'
        if os.path.exists(apksigpath):
            shutil.copy(apksigpath, apk['per_app_repo'])
        apkascpath = apkpath + '.asc'
        if os.path.exists(apkascpath):
            shutil.copy(apkascpath, apk['per_app_repo'])


def make_binary_transparency_log(repodirs):
    '''Log the indexes in a standalone git repo to serve as a "binary
    transparency" log.

    see: https://www.eff.org/deeplinks/2014/02/open-letter-to-tech-companies

    '''

    import git
    btrepo = 'binary_transparency'
    if os.path.exists(os.path.join(btrepo, '.git')):
        gitrepo = git.Repo(btrepo)
    else:
        if not os.path.exists(btrepo):
            os.mkdir(btrepo)
        gitrepo = git.Repo.init(btrepo)

        gitconfig = gitrepo.config_writer()
        gitconfig.set_value('user', 'name', 'fdroid update')
        gitconfig.set_value('user', 'email', 'fdroid@' + platform.node())

        url = config['repo_url'].rstrip('/')
        with open(os.path.join(btrepo, 'README.md'), 'w') as fp:
            fp.write("""
# Binary Transparency Log for %s

""" % url[:url.rindex('/')])  # strip '/repo'
        gitrepo.index.add(['README.md', ])
        gitrepo.index.commit('add README')

    for repodir in repodirs:
        cpdir = os.path.join(btrepo, repodir)
        if not os.path.exists(cpdir):
            os.mkdir(cpdir)
        for f in ('index.xml', 'index-v1.json'):
            dest = os.path.join(cpdir, f)
            shutil.copyfile(os.path.join(repodir, f), dest)
            gitrepo.index.add([os.path.join(repodir, f), ])
        for f in ('index.jar', 'index-v1.jar'):
            repof = os.path.join(repodir, f)
            dest = os.path.join(cpdir, f)
            jarin = zipfile.ZipFile(repof, 'r')
            jarout = zipfile.ZipFile(dest, 'w')
            for info in jarin.infolist():
                if info.filename.startswith('META-INF/'):
                    jarout.writestr(info, jarin.read(info.filename))
            jarout.close()
            jarin.close()
            gitrepo.index.add([repof, ])

        files = []
        for root, dirs, filenames in os.walk(repodir):
            for f in filenames:
                files.append(os.path.relpath(os.path.join(root, f), repodir))
        output = collections.OrderedDict()
        for f in sorted(files):
            repofile = os.path.join(repodir, f)
            stat = os.stat(repofile)
            output[f] = (
                stat.st_size,
                stat.st_ctime_ns,
                stat.st_mtime_ns,
                stat.st_mode,
                stat.st_uid,
                stat.st_gid,
            )
        fslogfile = os.path.join(cpdir, 'filesystemlog.json')
        with open(fslogfile, 'w') as fp:
            json.dump(output, fp, indent=2)
        gitrepo.index.add([os.path.join(repodir, 'filesystemlog.json'), ])

    gitrepo.index.commit('fdroid update')


config = None
options = None


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument("--create-key", action="store_true", default=False,
                        help="Create a repo signing key in a keystore")
    parser.add_argument("-c", "--create-metadata", action="store_true", default=False,
                        help="Create skeleton metadata files that are missing")
    parser.add_argument("--delete-unknown", action="store_true", default=False,
                        help="Delete APKs and/or OBBs without metadata from the repo")
    parser.add_argument("-b", "--buildreport", action="store_true", default=False,
                        help="Report on build data status")
    parser.add_argument("-i", "--interactive", default=False, action="store_true",
                        help="Interactively ask about things that need updating.")
    parser.add_argument("-I", "--icons", action="store_true", default=False,
                        help="Resize all the icons exceeding the max pixel size and exit")
    parser.add_argument("-e", "--editor", default="/etc/alternatives/editor",
                        help="Specify editor to use in interactive mode. Default " +
                        "is /etc/alternatives/editor")
    parser.add_argument("-w", "--wiki", default=False, action="store_true",
                        help="Update the wiki")
    parser.add_argument("--pretty", action="store_true", default=False,
                        help="Produce human-readable index.xml")
    parser.add_argument("--clean", action="store_true", default=False,
                        help="Clean update - don't uses caches, reprocess all apks")
    parser.add_argument("--nosign", action="store_true", default=False,
                        help="When configured for signed indexes, create only unsigned indexes at this stage")
    parser.add_argument("--use-date-from-apk", action="store_true", default=False,
                        help="Use date from apk instead of current time for newly added apks")
    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    metadata.warnings_action = options.W

    config = common.read_config(options)

    if not ('jarsigner' in config and 'keytool' in config):
        logging.critical('Java JDK not found! Install in standard location or set java_paths!')
        sys.exit(1)

    repodirs = ['repo']
    if config['archive_older'] != 0:
        repodirs.append('archive')
        if not os.path.exists('archive'):
            os.mkdir('archive')

    if options.icons:
        resize_all_icons(repodirs)
        sys.exit(0)

    # check that icons exist now, rather than fail at the end of `fdroid update`
    for k in ['repo_icon', 'archive_icon']:
        if k in config:
            if not os.path.exists(config[k]):
                logging.critical(k + ' "' + config[k] + '" does not exist! Correct it in config.py.')
                sys.exit(1)

    # if the user asks to create a keystore, do it now, reusing whatever it can
    if options.create_key:
        if os.path.exists(config['keystore']):
            logging.critical("Cowardily refusing to overwrite existing signing key setup!")
            logging.critical("\t'" + config['keystore'] + "'")
            sys.exit(1)

        if 'repo_keyalias' not in config:
            config['repo_keyalias'] = socket.getfqdn()
            common.write_to_config(config, 'repo_keyalias', config['repo_keyalias'])
        if 'keydname' not in config:
            config['keydname'] = 'CN=' + config['repo_keyalias'] + ', OU=F-Droid'
            common.write_to_config(config, 'keydname', config['keydname'])
        if 'keystore' not in config:
            config['keystore'] = common.default_config.keystore
            common.write_to_config(config, 'keystore', config['keystore'])

        password = common.genpassword()
        if 'keystorepass' not in config:
            config['keystorepass'] = password
            common.write_to_config(config, 'keystorepass', config['keystorepass'])
        if 'keypass' not in config:
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
    apks, cachechanged = scan_apks(apkcache, repodirs[0], knownapks, options.use_date_from_apk)

    files, fcachechanged = scan_repo_files(apkcache, repodirs[0], knownapks,
                                           options.use_date_from_apk)
    cachechanged = cachechanged or fcachechanged
    apks += files
    # Generate warnings for apk's with no metadata (or create skeleton
    # metadata files, if requested on the command line)
    newmetadata = False
    for apk in apks:
        if apk['packageName'] not in apps:
            if options.create_metadata:
                if 'name' not in apk:
                    logging.error(apk['packageName'] + ' does not have a name! Skipping...')
                    continue
                f = open(os.path.join('metadata', apk['packageName'] + '.txt'), 'w', encoding='utf8')
                f.write("License:Unknown\n")
                f.write("Web Site:\n")
                f.write("Source Code:\n")
                f.write("Issue Tracker:\n")
                f.write("Changelog:\n")
                f.write("Summary:" + apk['name'] + "\n")
                f.write("Description:\n")
                f.write(apk['name'] + "\n")
                f.write(".\n")
                f.write("Name:" + apk['name'] + "\n")
                f.close()
                logging.info("Generated skeleton metadata for " + apk['packageName'])
                newmetadata = True
            else:
                msg = apk['apkName'] + " (" + apk['packageName'] + ") has no metadata!"
                if options.delete_unknown:
                    logging.warn(msg + "\n\tdeleting: repo/" + apk['apkName'])
                    rmf = os.path.join(repodirs[0], apk['apkName'])
                    if not os.path.exists(rmf):
                        logging.error("Could not find {0} to remove it".format(rmf))
                    else:
                        os.remove(rmf)
                else:
                    logging.warn(msg + "\n\tUse `fdroid update -c` to create it.")

    # update the metadata with the newly created ones included
    if newmetadata:
        apps = metadata.read_metadata()

    insert_obbs(repodirs[0], apps, apks)
    insert_graphics(repodirs[0], apps)

    # Scan the archive repo for apks as well
    if len(repodirs) > 1:
        archapks, cc = scan_apks(apkcache, repodirs[1], knownapks, options.use_date_from_apk)
        if cc:
            cachechanged = True
    else:
        archapks = []

    # Apply information from latest apks to the application and update dates
    apply_info_from_latest_apk(apps, apks + archapks)

    # Sort the app list by name, then the web site doesn't have to by default.
    # (we had to wait until we'd scanned the apks to do this, because mostly the
    # name comes from there!)
    sortedids = sorted(apps.keys(), key=lambda appid: apps[appid].Name.upper())

    # APKs are placed into multiple repos based on the app package, providing
    # per-app subscription feeds for nightly builds and things like it
    if config['per_app_repos']:
        add_apks_to_per_app_repos(repodirs[0], apks)
        for appid, app in apps.items():
            repodir = os.path.join(appid, 'fdroid', 'repo')
            appdict = dict()
            appdict[appid] = app
            if os.path.isdir(repodir):
                index.make(appdict, [appid], apks, repodir, False)
            else:
                logging.info('Skipping index generation for ' + appid)
        return

    if len(repodirs) > 1:
        archive_old_apks(apps, apks, archapks, repodirs[0], repodirs[1], config['archive_older'])

    # Make the index for the main repo...
    index.make(apps, sortedids, apks, repodirs[0], False)
    make_categories_txt(repodirs[0], categories)

    # If there's an archive repo,  make the index for it. We already scanned it
    # earlier on.
    if len(repodirs) > 1:
        index.make(apps, sortedids, archapks, repodirs[1], True)

    if config.get('binary_transparency_remote'):
        make_binary_transparency_log(repodirs)

    if config['update_stats']:
        # Update known apks info...
        knownapks.writeifchanged()

        # Generate latest apps data for widget
        if os.path.exists(os.path.join('stats', 'latestapps.txt')):
            data = ''
            with open(os.path.join('stats', 'latestapps.txt'), 'r', encoding='utf8') as f:
                for line in f:
                    appid = line.rstrip()
                    data += appid + "\t"
                    app = apps[appid]
                    data += app.Name + "\t"
                    if app.icon is not None:
                        data += app.icon + "\t"
                    data += app.License + "\n"
            with open(os.path.join(repodirs[0], 'latestapps.dat'), 'w', encoding='utf8') as f:
                f.write(data)

    if cachechanged:
        write_cache(apkcache)

    # Update the wiki...
    if options.wiki:
        update_wiki(apps, sortedids, apks + archapks)

    logging.info("Finished.")


if __name__ == "__main__":
    main()
