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
import re
import socket
import zipfile
import hashlib
import pickle
import time
from datetime import datetime
from argparse import ArgumentParser

import collections
from binascii import hexlify

from PIL import Image, PngImagePlugin
import logging

from . import _
from . import common
from . import index
from . import metadata
from .common import SdkToolsPopen
from .exception import BuildException, FDroidException

METADATA_VERSION = 19

# less than the valid range of versionCode, i.e. Java's Integer.MIN_VALUE
UNSET_VERSION_CODE = -0x100000000

APK_NAME_PAT = re.compile(".*name='([a-zA-Z0-9._]*)'.*")
APK_VERCODE_PAT = re.compile(".*versionCode='([0-9]*)'.*")
APK_VERNAME_PAT = re.compile(".*versionName='([^']*)'.*")
APK_LABEL_ICON_PAT = re.compile(".*\s+label='(.*)'\s+icon='(.*?)'")
APK_SDK_VERSION_PAT = re.compile(".*'([0-9]*)'.*")
APK_PERMISSION_PAT = \
    re.compile(".*(name='(?P<name>.*?)')(.*maxSdkVersion='(?P<maxSdkVersion>.*?)')?.*")
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
            for af in sorted(app.AntiFeatures):
                wikidata += '{{AntiFeature|' + af + '}}\n'
        if app.RequiresRoot:
            requiresroot = 'Yes'
        else:
            requiresroot = 'No'
        wikidata += '{{App|id=%s|name=%s|added=%s|lastupdated=%s|source=%s|tracker=%s|web=%s|changelog=%s|donate=%s|flattr=%s|liberapay=%s|bitcoin=%s|litecoin=%s|license=%s|root=%s|author=%s|email=%s}}\n' % (
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
            app.LiberapayID,
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
        apppagename = app.Name
        for ch in '_{}:[]|':
            apppagename = apppagename.replace(ch, ' ')
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
                pagetxt = page.text()
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
    site.Pages['Repository Maintenance'].purge()

    # Write a page with the last build log for this version code
    wiki_page_path = 'update_' + time.strftime('%s', start_timestamp)
    newpage = site.Pages[wiki_page_path]
    txt = ''
    txt += "* command line: <code>" + ' '.join(sys.argv) + "</code>\n"
    txt += "* started at " + common.get_wiki_timestamp(start_timestamp) + '\n'
    txt += "* completed at " + common.get_wiki_timestamp() + '\n'
    txt += common.get_git_describe_link()
    txt += "\n\n"
    txt += common.get_android_tools_version_log()
    newpage.save(txt, summary='Run log')
    newpage = site.Pages['update']
    newpage.save('#REDIRECT [[' + wiki_page_path + ']]', summary='Update redirect')


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

    with zipfile.ZipFile(apkpath, 'r') as apk:
        certs = [n for n in apk.namelist() if common.CERT_PATH_REGEX.match(n)]

        if len(certs) < 1:
            logging.error(_("No signing certificates found in {path}").format(path=apkpath))
            return None
        if len(certs) > 1:
            logging.error(_("Found multiple signing certificates in {path}").format(path=apkpath))
            return None

        cert = apk.read(certs[0])

    cert_encoded = common.get_certificate(cert)

    return hashlib.md5(hexlify(cert_encoded)).hexdigest()


def get_cache_file():
    return os.path.join('tmp', 'apkcache')


def get_cache():
    """Get the cached dict of the APK index

    Gather information about all the apk files in the repo directory,
    using cached data if possible. Some of the index operations take a
    long time, like calculating the SHA-256 and verifying the APK
    signature.

    The cache is invalidated if the metadata version is different, or
    the 'allow_disabled_algorithms' config/option is different.  In
    those cases, there is no easy way to know what has changed from
    the cache, so just rerun the whole thing.

    :return: apkcache

    """
    apkcachefile = get_cache_file()
    ada = options.allow_disabled_algorithms or config['allow_disabled_algorithms']
    if not options.clean and os.path.exists(apkcachefile):
        with open(apkcachefile, 'rb') as cf:
            apkcache = pickle.load(cf, encoding='utf-8')
        if apkcache.get("METADATA_VERSION") != METADATA_VERSION \
           or apkcache.get('allow_disabled_algorithms') != ada:
            apkcache = {}
    else:
        apkcache = {}

    apkcache["METADATA_VERSION"] = METADATA_VERSION
    apkcache['allow_disabled_algorithms'] = ada

    return apkcache


def write_cache(apkcache):
    apkcachefile = get_cache_file()
    cache_path = os.path.dirname(apkcachefile)
    if not os.path.exists(cache_path):
        os.makedirs(cache_path)
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


def has_known_vulnerability(filename):
    """checks for known vulnerabilities in the APK

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
            if name.endswith('libcrypto.so') or name.endswith('libssl.so'):
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


def translate_per_build_anti_features(apps, apks):
    """Grab the anti-features list from the build metadata

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
        for build in app['builds']:
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
    '''get the dict to add localized store metadata to'''
    if 'localized' not in app:
        app['localized'] = collections.OrderedDict()
    if locale not in app['localized']:
        app['localized'][locale] = collections.OrderedDict()
    return app['localized'][locale]


def _set_localized_text_entry(app, locale, key, f):
    limit = config['char_limits'][key]
    localized = _get_localized_dict(app, locale)
    with open(f) as fp:
        text = fp.read()[:limit]
        if len(text) > 0:
            localized[key] = text


def _set_author_entry(app, key, f):
    limit = config['char_limits']['author']
    with open(f) as fp:
        text = fp.read()[:limit]
        if len(text) > 0:
            app[key] = text


def _strip_and_copy_image(inpath, outpath):
    """Remove any metadata from image and copy it to new path

    Sadly, image metadata like EXIF can be used to exploit devices.
    It is not used at all in the F-Droid ecosystem, so its much safer
    just to remove it entirely.

    """

    extension = common.get_extension(inpath)[1]
    if os.path.isdir(outpath):
        outpath = os.path.join(outpath, os.path.basename(inpath))
    if extension == 'png':
        with open(inpath, 'rb') as fp:
            in_image = Image.open(fp)
            in_image.save(outpath, "PNG", optimize=True,
                          pnginfo=BLANK_PNG_INFO, icc_profile=None)
    elif extension == 'jpg' or extension == 'jpeg':
        with open(inpath, 'rb') as fp:
            in_image = Image.open(fp)
            data = list(in_image.getdata())
            out_image = Image.new(in_image.mode, in_image.size)
        out_image.putdata(data)
        out_image.save(outpath, "JPEG", optimize=True)
    else:
        raise FDroidException(_('Unsupported file type "{extension}" for repo graphic')
                              .format(extension=extension))


def copy_triple_t_store_metadata(apps):
    """Include store metadata from the app's source repo

    The Triple-T Gradle Play Publisher is a plugin that has a standard
    file layout for all of the metadata and graphics that the Google
    Play Store accepts.  Since F-Droid has the git repo, it can just
    pluck those files directly.  This method reads any text files into
    the app dict, then copies any graphics into the fdroid repo
    directory structure.

    This needs to be run before insert_localized_app_metadata() so that
    the graphics files that are copied into the fdroid repo get
    properly indexed.

    https://github.com/Triple-T/gradle-play-publisher#upload-images
    https://github.com/Triple-T/gradle-play-publisher#play-store-metadata

    """

    if not os.path.isdir('build'):
        return  # nothing to do

    for packageName, app in apps.items():
        for d in glob.glob(os.path.join('build', packageName, '*', 'src', '*', 'play')):
            logging.debug('Triple-T Gradle Play Publisher: ' + d)
            for root, dirs, files in os.walk(d):
                segments = root.split('/')
                locale = segments[-2]
                for f in files:
                    if f == 'fulldescription':
                        _set_localized_text_entry(app, locale, 'description',
                                                  os.path.join(root, f))
                        continue
                    elif f == 'shortdescription':
                        _set_localized_text_entry(app, locale, 'summary',
                                                  os.path.join(root, f))
                        continue
                    elif f == 'title':
                        _set_localized_text_entry(app, locale, 'name',
                                                  os.path.join(root, f))
                        continue
                    elif f == 'video':
                        _set_localized_text_entry(app, locale, 'video',
                                                  os.path.join(root, f))
                        continue
                    elif f == 'whatsnew':
                        _set_localized_text_entry(app, segments[-1], 'whatsNew',
                                                  os.path.join(root, f))
                        continue
                    elif f == 'contactEmail':
                        _set_author_entry(app, 'authorEmail', os.path.join(root, f))
                        continue
                    elif f == 'contactPhone':
                        _set_author_entry(app, 'authorPhone', os.path.join(root, f))
                        continue
                    elif f == 'contactWebsite':
                        _set_author_entry(app, 'authorWebSite', os.path.join(root, f))
                        continue

                    base, extension = common.get_extension(f)
                    dirname = os.path.basename(root)
                    if extension in ALLOWED_EXTENSIONS \
                       and (dirname in GRAPHIC_NAMES or dirname in SCREENSHOT_DIRS):
                        if segments[-2] == 'listing':
                            locale = segments[-3]
                        else:
                            locale = segments[-2]
                        destdir = os.path.join('repo', packageName, locale, dirname)
                        os.makedirs(destdir, mode=0o755, exist_ok=True)
                        sourcefile = os.path.join(root, f)
                        destfile = os.path.join(destdir, os.path.basename(f))
                        logging.debug('copying ' + sourcefile + ' ' + destfile)
                        _strip_and_copy_image(sourcefile, destfile)


def insert_localized_app_metadata(apps):
    """scans standard locations for graphics and localized text

    Scans for localized description files, store graphics, and
    screenshot PNG files in statically defined screenshots directory
    and adds them to the app metadata.  The screenshots and graphic
    must be PNG or JPEG files ending with ".png", ".jpg", or ".jpeg"
    and must be in the following layout:
    # TODO replace these docs with link to All_About_Descriptions_Graphics_and_Screenshots

    repo/packageName/locale/featureGraphic.png
    repo/packageName/locale/phoneScreenshots/1.png
    repo/packageName/locale/phoneScreenshots/2.png

    The changelog files must be text files named with the versionCode
    ending with ".txt" and must be in the following layout:
    https://github.com/fastlane/fastlane/blob/2.28.7/supply/README.md#changelogs-whats-new

    repo/packageName/locale/changelogs/12345.txt

    This will scan the each app's source repo then the metadata/ dir
    for these standard locations of changelog files.  If it finds
    them, they will be added to the dict of all packages, with the
    versions in the metadata/ folder taking precendence over the what
    is in the app's source repo.

    Where "packageName" is the app's packageName and "locale" is the locale
    of the graphics, e.g. what language they are in, using the IETF RFC5646
    format (en-US, fr-CA, es-MX, etc).

    This will also scan the app's git for a fastlane folder, and the
    metadata/ folder and the apps' source repos for standard locations
    of graphic and screenshot files.  If it finds them, it will copy
    them into the repo.  The fastlane files follow this pattern:
    https://github.com/fastlane/fastlane/blob/2.28.7/supply/README.md#images-and-screenshots

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
            if apps[packageName] and 'builds' in apps[packageName] and len(apps[packageName].builds) > 0\
                    and 'gradle' in apps[packageName].builds[-1]:
                build_flavours = apps[packageName].builds[-1].gradle

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
                    logging.debug('copying ' + os.path.join(root, f) + ' ' + destdir)
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
                            logging.debug('copying ' + f + ' ' + screenshotdestdir)
                            _strip_and_copy_image(f, screenshotdestdir)

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
                logging.warning(_('Found "{path}" graphic without metadata for app "{name}"!')
                                .format(path=filename, name=packageName))
                continue
            graphics = _get_localized_dict(apps[packageName], locale)

            if extension not in ALLOWED_EXTENSIONS:
                logging.warning(_('Only PNG and JPEG are supported for graphics, found: {path}').format(path=f))
            elif base in GRAPHIC_NAMES:
                # there can only be zero or one of these per locale
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
    """Scan a repo for all files with an extension except APK/OBB

    :param apkcache: current cached info about all repo files
    :param repodir: repo directory to scan
    :param knownapks: list of all known files, as per metadata.read_metadata
    :param use_date_from_file: use date from file (instead of current date)
                               for newly added files
    """

    cachechanged = False
    repo_files = []
    repodir = repodir.encode('utf-8')
    for name in os.listdir(repodir):
        file_extension = common.get_file_extension(name)
        if file_extension == 'apk' or file_extension == 'obb':
            continue
        filename = os.path.join(repodir, name)
        name_utf8 = name.decode('utf-8')
        if filename.endswith(b'_src.tar.gz'):
            logging.debug(_('skipping source tarball: {path}')
                          .format(path=filename.decode('utf-8')))
            continue
        if not common.is_repo_file(filename):
            continue
        stat = os.stat(filename)
        if stat.st_size == 0:
            raise FDroidException(_('{path} is zero size!')
                                  .format(path=filename))

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
                repo_file['srcname'] = srcfilename.decode('utf-8')
            repo_file['size'] = stat.st_size

            apkcache[name] = repo_file
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


def scan_apk(apk_file):
    """
    Scans an APK file and returns dictionary with metadata of the APK.

    Attention: This does *not* verify that the APK signature is correct.

    :param apk_file: The (ideally absolute) path to the APK file
    :raises BuildException
    :return A dict containing APK metadata
    """
    apk = {
        'hash': sha256sum(apk_file),
        'hashType': 'sha256',
        'uses-permission': [],
        'uses-permission-sdk-23': [],
        'features': [],
        'icons_src': {},
        'icons': {},
        'antiFeatures': set(),
    }

    if common.use_androguard():
        scan_apk_androguard(apk, apk_file)
    else:
        scan_apk_aapt(apk, apk_file)

    # Get the signature, or rather the signing key fingerprints
    logging.debug('Getting signature of {0}'.format(os.path.basename(apk_file)))
    apk['sig'] = getsig(apk_file)
    if not apk['sig']:
        raise BuildException("Failed to get apk signature")
    apk['signer'] = common.apk_signer_fingerprint(os.path.join(os.getcwd(),
                                                               apk_file))
    if not apk.get('signer'):
        raise BuildException("Failed to get apk signing key fingerprint")

    # Get size of the APK
    apk['size'] = os.path.getsize(apk_file)

    if 'minSdkVersion' not in apk:
        logging.warning("No SDK version information found in {0}".format(apk_file))
        apk['minSdkVersion'] = 3  # aapt defaults to 3 as the min
    if 'targetSdkVersion' not in apk:
        apk['targetSdkVersion'] = apk['minSdkVersion']

    # Check for known vulnerabilities
    if has_known_vulnerability(apk_file):
        apk['antiFeatures'].add('KnownVuln')

    return apk


def _get_apk_icons_src(apkfile, icon_name):
    """Extract the paths to the app icon in all available densities

    """
    icons_src = dict()
    density_re = re.compile('^res/(.*)/{}\.(png|xml)$'.format(icon_name))
    with zipfile.ZipFile(apkfile) as zf:
        for filename in zf.namelist():
            m = density_re.match(filename)
            if m:
                folder = m.group(1).split('-')
                if len(folder) > 1 and folder[1].endswith('dpi'):
                    density = screen_resolutions[folder[1]]
                else:
                    density = '160'
                icons_src[density] = m.group(0)
    if icons_src.get('-1') is None and '160' in icons_src:
        icons_src['-1'] = icons_src['160']
    return icons_src


def scan_apk_aapt(apk, apkfile):
    p = SdkToolsPopen(['aapt', 'dump', 'badging', apkfile], output=False)
    if p.returncode != 0:
        if options.delete_unknown:
            if os.path.exists(apkfile):
                logging.error(_("Failed to get apk information, deleting {path}").format(path=apkfile))
                os.remove(apkfile)
            else:
                logging.error("Could not find {0} to remove it".format(apkfile))
        else:
            logging.error(_("Failed to get apk information, skipping {path}").format(path=apkfile))
        raise BuildException(_("Invalid APK"))
    icon_name = None
    for line in p.output.splitlines():
        if line.startswith("package:"):
            try:
                apk['packageName'] = re.match(APK_NAME_PAT, line).group(1)
                apk['versionCode'] = int(re.match(APK_VERCODE_PAT, line).group(1))
                apk['versionName'] = re.match(APK_VERNAME_PAT, line).group(1)
            except Exception as e:
                raise FDroidException("Package matching failed: " + str(e) + "\nLine was: " + line)
        elif line.startswith("application:"):
            m = re.match(APK_LABEL_ICON_PAT, line)
            if m:
                apk['name'] = m.group(1)
                icon_name = os.path.splitext(os.path.basename(m.group(2)))[0]
        elif not apk.get('name') and line.startswith("launchable-activity:"):
            # Only use launchable-activity as fallback to application
            apk['name'] = re.match(APK_LABEL_ICON_PAT, line).group(1)
        elif line.startswith("sdkVersion:"):
            m = re.match(APK_SDK_VERSION_PAT, line)
            if m is None:
                logging.error(line.replace('sdkVersion:', '')
                              + ' is not a valid minSdkVersion!')
            else:
                apk['minSdkVersion'] = m.group(1)
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

            apk['uses-permission'].append(permission)
        elif line.startswith('uses-permission-sdk-23:'):
            perm_match = re.match(APK_PERMISSION_PAT, line).groupdict()
            if perm_match['maxSdkVersion']:
                perm_match['maxSdkVersion'] = int(perm_match['maxSdkVersion'])
            permission_sdk_23 = UsesPermissionSdk23(
                perm_match['name'],
                perm_match['maxSdkVersion']
            )

            apk['uses-permission-sdk-23'].append(permission_sdk_23)

        elif line.startswith('uses-feature:'):
            feature = re.match(APK_FEATURE_PAT, line).group(1)
            # Filter out this, it's only added with the latest SDK tools and
            # causes problems for lots of apps.
            if feature != "android.hardware.screen.portrait" \
                    and feature != "android.hardware.screen.landscape":
                if feature.startswith("android.feature."):
                    feature = feature[16:]
                apk['features'].add(feature)
    apk['icons_src'] = _get_apk_icons_src(apkfile, icon_name)


def _sanitize_sdk_version(value):
    """Sanitize the raw values from androguard to handle bad values

    minSdkVersion/targetSdkVersion/maxSdkVersion must be integers,
    but that doesn't stop devs from doing strange things like
    setting them using Android XML strings.

    https://gitlab.com/souch/SMSbypass/blob/v0.9/app/src/main/AndroidManifest.xml#L29
    https://gitlab.com/souch/SMSbypass/blob/v0.9/app/src/main/res/values/strings.xml#L27
    """
    try:
        sdk_version = int(value)
        if sdk_version > 0:
            return str(sdk_version)  # heinous, but this is still str in the codebase
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
                    logging.error(_("Failed to get apk information, deleting {path}")
                                  .format(path=apkfile))
                    os.remove(apkfile)
                else:
                    logging.error(_("Could not find {path} to remove it")
                                  .format(path=apkfile))
            else:
                logging.error(_("Failed to get apk information, skipping {path}")
                              .format(path=apkfile))
            raise BuildException(_("Invalid APK"))
    except ImportError:
        raise FDroidException("androguard library is not installed and aapt not present")
    except FileNotFoundError:
        logging.error(_("Could not open apk file for analysis"))
        raise BuildException(_("Invalid APK"))

    apk['packageName'] = apkobject.get_package()
    apk['versionCode'] = int(apkobject.get_androidversion_code())
    apk['name'] = apkobject.get_app_name()

    apk['versionName'] = common.ensure_final_value(apk['packageName'], arsc,
                                                   apkobject.get_androidversion_name())

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
        icon_id = int(icon_id_str.replace("@", "0x"), 16)
        resource_id = arsc.get_id(apk['packageName'], icon_id)
        if resource_id:
            icon_name = arsc.get_id(apk['packageName'], icon_id)[1]
        else:
            icon_name = os.path.splitext(os.path.basename(apkobject.get_app_icon()))[0]
        apk['icons_src'] = _get_apk_icons_src(apkfile, icon_name)

    arch_re = re.compile("^lib/(.*)/.*$")
    arch = set([arch_re.match(file).group(1) for file in apkobject.get_files() if arch_re.match(file)])
    if len(arch) >= 1:
        apk['nativecode'] = []
        apk['nativecode'].extend(sorted(list(arch)))

    xml = apkobject.get_android_manifest_xml()
    xmlns = xml.nsmap.get('android')
    if not xmlns:
        xmlns = 'http://schemas.android.com/apk/res/android'

    for item in xml.findall('uses-permission'):
        name = str(item.attrib['{' + xmlns + '}name'])
        maxSdkVersion = item.attrib.get('{' + xmlns + '}maxSdkVersion')
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
        name = str(item.attrib['{' + xmlns + '}name'])
        maxSdkVersion = item.attrib.get('{' + xmlns + '}maxSdkVersion')
        maxSdkVersion = int(maxSdkVersion) if maxSdkVersion else None
        permission_sdk_23 = UsesPermissionSdk23(
            name,
            maxSdkVersion
        )
        apk['uses-permission-sdk-23'].append(permission_sdk_23)

    for item in xml.findall('uses-feature'):
        key = '{' + xmlns + '}name'
        if key not in item.attrib:
            continue
        feature = str(item.attrib[key])
        if feature != "android.hardware.screen.portrait" \
                and feature != "android.hardware.screen.landscape":
            if feature.startswith("android.feature."):
                feature = feature[16:]
        required = item.attrib.get('{' + xmlns + '}required')
        if required is None or required == 'true':
            apk['features'].append(feature)


def process_apk(apkcache, apkfilename, repodir, knownapks, use_date_from_apk=False,
                allow_disabled_algorithms=False, archive_bad_sig=False):
    """Processes the apk with the given filename in the given repo directory.

    This also extracts the icons.

    :param apkcache: current apk cache information
    :param apkfilename: the filename of the apk to scan
    :param repodir: repo directory to scan
    :param knownapks: known apks info
    :param use_date_from_apk: use date from APK (instead of current date)
                              for newly added APKs
    :param allow_disabled_algorithms: allow APKs with valid signatures that include
                                      disabled algorithms in the signature (e.g. MD5)
    :param archive_bad_sig: move APKs with a bad signature to the archive
    :returns: (skip, apk, cachechanged) where skip is a boolean indicating whether to skip this apk,
     apk is the scanned apk information, and cachechanged is True if the apkcache got changed.
    """

    apk = {}
    apkfile = os.path.join(repodir, apkfilename)

    cachechanged = False
    usecache = False
    if apkfilename in apkcache:
        apk = apkcache[apkfilename]
        if apk.get('hash') == sha256sum(apkfile):
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
        iconfilename = "%s.%s" % (apk['packageName'], apk['versionCode'])
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
    """Processes the apks in the given repo directory.

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
    for apkfile in sorted(glob.glob(os.path.join(repodir, '*.apk'))):
        apkfilename = apkfile[len(repodir) + 1:]
        ada = options.allow_disabled_algorithms or config['allow_disabled_algorithms']
        (skip, apk, cachethis) = process_apk(apkcache, apkfilename, repodir, knownapks,
                                             use_date_from_apk, ada, True)
        if skip:
            continue
        apks.append(apk)
        cachechanged = cachechanged or cachethis

    return apks, cachechanged


def extract_apk_icons(icon_filename, apk, apkzip, repo_dir):
    """Extracts PNG icons from an APK with the supported pixel densities

    Extracts icons from the given APK zip in various densities, saves
    them into given repo directory and stores their names in the APK
    metadata dictionary.  If the icon is an XML icon, then this tries
    to find PNG icon that can replace it.

    :param icon_filename: A string representing the icon's file name
    :param apk: A populated dictionary containing APK metadata.
                Needs to have 'icons_src' key
    :param apkzip: An opened zipfile.ZipFile of the APK file
    :param repo_dir: The directory of the APK's repository
    :return: A list of icon densities that are missing

    """
    res_name_re = re.compile(r'res/(drawable|mipmap)-(x*[hlm]dpi|anydpi).*/(.*)_[0-9]+dp.(png|xml)')
    pngs = dict()
    for f in apkzip.namelist():
        m = res_name_re.match(f)
        if m and m.group(4) == 'png':
            density = screen_resolutions[m.group(2)]
            pngs[m.group(3) + '/' + density] = m.group(0)

    icon_type = None
    empty_densities = []
    for density in screen_densities:
        if density not in apk['icons_src']:
            empty_densities.append(density)
            continue
        icon_src = apk['icons_src'][density]
        icon_dir = get_icon_dir(repo_dir, density)
        icon_type = '.png'

        # Extract the icon files per density
        if icon_src.endswith('.xml'):
            m = res_name_re.match(icon_src)
            if m:
                name = pngs.get(m.group(3) + '/' + str(density))
                if name:
                    icon_src = name
            if icon_src.endswith('.xml'):
                empty_densities.append(density)
                icon_type = '.xml'
        icon_dest = os.path.join(icon_dir, icon_filename + icon_type)

        try:
            with open(icon_dest, 'wb') as f:
                f.write(get_icon_bytes(apkzip, icon_src))
            apk['icons'][density] = icon_filename + icon_type
        except (zipfile.BadZipFile, ValueError, KeyError) as e:
            logging.warning("Error retrieving icon file: %s %s", icon_dest, e)
            del apk['icons_src'][density]
            empty_densities.append(density)

    # '-1' here is a remnant of the parsing of aapt output, meaning "no DPI specified"
    if '-1' in apk['icons_src']:
        icon_src = apk['icons_src']['-1']
        icon_type = icon_src[-4:]
        icon_path = os.path.join(get_icon_dir(repo_dir, '0'), icon_filename + icon_type)
        with open(icon_path, 'wb') as f:
            f.write(get_icon_bytes(apkzip, icon_src))
        if icon_type == '.png':
            im = None
            try:
                im = Image.open(icon_path)
                dpi = px_to_dpi(im.size[0])
                for density in screen_densities:
                    if density in apk['icons']:
                        break
                    if density == screen_densities[-1] or dpi >= int(density):
                        apk['icons'][density] = icon_filename + icon_type
                        shutil.move(icon_path,
                                    os.path.join(get_icon_dir(repo_dir, density), icon_filename + icon_type))
                        empty_densities.remove(density)
                        break
            except Exception as e:
                logging.warning(_("Failed reading {path}: {error}")
                                .format(path=icon_path, error=e))
            finally:
                if im and hasattr(im, 'close'):
                    im.close()

    if apk['icons']:
        apk['icon'] = icon_filename + icon_type

    return empty_densities


def fill_missing_icon_densities(empty_densities, icon_filename, apk, repo_dir):
    """
    Resize existing PNG icons for densities missing in the APK to ensure all densities are available

    :param empty_densities: A list of icon densities that are missing
    :param icon_filename: A string representing the icon's file name
    :param apk: A populated dictionary containing APK metadata. Needs to have 'icons' key
    :param repo_dir: The directory of the APK's repository

    """
    icon_filename += '.png'
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

    def filter_apk_list_sorted(apk_list):
        res = []
        for apk in apk_list:
            if apk['packageName'] == appid:
                res.append(apk)

        # Sort the apk list by version code. First is highest/newest.
        return sorted(res, key=lambda apk: apk['versionCode'], reverse=True)

    for appid, app in apps.items():

        if app.ArchivePolicy:
            keepversions = int(app.ArchivePolicy[:-9])
        else:
            keepversions = defaultkeepversions

        logging.debug(_("Checking archiving for {appid} - apks:{integer}, keepversions:{keep}, archapks:{arch}")
                      .format(appid=appid, integer=len(apks), keep=keepversions, arch=len(archapks)))

        current_app_apks = filter_apk_list_sorted(apks)
        if len(current_app_apks) > keepversions:
            # Move back the ones we don't want.
            for apk in current_app_apks[keepversions:]:
                move_apk_between_sections(repodir, archivedir, apk)
                archapks.append(apk)
                apks.remove(apk)

        current_app_archapks = filter_apk_list_sorted(archapks)
        if len(current_app_apks) < keepversions and len(current_app_archapks) > 0:
            kept = 0
            # Move forward the ones we want again, except DisableAlgorithm
            for apk in current_app_archapks:
                if 'DisabledAlgorithm' not in apk['antiFeatures']:
                    move_apk_between_sections(archivedir, repodir, apk)
                    archapks.remove(apk)
                    apks.append(apk)
                    kept += 1
                if kept == keepversions:
                    break


def move_apk_between_sections(from_dir, to_dir, apk):
    """move an APK from repo to archive or vice versa"""

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
    '''create a new metadata file using internal or external template

    Generate warnings for apk's with no metadata (or create skeleton
    metadata files, if requested on the command line).  Though the
    template file is YAML, this uses neither pyyaml nor ruamel.yaml
    since those impose things on the metadata file made from the
    template: field sort order, empty field value, formatting, etc.
    '''

    import yaml
    if os.path.exists('template.yml'):
        with open('template.yml') as f:
            metatxt = f.read()
        if 'name' in apk and apk['name'] != '':
            metatxt = re.sub(r'''^(((Auto)?Name|Summary):)[ '"\.]*$''',
                             r'\1 ' + apk['name'],
                             metatxt,
                             flags=re.IGNORECASE | re.MULTILINE)
        else:
            logging.warning(_('{appid} does not have a name! Using package name instead.')
                            .format(appid=apk['packageName']))
            metatxt = re.sub(r'^(((Auto)?Name|Summary):).*$',
                             r'\1 ' + apk['packageName'],
                             metatxt,
                             flags=re.IGNORECASE | re.MULTILINE)
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
            logging.warning(_('{appid} does not have a name! Using package name instead.')
                            .format(appid=apk['packageName']))
            app['Name'] = apk['packageName']
        with open(os.path.join('metadata', apk['packageName'] + '.yml'), 'w') as f:
            yaml.dump(app, f, default_flow_style=False)
    logging.info(_("Generated skeleton metadata for {appid}").format(appid=apk['packageName']))


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
    parser.add_argument("-b", "--buildreport", action="store_true", default=False,
                        help=_("Report on build data status"))
    parser.add_argument("-i", "--interactive", default=False, action="store_true",
                        help=_("Interactively ask about things that need updating."))
    parser.add_argument("-I", "--icons", action="store_true", default=False,
                        help=_("Resize all the icons exceeding the max pixel size and exit"))
    parser.add_argument("-e", "--editor", default="/etc/alternatives/editor",
                        help=_("Specify editor to use in interactive mode. Default " +
                               "is {path}").format(path='/etc/alternatives/editor'))
    parser.add_argument("-w", "--wiki", default=False, action="store_true",
                        help=_("Update the wiki"))
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

    if not ('jarsigner' in config and 'keytool' in config):
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
                logging.critical(_('{name} "{path}" does not exist! Correct it in config.py.')
                                 .format(name=k, path=config[k]))
                sys.exit(1)

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
    apks, cachechanged = process_apks(apkcache, repodirs[0], knownapks, options.use_date_from_apk)

    files, fcachechanged = scan_repo_files(apkcache, repodirs[0], knownapks,
                                           options.use_date_from_apk)
    cachechanged = cachechanged or fcachechanged
    apks += files
    for apk in apks:
        if apk['packageName'] not in apps:
            if options.create_metadata:
                create_metadata_from_template(apk)
                apps = metadata.read_metadata()
            else:
                msg = _("{apkfilename} ({appid}) has no metadata!") \
                    .format(apkfilename=apk['apkName'], appid=apk['packageName'])
                if options.delete_unknown:
                    logging.warn(msg + '\n\t' + _("deleting: repo/{apkfilename}")
                                 .format(apkfilename=apk['apkName']))
                    rmf = os.path.join(repodirs[0], apk['apkName'])
                    if not os.path.exists(rmf):
                        logging.error(_("Could not find {path} to remove it").format(path=rmf))
                    else:
                        os.remove(rmf)
                else:
                    logging.warn(msg + '\n\t' + _("Use `fdroid update -c` to create it."))

    copy_triple_t_store_metadata(apps)
    insert_obbs(repodirs[0], apps, apks)
    insert_localized_app_metadata(apps)
    translate_per_build_anti_features(apps, apks)

    # Scan the archive repo for apks as well
    if len(repodirs) > 1:
        archapks, cc = process_apks(apkcache, repodirs[1], knownapks, options.use_date_from_apk)
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
                logging.info(_('Skipping index generation for {appid}').format(appid=appid))
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

    git_remote = config.get('binary_transparency_remote')
    if git_remote or os.path.isdir(os.path.join('binary_transparency', '.git')):
        from . import btlog
        btlog.make_binary_transparency_log(repodirs)

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

    logging.info(_("Finished"))


if __name__ == "__main__":
    main()
