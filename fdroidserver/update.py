#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# update.py - part of the FDroid server tools
# Copyright (C) 2010-2013, Ciaran Gultnieks, ciaran@ciarang.com
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
import shutil
import glob
import re
import zipfile
import hashlib
import pickle
from xml.dom.minidom import Document
from optparse import OptionParser
import time
from PIL import Image
import logging

import common
import metadata
from common import FDroidPopen, SilentPopen
from metadata import MetaDataException


def get_densities():
    return ['640', '480', '320', '240', '160', '120']


def dpi_to_px(density):
    return (int(density) * 48) / 160


def px_to_dpi(px):
    return (int(px) * 160) / 48


def get_icon_dir(repodir, density):
    if density is None:
        return os.path.join(repodir, "icons")
    return os.path.join(repodir, "icons-%s" % density)


def get_icon_dirs(repodir):
    for density in get_densities():
        yield get_icon_dir(repodir, density)
    yield os.path.join(repodir, "icons")


def update_wiki(apps, apks):
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
    for app in apps:
        wikidata = ''
        if app['Disabled']:
            wikidata += '{{Disabled|' + app['Disabled'] + '}}\n'
        if app['AntiFeatures']:
            for af in app['AntiFeatures'].split(','):
                wikidata += '{{AntiFeature|' + af + '}}\n'
        wikidata += '{{App|id=%s|name=%s|added=%s|lastupdated=%s|source=%s|tracker=%s|web=%s|donate=%s|flattr=%s|bitcoin=%s|litecoin=%s|dogecoin=%s|license=%s|root=%s}}\n' % (
            app['id'],
            app['Name'],
            time.strftime('%Y-%m-%d', app['added']) if 'added' in app else '',
            time.strftime('%Y-%m-%d', app['lastupdated']) if 'lastupdated' in app else '',
            app['Source Code'],
            app['Issue Tracker'],
            app['Web Site'],
            app['Donate'],
            app['FlattrID'],
            app['Bitcoin'],
            app['Litecoin'],
            app['Dogecoin'],
            app['License'],
            app.get('Requires Root', 'No'))

        if app['Provides']:
            wikidata += "This app provides: %s" % ', '.join(app['Summary'].split(','))

        wikidata += app['Summary']
        wikidata += " - [https://f-droid.org/repository/browse/?fdid=" + app['id'] + " view in repository]\n\n"

        wikidata += "=Description=\n"
        wikidata += metadata.description_wiki(app['Description']) + "\n"

        wikidata += "=Maintainer Notes=\n"
        if 'Maintainer Notes' in app:
            wikidata += metadata.description_wiki(app['Maintainer Notes']) + "\n"
        wikidata += "\nMetadata: [https://gitlab.com/fdroid/fdroiddata/blob/master/metadata/{0}.txt current] [https://gitlab.com/fdroid/fdroiddata/commits/master/metadata/{0}.txt history]\n".format(app['id'])

        # Get a list of all packages for this application...
        apklist = []
        gotcurrentver = False
        cantupdate = False
        buildfails = False
        for apk in apks:
            if apk['id'] == app['id']:
                if str(apk['versioncode']) == app['Current Version Code']:
                    gotcurrentver = True
                apklist.append(apk)
        # Include ones we can't build, as a special case...
        for thisbuild in app['builds']:
            if thisbuild['disable']:
                if thisbuild['vercode'] == app['Current Version Code']:
                    cantupdate = True
                # TODO: Nasty: vercode is a string in the build, and an int elsewhere
                apklist.append({'versioncode': int(thisbuild['vercode']),
                                'version': thisbuild['version'],
                                'buildproblem': thisbuild['disable']
                                })
            else:
                builtit = False
                for apk in apklist:
                    if apk['versioncode'] == int(thisbuild['vercode']):
                        builtit = True
                        break
                if not builtit:
                    buildfails = True
                    apklist.append({'versioncode': int(thisbuild['vercode']),
                                    'version': thisbuild['version'],
                                    'buildproblem': "The build for this version appears to have failed. Check the [[{0}/lastbuild_{1}|build log]].".format(app['id'], thisbuild['vercode'])
                                    })
        if app['Current Version Code'] == '0':
            cantupdate = True
        # Sort with most recent first...
        apklist = sorted(apklist, key=lambda apk: apk['versioncode'], reverse=True)

        wikidata += "=Versions=\n"
        if len(apklist) == 0:
            wikidata += "We currently have no versions of this app available."
        elif not gotcurrentver:
            wikidata += "We don't have the current version of this app."
        else:
            wikidata += "We have the current version of this app."
        wikidata += " (Check mode: " + app['Update Check Mode'] + ") "
        wikidata += " (Auto-update mode: " + app['Auto Update Mode'] + ")\n\n"
        if len(app['No Source Since']) > 0:
            wikidata += "This application has partially or entirely been missing source code since version " + app['No Source Since'] + ".\n\n"
        if len(app['Current Version']) > 0:
            wikidata += "The current (recommended) version is " + app['Current Version']
            wikidata += " (version code " + app['Current Version Code'] + ").\n\n"
        validapks = 0
        for apk in apklist:
            wikidata += "==" + apk['version'] + "==\n"

            if 'buildproblem' in apk:
                wikidata += "We can't build this version: " + apk['buildproblem'] + "\n\n"
            else:
                validapks += 1
                wikidata += "This version is built and signed by "
                if 'srcname' in apk:
                    wikidata += "F-Droid, and guaranteed to correspond to the source tarball published with it.\n\n"
                else:
                    wikidata += "the original developer.\n\n"
            wikidata += "Version code: " + str(apk['versioncode']) + '\n'

        wikidata += '\n[[Category:' + wikicat + ']]\n'
        if len(app['No Source Since']) > 0:
            wikidata += '\n[[Category:Apps missing source code]]\n'
        if validapks == 0 and not app['Disabled']:
            wikidata += '\n[[Category:Apps with no packages]]\n'
        if cantupdate and not app['Disabled']:
            wikidata += "\n[[Category:Apps we can't update]]\n"
        if buildfails and not app['Disabled']:
            wikidata += "\n[[Category:Apps with failing builds]]\n"
        elif not gotcurrentver and not cantupdate and not app['Disabled'] and app['Update Check Mode'] != "Static":
            wikidata += '\n[[Category:Apps to Update]]\n'
        if app['Disabled']:
            wikidata += '\n[[Category:Apps that are disabled]]\n'
        if app['Update Check Mode'] == 'None' and not app['Disabled']:
            wikidata += '\n[[Category:Apps with no update check]]\n'
        for appcat in app['Categories']:
            wikidata += '\n[[Category:{0}]]\n'.format(appcat)

        # We can't have underscores in the page name, even if they're in
        # the package ID, because MediaWiki messes with them...
        pagename = app['id'].replace('_', ' ')

        # Drop a trailing newline, because mediawiki is going to drop it anyway
        # and it we don't we'll think the page has changed when it hasn't...
        if wikidata.endswith('\n'):
            wikidata = wikidata[:-1]

        generated_pages[pagename] = wikidata

        # Make a redirect from the name to the ID too, unless there's
        # already an existing page with the name and it isn't a redirect.
        noclobber = False
        apppagename = app['Name'].replace('_', ' ')
        apppagename = apppagename.replace('{', '')
        apppagename = apppagename.replace('}', ' ')
        apppagename = apppagename.replace(':', ' ')
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
                except:
                    logging.error("...FAILED to create page")

    # Purge server cache to ensure counts are up to date
    site.pages['Repository Maintenance'].purge()


def delete_disabled_builds(apps, apkcache, repodirs):
    """Delete disabled build outputs.

    :param apps: list of all applications, as per metadata.read_metadata
    :param apkcache: current apk cache information
    :param repodirs: the repo directories to process
    """
    for app in apps:
        for build in app['builds']:
            if build['disable']:
                apkfilename = app['id'] + '_' + str(build['vercode']) + '.apk'
                for repodir in repodirs:
                    apkpath = os.path.join(repodir, apkfilename)
                    srcpath = os.path.join(repodir, apkfilename[:-4] + "_src.tar.gz")
                    for name in [apkpath, srcpath]:
                        if os.path.exists(name):
                            logging.warn("Deleting disabled build output " + apkfilename)
                            os.remove(name)
                if apkfilename in apkcache:
                    del apkcache[apkfilename]


def resize_icon(iconpath, density):

    if not os.path.isfile(iconpath):
        return

    try:
        im = Image.open(iconpath)
        size = dpi_to_px(density)

        if any(length > size for length in im.size):
            oldsize = im.size
            im.thumbnail((size, size), Image.ANTIALIAS)
            logging.debug("%s was too large at %s - new size is %s" % (
                iconpath, oldsize, im.size))
            im.save(iconpath, "PNG")

    except Exception, e:
        logging.error("Failed resizing {0} - {1}".format(iconpath, e))


def resize_all_icons(repodirs):
    """Resize all icons that exceed the max size

    :param repodirs: the repo directories to process
    """
    for repodir in repodirs:
        for density in get_densities():
            icon_dir = get_icon_dir(repodir, density)
            icon_glob = os.path.join(icon_dir, '*.png')
            for iconpath in glob.glob(icon_glob):
                resize_icon(iconpath, density)


def scan_apks(apps, apkcache, repodir, knownapks):
    """Scan the apks in the given repo directory.

    This also extracts the icons.

    :param apps: list of all applications, as per metadata.read_metadata
    :param apkcache: current apk cache information
    :param repodir: repo directory to scan
    :param knownapks: known apks info
    :returns: (apks, cachechanged) where apks is a list of apk information,
              and cachechanged is True if the apkcache got changed.
    """

    cachechanged = False

    icon_dirs = get_icon_dirs(repodir)
    for icon_dir in icon_dirs:
        if os.path.exists(icon_dir):
            if options.clean:
                shutil.rmtree(icon_dir)
                os.makedirs(icon_dir)
        else:
            os.makedirs(icon_dir)

    apks = []
    name_pat = re.compile(".*name='([a-zA-Z0-9._]*)'.*")
    vercode_pat = re.compile(".*versionCode='([0-9]*)'.*")
    vername_pat = re.compile(".*versionName='([^']*)'.*")
    label_pat = re.compile(".*label='(.*?)'(\n| [a-z]*?=).*")
    icon_pat = re.compile(".*application-icon-([0-9]+):'([^']+?)'.*")
    icon_pat_nodpi = re.compile(".*icon='([^']+?)'.*")
    sdkversion_pat = re.compile(".*'([0-9]*)'.*")
    string_pat = re.compile(".*'([^']*)'.*")
    for apkfile in glob.glob(os.path.join(repodir, '*.apk')):

        apkfilename = apkfile[len(repodir) + 1:]
        if ' ' in apkfilename:
            logging.critical("Spaces in filenames are not allowed.")
            sys.exit(1)

        if apkfilename in apkcache:
            logging.debug("Reading " + apkfilename + " from cache")
            thisinfo = apkcache[apkfilename]

        else:
            logging.debug("Processing " + apkfilename)
            thisinfo = {}
            thisinfo['apkname'] = apkfilename
            srcfilename = apkfilename[:-4] + "_src.tar.gz"
            if os.path.exists(os.path.join(repodir, srcfilename)):
                thisinfo['srcname'] = srcfilename
            thisinfo['size'] = os.path.getsize(apkfile)
            thisinfo['permissions'] = []
            thisinfo['features'] = []
            thisinfo['icons_src'] = {}
            thisinfo['icons'] = {}
            p = SilentPopen([config['aapt'], 'dump', 'badging', apkfile])
            if p.returncode != 0:
                if options.delete_unknown:
                    if os.path.exists(apkfile):
                        logging.error("Failed to get apk information, deleting " + apkfile)
                        os.remove(apkfile)
                    else:
                        logging.error("Could not find {0} to remove it".format(apkfile))
                else:
                    logging.error("Failed to get apk information, skipping " + apkfile)
                continue
            for line in p.output.splitlines():
                if line.startswith("package:"):
                    try:
                        thisinfo['id'] = re.match(name_pat, line).group(1)
                        thisinfo['versioncode'] = int(re.match(vercode_pat, line).group(1))
                        thisinfo['version'] = re.match(vername_pat, line).group(1)
                    except Exception, e:
                        logging.error("Package matching failed: " + str(e))
                        logging.info("Line was: " + line)
                        sys.exit(1)
                elif line.startswith("application:"):
                    thisinfo['name'] = re.match(label_pat, line).group(1)
                    # Keep path to non-dpi icon in case we need it
                    match = re.match(icon_pat_nodpi, line)
                    if match:
                        thisinfo['icons_src']['-1'] = match.group(1)
                elif line.startswith("launchable-activity:"):
                    # Only use launchable-activity as fallback to application
                    if not thisinfo['name']:
                        thisinfo['name'] = re.match(label_pat, line).group(1)
                    if '-1' not in thisinfo['icons_src']:
                        match = re.match(icon_pat_nodpi, line)
                        if match:
                            thisinfo['icons_src']['-1'] = match.group(1)
                elif line.startswith("application-icon-"):
                    match = re.match(icon_pat, line)
                    if match:
                        density = match.group(1)
                        path = match.group(2)
                        thisinfo['icons_src'][density] = path
                elif line.startswith("sdkVersion:"):
                    m = re.match(sdkversion_pat, line)
                    if m is None:
                        logging.error(line.replace('sdkVersion:', '')
                                      + ' is not a valid minSdkVersion!')
                    else:
                        thisinfo['sdkversion'] = m.group(1)
                elif line.startswith("maxSdkVersion:"):
                    thisinfo['maxsdkversion'] = re.match(sdkversion_pat, line).group(1)
                elif line.startswith("native-code:"):
                    thisinfo['nativecode'] = []
                    for arch in line[13:].split(' '):
                        thisinfo['nativecode'].append(arch[1:-1])
                elif line.startswith("uses-permission:"):
                    perm = re.match(string_pat, line).group(1)
                    if perm.startswith("android.permission."):
                        perm = perm[19:]
                    thisinfo['permissions'].append(perm)
                elif line.startswith("uses-feature:"):
                    perm = re.match(string_pat, line).group(1)
                    # Filter out this, it's only added with the latest SDK tools and
                    # causes problems for lots of apps.
                    if perm != "android.hardware.screen.portrait" \
                            and perm != "android.hardware.screen.landscape":
                        if perm.startswith("android.feature."):
                            perm = perm[16:]
                        thisinfo['features'].append(perm)

            if 'sdkversion' not in thisinfo:
                logging.warn("no SDK version information found")
                thisinfo['sdkversion'] = 0

            # Check for debuggable apks...
            if common.isApkDebuggable(apkfile, config):
                logging.warn('{0} is set to android:debuggable="true"!'.format(apkfile))

            # Calculate the sha256...
            sha = hashlib.sha256()
            with open(apkfile, 'rb') as f:
                while True:
                    t = f.read(1024)
                    if len(t) == 0:
                        break
                    sha.update(t)
                thisinfo['sha256'] = sha.hexdigest()

            # Get the signature (or md5 of, to be precise)...
            getsig_dir = os.path.join(os.path.dirname(__file__), 'getsig')
            if not os.path.exists(getsig_dir + "/getsig.class"):
                logging.critical("getsig.class not found. To fix: cd '%s' && ./make.sh" % getsig_dir)
                sys.exit(1)
            p = FDroidPopen(['java', '-cp', os.path.join(os.path.dirname(__file__), 'getsig'),
                             'getsig', os.path.join(os.getcwd(), apkfile)])
            if p.returncode != 0 or not p.output.startswith('Result:'):
                logging.critical("Failed to get apk signature")
                sys.exit(1)
            thisinfo['sig'] = p.output[7:].strip()

            apk = zipfile.ZipFile(apkfile, 'r')

            iconfilename = "%s.%s.png" % (
                thisinfo['id'],
                thisinfo['versioncode'])

            # Extract the icon file...
            densities = get_densities()
            empty_densities = []
            for density in densities:
                if density not in thisinfo['icons_src']:
                    empty_densities.append(density)
                    continue
                iconsrc = thisinfo['icons_src'][density]
                icon_dir = get_icon_dir(repodir, density)
                icondest = os.path.join(icon_dir, iconfilename)

                try:
                    iconfile = open(icondest, 'wb')
                    iconfile.write(apk.read(iconsrc))
                    iconfile.close()
                    thisinfo['icons'][density] = iconfilename

                except:
                    logging.warn("Error retrieving icon file")
                    del thisinfo['icons'][density]
                    del thisinfo['icons_src'][density]
                    empty_densities.append(density)

            if '-1' in thisinfo['icons_src']:
                iconsrc = thisinfo['icons_src']['-1']
                iconpath = os.path.join(
                    get_icon_dir(repodir, None), iconfilename)
                iconfile = open(iconpath, 'wb')
                iconfile.write(apk.read(iconsrc))
                iconfile.close()
                try:
                    im = Image.open(iconpath)
                    dpi = px_to_dpi(im.size[0])
                    for density in densities:
                        if density in thisinfo['icons']:
                            break
                        if density == densities[-1] or dpi >= int(density):
                            thisinfo['icons'][density] = iconfilename
                            shutil.move(iconpath,
                                        os.path.join(get_icon_dir(repodir, density), iconfilename))
                            empty_densities.remove(density)
                            break
                except Exception, e:
                    logging.warn("Failed reading {0} - {1}".format(iconpath, e))

            if thisinfo['icons']:
                thisinfo['icon'] = iconfilename

            apk.close()

            # First try resizing down to not lose quality
            last_density = None
            for density in densities:
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
                try:
                    im = Image.open(last_iconpath)
                except:
                    logging.warn("Invalid image file at %s" % last_iconpath)
                    continue

                size = dpi_to_px(density)

                im.thumbnail((size, size), Image.ANTIALIAS)
                im.save(iconpath, "PNG")
                empty_densities.remove(density)

            # Then just copy from the highest resolution available
            last_density = None
            for density in reversed(densities):
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

            for density in densities:
                icon_dir = get_icon_dir(repodir, density)
                icondest = os.path.join(icon_dir, iconfilename)
                resize_icon(icondest, density)

            # Copy from icons-mdpi to icons since mdpi is the baseline density
            baseline = os.path.join(get_icon_dir(repodir, '160'), iconfilename)
            if os.path.isfile(baseline):
                shutil.copyfile(baseline,
                                os.path.join(get_icon_dir(repodir, None), iconfilename))

            # Record in known apks, getting the added date at the same time..
            added = knownapks.recordapk(thisinfo['apkname'], thisinfo['id'])
            if added:
                thisinfo['added'] = added

            apkcache[apkfilename] = thisinfo
            cachechanged = True

        apks.append(thisinfo)

    return apks, cachechanged


repo_pubkey_fingerprint = None


def make_index(apps, apks, repodir, archive, categories):
    """Make a repo index.

    :param apps: fully populated apps list
    :param apks: full populated apks list
    :param repodir: the repo directory
    :param archive: True if this is the archive repo, False if it's the
                    main one.
    :param categories: list of categories
    """

    doc = Document()

    def addElement(name, value, doc, parent):
        el = doc.createElement(name)
        el.appendChild(doc.createTextNode(value))
        parent.appendChild(el)

    def addElementCDATA(name, value, doc, parent):
        el = doc.createElement(name)
        el.appendChild(doc.createCDATASection(value))
        parent.appendChild(el)

    root = doc.createElement("fdroid")
    doc.appendChild(root)

    repoel = doc.createElement("repo")

    if archive:
        repoel.setAttribute("name", config['archive_name'])
        if config['repo_maxage'] != 0:
            repoel.setAttribute("maxage", str(config['repo_maxage']))
        repoel.setAttribute("icon", os.path.basename(config['archive_icon']))
        repoel.setAttribute("url", config['archive_url'])
        addElement('description', config['archive_description'], doc, repoel)

    else:
        repoel.setAttribute("name", config['repo_name'])
        if config['repo_maxage'] != 0:
            repoel.setAttribute("maxage", str(config['repo_maxage']))
        repoel.setAttribute("icon", os.path.basename(config['repo_icon']))
        repoel.setAttribute("url", config['repo_url'])
        addElement('description', config['repo_description'], doc, repoel)

    repoel.setAttribute("version", "12")
    repoel.setAttribute("timestamp", str(int(time.time())))

    if 'repo_keyalias' in config:

        # Generate a certificate fingerprint the same way keytool does it
        # (but with slightly different formatting)
        def cert_fingerprint(data):
            digest = hashlib.sha256(data).digest()
            ret = []
            ret.append(' '.join("%02X" % ord(b) for b in digest))
            return " ".join(ret)

        def extract_pubkey():
            p = FDroidPopen(['keytool', '-exportcert',
                             '-alias', config['repo_keyalias'],
                             '-keystore', config['keystore'],
                             '-storepass:file', config['keystorepassfile']]
                            + config['smartcardoptions'], output=False)
            if p.returncode != 0:
                msg = "Failed to get repo pubkey!"
                if config['keystore'] == 'NONE':
                    msg += ' Is your crypto smartcard plugged in?'
                logging.critical(msg)
                sys.exit(1)
            global repo_pubkey_fingerprint
            repo_pubkey_fingerprint = cert_fingerprint(p.output)
            return "".join("%02x" % ord(b) for b in p.output)

        repoel.setAttribute("pubkey", extract_pubkey())

    root.appendChild(repoel)

    for app in apps:

        if app['Disabled'] is not None:
            continue

        # Get a list of the apks for this app...
        apklist = []
        for apk in apks:
            if apk['id'] == app['id']:
                apklist.append(apk)

        if len(apklist) == 0:
            continue

        apel = doc.createElement("application")
        apel.setAttribute("id", app['id'])
        root.appendChild(apel)

        addElement('id', app['id'], doc, apel)
        if 'added' in app:
            addElement('added', time.strftime('%Y-%m-%d', app['added']), doc, apel)
        if 'lastupdated' in app:
            addElement('lastupdated', time.strftime('%Y-%m-%d', app['lastupdated']), doc, apel)
        addElement('name', app['Name'], doc, apel)
        addElement('summary', app['Summary'], doc, apel)
        if app['icon']:
            addElement('icon', app['icon'], doc, apel)

        def linkres(link):
            for app in apps:
                if app['id'] == link:
                    return ("fdroid.app:" + link, app['Name'])
            raise MetaDataException("Cannot resolve app id " + link)
        addElement('desc',
                   metadata.description_html(app['Description'], linkres),
                   doc, apel)
        addElement('license', app['License'], doc, apel)
        if 'Categories' in app:
            addElement('categories', ','.join(app["Categories"]), doc, apel)
            # We put the first (primary) category in LAST, which will have
            # the desired effect of making clients that only understand one
            # category see that one.
            addElement('category', app["Categories"][0], doc, apel)
        addElement('web', app['Web Site'], doc, apel)
        addElement('source', app['Source Code'], doc, apel)
        addElement('tracker', app['Issue Tracker'], doc, apel)
        if app['Donate']:
            addElement('donate', app['Donate'], doc, apel)
        if app['Bitcoin']:
            addElement('bitcoin', app['Bitcoin'], doc, apel)
        if app['Litecoin']:
            addElement('litecoin', app['Litecoin'], doc, apel)
        if app['Dogecoin']:
            addElement('dogecoin', app['Dogecoin'], doc, apel)
        if app['FlattrID']:
            addElement('flattr', app['FlattrID'], doc, apel)

        # These elements actually refer to the current version (i.e. which
        # one is recommended. They are historically mis-named, and need
        # changing, but stay like this for now to support existing clients.
        addElement('marketversion', app['Current Version'], doc, apel)
        addElement('marketvercode', app['Current Version Code'], doc, apel)

        if app['AntiFeatures']:
            af = app['AntiFeatures'].split(',')
            # TODO: Temporarily not including UpstreamNonFree in the index,
            # because current F-Droid clients do not understand it, and also
            # look ugly when they encounter an unknown antifeature. This
            # filtering can be removed in time...
            if 'UpstreamNonFree' in af:
                af.remove('UpstreamNonFree')
            if af:
                addElement('antifeatures', ','.join(af), doc, apel)
        if app['Provides']:
            pv = app['Provides'].split(',')
            addElement('provides', ','.join(pv), doc, apel)
        if app['Requires Root']:
            addElement('requirements', 'root', doc, apel)

        # Sort the apk list into version order, just so the web site
        # doesn't have to do any work by default...
        apklist = sorted(apklist, key=lambda apk: apk['versioncode'], reverse=True)

        # Check for duplicates - they will make the client unhappy...
        for i in range(len(apklist) - 1):
            if apklist[i]['versioncode'] == apklist[i + 1]['versioncode']:
                logging.critical("duplicate versions: '%s' - '%s'" % (
                    apklist[i]['apkname'], apklist[i + 1]['apkname']))
                sys.exit(1)

        for apk in apklist:
            apkel = doc.createElement("package")
            apel.appendChild(apkel)
            addElement('version', apk['version'], doc, apkel)
            addElement('versioncode', str(apk['versioncode']), doc, apkel)
            addElement('apkname', apk['apkname'], doc, apkel)
            if 'srcname' in apk:
                addElement('srcname', apk['srcname'], doc, apkel)
            for hash_type in ['sha256']:
                if hash_type not in apk:
                    continue
                hashel = doc.createElement("hash")
                hashel.setAttribute("type", hash_type)
                hashel.appendChild(doc.createTextNode(apk[hash_type]))
                apkel.appendChild(hashel)
            addElement('sig', apk['sig'], doc, apkel)
            addElement('size', str(apk['size']), doc, apkel)
            addElement('sdkver', str(apk['sdkversion']), doc, apkel)
            if 'maxsdkversion' in apk:
                addElement('maxsdkver', str(apk['maxsdkversion']), doc, apkel)
            if 'added' in apk:
                addElement('added', time.strftime('%Y-%m-%d', apk['added']), doc, apkel)
            if app['Requires Root']:
                if 'ACCESS_SUPERUSER' not in apk['permissions']:
                    apk['permissions'].append('ACCESS_SUPERUSER')

            if len(apk['permissions']) > 0:
                addElement('permissions', ','.join(apk['permissions']), doc, apkel)
            if 'nativecode' in apk and len(apk['nativecode']) > 0:
                addElement('nativecode', ','.join(apk['nativecode']), doc, apkel)
            if len(apk['features']) > 0:
                addElement('features', ','.join(apk['features']), doc, apkel)

    of = open(os.path.join(repodir, 'index.xml'), 'wb')
    if options.pretty:
        output = doc.toprettyxml()
    else:
        output = doc.toxml()
    of.write(output)
    of.close()

    if 'repo_keyalias' in config:

        logging.info("Creating signed index with this key (SHA256):")
        logging.info("%s" % repo_pubkey_fingerprint)

        # Create a jar of the index...
        p = FDroidPopen(['jar', 'cf', 'index.jar', 'index.xml'], cwd=repodir)
        if p.returncode != 0:
            logging.critical("Failed to create jar file")
            sys.exit(1)

        # Sign the index...
        args = ['jarsigner', '-keystore', config['keystore'],
                '-storepass:file', config['keystorepassfile'],
                '-digestalg', 'SHA1', '-sigalg', 'MD5withRSA',
                os.path.join(repodir, 'index.jar'), config['repo_keyalias']]
        if config['keystore'] == 'NONE':
            args += config['smartcardoptions']
        else:  # smardcards never use -keypass
            args += ['-keypass:file', config['keypassfile']]
        p = FDroidPopen(args)
        # TODO keypass should be sent via stdin
        if p.returncode != 0:
            logging.critical("Failed to sign index")
            sys.exit(1)

    # Copy the repo icon into the repo directory...
    icon_dir = os.path.join(repodir, 'icons')
    iconfilename = os.path.join(icon_dir, os.path.basename(config['repo_icon']))
    shutil.copyfile(config['repo_icon'], iconfilename)

    # Write a category list in the repo to allow quick access...
    catdata = ''
    for cat in categories:
        catdata += cat + '\n'
    f = open(os.path.join(repodir, 'categories.txt'), 'w')
    f.write(catdata)
    f.close()


def archive_old_apks(apps, apks, archapks, repodir, archivedir, defaultkeepversions):

    for app in apps:

        # Get a list of the apks for this app...
        apklist = []
        for apk in apks:
            if apk['id'] == app['id']:
                apklist.append(apk)

        # Sort the apk list into version order...
        apklist = sorted(apklist, key=lambda apk: apk['versioncode'], reverse=True)

        if app['Archive Policy']:
            keepversions = int(app['Archive Policy'][:-9])
        else:
            keepversions = defaultkeepversions

        if len(apklist) > keepversions:
            for apk in apklist[keepversions:]:
                logging.info("Moving " + apk['apkname'] + " to archive")
                shutil.move(os.path.join(repodir, apk['apkname']),
                            os.path.join(archivedir, apk['apkname']))
                if 'srcname' in apk:
                    shutil.move(os.path.join(repodir, apk['srcname']),
                                os.path.join(archivedir, apk['srcname']))
                    # Move GPG signature too...
                    sigfile = apk['srcname'] + '.asc'
                    sigsrc = os.path.join(repodir, sigfile)
                    if os.path.exists(sigsrc):
                        shutil.move(sigsrc, os.path.join(archivedir, sigfile))

                archapks.append(apk)
                apks.remove(apk)


config = None
options = None


def main():

    global config, options

    # Parse command line...
    parser = OptionParser()
    parser.add_option("-c", "--create-metadata", action="store_true", default=False,
                      help="Create skeleton metadata files that are missing")
    parser.add_option("--delete-unknown", action="store_true", default=False,
                      help="Delete APKs without metadata from the repo")
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help="Restrict output to warnings and errors")
    parser.add_option("-b", "--buildreport", action="store_true", default=False,
                      help="Report on build data status")
    parser.add_option("-i", "--interactive", default=False, action="store_true",
                      help="Interactively ask about things that need updating.")
    parser.add_option("-I", "--icons", action="store_true", default=False,
                      help="Resize all the icons exceeding the max pixel size and exit")
    parser.add_option("-e", "--editor", default="/etc/alternatives/editor",
                      help="Specify editor to use in interactive mode. Default " +
                      "is /etc/alternatives/editor")
    parser.add_option("-w", "--wiki", default=False, action="store_true",
                      help="Update the wiki")
    parser.add_option("", "--pretty", action="store_true", default=False,
                      help="Produce human-readable index.xml")
    parser.add_option("--clean", action="store_true", default=False,
                      help="Clean update - don't uses caches, reprocess all apks")
    (options, args) = parser.parse_args()

    config = common.read_config(options)

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

    # Get all apps...
    apps = metadata.read_metadata()

    # Generate a list of categories...
    categories = set()
    for app in apps:
        categories.update(app['Categories'])

    # Read known apks data (will be updated and written back when we've finished)
    knownapks = common.KnownApks()

    # Gather information about all the apk files in the repo directory, using
    # cached data if possible.
    apkcachefile = os.path.join('tmp', 'apkcache')
    if not options.clean and os.path.exists(apkcachefile):
        with open(apkcachefile, 'rb') as cf:
            apkcache = pickle.load(cf)
    else:
        apkcache = {}
    cachechanged = False

    delete_disabled_builds(apps, apkcache, repodirs)

    # Scan all apks in the main repo
    apks, cc = scan_apks(apps, apkcache, repodirs[0], knownapks)
    if cc:
        cachechanged = True

    # Generate warnings for apk's with no metadata (or create skeleton
    # metadata files, if requested on the command line)
    newmetadata = False
    for apk in apks:
        found = False
        for app in apps:
            if app['id'] == apk['id']:
                found = True
                break
        if not found:
            if options.create_metadata:
                if 'name' not in apk:
                    logging.error(apk['id'] + ' does not have a name! Skipping...')
                    continue
                f = open(os.path.join('metadata', apk['id'] + '.txt'), 'w')
                f.write("License:Unknown\n")
                f.write("Web Site:\n")
                f.write("Source Code:\n")
                f.write("Issue Tracker:\n")
                f.write("Summary:" + apk['name'] + "\n")
                f.write("Description:\n")
                f.write(apk['name'] + "\n")
                f.write(".\n")
                f.close()
                logging.info("Generated skeleton metadata for " + apk['id'])
                newmetadata = True
            else:
                msg = apk['apkname'] + " (" + apk['id'] + ") has no metadata!"
                if options.delete_unknown:
                    logging.warn(msg + "\n\tdeleting: repo/" + apk['apkname'])
                    rmf = os.path.join(repodirs[0], apk['apkname'])
                    if not os.path.exists(rmf):
                        logging.error("Could not find {0} to remove it".format(rmf))
                    else:
                        os.remove(rmf)
                else:
                    logging.warn(msg + "\n\tUse `fdroid update -c` to create it.")

    # update the metadata with the newly created ones included
    if newmetadata:
        apps = metadata.read_metadata()

    # Scan the archive repo for apks as well
    if len(repodirs) > 1:
        archapks, cc = scan_apks(apps, apkcache, repodirs[1], knownapks)
        if cc:
            cachechanged = True
    else:
        archapks = []

    # Some information from the apks needs to be applied up to the application
    # level. When doing this, we use the info from the most recent version's apk.
    # We deal with figuring out when the app was added and last updated at the
    # same time.
    for app in apps:
        bestver = 0
        added = None
        lastupdated = None
        for apk in apks + archapks:
            if apk['id'] == app['id']:
                if apk['versioncode'] > bestver:
                    bestver = apk['versioncode']
                    bestapk = apk

                if 'added' in apk:
                    if not added or apk['added'] < added:
                        added = apk['added']
                    if not lastupdated or apk['added'] > lastupdated:
                        lastupdated = apk['added']

        if added:
            app['added'] = added
        else:
            logging.warn("Don't know when " + app['id'] + " was added")
        if lastupdated:
            app['lastupdated'] = lastupdated
        else:
            logging.warn("Don't know when " + app['id'] + " was last updated")

        if bestver == 0:
            if app['Name'] is None:
                app['Name'] = app['id']
            app['icon'] = None
            logging.warn("Application " + app['id'] + " has no packages")
        else:
            if app['Name'] is None:
                app['Name'] = bestapk['name']
            app['icon'] = bestapk['icon'] if 'icon' in bestapk else None

    # Sort the app list by name, then the web site doesn't have to by default.
    # (we had to wait until we'd scanned the apks to do this, because mostly the
    # name comes from there!)
    apps = sorted(apps, key=lambda app: app['Name'].upper())

    if len(repodirs) > 1:
        archive_old_apks(apps, apks, archapks, repodirs[0], repodirs[1], config['archive_older'])

    # Make the index for the main repo...
    make_index(apps, apks, repodirs[0], False, categories)

    # If there's an archive repo,  make the index for it. We already scanned it
    # earlier on.
    if len(repodirs) > 1:
        make_index(apps, archapks, repodirs[1], True, categories)

    if config['update_stats']:

        # Update known apks info...
        knownapks.writeifchanged()

        # Generate latest apps data for widget
        if os.path.exists(os.path.join('stats', 'latestapps.txt')):
            data = ''
            for line in file(os.path.join('stats', 'latestapps.txt')):
                appid = line.rstrip()
                data += appid + "\t"
                for app in apps:
                    if app['id'] == appid:
                        data += app['Name'] + "\t"
                        if app['icon'] is not None:
                            data += app['icon'] + "\t"
                        data += app['License'] + "\n"
                        break
            f = open(os.path.join(repodirs[0], 'latestapps.dat'), 'w')
            f.write(data)
            f.close()

    if cachechanged:
        with open(apkcachefile, 'wb') as cf:
            pickle.dump(apkcache, cf)

    # Update the wiki...
    if options.wiki:
        update_wiki(apps, apks + archapks)

    logging.info("Finished.")

if __name__ == "__main__":
    main()
