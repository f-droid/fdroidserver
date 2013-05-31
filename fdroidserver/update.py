#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# update.py - part of the FDroid server tools
# Copyright (C) 2010-2013, Ciaran Gultnieks, ciaran@ciarang.com
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
import subprocess
import re
import zipfile
import hashlib
import pickle
from xml.dom.minidom import Document
from optparse import OptionParser
import time
import common
from common import MetaDataException

def update_wiki(apps, apks, verbose=False):
    """Update the wiki

    :param apps: fully populated list of all applications
    :param apks: all apks, except...
    :param verbose: True to make a lot of noise
    """
    print "Updating wiki"
    wikicat = 'Apps'
    import mwclient
    site = mwclient.Site(wiki_server, path=wiki_path)
    site.login(wiki_user, wiki_password)
    generated_pages = {}
    for app in apps:
        wikidata = ''
        if app['Disabled']:
            wikidata += '{{Disabled|' + app['Disabled'] + '}}\n'
        if app['AntiFeatures']:
            wikidata += '{{AntiFeatures|' + app['AntiFeatures'] + '}}\n'
        wikidata += '{{App|id=%s|name=%s|added=%s|lastupdated=%s|source=%s|tracker=%s|web=%s|donate=%s|flattr=%s|bitcoin=%s|license=%s|root=%s}}\n'%(
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
                app['License'],
                app.get('Requires Root', 'No'))

        wikidata += app['Summary']
        wikidata += " - [http://f-droid.org/repository/browse/?fdid=" + app['id'] + " view in repository]\n\n"

        wikidata += "=Description=\n"
        wikidata += common.description_wiki(app['Description']) + "\n"

        # Get a list of all packages for this application...
        apklist = []
        gotcurrentver = False
        cantupdate = False
        for apk in apks:
            if apk['id'] == app['id']:
                if str(apk['versioncode']) == app['Current Version Code']:
                    gotcurrentver = True
                apklist.append(apk)
        # Include ones we can't build, as a special case...
        for thisbuild in app['builds']:
            if thisbuild['commit'].startswith('!'):
                if thisbuild['vercode'] == app['Current Version Code']:
                    cantupdate = True
                apklist.append({
                        #TODO: Nasty: vercode is a string in the build, and an int elsewhere
                        'versioncode': int(thisbuild['vercode']),
                        'version': thisbuild['version'],
                        'buildproblem': thisbuild['commit'][1:]
                    })
        # Sort with most recent first...
        apklist = sorted(apklist, key=lambda apk: apk['versioncode'], reverse=True)

        wikidata += "=Versions=\n"
        if len(apklist) == 0:
            wikidata += "We currently have no versions of this app available."
        elif not gotcurrentver:
            wikidata += "We don't have the current version of this app."
        else:
            wikidata += "We have the current version of this app."
        wikidata += " (Check mode: " + app['Update Check Mode'] + ")\n\n"
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
        elif validapks == 0 and not app['Disabled']:
            wikidata += '\n[[Category:Apps with no packages]]\n'
        elif cantupdate and not app['Disabled']:
            wikidata += "\n[[Category:Apps we can't update]]\n"
        elif not gotcurrentver and not app['Disabled']:
            wikidata += '\n[[Category:Apps to Update]]\n'
        if app['Update Check Mode'] == 'None':
            wikidata += '\n[[Category:Apps with no update check]]\n'

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
        for page in site.allpages(prefix=app['Name'], filterredir='nonredirects'):
            if page.name == app['Name']:
                noclobber = True
        # Another reason not to make the redirect page is if the app name
        # is the same as it's ID, because that will overwrite the real page
        # with an redirect to itself! (Although it seems like an odd
        # scenario this happens a lot, e.g. where there is metadata but no
        # builds or binaries to extract a name from.
        apppagename = app['Name'].replace('_', ' ')
        if apppagename == pagename:
            noclobber = True
        if not noclobber:
            generated_pages[apppagename] = "#REDIRECT [[" + pagename + "]]\n[[Category:" + wikicat + "]]"

    catpages = site.Pages['Category:' + wikicat]
    existingpages = []
    for page in catpages:
        existingpages.append(page.name)
        if page.name in generated_pages:
            pagetxt = page.edit()
            if pagetxt != generated_pages[page.name]:
                print "Updating modified page " + page.name
                page.save(generated_pages[page.name], summary='Auto-updated')
            else:
                if verbose:
                    print "Page " + page.name + " is unchanged"
        else:
            print "Deleting page " + page.name
            page.delete('No longer published')
    for pagename, text in generated_pages.items():
        if verbose:
            print "Checking " + pagename
        if not pagename in existingpages:
            print "Creating page " + pagename
            try:
                newpage = site.Pages[pagename]
                newpage.save(text, summary='Auto-created')
            except:
                print "...FAILED to create page"


def delete_disabled_builds(apps, apkcache, repodirs):
    """Delete disabled build outputs.

    :param apps: list of all applications, as per common.read_metadata
    :param apkcache: current apk cache information
    :param repodirs: the repo directories to process
    """
    for app in apps:
        for build in app['builds']:
            if build['commit'].startswith('!'):
                apkfilename = app['id'] + '_' + str(build['vercode']) + '.apk'
                for repodir in repodirs:
                    apkpath = os.path.join(repodir, apkfilename)
                    srcpath = os.path.join(repodir, apkfilename[:-4] + "_src.tar.gz")
                    for name in [apkpath, srcpath]:
                        if os.path.exists(name):
                            print "Deleting disabled build output " + apkfilename
                            os.remove(name)
                if apkfilename in apkcache:
                    del apkcache[apkfilename]


def scan_apks(apps, apkcache, repodir, knownapks):
    """Scan the apks in the given repo directory.

    This also extracts the icons.

    :param apps: list of all applications, as per common.read_metadata
    :param apkcache: current apk cache information
    :param repodir: repo directory to scan
    :param knownapks: known apks info
    :returns: (apks, cachechanged) where apks is a list of apk information,
              and cachechanged is True if the apkcache got changed.
    """

    cachechanged = False

    icon_dir = os.path.join(repodir ,'icons')
    # Delete and re-create the icon directory...
    if options.clean and os.path.exists(icon_dir):
        shutil.rmtree(icon_dir)
    if not os.path.exists(icon_dir):
        os.makedirs(icon_dir)
    apks = []
    name_pat = re.compile(".*name='([a-zA-Z0-9._]*)'.*")
    vercode_pat = re.compile(".*versionCode='([0-9]*)'.*")
    vername_pat = re.compile(".*versionName='([^']*)'.*")
    label_pat = re.compile(".*label='(.*)'[\n '].*")
    icon_pat = re.compile(".*icon='([^']*)'.*")
    sdkversion_pat = re.compile(".*'([0-9]*)'.*")
    string_pat = re.compile(".*'([^']*)'.*")
    for apkfile in glob.glob(os.path.join(repodir, '*.apk')):

        apkfilename = apkfile[len(repodir) + 1:]
        if apkfilename.find(' ') != -1:
            print "No spaces in APK filenames!"
            sys.exit(1)

        if apkfilename in apkcache:
            if options.verbose:
                print "Reading " + apkfilename + " from cache"
            thisinfo = apkcache[apkfilename]

        else:

            if not options.quiet:
                print "Processing " + apkfilename
            thisinfo = {}
            thisinfo['apkname'] = apkfilename
            srcfilename = apkfilename[:-4] + "_src.tar.gz"
            if os.path.exists(os.path.join(repodir, srcfilename)):
                thisinfo['srcname'] = srcfilename
            thisinfo['size'] = os.path.getsize(apkfile)
            thisinfo['permissions'] = []
            thisinfo['features'] = []
            p = subprocess.Popen([os.path.join(sdk_path, 'platform-tools', 'aapt'),
                                  'dump', 'badging', apkfile],
                                 stdout=subprocess.PIPE)
            output = p.communicate()[0]
            if options.verbose:
                print output
            if p.returncode != 0:
                print "ERROR: Failed to get apk information"
                sys.exit(1)
            for line in output.splitlines():
                if line.startswith("package:"):
                    try:
                        thisinfo['id'] = re.match(name_pat, line).group(1)
                        thisinfo['versioncode'] = int(re.match(vercode_pat, line).group(1))
                        thisinfo['version'] = re.match(vername_pat, line).group(1)
                    except Exception, e:
                        print "Package matching failed: " + str(e)
                        print "Line was: " + line
                        sys.exit(1)
                elif line.startswith("application:"):
                    thisinfo['name'] = re.match(label_pat, line).group(1)
                    thisinfo['iconsrc'] = re.match(icon_pat, line).group(1)
                elif line.startswith("sdkVersion:"):
                    thisinfo['sdkversion'] = re.match(sdkversion_pat, line).group(1)
                elif line.startswith("native-code:"):
                    thisinfo['nativecode'] = re.match(string_pat, line).group(1)
                elif line.startswith("uses-permission:"):
                    perm = re.match(string_pat, line).group(1)
                    if perm.startswith("android.permission."):
                        perm = perm[19:]
                    thisinfo['permissions'].append(perm)
                elif line.startswith("uses-feature:"):
                    perm = re.match(string_pat, line).group(1)
                    #Filter out this, it's only added with the latest SDK tools and
                    #causes problems for lots of apps.
                    if (perm != "android.hardware.screen.portrait" and
                        perm != "android.hardware.screen.landscape"):
                        if perm.startswith("android.feature."):
                            perm = perm[16:]
                        thisinfo['features'].append(perm)

            if not 'sdkversion' in thisinfo:
                print "  WARNING: no SDK version information found"
                thisinfo['sdkversion'] = 0

            # Check for debuggable apks...
            if common.isApkDebuggable(apkfile, sdk_path):
                print "WARNING: {0} is debuggable... {1}".format(apkfile, line)

            # Calculate the md5 and sha256...
            m = hashlib.md5()
            sha = hashlib.sha256()
            with open(apkfile, 'rb') as f:
                while True:
                    t = f.read(1024)
                    if len(t) == 0:
                        break
                    m.update(t)
                    sha.update(t)
                thisinfo['md5'] = m.hexdigest()
                thisinfo['sha256'] = sha.hexdigest()

            # Get the signature (or md5 of, to be precise)...
            p = subprocess.Popen(['java', 'getsig',
                                  os.path.join(os.getcwd(), apkfile)],
                                 cwd=os.path.join(os.path.dirname(__file__), 'getsig'),
                                 stdout=subprocess.PIPE)
            output = p.communicate()[0]
            if options.verbose:
                print output
            if p.returncode != 0 or not output.startswith('Result:'):
                print "ERROR: Failed to get apk signature"
                sys.exit(1)
            thisinfo['sig'] = output[7:].strip()

            # Extract the icon file...
            apk = zipfile.ZipFile(apkfile, 'r')
            thisinfo['icon'] = (thisinfo['id'] + '.' +
                str(thisinfo['versioncode']) + '.png')
            iconfilename = os.path.join(icon_dir, thisinfo['icon'])
            try:
                iconfile = open(iconfilename, 'wb')
                iconfile.write(apk.read(thisinfo['iconsrc']))
                iconfile.close()
            except:
                print "WARNING: Error retrieving icon file"
            apk.close()

            # Record in known apks, getting the added date at the same time..
            added = knownapks.recordapk(thisinfo['apkname'], thisinfo['id'])
            if added:
                thisinfo['added'] = added

            apkcache[apkfilename] = thisinfo
            cachechanged = True

        apks.append(thisinfo)

    return apks, cachechanged


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
        repoel.setAttribute("name", archive_name)
        repoel.setAttribute("icon", os.path.basename(archive_icon))
        repoel.setAttribute("url", archive_url)
        addElement('description', archive_description, doc, repoel)
    else:
        repoel.setAttribute("name", repo_name)
        repoel.setAttribute("icon", os.path.basename(repo_icon))
        repoel.setAttribute("url", repo_url)
        addElement('description', repo_description, doc, repoel)

    if repo_keyalias != None:

        # Generate a certificate fingerprint the same way keytool does it
        # (but with slightly different formatting)
        def cert_fingerprint(data):
            digest = hashlib.sha1(data).digest()
            ret = []
            for i in range(4):
                ret.append(":".join("%02X" % ord(b) for b in digest[i*5:i*5+5]))
            return " ".join(ret)

        def extract_pubkey():
            p = subprocess.Popen(['keytool', '-exportcert',
                                  '-alias', repo_keyalias,
                                  '-keystore', keystore,
                                  '-storepass', keystorepass],
                                 stdout=subprocess.PIPE)
            cert = p.communicate()[0]
            if p.returncode != 0:
                print "ERROR: Failed to get repo pubkey"
                sys.exit(1)
            global repo_pubkey_fingerprint
            repo_pubkey_fingerprint = cert_fingerprint(cert)
            return "".join("%02x" % ord(b) for b in cert)

        repoel.setAttribute("pubkey", extract_pubkey())

    root.appendChild(repoel)

    for app in apps:

        if app['Disabled'] is None:

            # Get a list of the apks for this app...
            apklist = []
            for apk in apks:
                if apk['id'] == app['id']:
                    apklist.append(apk)

            if len(apklist) != 0:
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
                addElement('icon', app['icon'], doc, apel)
                def linkres(link):
                    for app in apps:
                        if app['id'] == link:
                            return ("fdroid.app:" + link, app['Name'])
                    raise MetaDataException("Cannot resolve app id " + link)
                addElement('description',
                        common.description_plain(app['Description'], linkres), doc, apel)
                addElement('desc', 
                        common.description_html(app['Description'], linkres), doc, apel)
                addElement('license', app['License'], doc, apel)
                if 'Category' in app:
                    # We put the first (primary) category in LAST, which will have
                    # the desired effect of making clients that only understand one
                    # category see that one.
                    cats = app['Category'].split(';')
                    cats.reverse()
                    for cat in cats:
                        addElement('category', cat, doc, apel)
                addElement('web', app['Web Site'], doc, apel)
                addElement('source', app['Source Code'], doc, apel)
                addElement('tracker', app['Issue Tracker'], doc, apel)
                if app['Donate'] != None:
                    addElement('donate', app['Donate'], doc, apel)
                if app['Bitcoin'] != None:
                    addElement('bitcoin', app['Bitcoin'], doc, apel)
                if app['FlattrID'] != None:
                    addElement('flattr', app['FlattrID'], doc, apel)

                # These elements actually refer to the current version (i.e. which
                # one is recommended. They are historically mis-named, and need
                # changing, but stay like this for now to support existing clients.
                addElement('marketversion', app['Current Version'], doc, apel)
                addElement('marketvercode', app['Current Version Code'], doc, apel)

                if app['AntiFeatures']:
                    addElement('antifeatures', app['AntiFeatures'], doc, apel)
                if app['Requires Root']:
                    addElement('requirements', 'root', doc, apel)

                # Sort the apk list into version order, just so the web site
                # doesn't have to do any work by default...
                apklist = sorted(apklist, key=lambda apk: apk['versioncode'], reverse=True)

                # Check for duplicates - they will make the client unhappy...
                for i in range(len(apklist) - 1):
                    if apklist[i]['versioncode'] == apklist[i+1]['versioncode']:
                        print "ERROR - duplicate versions"
                        print apklist[i]['apkname']
                        print apklist[i+1]['apkname']
                        sys.exit(1)

                for apk in apklist:
                    apkel = doc.createElement("package")
                    apel.appendChild(apkel)
                    addElement('version', apk['version'], doc, apkel)
                    addElement('versioncode', str(apk['versioncode']), doc, apkel)
                    addElement('apkname', apk['apkname'], doc, apkel)
                    if 'srcname' in apk:
                        addElement('srcname', apk['srcname'], doc, apkel)
                    for hash_type in ('sha256', 'md5'):
                        if not hash_type in apk:
                            continue
                        hashel = doc.createElement("hash")
                        hashel.setAttribute("type", hash_type)
                        hashel.appendChild(doc.createTextNode(apk[hash_type]))
                        apkel.appendChild(hashel)
                    addElement('sig', apk['sig'], doc, apkel)
                    addElement('size', str(apk['size']), doc, apkel)
                    addElement('sdkver', str(apk['sdkversion']), doc, apkel)
                    if 'added' in apk:
                        addElement('added', time.strftime('%Y-%m-%d', apk['added']), doc, apkel)
                    perms = ""
                    for p in apk['permissions']:
                        if len(perms) > 0:
                            perms += ","
                        perms += p
                    if len(perms) > 0:
                        addElement('permissions', perms, doc, apkel)
                    features = ""
                    for f in apk['features']:
                        if len(features) > 0:
                            features += ","
                        features += f
                    if len(features) > 0:
                        addElement('features', features, doc, apkel)

    of = open(os.path.join(repodir, 'index.xml'), 'wb')
    if options.pretty:
        output = doc.toprettyxml()
    else:
        output = doc.toxml()
    of.write(output)
    of.close()

    if repo_keyalias != None:

        if not options.quiet:
            print "Creating signed index."
            print "Key fingerprint:", repo_pubkey_fingerprint
        
        #Create a jar of the index...
        p = subprocess.Popen(['jar', 'cf', 'index.jar', 'index.xml'],
            cwd=repodir, stdout=subprocess.PIPE)
        output = p.communicate()[0]
        if options.verbose:
            print output
        if p.returncode != 0:
            print "ERROR: Failed to create jar file"
            sys.exit(1)

        # Sign the index...
        p = subprocess.Popen(['jarsigner', '-keystore', keystore,
            '-storepass', keystorepass, '-keypass', keypass,
            '-digestalg', 'SHA1', '-sigalg', 'MD5withRSA',
            os.path.join(repodir, 'index.jar') , repo_keyalias], stdout=subprocess.PIPE)
        output = p.communicate()[0]
        if p.returncode != 0:
            print "Failed to sign index"
            print output
            sys.exit(1)
        if options.verbose:
            print output

    # Copy the repo icon into the repo directory...
    icon_dir=os.path.join(repodir ,'icons')
    iconfilename = os.path.join(icon_dir, os.path.basename(repo_icon))
    shutil.copyfile(repo_icon, iconfilename)

    # Write a category list in the repo to allow quick access...
    catdata = ''
    for cat in categories:
        catdata += cat + '\n'
    f = open(os.path.join(repodir, 'categories.txt'), 'w')
    f.write(catdata)
    f.close()



def archive_old_apks(apps, apks, repodir, archivedir, keepversions):

    for app in apps:

        # Get a list of the apks for this app...
        apklist = []
        for apk in apks:
            if apk['id'] == app['id']:
                apklist.append(apk)

        # Sort the apk list into version order...
        apklist = sorted(apklist, key=lambda apk: apk['versioncode'], reverse=True)

        if len(apklist) > keepversions:
            for apk in apklist[keepversions:]:
                print "Moving " + apk['apkname'] + " to archive"
                shutil.move(os.path.join(repodir, apk['apkname']),
                    os.path.join(archivedir, apk['apkname']))
                if 'srcname' in apk:
                    shutil.move(os.path.join(repodir, apk['srcname']),
                        os.path.join(archivedir, apk['srcname']))
                apks.remove(apk)


def main():

    # Read configuration...
    global update_stats, archive_older
    update_stats = False
    archive_older = 0
    execfile('config.py', globals())

    # Parse command line...
    global options
    parser = OptionParser()
    parser.add_option("-c", "--createmeta", action="store_true", default=False,
                      help="Create skeleton metadata files that are missing")
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help="No output, except for warnings and errors")
    parser.add_option("-b", "--buildreport", action="store_true", default=False,
                      help="Report on build data status")
    parser.add_option("-i", "--interactive", default=False, action="store_true",
                      help="Interactively ask about things that need updating.")
    parser.add_option("-e", "--editor", default="/etc/alternatives/editor",
                      help="Specify editor to use in interactive mode. Default "+
                          "is /etc/alternatives/editor")
    parser.add_option("-w", "--wiki", default=False, action="store_true",
                      help="Update the wiki")
    parser.add_option("", "--pretty", action="store_true", default=False,
                      help="Produce human-readable index.xml")
    parser.add_option("--clean", action="store_true", default=False,
                      help="Clean update - don't uses caches, reprocess all apks")
    (options, args) = parser.parse_args()

    # Get all apps...
    apps = common.read_metadata(verbose=options.verbose)

    # Generate a list of categories...
    categories = []
    for app in apps:
        cats = app['Category'].split(';')
        for cat in cats:
            if cat not in categories:
                categories.append(cat)

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

    repodirs = ['repo']
    if archive_older != 0:
        repodirs.append('archive')
        if not os.path.exists('archive'):
            os.mkdir('archive')

    delete_disabled_builds(apps, apkcache, repodirs)

    apks, cc = scan_apks(apps, apkcache, repodirs[0], knownapks)
    if cc:
        cachechanged = True

    # Some information from the apks needs to be applied up to the application
    # level. When doing this, we use the info from the most recent version's apk.
    # We deal with figuring out when the app was added and last updated at the
    # same time.
    for app in apps:
        bestver = 0
        added = None
        lastupdated = None
        for apk in apks:
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
            print "WARNING: Don't know when " + app['id'] + " was added"
        if lastupdated:
            app['lastupdated'] = lastupdated
        else:
            print "WARNING: Don't know when " + app['id'] + " was last updated"

        if bestver == 0:
            if app['Name'] is None:
                app['Name'] = app['id']
            app['icon'] = ''
            if app['Disabled'] is None:
                print "WARNING: Application " + app['id'] + " has no packages"
        else:
            if app['Name'] is None:
                app['Name'] = bestapk['name']
            app['icon'] = bestapk['icon']

    # Sort the app list by name, then the web site doesn't have to by default.
    # (we had to wait until we'd scanned the apks to do this, because mostly the
    # name comes from there!)
    apps = sorted(apps, key=lambda app: app['Name'].upper())

    # Generate warnings for apk's with no metadata (or create skeleton
    # metadata files, if requested on the command line)
    for apk in apks:
        found = False
        for app in apps:
            if app['id'] == apk['id']:
                found = True
                break
        if not found:
            if options.createmeta:
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
                print "Generated skeleton metadata for " + apk['id']
            else:
                print "WARNING: " + apk['apkname'] + " (" + apk['id'] + ") has no metadata"
                print "       " + apk['name'] + " - " + apk['version']  

    if len(repodirs) > 1:
        archive_old_apks(apps, apks, repodirs[0], repodirs[1], archive_older)

    # Make the index for the main repo...
    make_index(apps, apks, repodirs[0], False, categories)

    # If there's an archive repo, scan the apks for that and make the index...
    archapks = None
    if len(repodirs) > 1:
        archapks, cc = scan_apks(apps, apkcache, repodirs[1], knownapks)
        if cc:
            cachechanged = True
        make_index(apps, archapks, repodirs[1], True, categories)

    if update_stats:

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
        if archapks:
            apks.extend(archapks)
        update_wiki(apps, apks, options.verbose)

    print "Finished."

if __name__ == "__main__":
    main()

