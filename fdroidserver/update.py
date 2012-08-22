#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# update.py - part of the FDroid server tools
# Copyright (C) 2010-12, Ciaran Gultnieks, ciaran@ciarang.com
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
from xml.dom.minidom import Document
from optparse import OptionParser
import time
import common


# Update the wiki. 'apps' is a list of all applications and everything we know
# about them, and 'apks' likewise. Set 'verbose' to True for verbose output.
def update_wiki(apps, apks, verbose=False):

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
        wikidata += '{{App|id=%s|name=%s|added=%s|lastupdated=%s|source=%s|tracker=%s|web=%s|donate=%s|flattr=%s|license=%s|root=%s}}\n'%(
                app['id'],
                app['Name'],
                time.strftime('%Y-%m-%d', app['added']) if 'added' in app else '',
                time.strftime('%Y-%m-%d', app['lastupdated']) if 'lastupdated' in app else '',
                app['Source Code'],
                app['Issue Tracker'],
                app['Web Site'],
                app['Donate'],
                app['FlattrID'],
                app['License'],
                app.get('Requires Root', 'No'))
        wikidata += "=Summary=\n"
        wikidata += app['Summary'] + "\n"
        wikidata += "=Description=\n"
        wikidata += common.parse_description(app['Description']) + "\n"

        apklist = []
        gotcurrentver = False
        for apk in apks:
            if apk['id'] == app['id']:
                if str(apk['versioncode']) == app['Current Version Code']:
                    gotcurrentver = True
                apklist.append(apk)
        apklist = sorted(apklist, key=lambda apk: apk['versioncode'], reverse=True)
        wikidata += "=Versions=\n"
        if len(apklist) == 0:
            wikidata += "We currently have no versions of this app available.\n\n"
        elif not gotcurrentver:
            wikidata += "We don't have the current version of this app.\n\n"
        if len(app['Current Version']) > 0:
            wikidata += "The current (recommended) version is " + app['Current Version']
            wikidata += " (version code " + app['Current Version Code'] + ").\n\n"
        for apk in apklist:
            wikidata += "==" + apk['version'] + "==\n"
            wikidata += "Version code: " + str(apk['versioncode']) + '\n'

        wikidata += '\n[[Category:' + wikicat + ']]\n'
        if len(apklist) == 0 and not app['Disabled']:
            wikidata += '\n[[Category:Apps with no packages]]\n'
        elif not gotcurrentver and not app['Disabled']:
            wikidata += '\n[[Category:Apps to Update]]\n'
        generated_pages[app['id']] = wikidata

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
        if app['Name'] == app['id']:
            noclobber = True
        if not noclobber:
            generated_pages[app['Name']] = "#REDIRECT [[" + app['id'] + "]]\n[[Category:" + wikicat + "]]"

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
                print "Page " + page.name + " is unchanged"
        else:
            print "Deleting page " + page.name
            page.delete('No longer published')
    for pagename, text in generated_pages.items():
        if verbose:
            print "Checking " + pagename
        if not pagename in existingpages:
            print "Creating page " + pagename
            newpage = site.Pages[pagename]
            newpage.save(text, summary='Auto-created')



def main():

    # Read configuration...
    execfile('config.py', globals())

    # Parse command line...
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
    (options, args) = parser.parse_args()


    icon_dir=os.path.join('repo','icons')

    # Delete and re-create the icon directory...
    if os.path.exists(icon_dir):
        shutil.rmtree(icon_dir)
    os.mkdir(icon_dir)

    warnings = 0

    # Get all apps...
    apps = common.read_metadata(verbose=options.verbose)

    # Generate a list of categories...
    categories = []
    for app in apps:
        if app['Category'] not in categories:
            categories.append(app['Category'])

    # Read known apks data (will be updated and written back when we've finished)
    knownapks = common.KnownApks()

    # Gather information about all the apk files in the repo directory...
    apks = []
    for apkfile in glob.glob(os.path.join('repo','*.apk')):

        apkfilename = apkfile[5:]
        if apkfilename.find(' ') != -1:
            print "No spaces in APK filenames!"
            sys.exit(1)
        srcfilename = apkfilename[:-4] + "_src.tar.gz"

        if not options.quiet:
            print "Processing " + apkfilename
        thisinfo = {}
        thisinfo['apkname'] = apkfilename
        if os.path.exists(os.path.join('repo', srcfilename)):
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
                pat = re.compile(".*name='([a-zA-Z0-9._]*)'.*")
                thisinfo['id'] = re.match(pat, line).group(1)
                pat = re.compile(".*versionCode='([0-9]*)'.*")
                thisinfo['versioncode'] = int(re.match(pat, line).group(1))
                pat = re.compile(".*versionName='([^']*)'.*")
                thisinfo['version'] = re.match(pat, line).group(1)
            if line.startswith("application:"):
                pat = re.compile(".*label='([^']*)'.*")
                thisinfo['name'] = re.match(pat, line).group(1)
                pat = re.compile(".*icon='([^']*)'.*")
                thisinfo['iconsrc'] = re.match(pat, line).group(1)
            if line.startswith("sdkVersion:"):
                pat = re.compile(".*'([0-9]*)'.*")
                thisinfo['sdkversion'] = re.match(pat, line).group(1)
            if line.startswith("native-code:"):
                pat = re.compile(".*'([^']*)'.*")
                thisinfo['nativecode'] = re.match(pat, line).group(1)
            if line.startswith("uses-permission:"):
                pat = re.compile(".*'([^']*)'.*")
                perm = re.match(pat, line).group(1)
                if perm.startswith("android.permission."):
                    perm = perm[19:]
                thisinfo['permissions'].append(perm)
            if line.startswith("uses-feature:"):
                pat = re.compile(".*'([^']*)'.*")
                perm = re.match(pat, line).group(1)
                #Filter out this, it's only added with the latest SDK tools and
                #causes problems for lots of apps.
                if (perm != "android.hardware.screen.portrait" and
                    perm != "android.hardware.screen.landscape"):
                    if perm.startswith("android.feature."):
                        perm = perm[16:]
                    thisinfo['features'].append(perm)

        if not thisinfo.has_key('sdkversion'):
            print "  WARNING: no SDK version information found"
            thisinfo['sdkversion'] = 0

        # Calculate the md5 and sha256...
        m = hashlib.md5()
        sha = hashlib.sha256()
        f = open(apkfile, 'rb')
        while True:
            t = f.read(1024)
            if len(t) == 0:
                break
            m.update(t)
            sha.update(t)
        thisinfo['md5'] = m.hexdigest()
        thisinfo['sha256'] = sha.hexdigest()
        f.close()

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
            warnings += 1
        apk.close()

        # Record in known apks, getting the added date at the same time..
        added = knownapks.recordapk(thisinfo['apkname'], thisinfo['id'])
        if added:
            thisinfo['added'] = added

        apks.append(thisinfo)

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

    #Sort the app list by name, then the web site doesn't have to by default:
    apps = sorted(apps, key=lambda app: app['Name'].upper())

    # Create the index
    doc = Document()

    def addElement(name, value, doc, parent):
        el = doc.createElement(name)
        el.appendChild(doc.createTextNode(value))
        parent.appendChild(el)

    root = doc.createElement("fdroid")
    doc.appendChild(root)

    repoel = doc.createElement("repo")
    repoel.setAttribute("name", repo_name)
    repoel.setAttribute("icon", os.path.basename(repo_icon))
    repoel.setAttribute("url", repo_url)

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

    addElement('description', repo_description, doc, repoel)
    root.appendChild(repoel)

    apps_inrepo = 0
    apps_disabled = 0
    apps_nopkg = 0

    for app in apps:

        if app['Disabled'] is None:

            # Get a list of the apks for this app...
            gotcurrentver = False
            apklist = []
            for apk in apks:
                if apk['id'] == app['id']:
                    if str(apk['versioncode']) == app['Current Version Code']:
                        gotcurrentver = True
                    apklist.append(apk)

            if len(apklist) == 0:
                apps_nopkg += 1
            else:
                apps_inrepo += 1
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
                addElement('description',
                        common.parse_description(app['Description']), doc, apel)
                addElement('license', app['License'], doc, apel)
                if 'Category' in app:
                    addElement('category', app['Category'], doc, apel)
                addElement('web', app['Web Site'], doc, apel)
                addElement('source', app['Source Code'], doc, apel)
                addElement('tracker', app['Issue Tracker'], doc, apel)
                if app['Donate'] != None:
                    addElement('donate', app['Donate'], doc, apel)

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
                    if apk.has_key('srcname'):
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

            if options.buildreport:
                if len(app['builds']) == 0:
                    print ("WARNING: No builds defined for " + app['id'] +
                            " Source: " + app['Source Code'])
                    warnings += 1
                else:
                    if app['Current Version Code'] != '0':
                        gotbuild = False
                        for build in app['builds']:
                            if build['vercode'] == app['Current Version Code']:
                                gotbuild = True
                        if not gotbuild:
                            print ("WARNING: No build data for current version of "
                                    + app['id'] + " (" + app['Current Version']
                                    + ") " + app['Source Code'])
                            warnings += 1

            # If we don't have the current version, check if there is a build
            # with a commit ID starting with '!' - this means we can't build it
            # for some reason, and don't want hassling about it...
            if not gotcurrentver and app['Current Version Code'] != '0':
                for build in app['builds']:
                    if build['vercode'] == app['Current Version Code']:
                        gotcurrentver = True

            # Output a message of harassment if we don't have the current version:
            if not gotcurrentver and app['Current Version Code'] != '0':
                addr = app['Source Code']
                print "WARNING: Don't have current version (" + app['Current Version'] + ") of " + app['Name']
                print "         (" + app['id'] + ") " + addr
                warnings += 1
                if options.verbose:
                    # A bit of extra debug info, basically for diagnosing
                    # app developer mistakes:
                    print "         Current vercode:" + app['Current Version Code']
                    print "         Got:"
                    for apk in apks:
                        if apk['id'] == app['id']:
                            print "           " + str(apk['versioncode']) + " - " + apk['version']
                if options.interactive:
                    print "Build data out of date for " + app['id']
                    while True:
                        answer = raw_input("[I]gnore, [E]dit or [Q]uit?").lower()
                        if answer == 'i':
                            break
                        elif answer == 'e':
                            subprocess.call([options.editor,
                                os.path.join('metadata',
                                app['id'] + '.txt')])
                            break
                        elif answer == 'q':
                            sys.exit(0)
        else:
            apps_disabled += 1

    of = open(os.path.join('repo','index.xml'), 'wb')
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
            cwd='repo', stdout=subprocess.PIPE)
        output = p.communicate()[0]
        if options.verbose:
            print output
        if p.returncode != 0:
            print "ERROR: Failed to create jar file"
            sys.exit(1)

        # Sign the index...
        p = subprocess.Popen(['jarsigner', '-keystore', keystore,
            '-storepass', keystorepass, '-keypass', keypass,
            os.path.join('repo', 'index.jar') , repo_keyalias], stdout=subprocess.PIPE)
        output = p.communicate()[0]
        if p.returncode != 0:
            print "Failed to sign index"
            print output
            sys.exit(1)
        if options.verbose:
            print output

    # Copy the repo icon into the repo directory...
    iconfilename = os.path.join(icon_dir, os.path.basename(repo_icon))
    shutil.copyfile(repo_icon, iconfilename)

    # Write a category list in the repo to allow quick access...
    catdata = ''
    for cat in categories:
        catdata += cat + '\n'
    f = open('repo/categories.txt', 'w')
    f.write(catdata)
    f.close()

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
        f = open('repo/latestapps.dat', 'w')
        f.write(data)
        f.close()

    # Update the wiki...
    if options.wiki:
        update_wiki(apps, apks, options.verbose)

    print "Finished."
    print str(apps_inrepo) + " apps in repo"
    print str(apps_disabled) + " disabled"
    print str(apps_nopkg) + " with no packages"
    print str(warnings) + " warnings"

if __name__ == "__main__":
    main()

