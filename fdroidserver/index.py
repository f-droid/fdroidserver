#!/usr/bin/env python3
#
# update.py - part of the FDroid server tools
# Copyright (C) 2017, Torsten Grote <t at grobox dot de>
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

import collections
import copy
import json
import logging
import os
import re
import shutil
import tempfile
import urllib.parse
import zipfile
import calendar
from binascii import hexlify, unhexlify
from datetime import datetime, timezone
from xml.dom.minidom import Document

from . import _
from . import common
from . import metadata
from . import net
from . import signindex
from fdroidserver.common import FDroidPopen, FDroidPopenBytes, load_stats_fdroid_signing_key_fingerprints
from fdroidserver.exception import FDroidException, VerificationException, MetaDataException


def make(apps, sortedids, apks, repodir, archive):
    """Generate the repo index files.

    This requires properly initialized options and config objects.

    :param apps: fully populated apps list
    :param sortedids: app package IDs, sorted
    :param apks: full populated apks list
    :param repodir: the repo directory
    :param archive: True if this is the archive repo, False if it's the
                    main one.
    """
    from fdroidserver.update import METADATA_VERSION

    def _resolve_description_link(appid):
        if appid in apps:
            return "fdroid.app:" + appid, apps[appid].Name
        raise MetaDataException("Cannot resolve app id " + appid)

    if not common.options.nosign:
        common.assert_config_keystore(common.config)

    repodict = collections.OrderedDict()
    repodict['timestamp'] = datetime.utcnow().replace(tzinfo=timezone.utc)
    repodict['version'] = METADATA_VERSION

    if common.config['repo_maxage'] != 0:
        repodict['maxage'] = common.config['repo_maxage']

    if archive:
        repodict['name'] = common.config['archive_name']
        repodict['icon'] = os.path.basename(common.config['archive_icon'])
        repodict['address'] = common.config['archive_url']
        repodict['description'] = common.config['archive_description']
        urlbasepath = os.path.basename(urllib.parse.urlparse(common.config['archive_url']).path)
    else:
        repodict['name'] = common.config['repo_name']
        repodict['icon'] = os.path.basename(common.config['repo_icon'])
        repodict['address'] = common.config['repo_url']
        repodict['description'] = common.config['repo_description']
        urlbasepath = os.path.basename(urllib.parse.urlparse(common.config['repo_url']).path)

    mirrorcheckfailed = False
    mirrors = []
    for mirror in sorted(common.config.get('mirrors', [])):
        base = os.path.basename(urllib.parse.urlparse(mirror).path.rstrip('/'))
        if common.config.get('nonstandardwebroot') is not True and base != 'fdroid':
            logging.error(_("mirror '%s' does not end with 'fdroid'!") % mirror)
            mirrorcheckfailed = True
        # must end with / or urljoin strips a whole path segment
        if mirror.endswith('/'):
            mirrors.append(urllib.parse.urljoin(mirror, urlbasepath))
        else:
            mirrors.append(urllib.parse.urljoin(mirror + '/', urlbasepath))
    for mirror in common.config.get('servergitmirrors', []):
        for url in get_mirror_service_urls(mirror):
            mirrors.append(url + '/' + repodir)
    if mirrorcheckfailed:
        raise FDroidException(_("Malformed repository mirrors."))
    if mirrors:
        repodict['mirrors'] = mirrors

    appsWithPackages = collections.OrderedDict()
    for packageName in sortedids:
        app = apps[packageName]
        if app['Disabled']:
            continue

        # only include apps with packages
        for apk in apks:
            if apk['packageName'] == packageName:
                newapp = copy.copy(app)  # update wiki needs unmodified description
                newapp['Description'] = metadata.description_html(app['Description'],
                                                                  _resolve_description_link)
                appsWithPackages[packageName] = newapp
                break

    requestsdict = collections.OrderedDict()
    for command in ('install', 'uninstall'):
        packageNames = []
        key = command + '_list'
        if key in common.config:
            if isinstance(common.config[key], str):
                packageNames = [common.config[key]]
            elif all(isinstance(item, str) for item in common.config[key]):
                packageNames = common.config[key]
            else:
                raise TypeError(_('only accepts strings, lists, and tuples'))
        requestsdict[command] = packageNames

    fdroid_signing_key_fingerprints = load_stats_fdroid_signing_key_fingerprints()

    make_v0(appsWithPackages, apks, repodir, repodict, requestsdict,
            fdroid_signing_key_fingerprints)
    make_v1(appsWithPackages, apks, repodir, repodict, requestsdict,
            fdroid_signing_key_fingerprints)


def make_v1(apps, packages, repodir, repodict, requestsdict, fdroid_signing_key_fingerprints):

    def _index_encoder_default(obj):
        if isinstance(obj, set):
            return sorted(list(obj))
        if isinstance(obj, datetime):
            # Java prefers milliseconds
            # we also need to accound for time zone/daylight saving time
            return int(calendar.timegm(obj.timetuple()) * 1000)
        if isinstance(obj, dict):
            d = collections.OrderedDict()
            for key in sorted(obj.keys()):
                d[key] = obj[key]
            return d
        raise TypeError(repr(obj) + " is not JSON serializable")

    output = collections.OrderedDict()
    output['repo'] = repodict
    output['requests'] = requestsdict

    # establish sort order of the index
    v1_sort_packages(packages, fdroid_signing_key_fingerprints)

    appslist = []
    output['apps'] = appslist
    for packageName, appdict in apps.items():
        d = collections.OrderedDict()
        appslist.append(d)
        for k, v in sorted(appdict.items()):
            if not v:
                continue
            if k in ('builds', 'comments', 'metadatapath',
                     'ArchivePolicy', 'AutoUpdateMode', 'MaintainerNotes',
                     'Provides', 'Repo', 'RepoType', 'RequiresRoot',
                     'UpdateCheckData', 'UpdateCheckIgnore', 'UpdateCheckMode',
                     'UpdateCheckName', 'NoSourceSince', 'VercodeOperation'):
                continue

            # name things after the App class fields in fdroidclient
            if k == 'id':
                k = 'packageName'
            elif k == 'CurrentVersionCode':  # TODO make SuggestedVersionCode the canonical name
                k = 'suggestedVersionCode'
            elif k == 'CurrentVersion':  # TODO make SuggestedVersionName the canonical name
                k = 'suggestedVersionName'
            elif k == 'AutoName':
                if 'Name' not in apps[packageName]:
                    d['name'] = v
                continue
            else:
                k = k[:1].lower() + k[1:]
            d[k] = v

    # establish sort order in localized dicts
    for app in output['apps']:
        localized = app.get('localized')
        if localized:
            lordered = collections.OrderedDict()
            for lkey, lvalue in sorted(localized.items()):
                lordered[lkey] = collections.OrderedDict()
                for ikey, iname in sorted(lvalue.items()):
                    lordered[lkey][ikey] = iname
            app['localized'] = lordered

    output_packages = collections.OrderedDict()
    output['packages'] = output_packages
    for package in packages:
        packageName = package['packageName']
        if packageName not in apps:
            logging.info(_('Ignoring package without metadata: ') + package['apkName'])
            continue
        if not package.get('versionName'):
            app = apps[packageName]
            versionCodeStr = str(package['versionCode'])  # TODO build.versionCode should be int!
            for build in app['builds']:
                if build['versionCode'] == versionCodeStr:
                    versionName = build.get('versionName')
                    logging.info(_('Overriding blank versionName in {apkfilename} from metadata: {version}')
                                 .format(apkfilename=package['apkName'], version=versionName))
                    package['versionName'] = versionName
                    break
        if packageName in output_packages:
            packagelist = output_packages[packageName]
        else:
            packagelist = []
            output_packages[packageName] = packagelist
        d = collections.OrderedDict()
        packagelist.append(d)
        for k, v in sorted(package.items()):
            if not v:
                continue
            if k in ('icon', 'icons', 'icons_src', 'name', ):
                continue
            d[k] = v

    json_name = 'index-v1.json'
    index_file = os.path.join(repodir, json_name)
    with open(index_file, 'w') as fp:
        if common.options.pretty:
            json.dump(output, fp, default=_index_encoder_default, indent=2)
        else:
            json.dump(output, fp, default=_index_encoder_default)

    if common.options.nosign:
        logging.debug(_('index-v1 must have a signature, use `fdroid signindex` to create it!'))
    else:
        signindex.config = common.config
        signindex.sign_index_v1(repodir, json_name)


def v1_sort_packages(packages, fdroid_signing_key_fingerprints):
    """Sorts the supplied list to ensure a deterministic sort order for
    package entries in the index file. This sort-order also expresses
    installation preference to the clients.
    (First in this list = first to install)

    :param packages: list of packages which need to be sorted before but into index file.
    """

    GROUP_DEV_SIGNED = 1
    GROUP_FDROID_SIGNED = 2
    GROUP_OTHER_SIGNED = 3

    def v1_sort_keys(package):
        packageName = package.get('packageName', None)

        sig = package.get('signer', None)

        dev_sig = common.metadata_find_developer_signature(packageName)
        group = GROUP_OTHER_SIGNED
        if dev_sig and dev_sig == sig:
            group = GROUP_DEV_SIGNED
        else:
            fdroidsig = fdroid_signing_key_fingerprints.get(packageName, {}).get('signer')
            if fdroidsig and fdroidsig == sig:
                group = GROUP_FDROID_SIGNED

        versionCode = None
        if package.get('versionCode', None):
            versionCode = -int(package['versionCode'])

        return(packageName, group, sig, versionCode)

    packages.sort(key=v1_sort_keys)


def make_v0(apps, apks, repodir, repodict, requestsdict, fdroid_signing_key_fingerprints):
    """
    aka index.jar aka index.xml
    """

    doc = Document()

    def addElement(name, value, doc, parent):
        el = doc.createElement(name)
        el.appendChild(doc.createTextNode(value))
        parent.appendChild(el)

    def addElementNonEmpty(name, value, doc, parent):
        if not value:
            return
        addElement(name, value, doc, parent)

    def addElementIfInApk(name, apk, key, doc, parent):
        if key not in apk:
            return
        value = str(apk[key])
        addElement(name, value, doc, parent)

    def addElementCDATA(name, value, doc, parent):
        el = doc.createElement(name)
        el.appendChild(doc.createCDATASection(value))
        parent.appendChild(el)

    def addElementCheckLocalized(name, app, key, doc, parent, default=''):
        '''Fill in field from metadata or localized block

        For name/summary/description, they can come only from the app source,
        or from a dir in fdroiddata.  They can be entirely missing from the
        metadata file if there is localized versions.  This will fetch those
        from the localized version if its not available in the metadata file.
        '''

        el = doc.createElement(name)
        value = app.get(key)
        lkey = key[:1].lower() + key[1:]
        localized = app.get('localized')
        if not value and localized:
            for lang in ['en-US'] + [x for x in localized.keys()]:
                if not lang.startswith('en'):
                    continue
                if lang in localized:
                    value = localized[lang].get(lkey)
                    if value:
                        break
        if not value and localized and len(localized) > 1:
            lang = list(localized.keys())[0]
            value = localized[lang].get(lkey)
        if not value:
            value = default
        el.appendChild(doc.createTextNode(value))
        parent.appendChild(el)

    root = doc.createElement("fdroid")
    doc.appendChild(root)

    repoel = doc.createElement("repo")

    repoel.setAttribute("name", repodict['name'])
    if 'maxage' in repodict:
        repoel.setAttribute("maxage", str(repodict['maxage']))
    repoel.setAttribute("icon", os.path.basename(repodict['icon']))
    repoel.setAttribute("url", repodict['address'])
    addElement('description', repodict['description'], doc, repoel)
    for mirror in repodict.get('mirrors', []):
        addElement('mirror', mirror, doc, repoel)

    repoel.setAttribute("version", str(repodict['version']))
    repoel.setAttribute("timestamp", '%d' % repodict['timestamp'].timestamp())

    pubkey, repo_pubkey_fingerprint = extract_pubkey()
    repoel.setAttribute("pubkey", pubkey.decode('utf-8'))
    root.appendChild(repoel)

    for command in ('install', 'uninstall'):
        for packageName in requestsdict[command]:
            element = doc.createElement(command)
            root.appendChild(element)
            element.setAttribute('packageName', packageName)

    for appid, appdict in apps.items():
        app = metadata.App(appdict)

        if app.Disabled is not None:
            continue

        # Get a list of the apks for this app...
        apklist = []
        apksbyversion = collections.defaultdict(lambda: [])
        for apk in apks:
            if apk.get('versionCode') and apk.get('packageName') == appid:
                apksbyversion[apk['versionCode']].append(apk)
        for versionCode, apksforver in apksbyversion.items():
            fdroidsig = fdroid_signing_key_fingerprints.get(appid, {}).get('signer')
            fdroid_signed_apk = None
            name_match_apk = None
            for x in apksforver:
                if fdroidsig and x.get('signer', None) == fdroidsig:
                    fdroid_signed_apk = x
                if common.apk_release_filename.match(x.get('apkName', '')):
                    name_match_apk = x
            # choose which of the available versions is most
            # suiteable for index v0
            if fdroid_signed_apk:
                apklist.append(fdroid_signed_apk)
            elif name_match_apk:
                apklist.append(name_match_apk)
            else:
                apklist.append(apksforver[0])

        if len(apklist) == 0:
            continue

        apel = doc.createElement("application")
        apel.setAttribute("id", app.id)
        root.appendChild(apel)

        addElement('id', app.id, doc, apel)
        if app.added:
            addElement('added', app.added.strftime('%Y-%m-%d'), doc, apel)
        if app.lastUpdated:
            addElement('lastupdated', app.lastUpdated.strftime('%Y-%m-%d'), doc, apel)

        addElementCheckLocalized('name', app, 'Name', doc, apel)
        addElementCheckLocalized('summary', app, 'Summary', doc, apel)

        if app.icon:
            addElement('icon', app.icon, doc, apel)

        addElementCheckLocalized('desc', app, 'Description', doc, apel,
                                 '<p>No description available</p>')

        addElement('license', app.License, doc, apel)
        if app.Categories:
            addElement('categories', ','.join(app.Categories), doc, apel)
            # We put the first (primary) category in LAST, which will have
            # the desired effect of making clients that only understand one
            # category see that one.
            addElement('category', app.Categories[0], doc, apel)
        addElement('web', app.WebSite, doc, apel)
        addElement('source', app.SourceCode, doc, apel)
        addElement('tracker', app.IssueTracker, doc, apel)
        addElementNonEmpty('changelog', app.Changelog, doc, apel)
        addElementNonEmpty('author', app.AuthorName, doc, apel)
        addElementNonEmpty('email', app.AuthorEmail, doc, apel)
        addElementNonEmpty('donate', app.Donate, doc, apel)
        addElementNonEmpty('bitcoin', app.Bitcoin, doc, apel)
        addElementNonEmpty('litecoin', app.Litecoin, doc, apel)
        addElementNonEmpty('flattr', app.FlattrID, doc, apel)
        addElementNonEmpty('liberapay', app.LiberapayID, doc, apel)

        # These elements actually refer to the current version (i.e. which
        # one is recommended. They are historically mis-named, and need
        # changing, but stay like this for now to support existing clients.
        addElement('marketversion', app.CurrentVersion, doc, apel)
        addElement('marketvercode', app.CurrentVersionCode, doc, apel)

        if app.Provides:
            pv = app.Provides.split(',')
            addElementNonEmpty('provides', ','.join(pv), doc, apel)
        if app.RequiresRoot:
            addElement('requirements', 'root', doc, apel)

        # Sort the apk list into version order, just so the web site
        # doesn't have to do any work by default...
        apklist = sorted(apklist, key=lambda apk: apk['versionCode'], reverse=True)

        if 'antiFeatures' in apklist[0]:
            app.AntiFeatures.extend(apklist[0]['antiFeatures'])
        if app.AntiFeatures:
            addElementNonEmpty('antifeatures', ','.join(app.AntiFeatures), doc, apel)

        # Check for duplicates - they will make the client unhappy...
        for i in range(len(apklist) - 1):
            first = apklist[i]
            second = apklist[i + 1]
            if first['versionCode'] == second['versionCode'] \
               and first['sig'] == second['sig']:
                if first['hash'] == second['hash']:
                    raise FDroidException('"{0}/{1}" and "{0}/{2}" are exact duplicates!'.format(
                        repodir, first['apkName'], second['apkName']))
                else:
                    raise FDroidException('duplicates: "{0}/{1}" - "{0}/{2}"'.format(
                        repodir, first['apkName'], second['apkName']))

        current_version_code = 0
        current_version_file = None
        for apk in apklist:
            file_extension = common.get_file_extension(apk['apkName'])
            # find the APK for the "Current Version"
            if current_version_code < apk['versionCode']:
                current_version_code = apk['versionCode']
            if current_version_code < int(app.CurrentVersionCode):
                current_version_file = apk['apkName']

            apkel = doc.createElement("package")
            apel.appendChild(apkel)

            versionName = apk.get('versionName')
            if not versionName:
                versionCodeStr = str(apk['versionCode'])  # TODO build.versionCode should be int!
                for build in app.builds:
                    if build['versionCode'] == versionCodeStr and 'versionName' in build:
                        versionName = build['versionName']
                        break
            if versionName:
                addElement('version', versionName, doc, apkel)

            addElement('versioncode', str(apk['versionCode']), doc, apkel)
            addElement('apkname', apk['apkName'], doc, apkel)
            addElementIfInApk('srcname', apk, 'srcname', doc, apkel)

            hashel = doc.createElement("hash")
            hashel.setAttribute('type', 'sha256')
            hashel.appendChild(doc.createTextNode(apk['hash']))
            apkel.appendChild(hashel)

            addElement('size', str(apk['size']), doc, apkel)
            addElementIfInApk('sdkver', apk,
                              'minSdkVersion', doc, apkel)
            addElementIfInApk('targetSdkVersion', apk,
                              'targetSdkVersion', doc, apkel)
            addElementIfInApk('maxsdkver', apk,
                              'maxSdkVersion', doc, apkel)
            addElementIfInApk('obbMainFile', apk,
                              'obbMainFile', doc, apkel)
            addElementIfInApk('obbMainFileSha256', apk,
                              'obbMainFileSha256', doc, apkel)
            addElementIfInApk('obbPatchFile', apk,
                              'obbPatchFile', doc, apkel)
            addElementIfInApk('obbPatchFileSha256', apk,
                              'obbPatchFileSha256', doc, apkel)
            if 'added' in apk:
                addElement('added', apk['added'].strftime('%Y-%m-%d'), doc, apkel)

            if file_extension == 'apk':  # sig is required for APKs, but only APKs
                addElement('sig', apk['sig'], doc, apkel)

                old_permissions = set()
                sorted_permissions = sorted(apk['uses-permission'])
                for perm in sorted_permissions:
                    perm_name = perm.name
                    if perm_name.startswith("android.permission."):
                        perm_name = perm_name[19:]
                    old_permissions.add(perm_name)
                addElementNonEmpty('permissions', ','.join(sorted(old_permissions)), doc, apkel)

                for permission in sorted_permissions:
                    permel = doc.createElement('uses-permission')
                    permel.setAttribute('name', permission.name)
                    if permission.maxSdkVersion is not None:
                        permel.setAttribute('maxSdkVersion', '%d' % permission.maxSdkVersion)
                        apkel.appendChild(permel)
                for permission_sdk_23 in sorted(apk['uses-permission-sdk-23']):
                    permel = doc.createElement('uses-permission-sdk-23')
                    permel.setAttribute('name', permission_sdk_23.name)
                    if permission_sdk_23.maxSdkVersion is not None:
                        permel.setAttribute('maxSdkVersion', '%d' % permission_sdk_23.maxSdkVersion)
                        apkel.appendChild(permel)
                if 'nativecode' in apk:
                    addElement('nativecode', ','.join(sorted(apk['nativecode'])), doc, apkel)
                addElementNonEmpty('features', ','.join(sorted(apk['features'])), doc, apkel)

        if current_version_file is not None \
                and common.config['make_current_version_link'] \
                and repodir == 'repo':  # only create these
            namefield = common.config['current_version_name_source']
            sanitized_name = re.sub(b'''[ '"&%?+=/]''', b'', app.get(namefield).encode('utf-8'))
            apklinkname = sanitized_name + os.path.splitext(current_version_file)[1].encode('utf-8')
            current_version_path = os.path.join(repodir, current_version_file).encode('utf-8', 'surrogateescape')
            if os.path.islink(apklinkname):
                os.remove(apklinkname)
            os.symlink(current_version_path, apklinkname)
            # also symlink gpg signature, if it exists
            for extension in (b'.asc', b'.sig'):
                sigfile_path = current_version_path + extension
                if os.path.exists(sigfile_path):
                    siglinkname = apklinkname + extension
                    if os.path.islink(siglinkname):
                        os.remove(siglinkname)
                    os.symlink(sigfile_path, siglinkname)

    if common.options.pretty:
        output = doc.toprettyxml(encoding='utf-8')
    else:
        output = doc.toxml(encoding='utf-8')

    with open(os.path.join(repodir, 'index.xml'), 'wb') as f:
        f.write(output)

    if 'repo_keyalias' in common.config:

        if common.options.nosign:
            logging.info(_("Creating unsigned index in preparation for signing"))
        else:
            logging.info(_("Creating signed index with this key (SHA256):"))
            logging.info("%s" % repo_pubkey_fingerprint)

        # Create a jar of the index...
        jar_output = 'index_unsigned.jar' if common.options.nosign else 'index.jar'
        p = FDroidPopen(['jar', 'cf', jar_output, 'index.xml'], cwd=repodir)
        if p.returncode != 0:
            raise FDroidException("Failed to create {0}".format(jar_output))

        # Sign the index...
        signed = os.path.join(repodir, 'index.jar')
        if common.options.nosign:
            # Remove old signed index if not signing
            if os.path.exists(signed):
                os.remove(signed)
        else:
            signindex.config = common.config
            signindex.sign_jar(signed)

    # Copy the repo icon into the repo directory...
    icon_dir = os.path.join(repodir, 'icons')
    iconfilename = os.path.join(icon_dir, os.path.basename(common.config['repo_icon']))
    shutil.copyfile(common.config['repo_icon'], iconfilename)


def extract_pubkey():
    """
    Extracts and returns the repository's public key from the keystore.
    :return: public key in hex, repository fingerprint
    """
    if 'repo_pubkey' in common.config:
        pubkey = unhexlify(common.config['repo_pubkey'])
    else:
        env_vars = {'FDROID_KEY_STORE_PASS': common.config['keystorepass']}
        p = FDroidPopenBytes([common.config['keytool'], '-exportcert',
                              '-alias', common.config['repo_keyalias'],
                              '-keystore', common.config['keystore'],
                              '-storepass:env', 'FDROID_KEY_STORE_PASS']
                             + common.config['smartcardoptions'],
                             envs=env_vars, output=False, stderr_to_stdout=False)
        if p.returncode != 0 or len(p.output) < 20:
            msg = "Failed to get repo pubkey!"
            if common.config['keystore'] == 'NONE':
                msg += ' Is your crypto smartcard plugged in?'
            raise FDroidException(msg)
        pubkey = p.output
    repo_pubkey_fingerprint = common.get_cert_fingerprint(pubkey)
    return hexlify(pubkey), repo_pubkey_fingerprint


def get_mirror_service_urls(url):
    '''Get direct URLs from git service for use by fdroidclient

    Via 'servergitmirrors', fdroidserver can create and push a mirror
    to certain well known git services like gitlab or github.  This
    will always use the 'master' branch since that is the default
    branch in git. The files are then accessible via alternate URLs,
    where they are served in their raw format via a CDN rather than
    from git.
    '''

    if url.startswith('git@'):
        url = re.sub(r'^git@(.*):(.*)', r'https://\1/\2', url)

    segments = url.split("/")

    if segments[4].endswith('.git'):
        segments[4] = segments[4][:-4]

    hostname = segments[2]
    user = segments[3]
    repo = segments[4]
    branch = "master"
    folder = "fdroid"

    urls = []
    if hostname == "github.com":
        # Github-like RAW segments "https://raw.githubusercontent.com/user/repo/branch/folder"
        segments[2] = "raw.githubusercontent.com"
        segments.extend([branch, folder])
        urls.append('/'.join(segments))
    elif hostname == "gitlab.com":
        # Both these Gitlab URLs will work with F-Droid, but only the first will work in the browser
        # This is because the `raw` URLs are not served with the correct mime types, so any
        # index.html which is put in the repo will not be rendered. Putting an index.html file in
        # the repo root is a common way for to make information about the repo available to end user.

        # Gitlab-like Pages segments "https://user.gitlab.io/repo/folder"
        gitlab_pages = ["https:", "", user + ".gitlab.io", repo, folder]
        urls.append('/'.join(gitlab_pages))
        # Gitlab Raw "https://gitlab.com/user/repo/raw/branch/folder"
        gitlab_raw = segments + ['raw', branch, folder]
        urls.append('/'.join(gitlab_raw))
        return urls

    return urls


def download_repo_index(url_str, etag=None, verify_fingerprint=True):
    """
    Downloads the repository index from the given :param url_str
    and verifies the repository's fingerprint if :param verify_fingerprint is not False.

    :raises: VerificationException() if the repository could not be verified

    :return: A tuple consisting of:
        - The index in JSON format or None if the index did not change
        - The new eTag as returned by the HTTP request
    """
    url = urllib.parse.urlsplit(url_str)

    fingerprint = None
    if verify_fingerprint:
        query = urllib.parse.parse_qs(url.query)
        if 'fingerprint' not in query:
            raise VerificationException(_("No fingerprint in URL."))
        fingerprint = query['fingerprint'][0]

    url = urllib.parse.SplitResult(url.scheme, url.netloc, url.path + '/index-v1.jar', '', '')
    download, new_etag = net.http_get(url.geturl(), etag)

    if download is None:
        return None, new_etag

    with tempfile.NamedTemporaryFile() as fp:
        # write and open JAR file
        fp.write(download)
        jar = zipfile.ZipFile(fp)

        # verify that the JAR signature is valid
        logging.debug(_('Verifying index signature:'))
        common.verify_jar_signature(fp.name)

        # get public key and its fingerprint from JAR
        public_key, public_key_fingerprint = get_public_key_from_jar(jar)

        # compare the fingerprint if verify_fingerprint is True
        if verify_fingerprint and fingerprint.upper() != public_key_fingerprint:
            raise VerificationException(_("The repository's fingerprint does not match."))

        # load repository index from JSON
        index = json.loads(jar.read('index-v1.json').decode("utf-8"))
        index["repo"]["pubkey"] = hexlify(public_key).decode("utf-8")
        index["repo"]["fingerprint"] = public_key_fingerprint

        # turn the apps into App objects
        index["apps"] = [metadata.App(app) for app in index["apps"]]

        return index, new_etag


def get_public_key_from_jar(jar):
    """
    Get the public key and its fingerprint from a JAR file.

    :raises: VerificationException() if the JAR was not signed exactly once

    :param jar: a zipfile.ZipFile object
    :return: the public key from the jar and its fingerprint
    """
    # extract certificate from jar
    certs = [n for n in jar.namelist() if common.CERT_PATH_REGEX.match(n)]
    if len(certs) < 1:
        raise VerificationException(_("Found no signing certificates for repository."))
    if len(certs) > 1:
        raise VerificationException(_("Found multiple signing certificates for repository."))

    # extract public key from certificate
    public_key = common.get_certificate(jar.read(certs[0]))
    public_key_fingerprint = common.get_cert_fingerprint(public_key).replace(' ', '')

    return public_key, public_key_fingerprint
