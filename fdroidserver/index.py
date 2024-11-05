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
import hashlib
import json
import logging
import os
import re
import ruamel.yaml
import shutil
import tempfile
import urllib.parse
import zipfile
import calendar
import qrcode
from binascii import hexlify, unhexlify
from datetime import datetime, timezone
from pathlib import Path
from xml.dom.minidom import Document

from . import _
from . import common
from . import metadata
from . import net
from . import signindex
from fdroidserver.common import ANTIFEATURES_CONFIG_NAME, CATEGORIES_CONFIG_NAME, CONFIG_CONFIG_NAME, MIRRORS_CONFIG_NAME, RELEASECHANNELS_CONFIG_NAME, DEFAULT_LOCALE, FDroidPopen, FDroidPopenBytes, load_stats_fdroid_signing_key_fingerprints
from fdroidserver.exception import FDroidException, VerificationException


def make(apps, apks, repodir, archive):
    """Generate the repo index files.

    This requires properly initialized options and config objects.

    Parameters
    ----------
    apps
      OrderedDict of apps to go into the index, each app should have
      at least one associated apk
    apks
      list of apks to go into the index
    repodir
      the repo directory
    archive
      True if this is the archive repo, False if it's the
      main one.
    """
    from fdroidserver.update import METADATA_VERSION

    if not hasattr(common.options, 'nosign') or not common.options.nosign:
        common.assert_config_keystore(common.config)

    # Historically the index has been sorted by App Name, so we enforce this ordering here
    sortedids = sorted(apps, key=lambda appid: common.get_app_display_name(apps[appid]).upper())
    sortedapps = collections.OrderedDict()
    for appid in sortedids:
        sortedapps[appid] = apps[appid]

    repodict = collections.OrderedDict()
    repodict['timestamp'] = datetime.now(timezone.utc)
    repodict['version'] = METADATA_VERSION

    if common.config['repo_maxage'] != 0:
        repodict['maxage'] = common.config['repo_maxage']

    if archive:
        repodict['name'] = common.config['archive_name']
        repodict['icon'] = common.config.get('archive_icon', common.default_config['repo_icon'])
        repodict['description'] = common.config['archive_description']
        archive_url = common.config.get('archive_url', common.config['repo_url'][:-4] + 'archive')
        repodict['address'] = archive_url
        if 'archive_web_base_url' in common.config:
            repodict["webBaseUrl"] = common.config['archive_web_base_url']
        repo_section = os.path.basename(urllib.parse.urlparse(archive_url).path)
    else:
        repodict['name'] = common.config['repo_name']
        repodict['icon'] = common.config.get('repo_icon', common.default_config['repo_icon'])
        repodict['address'] = common.config['repo_url']
        if 'repo_web_base_url' in common.config:
            repodict["webBaseUrl"] = common.config['repo_web_base_url']
        repodict['description'] = common.config['repo_description']
        repo_section = os.path.basename(urllib.parse.urlparse(common.config['repo_url']).path)

    add_mirrors_to_repodict(repo_section, repodict)

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

    make_v0(sortedapps, apks, repodir, repodict, requestsdict,
            fdroid_signing_key_fingerprints)
    make_v1(sortedapps, apks, repodir, repodict, requestsdict,
            fdroid_signing_key_fingerprints)
    make_v2(sortedapps, apks, repodir, repodict, requestsdict,
            fdroid_signing_key_fingerprints, archive)
    make_website(sortedapps, repodir, repodict)
    make_altstore(
        sortedapps,
        apks,
        common.config,
        repodir,
        pretty=common.options.pretty,
    )


def _should_file_be_generated(path, magic_string):
    if os.path.exists(path):
        with open(path) as f:
            # if the magic_string is not in the first line the file should be overwritten
            if magic_string not in f.readline():
                return False
    return True


def make_website(apps, repodir, repodict):
    _ignored, repo_pubkey_fingerprint = extract_pubkey()
    repo_pubkey_fingerprint_stripped = repo_pubkey_fingerprint.replace(" ", "")
    link = repodict["address"]
    link_fingerprinted = ('{link}?fingerprint={fingerprint}'
                          .format(link=link, fingerprint=repo_pubkey_fingerprint_stripped))
    # do not change this string, as it will break updates for files with older versions of this string
    autogenerate_comment = "auto-generated - fdroid index updates will overwrite this file"

    if not os.path.exists(repodir):
        os.makedirs(repodir)

    qrcode.make(link_fingerprinted).save(os.path.join(repodir, "index.png"))

    html_name = 'index.html'
    html_file = os.path.join(repodir, html_name)

    if _should_file_be_generated(html_file, autogenerate_comment):
        with open(html_file, 'w') as f:
            name = repodict["name"]
            description = repodict["description"]
            icon = repodict["icon"]
            f.write("""<!-- {autogenerate_comment} -->
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
  <head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type">
    <meta content="width=device-width; initial-scale=1.0; minimum-scale=0.5; maximum-scale=2.0; user-scalable=1;" name="viewport">
    <title>
   {name}
    </title>
    <base href="index.html">
    <link href="index.css" rel="stylesheet" type="text/css">
    <link href="icons/{icon}" rel="icon" type="image/png">
    <link href="icons/{icon}" rel="shortcut icon" type="image/png">
    <meta content="{name}" property="og:site_name">
    <meta content="{name}" property="og:title">
    <meta content property="og:determiner">
    <meta content="{description}" property="og:description">
    <meta content="index,nofollow" name="robots">
  </head>
  <body>
    <h2>
      {name}
    </h2>
    <div id="intro">
      <p style="margin-bottom:.2em;">
        <span style="float:right;width:100px;margin-left:.5em;">
          <a href="index.png" title="QR: test">
            <img alt="QR: test" src="index.png" width="100">
          </a>
        </span>
        {description}
        <br>
        <br>
        Currently it serves
        <kbd>
          {number_of_apps}
        </kbd>
        apps. To add it to your F-Droid app, scan the QR code (click it to enlarge) or use this link:
      </p>
      <p class="center" style="margin-top:.5em">
        <a href="https://fdroid.link/#{link_fingerprinted}">
          <code style="color:#000000;font-weight:bold;">
            {link}
          </code>
        </a>
      </p>
      <p>
        If you would like to manually verify the fingerprint (SHA-256) of the repository signing key, here it is:
        <br>
        <blockcode style="color:#000000;font-weight:bold;">
          {fingerprint}
        </blockcode>
      </p>
    </div>
  </body>
</html>
""".format(autogenerate_comment=autogenerate_comment,
                    description=description,
                    fingerprint=repo_pubkey_fingerprint,
                    icon=icon,
                    link=link,
                    link_fingerprinted=link_fingerprinted,
                    name=name,
                    number_of_apps=str(len(apps))))

    css_file = os.path.join(repodir, "index.css")
    if _should_file_be_generated(css_file, autogenerate_comment):
        with open(css_file, "w") as f:
            # this auto generated comment was not included via .format(), as python seems to have problems with css files in combination with .format()
            f.write("""/* auto-generated - fdroid index updates will overwrite this file */
BODY {
  font-family         : Arial, Helvetica, Sans-Serif;
  color               : #0000ee;
  background-color    : #ffffff;
}
p {
  text-align          : justify;
}
p.center {
  text-align          : center;
}
TD {
  font-family         : Arial, Helvetica, Sans-Serif;
  color               : #0000ee;
}
body,td {
  font-size           : 14px;
}
TH {
  font-family         : Arial, Helvetica, Sans-Serif;
  color               : #0000ee;
  background-color    : #F5EAD4;
}
a:link {
  color               : #bb0000;
}
a:visited {
  color               : #ff0000;
}
.zitat {
  margin-left         : 1cm;
  margin-right        : 1cm;
  font-style          : italic;
}
#intro {
  border-spacing      : 1em;
  border              : 1px solid gray;
  border-radius       : 0.5em;
  box-shadow          : 10px 10px 5px #888;
  margin              : 1.5em;
  font-size           : .9em;
  width               : 600px;
  max-width           : 90%;
  display             : table;
  margin-left         : auto;
  margin-right        : auto;
  font-size           : .8em;
  color               : #555555;
}
#intro > p {
  margin-top          : 0;
}
#intro p:last-child {
  margin-bottom       : 0;
}
.last {
  border-bottom       : 1px solid black;
  padding-bottom      : .5em;
  text-align          : center;
}
table {
  border-collapse     : collapse;
}
h2 {
  text-align          : center;
}
.perms {
  font-family         : monospace;
  font-size           : .8em;
}
.repoapplist {
  display             : table;
  border-collapse     : collapse;
  margin-left         : auto;
  margin-right        : auto;
  width               : 600px;
  max-width           : 90%;
}
.approw, appdetailrow {
  display             : table-row;
}
.appdetailrow {
  display             : flex;
  padding             : .5em;
}
.appiconbig, .appdetailblock, .appdetailcell {
  display             : table-cell
}
.appiconbig {
  vertical-align      : middle;
  text-align          : center;
}
.appdetailinner {
  width               : 100%;
}
.applinkcell {
  text-align          : center;
  float               : right;
  width               : 100%;
  margin-bottom       : .1em;
}
.paddedlink {
  margin              : 1em;
}
.approw {
  border-spacing      : 1em;
  border              : 1px solid gray;
  border-radius       : 0.5em;
  padding             : 0.5em;
  margin              : 1.5em;
}
.appdetailinner .appdetailrow:first-child {
  background-color    : #d5d5d5;
}
.appdetailinner .appdetailrow:first-child .appdetailcell {
  min-width           : 33%;
  flex                : 1 33%;
  text-align          : center;
}
.appdetailinner .appdetailrow:first-child .appdetailcell:first-child {
  text-align          : left;
}
.appdetailinner .appdetailrow:first-child .appdetailcell:last-child {
  float               : none;
  text-align          : right;
}
.minor-details {
  font-size           : .8em;
  color               : #555555;
}
.boldname {
  font-weight         : bold;
}
#appcount {
  text-align          : center;
  margin-bottom       : .5em;
}
kbd {
  padding             : 0.1em 0.6em;
  border              : 1px solid #CCC;
  background-color    : #F7F7F7;
  color               : #333;
  box-shadow          : 0px 1px 0px rgba(0, 0, 0, 0.2), 0px 0px 0px 2px #FFF inset;
  border-radius       : 3px;
  display             : inline-block;
  margin              : 0px 0.1em;
  text-shadow         : 0px 1px 0px #FFF;
  white-space         : nowrap;
}
div.filterline, div.repoline {
  display             : table;
  margin-left         : auto;
  margin-right        : auto;
  margin-bottom       : 1em;
  vertical-align      : middle;
  display             : table;
  font-size           : .8em;
}
.filterline form {
  display             : table-row;
}
.filterline .filtercell {
  display             : table-cell;
  vertical-align      : middle;
}
fieldset {
  float               : left;
}
fieldset select, fieldset input, #reposelect select, #reposelect input {
  font-size           : .9em;
}
.pager {
  display             : table;
  margin-left         : auto;
  margin-right        : auto;
  width               : 600px;
  max-width           : 90%;
  padding-top         : .6em;
}
/* should correspond to .repoapplist */
.pagerrow {
  display             : table-row;
}
.pagercell {
  display             : table-cell;
}
.pagercell.left {
  text-align          : left;
  padding-right       : 1em;
}
.pagercell.middle {
  text-align          : center;
  font-size           : .9em;
  color               : #555;
}
.pagercell.right {
  text-align          : right;
  padding-left        : 1em;
}
.anti {
  color               : peru;
}
.antibold {
  color               : crimson;
}
#footer {
  text-align          : center;
  margin-top          : 1em;
  font-size           : 11px;
  color               : #555;
}
#footer img {
  vertical-align      : middle;
}
@media (max-width: 600px) {
  .repoapplist {
    display             : block;
  }
  .appdetailinner, .appdetailrow {
    display             : block;
  }
  .appdetailcell {
    display             : block;
    float               : left;
    line-height         : 1.5em;
  }
}""")


def dict_diff(source, target):
    if not isinstance(target, dict) or not isinstance(source, dict):
        return target

    result = {key: None for key in source if key not in target}

    for key, value in target.items():
        if key not in source:
            result[key] = value
        elif value != source[key]:
            result[key] = dict_diff(source[key], value)

    return result


def convert_datetime(obj):
    if isinstance(obj, datetime):
        # Java prefers milliseconds
        # we also need to account for time zone/daylight saving time
        return int(calendar.timegm(obj.timetuple()) * 1000)
    return obj


def package_metadata(app, repodir):
    meta = {}
    for element in (
        "added",
        # "binaries",
        "Categories",
        "Changelog",
        "IssueTracker",
        "lastUpdated",
        "License",
        "SourceCode",
        "Translation",
        "WebSite",
        "featureGraphic",
        "promoGraphic",
        "tvBanner",
        "screenshots",
        "AuthorEmail",
        "AuthorName",
        "AuthorPhone",
        "AuthorWebSite",
        "Bitcoin",
        "Liberapay",
        "Litecoin",
        "OpenCollective",
    ):
        if element in app and app[element]:
            element_new = element[:1].lower() + element[1:]
            meta[element_new] = convert_datetime(app[element])

    for element in (
        "Name",
        "Summary",
        "Description",
        "video",
    ):
        element_new = element[:1].lower() + element[1:]
        if element in app and app[element]:
            meta[element_new] = {DEFAULT_LOCALE: convert_datetime(app[element])}
        elif "localized" in app:
            localized = {k: v[element_new] for k, v in app["localized"].items() if element_new in v}
            if localized:
                meta[element_new] = localized

    if "name" not in meta and app["AutoName"]:
        meta["name"] = {DEFAULT_LOCALE: app["AutoName"]}

    # fdroidserver/metadata.py App default
    if meta["license"] == "Unknown":
        del meta["license"]

    if app["Donate"]:
        meta["donate"] = [app["Donate"]]

    # TODO handle different resolutions
    if app.get("icon"):
        icon_path = os.path.join(repodir, "icons", app["icon"])
        meta["icon"] = {DEFAULT_LOCALE: common.file_entry(icon_path)}

    if "iconv2" in app:
        meta["icon"] = app["iconv2"]

    return meta


def convert_version(version, app, repodir):
    """Convert the internal representation of Builds: into index-v2 versions.

    The diff algorithm of index-v2 uses null/None to mean a field to
    be removed, so this function handles any Nones that are in the
    metadata file.

    """
    ver = {}
    if "added" in version:
        ver["added"] = convert_datetime(version["added"])
    else:
        ver["added"] = 0

    ver["file"] = {
        "name": "/{}".format(version["apkName"]),
        version["hashType"]: version["hash"],
        "size": version["size"],
    }

    ipfsCIDv1 = version.get("ipfsCIDv1")
    if ipfsCIDv1:
        ver["file"]["ipfsCIDv1"] = ipfsCIDv1

    if "srcname" in version:
        ver["src"] = common.file_entry(os.path.join(repodir, version["srcname"]))

    if "obbMainFile" in version:
        ver["obbMainFile"] = common.file_entry(
            os.path.join(repodir, version["obbMainFile"]),
            version["obbMainFileSha256"],
        )

    if "obbPatchFile" in version:
        ver["obbPatchFile"] = common.file_entry(
            os.path.join(repodir, version["obbPatchFile"]),
            version["obbPatchFileSha256"],
        )

    ver["manifest"] = manifest = {}

    for element in (
        "nativecode",
        "versionName",
        "maxSdkVersion",
    ):
        if element in version:
            manifest[element] = version[element]

    if "versionCode" in version:
        manifest["versionCode"] = version["versionCode"]

    if "features" in version and version["features"]:
        manifest["features"] = features = []
        for feature in version["features"]:
            # TODO get version from manifest, default (0) is omitted
            # features.append({"name": feature, "version": 1})
            features.append({"name": feature})

    if "minSdkVersion" in version:
        manifest["usesSdk"] = {}
        manifest["usesSdk"]["minSdkVersion"] = version["minSdkVersion"]
        if "targetSdkVersion" in version:
            manifest["usesSdk"]["targetSdkVersion"] = version["targetSdkVersion"]
        else:
            # https://developer.android.com/guide/topics/manifest/uses-sdk-element.html#target
            manifest["usesSdk"]["targetSdkVersion"] = manifest["usesSdk"]["minSdkVersion"]

    if "signer" in version:
        manifest["signer"] = {"sha256": [version["signer"]]}

    for element in ("uses-permission", "uses-permission-sdk-23"):
        en = element.replace("uses-permission", "usesPermission").replace("-sdk-23", "Sdk23")
        if element in version and version[element]:
            manifest[en] = []
            for perm in version[element]:
                if perm[1]:
                    manifest[en].append({"name": perm[0], "maxSdkVersion": perm[1]})
                else:
                    manifest[en].append({"name": perm[0]})

    # index-v2 has only per-version antifeatures, not per package.
    antiFeatures = app.get('AntiFeatures', {}).copy()
    for name, descdict in version.get('antiFeatures', dict()).items():
        antiFeatures[name] = descdict
    if antiFeatures:
        ver['antiFeatures'] = {
            k: dict(sorted(antiFeatures[k].items())) for k in sorted(antiFeatures)
        }

    if "versionCode" in version:
        if version["versionCode"] > app["CurrentVersionCode"]:
            ver[RELEASECHANNELS_CONFIG_NAME] = ["Beta"]

    builds = app.get("Builds", [])

    if len(builds) > 0 and version["versionCode"] == builds[-1]["versionCode"]:
        if "localized" in app:
            localized = {k: v["whatsNew"] for k, v in app["localized"].items() if "whatsNew" in v}
            if localized:
                ver["whatsNew"] = localized

    for build in builds:
        if build['versionCode'] == version['versionCode'] and "whatsNew" in build:
            ver["whatsNew"] = build["whatsNew"]
            break

    return ver


def v2_repo(repodict, repodir, archive):
    repo = {}

    repo["name"] = {DEFAULT_LOCALE: repodict["name"]}
    repo["description"] = {DEFAULT_LOCALE: repodict["description"]}
    repo["icon"] = {
        DEFAULT_LOCALE: common.file_entry("%s/icons/%s" % (repodir, repodict["icon"]))
    }

    config = common.load_localized_config(CONFIG_CONFIG_NAME, repodir)
    if config:
        repo["name"] = config["archive" if archive else "repo"]["name"]
        repo["description"] = config["archive" if archive else "repo"]["description"]
        repo["icon"] = config["archive" if archive else "repo"]["icon"]

    repo["address"] = repodict["address"]
    if "mirrors" in repodict:
        repo["mirrors"] = repodict["mirrors"]
    if "webBaseUrl" in repodict:
        repo["webBaseUrl"] = repodict["webBaseUrl"]

    repo["timestamp"] = repodict["timestamp"]

    antiFeatures = common.load_localized_config(ANTIFEATURES_CONFIG_NAME, repodir)
    if antiFeatures:
        repo[ANTIFEATURES_CONFIG_NAME] = antiFeatures

    categories = common.load_localized_config(CATEGORIES_CONFIG_NAME, repodir)
    if categories:
        repo[CATEGORIES_CONFIG_NAME] = categories

    releaseChannels = common.load_localized_config(RELEASECHANNELS_CONFIG_NAME, repodir)
    if releaseChannels:
        repo[RELEASECHANNELS_CONFIG_NAME] = releaseChannels

    return repo


def make_v2(apps, packages, repodir, repodict, requestsdict, fdroid_signing_key_fingerprints, archive):

    def _index_encoder_default(obj):
        if isinstance(obj, set):
            return sorted(list(obj))
        if isinstance(obj, datetime):
            # Java prefers milliseconds
            # we also need to account for time zone/daylight saving time
            return int(calendar.timegm(obj.timetuple()) * 1000)
        if isinstance(obj, dict):
            d = collections.OrderedDict()
            for key in sorted(obj.keys()):
                d[key] = obj[key]
            return d
        raise TypeError(repr(obj) + " is not JSON serializable")

    output = collections.OrderedDict()
    output["repo"] = v2_repo(repodict, repodir, archive)
    if requestsdict and (requestsdict["install"] or requestsdict["uninstall"]):
        output["repo"]["requests"] = requestsdict

    # establish sort order of the index
    v1_sort_packages(packages, fdroid_signing_key_fingerprints)

    output_packages = collections.OrderedDict()
    output['packages'] = output_packages
    categories_used_by_apps = set()
    for package in packages:
        packageName = package['packageName']
        if packageName not in apps:
            logging.info(_('Ignoring package without metadata: ') + package['apkName'])
            continue
        if not package.get('versionName'):
            app = apps[packageName]
            for build in app.get('Builds', []):
                if build['versionCode'] == package['versionCode']:
                    versionName = build.get('versionName')
                    logging.info(_('Overriding blank versionName in {apkfilename} from metadata: {version}')
                                 .format(apkfilename=package['apkName'], version=versionName))
                    package['versionName'] = versionName
                    break
        if packageName in output_packages:
            packagelist = output_packages[packageName]
        else:
            packagelist = {}
            output_packages[packageName] = packagelist
            app = apps[packageName]
            categories_used_by_apps.update(app.get('Categories', []))
            packagelist["metadata"] = package_metadata(app, repodir)
            if "signer" in package:
                packagelist["metadata"]["preferredSigner"] = package["signer"]

            packagelist["versions"] = {}

        packagelist["versions"][package["hash"]] = convert_version(package, apps[packageName], repodir)

    if categories_used_by_apps and not output['repo'].get(CATEGORIES_CONFIG_NAME):
        output['repo'][CATEGORIES_CONFIG_NAME] = dict()
    # include definitions for "auto-defined" categories, e.g. just used in app metadata
    for category in sorted(categories_used_by_apps):
        if category not in output['repo'][CATEGORIES_CONFIG_NAME]:
            output['repo'][CATEGORIES_CONFIG_NAME][category] = {"name": {DEFAULT_LOCALE: category}}
    # do not include defined categories if no apps use them
    for category in list(output['repo'].get(CATEGORIES_CONFIG_NAME, list())):
        if category not in categories_used_by_apps:
            del output['repo'][CATEGORIES_CONFIG_NAME][category]
            msg = _('Category "{category}" defined but not used for any apps!')
            logging.warning(msg.format(category=category))

    entry = {}
    entry["timestamp"] = repodict["timestamp"]

    entry["version"] = repodict["version"]
    if "maxage" in repodict:
        entry["maxAge"] = repodict["maxage"]

    json_name = 'index-v2.json'
    index_file = os.path.join(repodir, json_name)
    with open(index_file, "w", encoding="utf-8") as fp:
        if common.options.pretty:
            json.dump(output, fp, default=_index_encoder_default, indent=2, ensure_ascii=False)
        else:
            json.dump(output, fp, default=_index_encoder_default, ensure_ascii=False)

    json_name = "tmp/{}_{}.json".format(repodir, convert_datetime(repodict["timestamp"]))
    with open(json_name, "w", encoding="utf-8") as fp:
        if common.options.pretty:
            json.dump(output, fp, default=_index_encoder_default, indent=2, ensure_ascii=False)
        else:
            json.dump(output, fp, default=_index_encoder_default, ensure_ascii=False)

    entry["index"] = common.file_entry(index_file)
    entry["index"]["numPackages"] = len(output.get("packages", []))

    indexes = sorted(Path().glob("tmp/{}*.json".format(repodir)), key=lambda x: x.name)
    indexes.pop()  # remove current index
    # remove older indexes
    while len(indexes) > 10:
        indexes.pop(0).unlink()

    indexes = [json.loads(Path(fn).read_text(encoding="utf-8")) for fn in indexes]

    for diff in Path().glob("{}/diff/*.json".format(repodir)):
        diff.unlink()

    entry["diffs"] = {}
    for old in indexes:
        diff_name = str(old["repo"]["timestamp"]) + ".json"
        diff_file = os.path.join(repodir, "diff", diff_name)
        diff = dict_diff(old, output)
        if not os.path.exists(os.path.join(repodir, "diff")):
            os.makedirs(os.path.join(repodir, "diff"))
        with open(diff_file, "w", encoding="utf-8") as fp:
            if common.options.pretty:
                json.dump(diff, fp, default=_index_encoder_default, indent=2, ensure_ascii=False)
            else:
                json.dump(diff, fp, default=_index_encoder_default, ensure_ascii=False)

        entry["diffs"][old["repo"]["timestamp"]] = common.file_entry(diff_file)
        entry["diffs"][old["repo"]["timestamp"]]["numPackages"] = len(diff.get("packages", []))

    json_name = "entry.json"
    index_file = os.path.join(repodir, json_name)
    with open(index_file, "w", encoding="utf-8") as fp:
        if common.options.pretty:
            json.dump(entry, fp, default=_index_encoder_default, indent=2, ensure_ascii=False)
        else:
            json.dump(entry, fp, default=_index_encoder_default, ensure_ascii=False)

    if common.options.nosign:
        _copy_to_local_copy_dir(repodir, index_file)
        logging.debug(_('index-v2 must have a signature, use `fdroid signindex` to create it!'))
    else:
        signindex.config = common.config
        signindex.sign_index(repodir, json_name)


def make_v1(apps, packages, repodir, repodict, requestsdict, fdroid_signing_key_fingerprints):

    def _index_encoder_default(obj):
        if isinstance(obj, set):
            return sorted(list(obj))
        if isinstance(obj, datetime):
            # Java prefers milliseconds
            # we also need to account for time zone/daylight saving time
            return int(calendar.timegm(obj.timetuple()) * 1000)
        if isinstance(obj, dict):
            d = collections.OrderedDict()
            for key in sorted(obj.keys()):
                d[key] = obj[key]
            return d
        raise TypeError(repr(obj) + " is not JSON serializable")

    output = collections.OrderedDict()
    output['repo'] = repodict.copy()
    output['requests'] = requestsdict

    # index-v1 only supports a list of URL strings for additional mirrors
    mirrors = []
    for mirror in repodict.get('mirrors', []):
        url = mirror['url']
        if url != repodict['address']:
            mirrors.append(mirror['url'])
    if mirrors:
        output['repo']['mirrors'] = mirrors

    # establish sort order of the index
    v1_sort_packages(packages, fdroid_signing_key_fingerprints)

    appslist = []
    output['apps'] = appslist
    for packageName, app_dict in apps.items():
        d = collections.OrderedDict()
        appslist.append(d)
        for k, v in sorted(app_dict.items()):
            if not v:
                continue
            if k in ('Builds', 'metadatapath',
                     'ArchivePolicy', 'AutoName', 'AutoUpdateMode', 'MaintainerNotes',
                     'Provides', 'Repo', 'RepoType', 'RequiresRoot',
                     'UpdateCheckData', 'UpdateCheckIgnore', 'UpdateCheckMode',
                     'UpdateCheckName', 'NoSourceSince', 'VercodeOperation',
                     'summary', 'description', 'promoGraphic', 'screenshots', 'whatsNew',
                     'featureGraphic', 'iconv2', 'tvBanner',
                     ):
                continue

            # name things after the App class fields in fdroidclient
            if k == 'id':
                k = 'packageName'
            elif k == 'CurrentVersionCode':  # TODO make SuggestedVersionCode the canonical name
                k = 'suggestedVersionCode'
                v = str(v)
            elif k == 'CurrentVersion':  # TODO make SuggestedVersionName the canonical name
                k = 'suggestedVersionName'
            else:
                k = k[:1].lower() + k[1:]
            d[k] = v

    # establish sort order in lists, sets, and localized dicts
    for app_dict in output['apps']:
        localized = app_dict.get('localized')
        if localized:
            lordered = collections.OrderedDict()
            for lkey, lvalue in sorted(localized.items()):
                lordered[lkey] = collections.OrderedDict()
                for ikey, iname in sorted(lvalue.items()):
                    lordered[lkey][ikey] = iname
            app_dict['localized'] = lordered
        # v1 uses a list of keys for Anti-Features
        antiFeatures = app_dict.get('antiFeatures', dict()).keys()
        if antiFeatures:
            app_dict['antiFeatures'] = sorted(set(antiFeatures))

    output_packages = collections.OrderedDict()
    output['packages'] = output_packages
    for package in packages:
        packageName = package['packageName']
        if packageName not in apps:
            logging.info(_('Ignoring package without metadata: ') + package['apkName'])
            continue
        if not package.get('versionName'):
            app = apps[packageName]
            for build in app.get('Builds', []):
                if build['versionCode'] == package['versionCode']:
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
            if k in ('icon', 'icons', 'icons_src', 'ipfsCIDv1', 'name'):
                continue
            if k == 'antiFeatures':
                d[k] = sorted(v.keys())
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
        _copy_to_local_copy_dir(repodir, index_file)
        logging.debug(_('index-v1 must have a signature, use `fdroid signindex` to create it!'))
    else:
        signindex.config = common.config
        signindex.sign_index(repodir, json_name)


def _copy_to_local_copy_dir(repodir, f):
    local_copy_dir = common.config.get('local_copy_dir', '')
    if os.path.exists(local_copy_dir):
        destdir = os.path.join(local_copy_dir, repodir)
        if not os.path.exists(destdir):
            os.mkdir(destdir)
        shutil.copy2(f, destdir, follow_symlinks=False)
    elif local_copy_dir:
        raise FDroidException(_('"local_copy_dir" {path} does not exist!')
                              .format(path=local_copy_dir))


def v1_sort_packages(packages, fdroid_signing_key_fingerprints):
    """Sort the supplied list to ensure a deterministic sort order for package entries in the index file.

    This sort-order also expresses
    installation preference to the clients.
    (First in this list = first to install)

    Parameters
    ----------
    packages
      list of packages which need to be sorted before but into index file.
    """
    GROUP_DEV_SIGNED = 1
    GROUP_FDROID_SIGNED = 2
    GROUP_OTHER_SIGNED = 3

    def v1_sort_keys(package):
        packageName = package.get('packageName', None)

        signer = package.get('signer', None)

        dev_signer = common.metadata_find_developer_signature(packageName)
        group = GROUP_OTHER_SIGNED
        if dev_signer and dev_signer == signer:
            group = GROUP_DEV_SIGNED
        else:
            fdroid_signer = fdroid_signing_key_fingerprints.get(packageName, {}).get('signer')
            if fdroid_signer and fdroid_signer == signer:
                group = GROUP_FDROID_SIGNED

        versionCode = None
        if package.get('versionCode', None):
            versionCode = -package['versionCode']

        return packageName, group, signer, versionCode

    packages.sort(key=v1_sort_keys)


def make_v0(apps, apks, repodir, repodict, requestsdict, fdroid_signing_key_fingerprints):
    """Aka index.jar aka index.xml."""
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

    def addElementCheckLocalized(name, app, key, doc, parent, default=''):
        """Fill in field from metadata or localized block.

        For name/summary/description, they can come only from the app source,
        or from a dir in fdroiddata.  They can be entirely missing from the
        metadata file if there is localized versions.  This will fetch those
        from the localized version if its not available in the metadata file.

        Attributes should be alpha-sorted, so they must be added in
        alpha- sort order.

        """
        el = doc.createElement(name)
        value = app.get(key)
        lkey = key[:1].lower() + key[1:]
        localized = app.get('localized')
        if not value and localized:
            for lang in [DEFAULT_LOCALE] + [x for x in localized.keys()]:
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
        if not value and name == 'name' and app.get('AutoName'):
            value = app['AutoName']
        el.appendChild(doc.createTextNode(value))
        parent.appendChild(el)

    root = doc.createElement("fdroid")
    doc.appendChild(root)

    repoel = doc.createElement("repo")
    repoel.setAttribute("icon", repodict['icon'])
    if 'maxage' in repodict:
        repoel.setAttribute("maxage", str(repodict['maxage']))
    repoel.setAttribute("name", repodict['name'])
    pubkey, repo_pubkey_fingerprint = extract_pubkey()
    repoel.setAttribute("pubkey", pubkey.decode('utf-8'))
    repoel.setAttribute("timestamp", '%d' % repodict['timestamp'].timestamp())
    repoel.setAttribute("url", repodict['address'])
    repoel.setAttribute("version", str(repodict['version']))

    addElement('description', repodict['description'], doc, repoel)
    # index v0 only supports a list of URL strings for additional mirrors
    for mirror in repodict.get('mirrors', []):
        url = mirror['url']
        if url != repodict['address']:
            addElement('mirror', url, doc, repoel)

    root.appendChild(repoel)

    for command in ('install', 'uninstall'):
        for packageName in requestsdict[command]:
            element = doc.createElement(command)
            root.appendChild(element)
            element.setAttribute('packageName', packageName)

    for appid, app_dict in apps.items():
        app = metadata.App(app_dict)

        if app.get('Disabled') is not None:
            continue

        # Get a list of the apks for this app...
        apklist = []
        name_from_apk = None
        apksbyversion = collections.defaultdict(lambda: [])
        for apk in apks:
            if apk.get('versionCode') and apk.get('packageName') == appid:
                apksbyversion[apk['versionCode']].append(apk)
                if name_from_apk is None:
                    name_from_apk = apk.get('name')
        for versionCode, apksforver in apksbyversion.items():
            fdroid_signer = fdroid_signing_key_fingerprints.get(appid, {}).get('signer')
            fdroid_signed_apk = None
            name_match_apk = None
            for x in apksforver:
                if fdroid_signer and x.get('signer', None) == fdroid_signer:
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

        addElementCheckLocalized('name', app, 'Name', doc, apel, name_from_apk)
        addElementCheckLocalized('summary', app, 'Summary', doc, apel)

        if app.icon:
            addElement('icon', app.icon, doc, apel)

        addElementCheckLocalized('desc', app, 'Description', doc, apel,
                                 'No description available')

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
        addElementNonEmpty('openCollective', app.OpenCollective, doc, apel)

        # These elements actually refer to the current version (i.e. which
        # one is recommended. They are historically mis-named, and need
        # changing, but stay like this for now to support existing clients.
        addElement('marketversion', app.CurrentVersion, doc, apel)
        addElement('marketvercode', str(app.CurrentVersionCode), doc, apel)

        if app.Provides:
            pv = app.Provides.split(',')
            addElementNonEmpty('provides', ','.join(pv), doc, apel)
        if app.RequiresRoot:
            addElement('requirements', 'root', doc, apel)

        # Sort the APK list into version order, just so the web site
        # doesn't have to do any work by default...
        apklist = sorted(apklist, key=lambda apk: apk['versionCode'], reverse=True)

        antiFeatures = list(app.AntiFeatures)
        if 'antiFeatures' in apklist[0]:
            antiFeatures.extend(apklist[0]['antiFeatures'])
        if antiFeatures:
            afout = sorted(set(antiFeatures))
            addElementNonEmpty('antifeatures', ','.join(afout), doc, apel)

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
            if current_version_code < app.CurrentVersionCode:
                current_version_file = apk['apkName']
            if current_version_code < apk['versionCode']:
                current_version_code = apk['versionCode']

            apkel = doc.createElement("package")
            apel.appendChild(apkel)

            versionName = apk.get('versionName')
            if not versionName:
                for build in app.get('Builds', []):
                    if (
                        build['versionCode'] == apk['versionCode']
                        and 'versionName' in build
                    ):
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
                    perm_name = perm[0]
                    if perm_name.startswith("android.permission."):
                        perm_name = perm_name[19:]
                    old_permissions.add(perm_name)
                addElementNonEmpty('permissions', ','.join(sorted(old_permissions)), doc, apkel)

                for permission in sorted_permissions:
                    permel = doc.createElement('uses-permission')
                    if permission[1] is not None:
                        permel.setAttribute('maxSdkVersion', '%d' % permission[1])
                        apkel.appendChild(permel)
                    permel.setAttribute('name', permission[0])
                for permission_sdk_23 in sorted(apk['uses-permission-sdk-23']):
                    permel = doc.createElement('uses-permission-sdk-23')
                    if permission_sdk_23[1] is not None:
                        permel.setAttribute('maxSdkVersion', '%d' % permission_sdk_23[1])
                        apkel.appendChild(permel)
                    permel.setAttribute('name', permission_sdk_23[0])
                if 'nativecode' in apk:
                    addElement('nativecode', ','.join(sorted(apk['nativecode'])), doc, apkel)
                addElementNonEmpty('features', ','.join(sorted(apk['features'])), doc, apkel)

        if current_version_file is not None \
                and common.config['make_current_version_link'] \
                and repodir == 'repo':  # only create these
            namefield = common.config['current_version_name_source']
            name = app.get(namefield)
            if not name and namefield == 'Name':
                name = app.get('localized', {}).get(DEFAULT_LOCALE, {}).get('name')
            if not name:
                name = app.id
            sanitized_name = re.sub(b'''[ '"&%?+=/]''', b'', str(name).encode('utf-8'))
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

    if 'repo_keyalias' in common.config \
       or (common.options.nosign and 'repo_pubkey' in common.config):

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
            _copy_to_local_copy_dir(repodir, os.path.join(repodir, jar_output))
            # Remove old signed index if not signing
            if os.path.exists(signed):
                os.remove(signed)
        else:
            signindex.config = common.config
            signindex.sign_jar(signed, use_old_algs=True)

    # Copy the repo icon into the repo directory...
    icon_dir = os.path.join(repodir, 'icons')
    repo_icon = common.config.get('repo_icon', common.default_config['repo_icon'])
    iconfilename = os.path.join(icon_dir, os.path.basename(repo_icon))
    if os.path.exists(repo_icon):
        shutil.copyfile(common.config['repo_icon'], iconfilename)
    else:
        logging.warning(_('repo_icon "repo/icons/%s" does not exist, generating placeholder.')
                        % repo_icon)
        os.makedirs(os.path.dirname(iconfilename), exist_ok=True)
        try:
            qrcode.make(common.config['repo_url']).save(iconfilename)
        except Exception:
            exampleicon = os.path.join(common.get_examples_dir(),
                                       common.default_config['repo_icon'])
            shutil.copy(exampleicon, iconfilename)


def extract_pubkey():
    """Extract and return the repository's public key from the keystore.

    Returns
    -------
    public key in hex
    repository fingerprint
    """
    if 'repo_pubkey' in common.config:
        pubkey = unhexlify(common.config['repo_pubkey'])
    elif 'keystorepass' in common.config:
        env_vars = {'LC_ALL': 'C.UTF-8',
                    'FDROID_KEY_STORE_PASS': common.config['keystorepass']}
        p = FDroidPopenBytes([common.config['keytool'], '-exportcert',
                              '-alias', common.config['repo_keyalias'],
                              '-keystore', common.config['keystore'],
                              '-storepass:env', 'FDROID_KEY_STORE_PASS']
                             + list(common.config['smartcardoptions']),
                             envs=env_vars, output=False, stderr_to_stdout=False)
        if p.returncode != 0 or len(p.output) < 20:
            msg = "Failed to get repo pubkey!"
            if common.config['keystore'] == 'NONE':
                msg += ' Is your crypto smartcard plugged in?'
            raise FDroidException(msg)
        pubkey = p.output
    else:
        raise FDroidException(_('Neither "repo_pubkey" nor "keystorepass" set in config.yml'))

    repo_pubkey_fingerprint = common.get_cert_fingerprint(pubkey)
    return hexlify(pubkey), repo_pubkey_fingerprint


def add_mirrors_to_repodict(repo_section, repodict):
    """Convert config into final dict of mirror metadata for the repo.

    Internally and in index-v2, mirrors is a list of dicts, but it can
    be specified in the config as a string or list of strings.  Also,
    index v0 and v1 use a list of URL strings as the data structure.

    The first entry is traditionally the primary mirror and canonical
    URL.  'mirrors' should not be present in the index if there is
    only the canonical URL, and no other mirrors.

    The metadata items for each mirror entry are sorted by key to
    ensure minimum diffs in the index files.

    """
    mirrors_config = common.config.get('mirrors', [])
    if type(mirrors_config) not in (list, tuple):
        mirrors_config = [mirrors_config]

    mirrors_yml = Path(f'config/{MIRRORS_CONFIG_NAME}.yml')
    if mirrors_yml.exists():
        if mirrors_config:
            raise FDroidException(
                _('mirrors set twice, in config.yml and {path}!').format(
                    path=mirrors_yml
                )
            )
        with mirrors_yml.open() as fp:
            mirrors_config = ruamel.yaml.YAML(typ='safe').load(fp)
        if not isinstance(mirrors_config, list):
            msg = _('{path} is not list, but a {datatype}!')
            raise TypeError(
                msg.format(path=mirrors_yml, datatype=type(mirrors_config).__name__)
            )

    if type(mirrors_config) not in (list, tuple, set):
        msg = 'In config.yml, mirrors: is not list, but a {datatype}!'
        raise TypeError(msg.format(datatype=type(mirrors_config).__name__))

    mirrorcheckfailed = False
    mirrors = []
    urls = set()
    for mirror in mirrors_config:
        if isinstance(mirror, str):
            mirror = {'url': mirror}
        elif not isinstance(mirror, dict):
            logging.error(
                _('Bad entry type "{mirrortype}" in mirrors config: {mirror}').format(
                    mirrortype=type(mirror), mirror=mirror
                )
            )
            mirrorcheckfailed = True
            continue
        config_url = mirror['url']
        base = os.path.basename(urllib.parse.urlparse(config_url).path.rstrip('/'))
        if common.config.get('nonstandardwebroot') is not True and base != 'fdroid':
            logging.error(_("mirror '%s' does not end with 'fdroid'!") % config_url)
            mirrorcheckfailed = True
        # must end with / or urljoin strips a whole path segment
        if config_url.endswith('/'):
            mirror['url'] = urllib.parse.urljoin(config_url, repo_section)
        else:
            mirror['url'] = urllib.parse.urljoin(config_url + '/', repo_section)
        mirrors.append(mirror)
        if mirror['url'] in urls:
            mirrorcheckfailed = True
            logging.error(
                _('Duplicate entry "%s" in mirrors config!') % mirror['url']
            )
        urls.add(mirror['url'])
    for mirror in common.config.get('servergitmirrors', []):
        for url in get_mirror_service_urls(mirror):
            mirrors.append({'url': url + '/' + repo_section})
    if mirrorcheckfailed:
        raise FDroidException(_("Malformed repository mirrors."))

    if not mirrors:
        return

    repodict['mirrors'] = []
    canonical_url = repodict['address']
    found_primary = False
    for mirror in mirrors:
        if canonical_url == mirror['url']:
            found_primary = True
            mirror['isPrimary'] = True
            sortedmirror = dict()
            for k in sorted(mirror.keys()):
                sortedmirror[k] = mirror[k]
            repodict['mirrors'].insert(0, sortedmirror)
        else:
            repodict['mirrors'].append(mirror)

    if repodict['mirrors'] and not found_primary:
        repodict['mirrors'].insert(0, {'isPrimary': True, 'url': repodict['address']})


def get_mirror_service_urls(mirror):
    """Get direct URLs from git service for use by fdroidclient.

    Via 'servergitmirrors', fdroidserver can create and push a mirror
    to certain well known git services like GitLab or GitHub.  This
    will always use the 'master' branch since that is the default
    branch in git. The files are then accessible via alternate URLs,
    where they are served in their raw format via a CDN rather than
    from git.

    Both of the GitLab URLs will work with F-Droid, but only the
    GitLab Pages will work in the browser This is because the "raw"
    URLs are not served with the correct mime types, so any index.html
    which is put in the repo will not be rendered. Putting an
    index.html file in the repo root is a common way for to make
    information about the repo available to end user.

    """
    url = mirror['url']
    if url.startswith('git@'):
        url = re.sub(r'^git@([^:]+):(.+)', r'https://\1/\2', url)

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
        git_mirror_path = os.path.join('git-mirror', folder)
        if (
            mirror.get('index_only')
            or common.get_dir_size(git_mirror_path) <= common.GITLAB_COM_PAGES_MAX_SIZE
        ):
            # Gitlab-like Pages segments "https://user.gitlab.io/repo/folder"
            gitlab_pages = ["https:", "", user + ".gitlab.io", repo, folder]
            urls.append('/'.join(gitlab_pages))
        else:
            logging.warning(
                _(
                    'Skipping GitLab Pages mirror because the repo is too large (>%.2fGB)!'
                )
                % (common.GITLAB_COM_PAGES_MAX_SIZE / 1000000000)
            )
        # GitLab Raw "https://gitlab.com/user/repo/-/raw/branch/folder"
        gitlab_raw = segments + ['-', 'raw', branch, folder]
        urls.append('/'.join(gitlab_raw))
        # GitLab Artifacts "https://user.gitlab.io/-/repo/-/jobs/job_id/artifacts/public/folder"
        job_id = os.getenv('CI_JOB_ID')
        try:
            int(job_id)
            gitlab_artifacts = [
                "https:",
                "",
                user + ".gitlab.io",
                '-',
                repo,
                '-',
                'jobs',
                job_id,
                'artifacts',
                'public',
                folder,
            ]
            urls.append('/'.join(gitlab_artifacts))
        except (TypeError, ValueError):
            pass  # no Job ID to use, ignore

    return urls


def download_repo_index(url_str, etag=None, verify_fingerprint=True, timeout=600):
    """Download and verifies index v1 file, then returns its data.

    Use the versioned functions to be sure you are getting the
    expected data format.

    """
    return download_repo_index_v1(url_str, etag, verify_fingerprint, timeout)


def download_repo_index_v1(url_str, etag=None, verify_fingerprint=True, timeout=600):
    """Download and verifies index v1 file, then returns its data.

    Downloads the repository index from the given :param url_str and
    verifies the repository's fingerprint if :param verify_fingerprint
    is not False.

    Raises
    ------
    VerificationException() if the repository could not be verified

    Returns
    -------
    A tuple consisting of:
        - The index in JSON v1 format or None if the index did not change
        - The new eTag as returned by the HTTP request

    """
    url = urllib.parse.urlsplit(url_str)

    fingerprint = None
    if verify_fingerprint:
        query = urllib.parse.parse_qs(url.query)
        if 'fingerprint' not in query:
            raise VerificationException(_("No fingerprint in URL."))
        fingerprint = query['fingerprint'][0]

    if url.path.endswith('/index-v1.jar'):
        path = url.path[:-13].rstrip('/')
    else:
        path = url.path.rstrip('/')

    url = urllib.parse.SplitResult(url.scheme, url.netloc, path + '/index-v1.jar', '', '')
    download, new_etag = net.http_get(url.geturl(), etag, timeout)

    if download is None:
        return None, new_etag

    with tempfile.NamedTemporaryFile() as fp:
        fp.write(download)
        fp.flush()
        index, public_key, public_key_fingerprint = get_index_from_jar(
            fp.name, fingerprint, allow_deprecated=True
        )
        index["repo"]["pubkey"] = hexlify(public_key).decode()
        index["repo"]["fingerprint"] = public_key_fingerprint
        index["apps"] = [metadata.App(app) for app in index["apps"]]
        return index, new_etag


def download_repo_index_v2(url_str, etag=None, verify_fingerprint=True, timeout=None):
    """Download and verifies index v2 file, then returns its data.

    Downloads the repository index from the given :param url_str and
    verifies the repository's fingerprint if :param verify_fingerprint
    is not False.  In order to verify the data, the fingerprint must
    be provided as part of the URL.

    Raises
    ------
    VerificationException() if the repository could not be verified

    Returns
    -------
    A tuple consisting of:
        - The index in JSON v2 format or None if the index did not change
        - The new eTag as returned by the HTTP request

    """
    etag  # etag is unused but needs to be there to keep the same API as the earlier functions.

    url = urllib.parse.urlsplit(url_str)

    if timeout is not None:
        logging.warning('"timeout" argument of download_repo_index_v2() is deprecated!')

    fingerprint = None
    if verify_fingerprint:
        query = urllib.parse.parse_qs(url.query)
        if 'fingerprint' not in query:
            raise VerificationException(_("No fingerprint in URL."))
        fingerprint = query['fingerprint'][0]

    if url.path.endswith('/entry.jar') or url.path.endswith('/index-v2.json'):
        path = url.path.rsplit('/', 1)[0]
    else:
        path = url.path.rstrip('/')
    url = urllib.parse.SplitResult(url.scheme, url.netloc, path, '', '')

    mirrors = common.get_mirrors(url, 'entry.jar')
    f = net.download_using_mirrors(mirrors)
    entry, public_key, fingerprint = get_index_from_jar(f, fingerprint)

    sha256 = entry['index']['sha256']
    mirrors = common.get_mirrors(url, entry['index']['name'][1:])
    f = net.download_using_mirrors(mirrors)
    with open(f, 'rb') as fp:
        index = fp.read()
    if sha256 != hashlib.sha256(index).hexdigest():
        raise VerificationException(
            _("SHA-256 of {url} does not match entry!").format(url=url)
        )
    return json.loads(index), None


def get_index_from_jar(jarfile, fingerprint=None, allow_deprecated=False):
    """Return the data, public key and fingerprint from an index JAR with one JSON file.

    The F-Droid index files always contain a single data file and a
    JAR Signature.  Since index-v1, the data file is always JSON.
    That single data file is named the same as the JAR file.

    Parameters
    ----------
    fingerprint is the SHA-256 fingerprint of signing key. Only
      hex digits count, all other chars will can be discarded.

    Raises
    ------
    VerificationException() if the repository could not be verified

    """
    logging.debug(_('Verifying index signature:'))

    if allow_deprecated:
        common.verify_deprecated_jar_signature(jarfile)
    else:
        common.verify_jar_signature(jarfile)

    with zipfile.ZipFile(jarfile) as jar:
        public_key, public_key_fingerprint = get_public_key_from_jar(jar)
        if fingerprint is not None:
            fingerprint = re.sub(r'[^0-9A-F]', r'', fingerprint.upper())
            if fingerprint != public_key_fingerprint:
                raise VerificationException(
                    _("The repository's fingerprint does not match.")
                )
        for f in jar.namelist():
            if not f.startswith('META-INF/'):
                jsonfile = f
                break
        data = json.loads(jar.read(jsonfile))
        return data, public_key, public_key_fingerprint


def get_public_key_from_jar(jar):
    """Get the public key and its fingerprint from a JAR file.

    Raises
    ------
    VerificationException() if the JAR was not signed exactly once

    Parameters
    ----------
    jar
      a zipfile.ZipFile object

    Returns
    -------
    the public key from the jar and its fingerprint
    """
    # extract certificate from jar
    certs = [n for n in jar.namelist() if common.SIGNATURE_BLOCK_FILE_REGEX.match(n)]
    if len(certs) < 1:
        raise VerificationException(_("Found no signing certificates for repository."))
    if len(certs) > 1:
        raise VerificationException(_("Found multiple signing certificates for repository."))

    # extract public key from certificate
    public_key = common.get_certificate(jar.read(certs[0]))
    public_key_fingerprint = common.get_cert_fingerprint(public_key).replace(' ', '')

    return public_key, public_key_fingerprint


def make_altstore(apps, apks, config, repodir, pretty=False):
    """Assemble altstore-index.json for iOS (.ipa) apps.

    builds index files based on:
    https://faq.altstore.io/distribute-your-apps/make-a-source
    https://faq.altstore.io/distribute-your-apps/updating-apps
    """
    if not any(Path(repodir).glob('*.ipa')):
        # no IPA files present in repo, nothing to do here, exiting early
        return

    indent = 2 if pretty else None
    # for now alt-store support is english only
    for lang in ['en']:

        # prepare minimal altstore index
        idx = {
            'name': config['repo_name'],
            "apps": [],
            "news": [],
        }

        # add optional values if available
        # idx["subtitle"] F-Droid doesn't have a corresponding value
        if config.get("repo_description"):
            idx['description'] = config['repo_description']
        if (Path(repodir) / 'icons' / config['repo_icon']).exists():
            idx['iconURL'] = f"{config['repo_url']}/icons/{config['repo_icon']}"
        # idx["headerURL"] F-Droid doesn't have a corresponding value
        # idx["website"] F-Droid doesn't have a corresponding value
        # idx["patreonURL"] F-Droid doesn't have a corresponding value
        # idx["tintColor"] F-Droid doesn't have a corresponding value
        # idx["featuredApps"] = [] maybe mappable to F-Droids what's new?

        # assemble "apps"
        for packageName, app in apps.items():
            app_name = app.get("Name") or app.get("AutoName")
            icon_url = "{}{}".format(
                config['repo_url'],
                app.get('iconv2', {}).get(DEFAULT_LOCALE, {}).get('name', ''),
            )
            screenshot_urls = [
                "{}{}".format(config["repo_url"], s["name"])
                for s in app.get("screenshots", {})
                .get("phone", {})
                .get(DEFAULT_LOCALE, {})
            ]

            a = {
                "name": app_name,
                'bundleIdentifier': packageName,
                'developerName': app.get("AuthorName") or f"{app_name} team",
                'iconURL': icon_url,
                "localizedDescription": "",
                'appPermissions': {
                    "entitlements": set(),
                    "privacy": {},
                },
                'versions': [],
            }

            if app.get('summary'):
                a['subtitle'] = app['summary']
            # a["tintColor"] F-Droid doesn't have a corresponding value
            # a["category"] F-Droid doesn't have a corresponding value
            # a['patreon'] F-Droid doesn't have a corresponding value
            a["screenshots"] = screenshot_urls

            # populate 'versions'
            for apk in apks:
                last4 = apk.get('apkName', '').lower()[-4:]
                if apk['packageName'] == packageName and last4 == '.ipa':
                    v = {
                        "version": apk["versionName"],
                        "date": apk["added"].isoformat(),
                        "downloadURL": f"{config['repo_url']}/{apk['apkName']}",
                        "size": apk['size'],
                    }

                    # v['localizedDescription'] maybe what's new text?
                    v["minOSVersion"] = apk["ipa_MinimumOSVersion"]
                    v["maxOSVersion"] = apk["ipa_DTPlatformVersion"]

                    # writing this spot here has the effect that always the
                    # permissions of the latest processed permissions list used
                    a['appPermissions']['privacy'] = apk['ipa_permissions']
                    a['appPermissions']['entitlements'] = list(apk['ipa_entitlements'])

                    a['versions'].append(v)

            if len(a['versions']) > 0:
                idx['apps'].append(a)

        with open(Path(repodir) / 'altstore-index.json', "w", encoding="utf-8") as f:
            json.dump(idx, f, indent=indent)
