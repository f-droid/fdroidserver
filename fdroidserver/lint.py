#!/usr/bin/env python3
#
# lint.py - part of the FDroid server tool
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See th
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public Licen
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from argparse import ArgumentParser
import glob
import os
import re
import sys
import urllib.parse

from . import _
from . import common
from . import metadata
from . import rewritemeta

config = None
options = None


def enforce_https(domain):
    return (re.compile(r'^[^h][^t][^t][^p][^s]://[^/]*' + re.escape(domain) + r'(/.*)?', re.IGNORECASE),
            domain + " URLs should always use https://")


https_enforcings = [
    enforce_https('github.com'),
    enforce_https('gitlab.com'),
    enforce_https('bitbucket.org'),
    enforce_https('apache.org'),
    enforce_https('google.com'),
    enforce_https('git.code.sf.net'),
    enforce_https('svn.code.sf.net'),
    enforce_https('anongit.kde.org'),
    enforce_https('savannah.nongnu.org'),
    enforce_https('git.savannah.nongnu.org'),
    enforce_https('download.savannah.nongnu.org'),
    enforce_https('savannah.gnu.org'),
    enforce_https('git.savannah.gnu.org'),
    enforce_https('download.savannah.gnu.org'),
    enforce_https('github.io'),
    enforce_https('gitlab.io'),
    enforce_https('githubusercontent.com'),
]


def forbid_shortener(domain):
    return (re.compile(r'https?://[^/]*' + re.escape(domain) + r'/.*'),
            _("URL shorteners should not be used"))


http_url_shorteners = [
    forbid_shortener('1url.com'),
    forbid_shortener('adf.ly'),
    forbid_shortener('bc.vc'),
    forbid_shortener('bit.do'),
    forbid_shortener('bit.ly'),
    forbid_shortener('bitly.com'),
    forbid_shortener('budurl.com'),
    forbid_shortener('buzurl.com'),
    forbid_shortener('cli.gs'),
    forbid_shortener('cur.lv'),
    forbid_shortener('cutt.us'),
    forbid_shortener('db.tt'),
    forbid_shortener('filoops.info'),
    forbid_shortener('goo.gl'),
    forbid_shortener('is.gd'),
    forbid_shortener('ity.im'),
    forbid_shortener('j.mp'),
    forbid_shortener('l.gg'),
    forbid_shortener('lnkd.in'),
    forbid_shortener('moourl.com'),
    forbid_shortener('ow.ly'),
    forbid_shortener('para.pt'),
    forbid_shortener('po.st'),
    forbid_shortener('q.gs'),
    forbid_shortener('qr.ae'),
    forbid_shortener('qr.net'),
    forbid_shortener('rdlnk.com'),
    forbid_shortener('scrnch.me'),
    forbid_shortener('short.nr'),
    forbid_shortener('sn.im'),
    forbid_shortener('snipurl.com'),
    forbid_shortener('su.pr'),
    forbid_shortener('t.co'),
    forbid_shortener('tiny.cc'),
    forbid_shortener('tinyarrows.com'),
    forbid_shortener('tinyurl.com'),
    forbid_shortener('tr.im'),
    forbid_shortener('tweez.me'),
    forbid_shortener('twitthis.com'),
    forbid_shortener('twurl.nl'),
    forbid_shortener('tyn.ee'),
    forbid_shortener('u.bb'),
    forbid_shortener('u.to'),
    forbid_shortener('ur1.ca'),
    forbid_shortener('urlof.site'),
    forbid_shortener('v.gd'),
    forbid_shortener('vzturl.com'),
    forbid_shortener('x.co'),
    forbid_shortener('xrl.us'),
    forbid_shortener('yourls.org'),
    forbid_shortener('zip.net'),
    forbid_shortener('✩.ws'),
    forbid_shortener('➡.ws'),
]

http_checks = https_enforcings + http_url_shorteners + [
    (re.compile(r'.*github\.com/[^/]+/[^/]+\.git'),
     _("Appending .git is not necessary")),
    (re.compile(r'.*://[^/]*(github|gitlab|bitbucket|rawgit)[^/]*/([^/]+/){1,3}master'),
     _("Use /HEAD instead of /master to point at a file in the default branch")),
]

regex_checks = {
    'WebSite': http_checks,
    'SourceCode': http_checks,
    'Repo': https_enforcings,
    'UpdateCheckMode': https_enforcings,
    'IssueTracker': http_checks + [
        (re.compile(r'.*github\.com/[^/]+/[^/]+/*$'),
         _("/issues is missing")),
        (re.compile(r'.*gitlab\.com/[^/]+/[^/]+/*$'),
         _("/issues is missing")),
    ],
    'Donate': http_checks + [
        (re.compile(r'.*flattr\.com'),
         _("Flattr donation methods belong in the FlattrID flag")),
        (re.compile(r'.*liberapay\.com'),
         _("Liberapay donation methods belong in the LiberapayID flag")),
    ],
    'Changelog': http_checks,
    'Author Name': [
        (re.compile(r'^\s'),
         _("Unnecessary leading space")),
        (re.compile(r'.*\s$'),
         _("Unnecessary trailing space")),
    ],
    'Summary': [
        (re.compile(r'.*\b(free software|open source)\b.*', re.IGNORECASE),
         _("No need to specify that the app is Free Software")),
        (re.compile(r'.*((your|for).*android|android.*(app|device|client|port|version))', re.IGNORECASE),
         _("No need to specify that the app is for Android")),
        (re.compile(r'.*[a-z0-9][.!?]( |$)'),
         _("Punctuation should be avoided")),
        (re.compile(r'^\s'),
         _("Unnecessary leading space")),
        (re.compile(r'.*\s$'),
         _("Unnecessary trailing space")),
    ],
    'Description': https_enforcings + http_url_shorteners + [
        (re.compile(r'\s*[*#][^ .]'),
         _("Invalid bulleted list")),
        (re.compile(r'^\s'),
         _("Unnecessary leading space")),
        (re.compile(r'.*\s$'),
         _("Unnecessary trailing space")),
        (re.compile(r'.*<(applet|base|body|button|embed|form|head|html|iframe|img|input|link|object|picture|script|source|style|svg|video).*', re.IGNORECASE),
         _("Forbidden HTML tags")),
        (re.compile(r'''.*\s+src=["']javascript:.*'''),
         _("Javascript in HTML src attributes")),
    ],
}

locale_pattern = re.compile(r'^[a-z]{2,3}(-[A-Z][A-Z])?$')


def check_regexes(app):
    for f, checks in regex_checks.items():
        for m, r in checks:
            v = app.get(f)
            t = metadata.fieldtype(f)
            if t == metadata.TYPE_MULTILINE:
                for l in v.splitlines():
                    if m.match(l):
                        yield "%s at line '%s': %s" % (f, l, r)
            else:
                if v is None:
                    continue
                if m.match(v):
                    yield "%s '%s': %s" % (f, v, r)


def get_lastbuild(builds):
    lowest_vercode = -1
    lastbuild = None
    for build in builds:
        if not build.disable:
            vercode = int(build.versionCode)
            if lowest_vercode == -1 or vercode < lowest_vercode:
                lowest_vercode = vercode
        if not lastbuild or int(build.versionCode) > int(lastbuild.versionCode):
            lastbuild = build
    return lastbuild


def check_update_check_data_url(app):
    """UpdateCheckData must have a valid HTTPS URL to protect checkupdates runs
    """
    if app.UpdateCheckData:
        urlcode, codeex, urlver, verex = app.UpdateCheckData.split('|')
        for url in (urlcode, urlver):
            if url != '.':
                parsed = urllib.parse.urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    yield _('UpdateCheckData not a valid URL: {url}').format(url=url)
                if parsed.scheme != 'https':
                    yield _('UpdateCheckData must use HTTPS URL: {url}').format(url=url)


def check_vercode_operation(app):
    if app.VercodeOperation and not common.VERCODE_OPERATION_RE.match(app.VercodeOperation):
        yield _('Invalid VercodeOperation: {field}').format(field=app.VercodeOperation)


def check_ucm_tags(app):
    lastbuild = get_lastbuild(app.builds)
    if (lastbuild is not None
            and lastbuild.commit
            and app.UpdateCheckMode == 'RepoManifest'
            and not lastbuild.commit.startswith('unknown')
            and lastbuild.versionCode == app.CurrentVersionCode
            and not lastbuild.forcevercode
            and any(s in lastbuild.commit for s in '.,_-/')):
        yield _("Last used commit '{commit}' looks like a tag, but Update Check Mode is '{ucm}'")\
            .format(commit=lastbuild.commit, ucm=app.UpdateCheckMode)


def check_char_limits(app):
    limits = config['char_limits']

    if len(app.Summary) > limits['summary']:
        yield _("Summary of length {length} is over the {limit} char limit")\
            .format(length=len(app.Summary), limit=limits['summary'])

    if len(app.Description) > limits['description']:
        yield _("Description of length {length} is over the {limit} char limit")\
            .format(length=len(app.Description), limit=limits['description'])


def check_old_links(app):
    usual_sites = [
        'github.com',
        'gitlab.com',
        'bitbucket.org',
    ]
    old_sites = [
        'gitorious.org',
        'code.google.com',
    ]
    if any(s in app.Repo for s in usual_sites):
        for f in ['WebSite', 'SourceCode', 'IssueTracker', 'Changelog']:
            v = app.get(f)
            if any(s in v for s in old_sites):
                yield _("App is in '{repo}' but has a link to {url}")\
                    .format(repo=app.Repo, url=v)


def check_useless_fields(app):
    if app.UpdateCheckName == app.id:
        yield _("Update Check Name is set to the known app id - it can be removed")


filling_ucms = re.compile(r'^(Tags.*|RepoManifest.*)')


def check_checkupdates_ran(app):
    if filling_ucms.match(app.UpdateCheckMode):
        if not app.AutoName and not app.CurrentVersion and app.CurrentVersionCode == '0':
            yield _("UCM is set but it looks like checkupdates hasn't been run yet")


def check_empty_fields(app):
    if not app.Categories:
        yield _("Categories are not set")


all_categories = set([
    "Connectivity",
    "Development",
    "Games",
    "Graphics",
    "Internet",
    "Money",
    "Multimedia",
    "Navigation",
    "Phone & SMS",
    "Reading",
    "Science & Education",
    "Security",
    "Sports & Health",
    "System",
    "Theming",
    "Time",
    "Writing",
])


def check_categories(app):
    for categ in app.Categories:
        if categ not in all_categories:
            yield _("Category '%s' is not valid" % categ)


def check_duplicates(app):
    if app.Name and app.Name == app.AutoName:
        yield _("Name '%s' is just the auto name - remove it") % app.Name

    links_seen = set()
    for f in ['Source Code', 'Web Site', 'Issue Tracker', 'Changelog']:
        v = app.get(f)
        if not v:
            continue
        v = v.lower()
        if v in links_seen:
            yield _("Duplicate link in '{field}': {url}").format(field=f, url=v)
        else:
            links_seen.add(v)

    name = app.Name or app.AutoName
    if app.Summary and name:
        if app.Summary.lower() == name.lower():
            yield _("Summary '%s' is just the app's name") % app.Summary

    if app.Summary and app.Description and len(app.Description) == 1:
        if app.Summary.lower() == app.Description[0].lower():
            yield _("Description '%s' is just the app's summary") % app.Summary

    seenlines = set()
    for l in app.Description.splitlines():
        if len(l) < 1:
            continue
        if l in seenlines:
            yield _("Description has a duplicate line")
        seenlines.add(l)


desc_url = re.compile(r'(^|[^[])\[([^ ]+)( |\]|$)')


def check_mediawiki_links(app):
    wholedesc = ' '.join(app.Description)
    for um in desc_url.finditer(wholedesc):
        url = um.group(1)
        for m, r in http_checks:
            if m.match(url):
                yield _("URL {url} in Description: {error}").format(url=url, error=r)


def check_bulleted_lists(app):
    validchars = ['*', '#']
    lchar = ''
    lcount = 0
    for l in app.Description.splitlines():
        if len(l) < 1:
            lcount = 0
            continue

        if l[0] == lchar and l[1] == ' ':
            lcount += 1
            if lcount > 2 and lchar not in validchars:
                yield _("Description has a list (%s) but it isn't bulleted (*) nor numbered (#)") % lchar
                break
        else:
            lchar = l[0]
            lcount = 1


def check_builds(app):
    supported_flags = set(metadata.build_flags)
    # needed for YAML and JSON
    for build in app.builds:
        if build.disable:
            if build.disable.startswith('Generated by import.py'):
                yield _("Build generated by `fdroid import` - remove disable line once ready")
            continue
        for s in ['master', 'origin', 'HEAD', 'default', 'trunk']:
            if build.commit and build.commit.startswith(s):
                yield _("Branch '{branch}' used as commit in build '{versionName}'")\
                    .format(branch=s, versionName=build.versionName)
            for srclib in build.srclibs:
                if '@' in srclib:
                    ref = srclib.split('@')[1].split('/')[0]
                    if ref.startswith(s):
                        yield _("Branch '{branch}' used as commit in srclib '{srclib}'")\
                            .format(branch=s, srclib=srclib)
                else:
                    yield _('srclibs missing name and/or @') + ' (srclibs: ' + srclib + ')'
        for key in build.keys():
            if key not in supported_flags:
                yield _('%s is not an accepted build field') % key


def check_files_dir(app):
    dir_path = os.path.join('metadata', app.id)
    if not os.path.isdir(dir_path):
        return
    files = set()
    for name in os.listdir(dir_path):
        path = os.path.join(dir_path, name)
        if not (os.path.isfile(path) or name == 'signatures' or locale_pattern.match(name)):
            yield _("Found non-file at %s") % path
            continue
        files.add(name)

    used = {'signatures', }
    for build in app.builds:
        for fname in build.patch:
            if fname not in files:
                yield _("Unknown file '{filename}' in build '{versionName}'")\
                    .format(filename=fname, versionName=build.versionName)
            else:
                used.add(fname)

    for name in files.difference(used):
        if locale_pattern.match(name):
            continue
        yield _("Unused file at %s") % os.path.join(dir_path, name)


def check_format(app):
    if options.format and not rewritemeta.proper_format(app):
        yield _("Run rewritemeta to fix formatting")


def check_license_tag(app):
    '''Ensure all license tags are in https://spdx.org/license-list'''
    if app.License.rstrip('+') not in SPDX:
        yield _('Invalid license tag "%s"! Use only tags from https://spdx.org/license-list') \
            % (app.License)


def check_extlib_dir(apps):
    dir_path = os.path.join('build', 'extlib')
    unused_extlib_files = set()
    for root, dirs, files in os.walk(dir_path):
        for name in files:
            unused_extlib_files.add(os.path.join(root, name)[len(dir_path) + 1:])

    used = set()
    for app in apps:
        for build in app.builds:
            for path in build.extlibs:
                if path not in unused_extlib_files:
                    yield _("{appid}: Unknown extlib {path} in build '{versionName}'")\
                        .format(appid=app.id, path=path, versionName=build.versionName)
                else:
                    used.add(path)

    for path in unused_extlib_files.difference(used):
        if any(path.endswith(s) for s in [
                '.gitignore',
                'source.txt', 'origin.txt', 'md5.txt',
                'LICENSE', 'LICENSE.txt',
                'COPYING', 'COPYING.txt',
                'NOTICE', 'NOTICE.txt',
                ]):
            continue
        yield _("Unused extlib at %s") % os.path.join(dir_path, path)


def check_for_unsupported_metadata_files(basedir=""):
    """Checks whether any non-metadata files are in metadata/"""

    global config

    return_value = False
    formats = config['accepted_formats']
    for f in glob.glob(basedir + 'metadata/*') + glob.glob(basedir + 'metadata/.*'):
        if os.path.isdir(f):
            exists = False
            for t in formats:
                exists = exists or os.path.exists(f + '.' + t)
            if not exists:
                print(_('"%s/" has no matching metadata file!') % f)
                return_value = True
        elif not os.path.splitext(f)[1][1:] in formats:
            print('"' + f.replace(basedir, '')
                  + '" is not a supported file format: (' + ','.join(formats) + ')')
            return_value = True

    return return_value


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser(usage="%(prog)s [options] [APPID [APPID ...]]")
    common.setup_global_opts(parser)
    parser.add_argument("-f", "--format", action="store_true", default=False,
                        help=_("Also warn about formatting issues, like rewritemeta -l"))
    parser.add_argument("appid", nargs='*', help=_("applicationId in the form APPID"))
    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    metadata.warnings_action = options.W

    config = common.read_config(options)

    # Get all apps...
    allapps = metadata.read_metadata(xref=True)
    apps = common.read_app_args(options.appid, allapps, False)

    anywarns = check_for_unsupported_metadata_files()

    apps_check_funcs = []
    if len(options.appid) == 0:
        # otherwise it finds tons of unused extlibs
        apps_check_funcs.append(check_extlib_dir)
    for check_func in apps_check_funcs:
        for warn in check_func(apps.values()):
            anywarns = True
            print(warn)

    for appid, app in apps.items():
        if app.Disabled:
            continue

        app_check_funcs = [
            check_regexes,
            check_update_check_data_url,
            check_vercode_operation,
            check_ucm_tags,
            check_char_limits,
            check_old_links,
            check_checkupdates_ran,
            check_useless_fields,
            check_empty_fields,
            check_categories,
            check_duplicates,
            check_mediawiki_links,
            check_bulleted_lists,
            check_builds,
            check_files_dir,
            check_format,
            check_license_tag,
        ]

        for check_func in app_check_funcs:
            for warn in check_func(app):
                anywarns = True
                print("%s: %s" % (appid, warn))

    if anywarns:
        sys.exit(1)


# A compiled, public domain list of official SPDX license tags from:
# https://github.com/sindresorhus/spdx-license-list/blob/v4.0.0/spdx-simple.json
# The deprecated license tags have been removed from the list, they are at the
# bottom, starting after the last license tags that start with Z.
# This is at the bottom, since its a long list of data
SPDX = [
    "PublicDomain",  # an F-Droid addition, until we can enforce a better option
    "0BSD",
    "AAL",
    "Abstyles",
    "Adobe-2006",
    "Adobe-Glyph",
    "ADSL",
    "AFL-1.1",
    "AFL-1.2",
    "AFL-2.0",
    "AFL-2.1",
    "AFL-3.0",
    "Afmparse",
    "AGPL-1.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "Aladdin",
    "AMDPLPA",
    "AML",
    "AMPAS",
    "ANTLR-PD",
    "Apache-1.0",
    "Apache-1.1",
    "Apache-2.0",
    "APAFML",
    "APL-1.0",
    "APSL-1.0",
    "APSL-1.1",
    "APSL-1.2",
    "APSL-2.0",
    "Artistic-1.0-cl8",
    "Artistic-1.0-Perl",
    "Artistic-1.0",
    "Artistic-2.0",
    "Bahyph",
    "Barr",
    "Beerware",
    "BitTorrent-1.0",
    "BitTorrent-1.1",
    "Borceux",
    "BSD-1-Clause",
    "BSD-2-Clause-FreeBSD",
    "BSD-2-Clause-NetBSD",
    "BSD-2-Clause-Patent",
    "BSD-2-Clause",
    "BSD-3-Clause-Attribution",
    "BSD-3-Clause-Clear",
    "BSD-3-Clause-LBNL",
    "BSD-3-Clause-No-Nuclear-License-2014",
    "BSD-3-Clause-No-Nuclear-License",
    "BSD-3-Clause-No-Nuclear-Warranty",
    "BSD-3-Clause",
    "BSD-4-Clause-UC",
    "BSD-4-Clause",
    "BSD-Protection",
    "BSD-Source-Code",
    "BSL-1.0",
    "bzip2-1.0.5",
    "bzip2-1.0.6",
    "Caldera",
    "CATOSL-1.1",
    "CC-BY-1.0",
    "CC-BY-2.0",
    "CC-BY-2.5",
    "CC-BY-3.0",
    "CC-BY-4.0",
    "CC-BY-NC-1.0",
    "CC-BY-NC-2.0",
    "CC-BY-NC-2.5",
    "CC-BY-NC-3.0",
    "CC-BY-NC-4.0",
    "CC-BY-NC-ND-1.0",
    "CC-BY-NC-ND-2.0",
    "CC-BY-NC-ND-2.5",
    "CC-BY-NC-ND-3.0",
    "CC-BY-NC-ND-4.0",
    "CC-BY-NC-SA-1.0",
    "CC-BY-NC-SA-2.0",
    "CC-BY-NC-SA-2.5",
    "CC-BY-NC-SA-3.0",
    "CC-BY-NC-SA-4.0",
    "CC-BY-ND-1.0",
    "CC-BY-ND-2.0",
    "CC-BY-ND-2.5",
    "CC-BY-ND-3.0",
    "CC-BY-ND-4.0",
    "CC-BY-SA-1.0",
    "CC-BY-SA-2.0",
    "CC-BY-SA-2.5",
    "CC-BY-SA-3.0",
    "CC-BY-SA-4.0",
    "CC0-1.0",
    "CDDL-1.0",
    "CDDL-1.1",
    "CDLA-Permissive-1.0",
    "CDLA-Sharing-1.0",
    "CECILL-1.0",
    "CECILL-1.1",
    "CECILL-2.0",
    "CECILL-2.1",
    "CECILL-B",
    "CECILL-C",
    "ClArtistic",
    "CNRI-Jython",
    "CNRI-Python-GPL-Compatible",
    "CNRI-Python",
    "Condor-1.1",
    "CPAL-1.0",
    "CPL-1.0",
    "CPOL-1.02",
    "Crossword",
    "CrystalStacker",
    "CUA-OPL-1.0",
    "Cube",
    "curl",
    "D-FSL-1.0",
    "diffmark",
    "DOC",
    "Dotseqn",
    "DSDP",
    "dvipdfm",
    "ECL-1.0",
    "ECL-2.0",
    "EFL-1.0",
    "EFL-2.0",
    "eGenix",
    "Entessa",
    "EPL-1.0",
    "EPL-2.0",
    "ErlPL-1.1",
    "EUDatagrid",
    "EUPL-1.0",
    "EUPL-1.1",
    "EUPL-1.2",
    "Eurosym",
    "Fair",
    "Frameworx-1.0",
    "FreeImage",
    "FSFAP",
    "FSFUL",
    "FSFULLR",
    "FTL",
    "GFDL-1.1-only",
    "GFDL-1.1-or-later",
    "GFDL-1.2-only",
    "GFDL-1.2-or-later",
    "GFDL-1.3-only",
    "GFDL-1.3-or-later",
    "Giftware",
    "GL2PS",
    "Glide",
    "Glulxe",
    "gnuplot",
    "GPL-1.0-only",
    "GPL-1.0-or-later",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "gSOAP-1.3b",
    "HaskellReport",
    "HPND",
    "IBM-pibs",
    "ICU",
    "IJG",
    "ImageMagick",
    "iMatix",
    "Imlib2",
    "Info-ZIP",
    "Intel-ACPI",
    "Intel",
    "Interbase-1.0",
    "IPA",
    "IPL-1.0",
    "ISC",
    "JasPer-2.0",
    "JSON",
    "LAL-1.2",
    "LAL-1.3",
    "Latex2e",
    "Leptonica",
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "LGPLLR",
    "Libpng",
    "libtiff",
    "LiLiQ-P-1.1",
    "LiLiQ-R-1.1",
    "LiLiQ-Rplus-1.1",
    "LPL-1.0",
    "LPL-1.02",
    "LPPL-1.0",
    "LPPL-1.1",
    "LPPL-1.2",
    "LPPL-1.3a",
    "LPPL-1.3c",
    "MakeIndex",
    "MirOS",
    "MIT-advertising",
    "MIT-CMU",
    "MIT-enna",
    "MIT-feh",
    "MIT",
    "MITNFA",
    "Motosoto",
    "mpich2",
    "MPL-1.0",
    "MPL-1.1",
    "MPL-2.0-no-copyleft-exception",
    "MPL-2.0",
    "MS-PL",
    "MS-RL",
    "MTLL",
    "Multics",
    "Mup",
    "NASA-1.3",
    "Naumen",
    "NBPL-1.0",
    "NCSA",
    "Net-SNMP",
    "NetCDF",
    "Newsletr",
    "NGPL",
    "NLOD-1.0",
    "NLPL",
    "Nokia",
    "NOSL",
    "Noweb",
    "NPL-1.0",
    "NPL-1.1",
    "NPOSL-3.0",
    "NRL",
    "NTP",
    "OCCT-PL",
    "OCLC-2.0",
    "ODbL-1.0",
    "OFL-1.0",
    "OFL-1.1",
    "OGTSL",
    "OLDAP-1.1",
    "OLDAP-1.2",
    "OLDAP-1.3",
    "OLDAP-1.4",
    "OLDAP-2.0.1",
    "OLDAP-2.0",
    "OLDAP-2.1",
    "OLDAP-2.2.1",
    "OLDAP-2.2.2",
    "OLDAP-2.2",
    "OLDAP-2.3",
    "OLDAP-2.4",
    "OLDAP-2.5",
    "OLDAP-2.6",
    "OLDAP-2.7",
    "OLDAP-2.8",
    "OML",
    "OpenSSL",
    "OPL-1.0",
    "OSET-PL-2.1",
    "OSL-1.0",
    "OSL-1.1",
    "OSL-2.0",
    "OSL-2.1",
    "OSL-3.0",
    "PDDL-1.0",
    "PHP-3.0",
    "PHP-3.01",
    "Plexus",
    "PostgreSQL",
    "psfrag",
    "psutils",
    "Python-2.0",
    "Qhull",
    "QPL-1.0",
    "Rdisc",
    "RHeCos-1.1",
    "RPL-1.1",
    "RPL-1.5",
    "RPSL-1.0",
    "RSA-MD",
    "RSCPL",
    "Ruby",
    "SAX-PD",
    "Saxpath",
    "SCEA",
    "Sendmail",
    "SGI-B-1.0",
    "SGI-B-1.1",
    "SGI-B-2.0",
    "SimPL-2.0",
    "SISSL-1.2",
    "SISSL",
    "Sleepycat",
    "SMLNJ",
    "SMPPL",
    "SNIA",
    "Spencer-86",
    "Spencer-94",
    "Spencer-99",
    "SPL-1.0",
    "SugarCRM-1.1.3",
    "SWL",
    "TCL",
    "TCP-wrappers",
    "TMate",
    "TORQUE-1.1",
    "TOSL",
    "Unicode-DFS-2015",
    "Unicode-DFS-2016",
    "Unicode-TOU",
    "Unlicense",
    "UPL-1.0",
    "Vim",
    "VOSTROM",
    "VSL-1.0",
    "W3C-19980720",
    "W3C-20150513",
    "W3C",
    "Watcom-1.0",
    "Wsuipa",
    "WTFPL",
    "X11",
    "Xerox",
    "XFree86-1.1",
    "xinetd",
    "Xnet",
    "xpp",
    "XSkat",
    "YPL-1.0",
    "YPL-1.1",
    "Zed",
    "Zend-2.0",
    "Zimbra-1.3",
    "Zimbra-1.4",
    "zlib-acknowledgement",
    "Zlib",
    "ZPL-1.1",
    "ZPL-2.0",
    "ZPL-2.1",
]

if __name__ == "__main__":
    main()
