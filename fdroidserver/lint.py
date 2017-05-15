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
import os
import re
import sys

from . import common
from . import metadata
from . import rewritemeta

config = None
options = None


def enforce_https(domain):
    return (re.compile(r'.*[^sS]://[^/]*' + re.escape(domain) + r'(/.*)?'),
            domain + " URLs should always use https://")


https_enforcings = [
    enforce_https('github.com'),
    enforce_https('gitlab.com'),
    enforce_https('bitbucket.org'),
    enforce_https('apache.org'),
    enforce_https('google.com'),
    enforce_https('svn.code.sf.net'),
]


def forbid_shortener(domain):
    return (re.compile(r'https?://[^/]*' + re.escape(domain) + r'/.*'),
            "URL shorteners should not be used")


http_url_shorteners = [
    forbid_shortener('goo.gl'),
    forbid_shortener('t.co'),
    forbid_shortener('ur1.ca'),
    forbid_shortener('is.gd'),
    forbid_shortener('bit.ly'),
    forbid_shortener('tiny.cc'),
    forbid_shortener('tinyurl.com'),
]

http_checks = https_enforcings + http_url_shorteners + [
    (re.compile(r'.*github\.com/[^/]+/[^/]+\.git'),
     "Appending .git is not necessary"),
    (re.compile(r'.*://[^/]*(github|gitlab|bitbucket|rawgit)[^/]*/([^/]+/){1,3}master'),
     "Use /HEAD instead of /master to point at a file in the default branch"),
]

regex_checks = {
    'WebSite': http_checks,
    'SourceCode': http_checks,
    'Repo': https_enforcings,
    'IssueTracker': http_checks + [
        (re.compile(r'.*github\.com/[^/]+/[^/]+/*$'),
         "/issues is missing"),
        (re.compile(r'.*gitlab\.com/[^/]+/[^/]+/*$'),
         "/issues is missing"),
    ],
    'Donate': http_checks + [
        (re.compile(r'.*flattr\.com'),
         "Flattr donation methods belong in the FlattrID flag"),
    ],
    'Changelog': http_checks,
    'Author Name': [
        (re.compile(r'^\s'),
         "Unnecessary leading space"),
        (re.compile(r'.*\s$'),
         "Unnecessary trailing space"),
    ],
    'License': [
        (re.compile(r'^(|None|Unknown)$'),
         "No license specified"),
    ],
    'Summary': [
        (re.compile(r'^$'),
         "Summary yet to be filled"),
        (re.compile(r'.*\b(free software|open source)\b.*', re.IGNORECASE),
         "No need to specify that the app is Free Software"),
        (re.compile(r'.*((your|for).*android|android.*(app|device|client|port|version))', re.IGNORECASE),
         "No need to specify that the app is for Android"),
        (re.compile(r'.*[a-z0-9][.!?]( |$)'),
         "Punctuation should be avoided"),
        (re.compile(r'^\s'),
         "Unnecessary leading space"),
        (re.compile(r'.*\s$'),
         "Unnecessary trailing space"),
    ],
    'Description': [
        (re.compile(r'^No description available$'),
         "Description yet to be filled"),
        (re.compile(r'\s*[*#][^ .]'),
         "Invalid bulleted list"),
        (re.compile(r'^\s'),
         "Unnecessary leading space"),
        (re.compile(r'.*\s$'),
         "Unnecessary trailing space"),
        (re.compile(r'.*([^[]|^)\[[^:[\]]+( |\]|$)'),
         "Invalid link - use [http://foo.bar Link title] or [http://foo.bar]"),
        (re.compile(r'(^|.* )https?://[^ ]+'),
         "Unlinkified link - use [http://foo.bar Link title] or [http://foo.bar]"),
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


def check_ucm_tags(app):
    lastbuild = get_lastbuild(app.builds)
    if (lastbuild is not None
            and lastbuild.commit
            and app.UpdateCheckMode == 'RepoManifest'
            and not lastbuild.commit.startswith('unknown')
            and lastbuild.versionCode == app.CurrentVersionCode
            and not lastbuild.forcevercode
            and any(s in lastbuild.commit for s in '.,_-/')):
        yield "Last used commit '%s' looks like a tag, but Update Check Mode is '%s'" % (
            lastbuild.commit, app.UpdateCheckMode)


def check_char_limits(app):
    limits = config['char_limits']

    if len(app.Summary) > limits['summary']:
        yield "Summary of length %s is over the %i char limit" % (
            len(app.Summary), limits['summary'])

    if len(app.Description) > limits['description']:
        yield "Description of length %s is over the %i char limit" % (
            len(app.Description), limits['description'])


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
                yield "App is in '%s' but has a link to '%s'" % (app.Repo, v)


def check_useless_fields(app):
    if app.UpdateCheckName == app.id:
        yield "Update Check Name is set to the known app id - it can be removed"


filling_ucms = re.compile(r'^(Tags.*|RepoManifest.*)')


def check_checkupdates_ran(app):
    if filling_ucms.match(app.UpdateCheckMode):
        if not app.AutoName and not app.CurrentVersion and app.CurrentVersionCode == '0':
            yield "UCM is set but it looks like checkupdates hasn't been run yet"


def check_empty_fields(app):
    if not app.Categories:
        yield "Categories are not set"


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
            yield "Category '%s' is not valid" % categ


def check_duplicates(app):
    if app.Name and app.Name == app.AutoName:
        yield "Name '%s' is just the auto name - remove it" % app.Name

    links_seen = set()
    for f in ['Source Code', 'Web Site', 'Issue Tracker', 'Changelog']:
        v = app.get(f)
        if not v:
            continue
        v = v.lower()
        if v in links_seen:
            yield "Duplicate link in '%s': %s" % (f, v)
        else:
            links_seen.add(v)

    name = app.Name or app.AutoName
    if app.Summary and name:
        if app.Summary.lower() == name.lower():
            yield "Summary '%s' is just the app's name" % app.Summary

    if app.Summary and app.Description and len(app.Description) == 1:
        if app.Summary.lower() == app.Description[0].lower():
            yield "Description '%s' is just the app's summary" % app.Summary

    seenlines = set()
    for l in app.Description.splitlines():
        if len(l) < 1:
            continue
        if l in seenlines:
            yield "Description has a duplicate line"
        seenlines.add(l)


desc_url = re.compile(r'(^|[^[])\[([^ ]+)( |\]|$)')


def check_mediawiki_links(app):
    wholedesc = ' '.join(app.Description)
    for um in desc_url.finditer(wholedesc):
        url = um.group(1)
        for m, r in http_checks:
            if m.match(url):
                yield "URL '%s' in Description: %s" % (url, r)


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
                yield "Description has a list (%s) but it isn't bulleted (*) nor numbered (#)" % lchar
                break
        else:
            lchar = l[0]
            lcount = 1


def check_builds(app):
    for build in app.builds:
        if build.disable:
            if build.disable.startswith('Generated by import.py'):
                yield "Build generated by `fdroid import` - remove disable line once ready"
            continue
        for s in ['master', 'origin', 'HEAD', 'default', 'trunk']:
            if build.commit and build.commit.startswith(s):
                yield "Branch '%s' used as commit in build '%s'" % (s, build.versionName)
            for srclib in build.srclibs:
                ref = srclib.split('@')[1].split('/')[0]
                if ref.startswith(s):
                    yield "Branch '%s' used as commit in srclib '%s'" % (s, srclib)


def check_files_dir(app):
    dir_path = os.path.join('metadata', app.id)
    if not os.path.isdir(dir_path):
        return
    files = set()
    for name in os.listdir(dir_path):
        path = os.path.join(dir_path, name)
        if not (os.path.isfile(path) or name == 'signatures' or locale_pattern.match(name)):
            yield "Found non-file at %s" % path
            continue
        files.add(name)

    used = {'signatures', }
    for build in app.builds:
        for fname in build.patch:
            if fname not in files:
                yield "Unknown file %s in build '%s'" % (fname, build.versionName)
            else:
                used.add(fname)

    for name in files.difference(used):
        if locale_pattern.match(name):
            continue
        yield "Unused file at %s" % os.path.join(dir_path, name)


def check_format(app):
    if options.format and not rewritemeta.proper_format(app):
        yield "Run rewritemeta to fix formatting"


def check_extlib_dir(apps):
    dir_path = os.path.join('build', 'extlib')
    files = set()
    for root, dirs, names in os.walk(dir_path):
        for name in names:
            files.add(os.path.join(root, name)[len(dir_path) + 1:])

    used = set()
    for app in apps:
        for build in app.builds:
            for path in build.extlibs:
                if path not in files:
                    yield "%s: Unknown extlib %s in build '%s'" % (app.id, path, build.versionName)
                else:
                    used.add(path)

    for path in files.difference(used):
        if any(path.endswith(s) for s in [
                '.gitignore',
                'source.txt', 'origin.txt', 'md5.txt',
                'LICENSE', 'LICENSE.txt',
                'COPYING', 'COPYING.txt',
                'NOTICE', 'NOTICE.txt',
                ]):
            continue
        yield "Unused extlib at %s" % os.path.join(dir_path, path)


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser(usage="%(prog)s [options] [APPID [APPID ...]]")
    common.setup_global_opts(parser)
    parser.add_argument("-f", "--format", action="store_true", default=False,
                        help="Also warn about formatting issues, like rewritemeta -l")
    parser.add_argument("appid", nargs='*', help="app-id in the form APPID")
    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    metadata.warnings_action = options.W

    config = common.read_config(options)

    # Get all apps...
    allapps = metadata.read_metadata(xref=True)
    apps = common.read_app_args(options.appid, allapps, False)

    anywarns = False

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
        ]

        for check_func in app_check_funcs:
            for warn in check_func(app):
                anywarns = True
                print("%s: %s" % (appid, warn))

    if anywarns:
        sys.exit(1)


if __name__ == "__main__":
    main()
