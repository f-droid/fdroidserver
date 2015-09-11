#!/usr/bin/env python2
# -*- coding: utf-8 -*-
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
import re
import common
import metadata
import sys
from sets import Set

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
]

http_checks = https_enforcings + http_url_shorteners + [
    (re.compile(r'.*github\.com/[^/]+/[^/]+\.git'),
     "Appending .git is not necessary"),
    (re.compile(r'(.*/blob/master/|.*raw\.github.com/[^/]*/[^/]*/master/)'),
     "Use /HEAD/ instead of /master/ to point at a file in the default branch"),
]

regex_checks = {
    'Web Site': http_checks + [
    ],
    'Source Code': http_checks + [
    ],
    'Repo': https_enforcings + [
    ],
    'Issue Tracker': http_checks + [
        (re.compile(r'.*github\.com/[^/]+/[^/]+[/]*$'),
         "/issues is missing"),
    ],
    'Donate': http_checks + [
        (re.compile(r'.*flattr\.com'),
         "Flattr donation methods belong in the FlattrID flag"),
    ],
    'Changelog': http_checks + [
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
        (re.compile(r'.*[^[]https?://[^ ]+'),
         "Unlinkified link - use [http://foo.bar Link title] or [http://foo.bar]"),
    ],
}


def check_regexes(app):
    for f, checks in regex_checks.iteritems():
        for m, r in checks:
            v = app[f]
            if type(v) == str:
                if v is None:
                    continue
                if m.match(v):
                    yield "%s '%s': %s" % (f, v, r)
            elif type(v) == list:
                for l in v:
                    if m.match(l):
                        yield "%s at line '%s': %s" % (f, l, r)

desc_url = re.compile("[^[]\[([^ ]+)( |\]|$)")


def get_lastbuild(builds):
    lowest_vercode = -1
    lastbuild = None
    for build in builds:
        if not build['disable']:
            vercode = int(build['vercode'])
            if lowest_vercode == -1 or vercode < lowest_vercode:
                lowest_vercode = vercode
        if not lastbuild or int(build['vercode']) > int(lastbuild['vercode']):
            lastbuild = build
    return lastbuild


def check_ucm_tags(app):
    lastbuild = get_lastbuild(app['builds'])
    if (lastbuild is not None
            and lastbuild['commit']
            and app['Update Check Mode'] == 'RepoManifest'
            and not lastbuild['commit'].startswith('unknown')
            and lastbuild['vercode'] == app['Current Version Code']
            and not lastbuild['forcevercode']
            and any(s in lastbuild['commit'] for s in '.,_-/')):
        yield "Last used commit '%s' looks like a tag, but Update Check Mode is '%s'" % (
            lastbuild['commit'], app['Update Check Mode'])


def check_char_limits(app):
    limits = config['char_limits']

    summ_chars = len(app['Summary'])
    if summ_chars > limits['Summary']:
        yield "Summary of length %s is over the %i char limit" % (
            summ_chars, limits['Summary'])

    desc_charcount = sum(len(l) for l in app['Description'])
    if desc_charcount > limits['Description']:
        yield "Description of length %s is over the %i char limit" % (
            desc_charcount, limits['Description'])


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
    if any(s in app['Repo'] for s in usual_sites):
        for f in ['Web Site', 'Source Code', 'Issue Tracker', 'Changelog']:
            if any(s in app[f] for s in old_sites):
                yield "App is in '%s' but has a link to '%s'" % (app['Repo'], app[f])


def check_useless_fields(app):
    if app['Update Check Name'] == app['id']:
        yield "Update Check Name is set to the known app id - it can be removed"

filling_ucms = re.compile('^(Tags.*|RepoManifest.*)')


def check_checkupdates_ran(app):
    if filling_ucms.match(app['Update Check Mode']):
        if all(app[f] == metadata.app_defaults[f] for f in [
                'Auto Name',
                'Current Version',
                'Current Version Code',
                ]):
            yield "UCM is set but it looks like checkupdates hasn't been run yet"


def check_empty_fields(app):
    if not app['Categories']:
        yield "Categories are not set"

all_categories = Set([
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
    for categ in app['Categories']:
        if categ not in all_categories:
            yield "Category '%s' is not valid" % categ


def check_duplicates(app):
    if app['Web Site'] and app['Source Code']:
        if app['Web Site'].lower() == app['Source Code'].lower():
            yield "Website '%s' is just the app's source code link" % app['Web Site']

    if app['Name'] and app['Name'] == app['Auto Name']:
        yield "Name '%s' is just the auto name" % app['Name']

    name = app['Name'] or app['Auto Name']
    if app['Summary'] and name:
        if app['Summary'].lower() == name.lower():
            yield "Summary '%s' is just the app's name" % app['Summary']

    desc = app['Description']
    if app['Summary'] and desc and len(desc) == 1:
        if app['Summary'].lower() == desc[0].lower():
            yield "Description '%s' is just the app's summary" % app['Summary']

    seenlines = set()
    for l in app['Description']:
        if len(l) < 1:
            continue
        if l in seenlines:
            yield "Description has a duplicate line"
        seenlines.add(l)


def check_text_wrap(app):
    maxcols = 140
    for l in app['Description']:
        if any(l.startswith(c) for c in ['*', '#']):
            continue
        if any(len(w) > maxcols for w in l.split(' ')):
            continue
        if len(l) > maxcols:
            yield "Description should be wrapped to 80-120 chars"
            break


def check_mediawiki_links(app):
    for l in app['Description']:
        for um in desc_url.finditer(l):
            url = um.group(1)
            for m, r in http_checks:
                if m.match(url):
                    yield "URL '%s' in Description: %s" % (url, r)


def check_extra_spacing(app):
    desc = app['Description']
    if (not desc[0] or not desc[-1]
            or any(not desc[l - 1] and not desc[l] for l in range(1, len(desc)))):
        yield "Description has an extra empty line"


def check_bulleted_lists(app):
    validchars = ['*', '#']
    lchar = ''
    lcount = 0
    for l in app['Description']:
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
    for build in app['builds']:
        if build['disable']:
            continue
        for s in ['master', 'origin', 'HEAD', 'default', 'trunk']:
            if build['commit'] and build['commit'].startswith(s):
                yield "Branch '%s' used as commit in build '%s'" % (s, build['version'])
            for srclib in build['srclibs']:
                ref = srclib.split('@')[1].split('/')[0]
                if ref.startswith(s):
                    yield "Branch '%s' used as commit in srclib '%s'" % (s, srclib)


def main():

    global config, options

    anywarns = False

    # Parse command line...
    parser = ArgumentParser(usage="%(prog)s [options] [APPID [APPID ...]]")
    parser.add_argument("appid", nargs='*', help="app-id in the form APPID")
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                        help="Spew out even more information than normal")
    parser.add_argument("-q", "--quiet", action="store_true", default=False,
                        help="Restrict output to warnings and errors")
    options = parser.parse_args()

    config = common.read_config(options)

    # Get all apps...
    allapps = metadata.read_metadata(xref=True)
    apps = common.read_app_args(options.appid, allapps, False)

    for appid, app in apps.iteritems():
        if app['Disabled']:
            continue

        warns = []

        for check_func in [
                check_regexes,
                check_ucm_tags,
                check_char_limits,
                check_old_links,
                check_checkupdates_ran,
                check_useless_fields,
                check_empty_fields,
                check_categories,
                check_duplicates,
                check_text_wrap,
                check_mediawiki_links,
                check_extra_spacing,
                check_bulleted_lists,
                check_builds,
                ]:
            warns += check_func(app)

        if warns:
            anywarns = True
            for warn in warns:
                print "%s: %s" % (appid, warn)

    if anywarns:
        sys.exit(1)


if __name__ == "__main__":
    main()
