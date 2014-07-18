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

from optparse import OptionParser
import re
import logging
import common
import metadata
from collections import Counter

config = None
options = None

regex_warnings = {
    'Web Site': [
        (re.compile(r'.*[^sS]://github\.com/.*'),
         "github URLs should always use https:// not http://"),
        (re.compile(r'.*[^sS]://code\.google\.com/.*'),
         "code.google.com URLs should always use https:// not http://"),
        ],
    'Source Code': [
        (re.compile(r'.*[^sS]://github\.com/.*'),
         "github URLs should always use https:// (not http://, git://, or git@)"),
        (re.compile(r'.*code\.google\.com/p/[^/]+[/]*$'),
         "/source is missing"),
        (re.compile(r'.*[^sS]://code\.google\.com/.*'),
         "code.google.com URLs should always use https:// not http://"),
        (re.compile(r'.*[^sS]://dl\.google\.com/.*'),
         "dl.google.com URLs should always use https:// not http://"),
        (re.compile(r'.*[^sS]://gitorious\.org/.*'),
         "gitorious URLs should always use https:// (not http://, git://, or git@)"),
        ],
    'Repo': [
        (re.compile(r'.*[^sS]://code\.google\.com/.*'),
         "code.google.com URLs should always use https:// not http://"),
        (re.compile(r'.*[^sS]://dl\.google\.com/.*'),
         "dl.google.com URLs should always use https:// not http://"),
        (re.compile(r'.*[^sS]://github\.com/.*'),
         "github URLs should always use https:// (not http://, git://, or git@)"),
        (re.compile(r'.*[^sS]://gitorious\.org/.*'),
         "gitorious URLs should always use https:// (not http://, git://, or git@)"),
        (re.compile(r'.*[^sS]://[^.]*\.googlecode\.com/svn/?.*'),
         "Google Code SVN URLs should always use https:// (not http:// or svn://)"),
        (re.compile(r'.*[^sS]://svn\.apache\.org/repos/?.*'),
         "Apache SVN URLs should always use https:// (not http:// or svn://)"),
        (re.compile(r'.*[^sS]://svn\.code\.sf\.net/.*'),
         "Sourceforge SVN URLs should always use https:// (not http:// or svn://)"),
        ],
    'Issue Tracker': [
        (re.compile(r'.*code\.google\.com/p/[^/]+[/]*$'),
         "/issues is missing"),
        (re.compile(r'.*[^sS]://code\.google\.com/.*'),
         "code.google.com URLs should always use https:// not http://"),
        (re.compile(r'.*github\.com/[^/]+/[^/]+[/]*$'),
         "/issues is missing"),
        (re.compile(r'.*[^sS]://github\.com/.*'),
         "github URLs should always use https:// not http://"),
        (re.compile(r'.*[^sS]://gitorious\.org/.*'),
         "gitorious URLs should always use https:// not http://"),
        ],
    'License': [
        (re.compile(r'^(|None|Unknown)$'),
         "No license specified"),
        ],
    'Description': [
        (re.compile(r'^No description available$'),
         "Description yet to be filled"),
        (re.compile(r'[ ]*[*#][^ .]'),
         "Invalid bulleted list"),
        (re.compile(r'^ '),
         "Unnecessary leading space"),
        ],
}

regex_pedantic = {
    'Web Site': [
        (re.compile(r'.*github\.com/[^/]+/[^/]+\.git'),
         "Appending .git is not necessary"),
        (re.compile(r'.*code\.google\.com/p/[^/]+/[^w]'),
         "Possible incorrect path appended to google code project site"),
        ],
    'Source Code': [
        (re.compile(r'.*github\.com/[^/]+/[^/]+\.git'),
         "Appending .git is not necessary"),
        (re.compile(r'.*code\.google\.com/p/[^/]+/source/.*'),
         "/source is often enough on its own"),
        ],
    'Repo': [
        (re.compile(r'^http://.*'),
         "use https:// if available"),
        (re.compile(r'^svn://.*'),
         "use https:// if available"),
        ],
    'Issue Tracker': [
        (re.compile(r'.*code\.google\.com/p/[^/]+/issues/.*'),
         "/issues is often enough on its own"),
        (re.compile(r'.*github\.com/[^/]+/[^/]+/issues/.*'),
         "/issues is often enough on its own"),
        ],
    'Summary': [
        (re.compile(r'^[a-z]'),
         "No capitalization was done"),
        (re.compile(r'.*\bandroid\b.*', re.IGNORECASE),
         "No need to specify that the app is for Android"),
        (re.compile(r'.*\b(app|application)\b.*', re.IGNORECASE),
         "No need to specify that the app is... an app"),
        (re.compile(r'.*\b(free software|open source)\b.*', re.IGNORECASE),
         "No need to specify that the app is Free Software"),
        (re.compile(r'.*[a-z0-9][.,!?][ $]'),
         "Punctuation should be avoided"),
        ],
    }


def main():

    global config, options, appid, count
    appid = None

    count = Counter()

    def warn(message):
        global appid, count
        if appid:
            print "%s:" % appid
            appid = None
            count['app'] += 1
        print '    %s' % message
        count['warn'] += 1

    def pwarn(message):
        if options.pedantic:
            warn(message)

    # Parse command line...
    parser = OptionParser(usage="Usage: %prog [options] [APPID [APPID ...]]")
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help="Restrict output to warnings and errors")
    parser.add_option("-p", "--pedantic", action="store_true", default=False,
                      help="Show pedantic warnings that might give false positives")
    (options, args) = parser.parse_args()

    config = common.read_config(options)

    # Get all apps...
    allapps = metadata.read_metadata(xref=False)
    apps = common.read_app_args(args, allapps, False)

    for app in apps:
        appid = app['id']
        lastcommit = ''

        if app['Disabled']:
            continue

        for build in app['builds']:
            if build['commit'] and not build['disable']:
                lastcommit = build['commit']

        # Potentially incorrect UCM
        if (app['Update Check Mode'] == 'RepoManifest' and
                any(s in lastcommit for s in '.,_-/')):
            pwarn("Last used commit '%s' looks like a tag, but Update Check Mode is '%s'" % (
                lastcommit, app['Update Check Mode']))

        # Summary size limit
        summ_chars = len(app['Summary'])
        if summ_chars > config['char_limits']['Summary']:
            warn("Summary of length %s is over the %i char limit" % (
                summ_chars, config['char_limits']['Summary']))

        # Redundant summaries
        summary = app['Summary']
        name = app['Name'] or app['Auto Name']
        if summary and name:
            summary_l = summary.lower()
            name_l = name.lower()
            if summary_l == name_l:
                warn("Summary '%s' is just the app's name" % summary)
            elif (summary_l in name_l or name_l in summary_l):
                pwarn("Summary '%s' probably contains redundant info already in app name '%s'" % (
                    summary, name))

        # Description size limit
        desc_chars = sum(len(l) for l in app['Description'])
        if desc_chars > config['char_limits']['Description']:
            warn("Description of length %s is over the %i char limit" % (
                desc_chars, config['char_limits']['Description']))

        # Regex checks in all kinds of fields
        for f in regex_warnings:
            for m, r in regex_warnings[f]:
                t = metadata.metafieldtype(f)
                if t == 'string':
                    if m.match(app[f]):
                        warn("%s '%s': %s" % (f, app[f], r))
                elif t == 'multiline':
                    for l in app[f]:
                        if m.match(l):
                            warn("%s at line '%s': %s" % (f, l, r))

        # Regex pedantic checks in all kinds of fields
        if options.pedantic:
            for f in regex_pedantic:
                for m, r in regex_pedantic[f]:
                    if m.match(app[f]):
                        warn("%s '%s': %s" % (f, app[f], r))

        # Build warnings
        for build in app['builds']:
            for s in ['master', 'origin/', 'default', 'trunk']:
                if build['commit'] and build['commit'].startswith(s):
                    warn("Branch '%s' used as commit in build '%s'" % (
                        s, build['version']))
                for srclib in build['srclibs']:
                    ref = srclib.split('@')[1].split('/')[0]
                    if ref.startswith(s):
                        warn("Branch '%s' used as commit in srclib '%s'" % (
                            s, srclib))
            for s in ['git clone', 'git svn clone', 'svn checkout', 'svn co', 'hg clone']:
                for flag in ['init', 'prebuild', 'build']:
                    if not build[flag]:
                        continue
                    if s in build[flag]:
                        # TODO: This should not be pedantic!
                        pwarn("'%s' used in %s '%s'" % (s, flag, build[flag]))

        if not appid:
            print

    logging.info("Found a total of %i warnings in %i apps." % (count['warn'], count['app']))

if __name__ == "__main__":
    main()
