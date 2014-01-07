#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# rewritemeta.py - part of the FDroid server tool
# Copyright (C) 2010-12, Ciaran Gultnieks, ciaran@ciarang.com
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
import common, metadata

config = None
options = None

appid = None

def warn(message):
    global appid
    if appid:
        print "%s:" % appid
        appid = None
    print('    %s' % message)

def main():

    global config, options, appid

    # Parse command line...
    parser = OptionParser(usage="Usage: %prog [options] [APPID [APPID ...]]")
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    (options, args) = parser.parse_args()

    config = common.read_config(options)

    # Get all apps...
    allapps = metadata.read_metadata(xref=False)
    apps = common.read_app_args(args, allapps, False)

    for app in apps:
        appid = app['id']
        lastcommit = ''

        for build in app['builds']:
            if 'commit' in build and 'disable' not in build:
                lastcommit = build['commit']

        if (app['Update Check Mode'] == 'RepoManifest' and
                any(s in lastcommit for s in ('.', ',', '_', '-', '/'))):
            warn("Last used commit '%s' looks like a tag, but Update Check Mode is RepoManifest" % lastcommit)

        summ_chars = len(app['Summary'])
        if summ_chars > config['char_limits']['Summary']:
            warn("Summary of length %s is over the %i char limit" % (
                summ_chars, config['char_limits']['Summary']))

        if app['Summary']:
            lastchar = app['Summary'][-1]
            if any(lastchar==c for c in ['.', ',', '!', '?']):
                warn("Summary should not end with a %s" % lastchar)

        desc_chars = 0
        for line in app['Description']:
            desc_chars += len(line)
        if desc_chars > config['char_limits']['Description']:
            warn("Description of length %s is over the %i char limit" % (
                desc_chars, config['char_limits']['Description']))

        if not appid:
            print

    print "Finished."

if __name__ == "__main__":
    main()

