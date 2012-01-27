#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# checkmarket2.py - part of the FDroid server tools
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
import re
import urllib
import time
from optparse import OptionParser
import HTMLParser
import common

#Read configuration...
execfile('config.py')


# Check for a new version by looking at the Google market.
# Returns (None, "a message") if this didn't work, or (version, vercode) for
# the details of the current version.
def check_market(app):
    time.sleep(5)
    url = 'http://market.android.com/details?id=' + app['id']
    req = urllib.urlopen(url)
    if req.getcode() == 404:
        return (None, 'Not in market')
    elif req.getcode() != 200:
        return (None, 'Return code ' + str(req.getcode()))
    page = req.read()

    version = None
    vercode = None

    m = re.search('<dd itemprop="softwareVersion">([^>]+)</dd>', page)
    if m:
        version = html_parser.unescape(m.group(1))

    if version == 'Varies with device':
        return (None, 'Device-variable version, cannot use this method')

    m = re.search('data-paramValue="(\d+)"><div class="goog-menuitem-content">Latest Version<', page)
    if m:
        vercode = m.group(1)

    if not vercode:
        return (None, "Couldn't find version code")
    if not version:
        return (None, "Couldn't find version")
    return (version, vercode)




# Parse command line...
parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true", default=False,
                  help="Spew out even more information than normal")
parser.add_option("-p", "--package", default=None,
                  help="Build only the specified package")
(options, args) = parser.parse_args()

# Get all apps...
apps = common.read_metadata(options.verbose)

html_parser = HTMLParser.HTMLParser()

for app in apps:

    if options.package and options.package != app['id']:
        # Silent skip...
        pass
    else:
        print "Processing " + app['id'] + '...'

        mode = app['Update Check Mode']
        if mode == 'Market':
            (version, vercode) = check_market(app)
        elif mode == 'None':
            version = None
            vercode = 'Checking disabled'
        else:
            version = None
            vercode = 'Invalid update check method'

        if not version:
            print "..." + vercode
        elif vercode == app['Current Version Code'] and version == app['Current Version']:
            print "...up to date"
        else:
            print '...updating to version:' + version + ' vercode:' + vercode
            app['Current Version'] = version
            app['Current Version Code'] = vercode
            metafile = os.path.join('metadata', app['id'] + '.txt')
            common.write_metadata(metafile, app)

print "Finished."

