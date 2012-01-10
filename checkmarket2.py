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


# Parse command line...
parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true", default=False,
                  help="Spew out even more information than normal")
(options, args) = parser.parse_args()

# Get all apps...
apps = common.read_metadata(options.verbose)

html_parser = HTMLParser.HTMLParser()

for app in apps:

    print "Processing " + app['id']
    url = 'http://market.android.com/details?id=' + app['id']
    page = urllib.urlopen(url).read()

    version = None
    vercode = None

    m = re.search('<dd itemprop="softwareVersion">([^>]+)</dd>', page)
    if m:
        version = html_parser.unescape(m.group(1))

    m = re.search('data-paramValue="(\d+)"><div class="goog-menuitem-content">Latest Version<', page)
    if m:
        vercode = m.group(1)

    if not vercode:
        print "...couldn't find version code"
    elif not version:
        print "...couldn't find version"
    elif vercode == app['Market Version Code'] and version == app['Market Version']:
        print "...up to date"
    else:
        print '...updating to version:' + version + ' vercode:' + vercode
        newdata = ''
        metafile = os.path.join('metadata', app['id'] + '.txt')
        mf = open(metafile, 'r')
        for line in mf:
            if line.startswith('Market Version:'):
                newdata += 'Market Version:' + version + '\n'
            elif line.startswith('Market Version Code:'):
                newdata += 'Market Version Code:' + vercode + '\n'
            else:
                newdata += line
        mf.close()
        mf = open(metafile, 'w')
        mf.write(newdata)
        mf.close()

    time.sleep(5)

print "Finished."

