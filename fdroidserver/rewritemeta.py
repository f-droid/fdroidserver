#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# rewritemeta.py - part of the FDroid server tools
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
from optparse import OptionParser
import common

config = None
options = None

def main():

    global config, options

    # Parse command line...
    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-p", "--package", default=None,
                      help="Process only the specified package")
    (options, args) = parser.parse_args()

    config = common.read_config(options)

    # Get all apps...
    apps = common.read_metadata(package=options.package)

    if len(apps) == 0 and options.package:
        print "No such package"
        sys.exit(1)

    for app in apps:
        print "Writing " + app['id']
        common.write_metadata(os.path.join('metadata', app['id']) + '.txt', app)

    print "Finished."

if __name__ == "__main__":
    main()

