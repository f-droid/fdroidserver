# -*- coding: utf-8 -*-
#
# common.py - part of the FDroid server tools
# Copyright (C) 2010, Ciaran Gultnieks, ciaran@ciarang.com
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

import glob, os, sys

def read_metadata(verbose=False):

    apps = []

    for metafile in glob.glob(os.path.join('metadata','*.txt')):

        thisinfo = {}

        # Get metadata...
        thisinfo['id'] = metafile[9:-4]
        if verbose:
            print "Reading metadata for " + thisinfo['id']
        thisinfo['description'] = ''
        thisinfo['name'] = None
        thisinfo['summary'] = ''
        thisinfo['license'] = 'Unknown'
        thisinfo['web'] = ''
        thisinfo['source'] = ''
        thisinfo['tracker'] = ''
        thisinfo['donate'] = None
        thisinfo['disabled'] = None
        thisinfo['antifeatures'] = None
        thisinfo['marketversion'] = ''
        thisinfo['marketvercode'] = '0'
        thisinfo['repotype'] = ''
        thisinfo['repo'] = ''
        thisinfo['builds'] = []
        thisinfo['usebuilt'] = False
        f = open(metafile, 'r')
        mode = 0
        for line in f.readlines():
            if not line.startswith("#"):
                line = line.rstrip('\r\n')
                if len(line) == 0:
                    pass
                elif mode == 0:
                    index = line.find(':')
                    if index == -1:
                        print "Invalid metadata in " + metafile + " at:" + line
                        sys.exit(1)
                    field = line[:index]
                    value = line[index+1:]
                    if field == 'Description':
                        mode = 1
                    elif field == 'Name':
                        thisinfo['name'] = value
                    elif field == 'Summary':
                        thisinfo['summary'] = value
                    elif field == 'Source Code':
                        thisinfo['source'] = value
                    elif field == 'License':
                        thisinfo['license'] = value
                    elif field == 'Web Site':
                        thisinfo['web'] = value
                    elif field == 'Issue Tracker':
                        thisinfo['tracker'] = value
                    elif field == 'Donate':
                        thisinfo['donate'] = value
                    elif field == 'Disabled':
                        thisinfo['disabled'] = value
                    elif field == 'AntiFeatures':
                        parts = value.split(",")
                        for part in parts:
                            if (part != "Ads" and
                                part != "Tracking" and
                                part != "NonFreeNet" and
                                part != "NonFreeAdd"):
                                print "Unrecognised antifeature '" + part + "' in "+ metafile
                                sys.exit(1)
                        thisinfo['antifeatures'] = value
                    elif field == 'Market Version':
                        thisinfo['marketversion'] = value
                    elif field == 'Market Version Code':
                        thisinfo['marketvercode'] = value
                    elif field == 'Repo Type':
                        thisinfo['repotype'] = value
                    elif field == 'Repo':
                        thisinfo['repo'] = value
                    elif field == 'Build Version':
                        parts = value.split(",")
                        if len(parts) < 3:
                            print "Invalid build format: " + value + " in " + metafile
                            sys.exit(1)
                        thisbuild = {}
                        thisbuild['version'] = parts[0]
                        thisbuild['vercode'] = parts[1]
                        thisbuild['commit'] = parts[2]
                        for p in parts[3:]:
                            pk, pv = p.split('=', 1)
                            thisbuild[pk] = pv
                        thisinfo['builds'].append(thisbuild)
                    elif field == "Use Built":
                        if value == "Yes":
                            thisinfo['usebuilt'] = True
                    else:
                        print "Unrecognised field " + field + " in " + metafile
                        sys.exit(1)
                elif mode == 1:
                    if line == '.':
                        mode = 0
                    else:
                        if len(line) == 0:
                            thisinfo['description'] += '\n\n'
                        else:
                            if (not thisinfo['description'].endswith('\n') and
                                len(thisinfo['description']) > 0):
                                thisinfo['description'] += ' '
                            thisinfo['description'] += line

        if mode == 1:
            print "Description not terminated in " + metafile
            sys.exit(1)
        if len(thisinfo['description']) == 0:
            thisinfo['description'] = 'No description available'

        apps.append(thisinfo)

    return apps
