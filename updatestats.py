#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# updatestats.py - part of the FDroid server tools
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
import traceback
import glob
from optparse import OptionParser
import HTMLParser
import paramiko
import common

#Read configuration...
execfile('config.py')


# Parse command line...
parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true", default=False,
                  help="Spew out even more information than normal")
parser.add_option("-d", "--download", action="store_true", default=False,
                  help="Download logs we don't have")
(options, args) = parser.parse_args()


statsdir = 'stats'
logsdir = os.path.join(statsdir, 'logs')
logsarchivedir = os.path.join(logsdir, 'archive')
datadir = os.path.join(statsdir, 'data')
if not os.path.exists(statsdir):
    os.mkdir(statsdir)
if not os.path.exists(logsdir):
    os.mkdir(logsdir)
if not os.path.exists(datadir):
    os.mkdir(datadir)

if options.download:
    # Get any access logs we don't have...
    ssh = None
    ftp = None
    try:
        print 'Retrieving logs'
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.connect('f-droid.org', username='fdroid', timeout=10,
                key_filename=webserver_keyfile)
        ftp = ssh.open_sftp()
        ftp.get_channel().settimeout(15)
        print "...connected"

        ftp.chdir('logs')
        files = ftp.listdir()
        for file in files:
            if file.startswith('access-') and file.endswith('.log'):

                destpath = os.path.join(logsdir, file)
                archivepath = os.path.join(logsarchivedir, file + '.gz')
                if os.path.exists(archivepath):
                    if os.path.exists(destpath):
                        # Just in case we have it archived but failed to remove
                        # the original...
                        os.remove(destpath)
                else:
                    destsize = ftp.stat(file).st_size
                    if (not os.path.exists(destpath) or
                            os.path.getsize(destpath) != destsize):
                        print "...retrieving " + file
                        ftp.get(file, destpath)
    except Exception as e:
        traceback.print_exc()
        sys.exit(1)
    finally:
        #Disconnect
        if ftp != None:
            ftp.close()
        if ssh != None:
            ssh.close()

# Process logs
logexpr = '(?P<ip>[.:0-9a-fA-F]+) - - \[(?P<time>.*?)\] "GET (?P<uri>.*?) HTTP/1.\d" (?P<statuscode>\d+) \d+ "(?P<referral>.*?)" "(?P<useragent>.*?)"'
logsearch = re.compile(logexpr).search
apps = {}
unknownapks = []
knownapks = common.KnownApks()
for logfile in glob.glob(os.path.join(logsdir,'access-*.log')):
    logdate = logfile[len(logsdir) + 1 + len('access-'):-4]
    matches = (logsearch(line) for line in file(logfile))
    for match in matches:
        if match and match.group('statuscode') == '200':
            uri = match.group('uri')
            if uri.endswith('.apk'):
                _, apkname = os.path.split(uri)
                app = knownapks.getapp(apkname)
                if app:
                    appid, _ = app
                    if appid in apps:
                        apps[appid] += 1
                    else:
                        apps[appid] = 1
                else:
                    if not apkname in unknownapks:
                        unknownapks.append(apkname)

for app, count in apps.iteritems():
    print app + " " + str(count)

if len(unknownapks) > 0:
    print '\nUnknown apks:'
    for apk in unknownapks:
        print apk

print "Finished."

