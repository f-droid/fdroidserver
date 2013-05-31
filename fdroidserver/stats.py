#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# stats.py - part of the FDroid server tools
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
import socket
import subprocess

def carbon_send(key, value):
    s = socket.socket()
    s.connect((carbon_host, carbon_port))
    msg = '%s %d %d\n' % (key, value, int(time.time()))
    s.sendall(msg)
    s.close()

def main():

    # Read configuration...
    global update_stats, stats_to_carbon
    update_stats = False
    stats_to_carbon = False
    execfile('config.py', globals())

    if not update_stats:
        print "Stats are disabled - check your configuration"
        sys.exit(1)

    # Parse command line...
    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-d", "--download", action="store_true", default=False,
                      help="Download logs we don't have")
    (options, args) = parser.parse_args()

    # Get all metadata-defined apps...
    metaapps = common.read_metadata(options.verbose)

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
            ftp.get_channel().settimeout(60)
            print "...connected"

            ftp.chdir('logs')
            files = ftp.listdir()
            for f in files:
                if f.startswith('access-') and f.endswith('.log.gz'):

                    destpath = os.path.join(logsdir, f)
                    destsize = ftp.stat(f).st_size
                    if (not os.path.exists(destpath) or
                            os.path.getsize(destpath) != destsize):
                        print "...retrieving " + f
                        ftp.get(f, destpath)
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
    if options.verbose:
        print 'Processing logs...'
    logexpr = '(?P<ip>[.:0-9a-fA-F]+) - - \[(?P<time>.*?)\] "GET (?P<uri>.*?) HTTP/1.\d" (?P<statuscode>\d+) \d+ "(?P<referral>.*?)" "(?P<useragent>.*?)"'
    logsearch = re.compile(logexpr).search
    apps = {}
    unknownapks = []
    knownapks = common.KnownApks()
    for logfile in glob.glob(os.path.join(logsdir,'access-*.log.gz')):
        if options.verbose:
            print '...' + logfile
        logdate = logfile[len(logsdir) + 1 + len('access-'):-7]
        p = subprocess.Popen(["zcat", logfile], stdout = subprocess.PIPE)
        matches = (logsearch(line) for line in p.stdout)
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

    # Calculate and write stats for total downloads...
    lst = []
    alldownloads = 0
    for app, count in apps.iteritems():
        lst.append(app + " " + str(count))
        if stats_to_carbon:
            carbon_send('fdroid.download.' + app.replace('.', '_'), count)
        alldownloads += count
    lst.append("ALL " + str(alldownloads))
    f = open('stats/total_downloads_app.txt', 'w')
    f.write('# Total downloads by application, since October 2011\n')
    for line in sorted(lst):
        f.write(line + '\n')
    f.close()

    # Calculate and write stats for repo types...
    repotypes = {}
    for app in metaapps:
        if len(app['Repo Type']) == 0:
            rtype = 'none'
        else:
            if app['Repo Type'] == 'srclib':
                rtype = common.getsrclibvcs(app['Repo'])
            else:
                rtype = app['Repo Type']
        if rtype in repotypes:
            repotypes[rtype] += 1;
        else:
            repotypes[rtype] = 1
    f = open('stats/repotypes.txt', 'w')
    for rtype, count in repotypes.iteritems():
        f.write(rtype + ' ' + str(count) + '\n')
    f.close()

    # Calculate and write stats for update check modes...
    ucms = {}
    for app in metaapps:
        checkmode = app['Update Check Mode'].split('/')[0]
        if checkmode in ucms:
            ucms[checkmode] += 1;
        else:
            ucms[checkmode] = 1
    f = open('stats/update_check_modes.txt', 'w')
    for checkmode, count in ucms.iteritems():
        f.write(checkmode + ' ' + str(count) + '\n')
    f.close()

    # Calculate and write stats for licenses...
    licenses = {}
    for app in metaapps:
        license = app['License']
        if license in licenses:
            licenses[license] += 1;
        else:
            licenses[license] = 1
    f = open('stats/licenses.txt', 'w')
    for license, count in licenses.iteritems():
        f.write(license + ' ' + str(count) + '\n')
    f.close()

    # Write list of latest apps added to the repo...
    latest = knownapks.getlatest(10)
    f = open('stats/latestapps.txt', 'w')
    for app in latest:
        f.write(app + '\n')
    f.close()

    if len(unknownapks) > 0:
        print '\nUnknown apks:'
        for apk in unknownapks:
            print apk

    print "Finished."

if __name__ == "__main__":
    main()

