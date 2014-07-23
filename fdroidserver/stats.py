#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# stats.py - part of the FDroid server tools
# Copyright (C) 2010-13, Ciaran Gultnieks, ciaran@ciarang.com
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
import re
import time
import traceback
import glob
import json
from optparse import OptionParser
import paramiko
import socket
import logging
import common
import metadata
import subprocess
from collections import Counter


def carbon_send(key, value):
    s = socket.socket()
    s.connect((config['carbon_host'], config['carbon_port']))
    msg = '%s %d %d\n' % (key, value, int(time.time()))
    s.sendall(msg)
    s.close()

options = None
config = None


def main():

    global options, config

    # Parse command line...
    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help="Restrict output to warnings and errors")
    parser.add_option("-d", "--download", action="store_true", default=False,
                      help="Download logs we don't have")
    parser.add_option("--recalc", action="store_true", default=False,
                      help="Recalculate aggregate stats - use when changes "
                      "have been made that would invalidate old cached data.")
    parser.add_option("--nologs", action="store_true", default=False,
                      help="Don't do anything logs-related")
    (options, args) = parser.parse_args()

    config = common.read_config(options)

    if not config['update_stats']:
        logging.info("Stats are disabled - check your configuration")
        sys.exit(1)

    # Get all metadata-defined apps...
    metaapps = [a for a in metadata.read_metadata() if not a['Disabled']]

    statsdir = 'stats'
    logsdir = os.path.join(statsdir, 'logs')
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
            logging.info('Retrieving logs')
            ssh = paramiko.SSHClient()
            ssh.load_system_host_keys()
            ssh.connect('f-droid.org', username='fdroid', timeout=10,
                        key_filename=config['webserver_keyfile'])
            ftp = ssh.open_sftp()
            ftp.get_channel().settimeout(60)
            logging.info("...connected")

            ftp.chdir('logs')
            files = ftp.listdir()
            for f in files:
                if f.startswith('access-') and f.endswith('.log.gz'):

                    destpath = os.path.join(logsdir, f)
                    destsize = ftp.stat(f).st_size
                    if (not os.path.exists(destpath) or
                            os.path.getsize(destpath) != destsize):
                        logging.debug("...retrieving " + f)
                        ftp.get(f, destpath)
        except Exception:
            traceback.print_exc()
            sys.exit(1)
        finally:
            # Disconnect
            if ftp is not None:
                ftp.close()
            if ssh is not None:
                ssh.close()

    knownapks = common.KnownApks()
    unknownapks = []

    if not options.nologs:
        # Process logs
        logging.info('Processing logs...')
        appscount = Counter()
        appsvercount = Counter()
        logexpr = '(?P<ip>[.:0-9a-fA-F]+) - - \[(?P<time>.*?)\] ' + \
            '"GET (?P<uri>.*?) HTTP/1.\d" (?P<statuscode>\d+) ' + \
            '\d+ "(?P<referral>.*?)" "(?P<useragent>.*?)"'
        logsearch = re.compile(logexpr).search
        for logfile in glob.glob(os.path.join(logsdir, 'access-*.log.gz')):
            logging.debug('...' + logfile)

            # Get the date for this log - e.g. 2012-02-28
            thisdate = os.path.basename(logfile)[7:-7]

            agg_path = os.path.join(datadir, thisdate + '.json')
            if not options.recalc and os.path.exists(agg_path):
                # Use previously calculated aggregate data
                with open(agg_path, 'r') as f:
                    today = json.load(f)

            else:
                # Calculate from logs...

                today = {
                    'apps': Counter(),
                    'appsver': Counter(),
                    'unknown': []
                    }

                p = subprocess.Popen(["zcat", logfile], stdout=subprocess.PIPE)
                matches = (logsearch(line) for line in p.stdout)
                for match in matches:
                    if match and match.group('statuscode') == '200':
                        uri = match.group('uri')
                        if uri.endswith('.apk'):
                            _, apkname = os.path.split(uri)
                            app = knownapks.getapp(apkname)
                            if app:
                                appid, _ = app
                                today['apps'][appid] += 1
                                # Strip the '.apk' from apkname
                                appver = apkname[:-4]
                                today['appsver'][appver] += 1
                            else:
                                if apkname not in today['unknown']:
                                    today['unknown'].append(apkname)

                # Save calculated aggregate data for today to cache
                with open(agg_path, 'w') as f:
                    json.dump(today, f)

            # Add today's stats (whether cached or recalculated) to the total
            for appid in today['apps']:
                appscount[appid] += today['apps'][appid]
            for appid in today['appsver']:
                appsvercount[appid] += today['appsver'][appid]
            for uk in today['unknown']:
                if uk not in unknownapks:
                    unknownapks.append(uk)

        # Calculate and write stats for total downloads...
        lst = []
        alldownloads = 0
        for appid in appscount:
            count = appscount[appid]
            lst.append(appid + " " + str(count))
            if config['stats_to_carbon']:
                carbon_send('fdroid.download.' + appid.replace('.', '_'),
                            count)
            alldownloads += count
        lst.append("ALL " + str(alldownloads))
        f = open('stats/total_downloads_app.txt', 'w')
        f.write('# Total downloads by application, since October 2011\n')
        for line in sorted(lst):
            f.write(line + '\n')
        f.close()

        f = open('stats/total_downloads_app_version.txt', 'w')
        f.write('# Total downloads by application and version, '
                'since October 2011\n')
        lst = []
        for appver in appsvercount:
            count = appsvercount[appver]
            lst.append(appver + " " + str(count))
        for line in sorted(lst):
            f.write(line + "\n")
        f.close()

    # Calculate and write stats for repo types...
    logging.info("Processing repo types...")
    repotypes = Counter()
    for app in metaapps:
        if len(app['Repo Type']) == 0:
            rtype = 'none'
        else:
            if app['Repo Type'] == 'srclib':
                rtype = common.getsrclibvcs(app['Repo'])
            else:
                rtype = app['Repo Type']
        repotypes[rtype] += 1
    f = open('stats/repotypes.txt', 'w')
    for rtype in repotypes:
        count = repotypes[rtype]
        f.write(rtype + ' ' + str(count) + '\n')
    f.close()

    # Calculate and write stats for update check modes...
    logging.info("Processing update check modes...")
    ucms = Counter()
    for app in metaapps:
        checkmode = app['Update Check Mode']
        if checkmode.startswith('RepoManifest/'):
            checkmode = checkmode[:12]
        if checkmode.startswith('Tags '):
            checkmode = checkmode[:4]
        ucms[checkmode] += 1
    f = open('stats/update_check_modes.txt', 'w')
    for checkmode in ucms:
        count = ucms[checkmode]
        f.write(checkmode + ' ' + str(count) + '\n')
    f.close()

    logging.info("Processing categories...")
    ctgs = Counter()
    for app in metaapps:
        for category in app['Categories']:
            ctgs[category] += 1
    f = open('stats/categories.txt', 'w')
    for category in ctgs:
        count = ctgs[category]
        f.write(category + ' ' + str(count) + '\n')
    f.close()

    logging.info("Processing antifeatures...")
    afs = Counter()
    for app in metaapps:
        if app['AntiFeatures'] is None:
            continue
        antifeatures = [a.strip() for a in app['AntiFeatures'].split(',')]
        for antifeature in antifeatures:
            afs[antifeature] += 1
    f = open('stats/antifeatures.txt', 'w')
    for antifeature in afs:
        count = afs[antifeature]
        f.write(antifeature + ' ' + str(count) + '\n')
    f.close()

    # Calculate and write stats for licenses...
    logging.info("Processing licenses...")
    licenses = Counter()
    for app in metaapps:
        license = app['License']
        licenses[license] += 1
    f = open('stats/licenses.txt', 'w')
    for license in licenses:
        count = licenses[license]
        f.write(license + ' ' + str(count) + '\n')
    f.close()

    # Write list of latest apps added to the repo...
    logging.info("Processing latest apps...")
    latest = knownapks.getlatest(10)
    f = open('stats/latestapps.txt', 'w')
    for app in latest:
        f.write(app + '\n')
    f.close()

    if unknownapks:
        logging.info('\nUnknown apks:')
        for apk in unknownapks:
            logging.info(apk)

    logging.info("Finished.")

if __name__ == "__main__":
    main()
