#!/usr/bin/env python3
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
from argparse import ArgumentParser
import paramiko
import socket
import logging
import subprocess
from collections import Counter

from . import _
from . import common
from . import metadata


def carbon_send(key, value):
    s = socket.socket()
    s.connect((config['carbon_host'], config['carbon_port']))
    msg = '%s %d %d\n' % (key, value, int(time.time()))
    s.sendall(msg)
    s.close()


options = None
config = None


def most_common_stable(counts):
    pairs = []
    for s in counts:
        pairs.append((s, counts[s]))
    return sorted(pairs, key=lambda t: (-t[1], t[0]))


def main():

    global options, config

    # Parse command line...
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument("-d", "--download", action="store_true", default=False,
                        help=_("Download logs we don't have"))
    parser.add_argument("--recalc", action="store_true", default=False,
                        help=_("Recalculate aggregate stats - use when changes "
                               "have been made that would invalidate old cached data."))
    parser.add_argument("--nologs", action="store_true", default=False,
                        help=_("Don't do anything logs-related"))
    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    metadata.warnings_action = options.W

    config = common.read_config(options)

    if not config['update_stats']:
        logging.info("Stats are disabled - set \"update_stats = True\" in your config.yml")
        sys.exit(1)

    # Get all metadata-defined apps...
    allmetaapps = [app for app in metadata.read_metadata().values()]
    metaapps = [app for app in allmetaapps if not app.Disabled]

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
            ssh.connect(config['stats_server'], username=config['stats_user'],
                        timeout=10, key_filename=config['webserver_keyfile'])
            ftp = ssh.open_sftp()
            ftp.get_channel().settimeout(60)
            logging.info("...connected")

            ftp.chdir('logs')
            files = ftp.listdir()
            for f in files:
                if f.startswith('access-') and f.endswith('.log.gz'):

                    destpath = os.path.join(logsdir, f)
                    destsize = ftp.stat(f).st_size
                    if not os.path.exists(destpath) \
                       or os.path.getsize(destpath) != destsize:
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
        logexpr = r'(?P<ip>[.:0-9a-fA-F]+) - - \[(?P<time>.*?)\] ' \
            + r'"GET (?P<uri>.*?) HTTP/1.\d" (?P<statuscode>\d+) ' \
            + r'\d+ "(?P<referral>.*?)" "(?P<useragent>.*?)"'
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
                    if not match:
                        continue
                    if match.group('statuscode') != '200':
                        continue
                    if match.group('ip') in config['stats_ignore']:
                        continue
                    uri = match.group('uri')
                    if not uri.endswith('.apk'):
                        continue
                    _ignored, apkname = os.path.split(uri)
                    app = knownapks.getapp(apkname)
                    if app:
                        appid, _ignored = app
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
        with open(os.path.join(statsdir, 'total_downloads_app.txt'), 'w') as f:
            f.write('# Total downloads by application, since October 2011\n')
            for line in sorted(lst):
                f.write(line + '\n')

        lst = []
        for appver in appsvercount:
            count = appsvercount[appver]
            lst.append(appver + " " + str(count))

        with open(os.path.join(statsdir, 'total_downloads_app_version.txt'), 'w') as f:
            f.write('# Total downloads by application and version, '
                    'since October 2011\n')
            for line in sorted(lst):
                f.write(line + "\n")

    # Calculate and write stats for repo types...
    logging.info("Processing repo types...")
    repotypes = Counter()
    for app in metaapps:
        rtype = app.RepoType or 'none'
        if rtype == 'srclib':
            rtype = common.getsrclibvcs(app.Repo)
        repotypes[rtype] += 1
    with open(os.path.join(statsdir, 'repotypes.txt'), 'w') as f:
        for rtype, count in most_common_stable(repotypes):
            f.write(rtype + ' ' + str(count) + '\n')

    # Calculate and write stats for update check modes...
    logging.info("Processing update check modes...")
    ucms = Counter()
    for app in metaapps:
        checkmode = app.UpdateCheckMode
        if checkmode.startswith('RepoManifest/'):
            checkmode = checkmode[:12]
        if checkmode.startswith('Tags '):
            checkmode = checkmode[:4]
        ucms[checkmode] += 1
    with open(os.path.join(statsdir, 'update_check_modes.txt'), 'w') as f:
        for checkmode, count in most_common_stable(ucms):
            f.write(checkmode + ' ' + str(count) + '\n')

    logging.info("Processing categories...")
    ctgs = Counter()
    for app in metaapps:
        for category in app.Categories:
            ctgs[category] += 1
    with open(os.path.join(statsdir, 'categories.txt'), 'w') as f:
        for category, count in most_common_stable(ctgs):
            f.write(category + ' ' + str(count) + '\n')

    logging.info("Processing antifeatures...")
    afs = Counter()
    for app in metaapps:
        if app.AntiFeatures is None:
            continue
        for antifeature in app.AntiFeatures:
            afs[antifeature] += 1
    with open(os.path.join(statsdir, 'antifeatures.txt'), 'w') as f:
        for antifeature, count in most_common_stable(afs):
            f.write(antifeature + ' ' + str(count) + '\n')

    # Calculate and write stats for licenses...
    logging.info("Processing licenses...")
    licenses = Counter()
    for app in metaapps:
        license = app.License
        licenses[license] += 1
    with open(os.path.join(statsdir, 'licenses.txt'), 'w') as f:
        for license, count in most_common_stable(licenses):
            f.write(license + ' ' + str(count) + '\n')

    # Write list of disabled apps...
    logging.info("Processing disabled apps...")
    disabled = [app.id for app in allmetaapps if app.Disabled]
    with open(os.path.join(statsdir, 'disabled_apps.txt'), 'w') as f:
        for appid in sorted(disabled):
            f.write(appid + '\n')

    # Write list of latest apps added to the repo...
    logging.info("Processing latest apps...")
    latest = knownapks.getlatest(10)
    with open(os.path.join(statsdir, 'latestapps.txt'), 'w') as f:
        for appid in latest:
            f.write(appid + '\n')

    if unknownapks:
        logging.info('\nUnknown apks:')
        for apk in unknownapks:
            logging.info(apk)

    logging.info(_("Finished"))


if __name__ == "__main__":
    main()
