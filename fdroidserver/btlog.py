#!/usr/bin/env python3
#
# btlog.py - part of the FDroid server tools
# Copyright (C) 2017, Hans-Christoph Steiner <hans@eds.org>
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

# This is for creating a binary transparency log in a git repo for any
# F-Droid repo accessible via HTTP.  It is meant to run very often,
# even once a minute in a cronjob, so it uses HEAD requests and the
# HTTP ETag to check if the file has changed.  HEAD requests should
# not count against the download counts.  This pattern of a HEAD then
# a GET is what fdroidclient uses to avoid ETags being abused as
# cookies. This also uses the same HTTP User Agent as the F-Droid
# client app so its not easy for the server to distinguish this from
# the F-Droid client.

import os
import json
import logging
import requests
import shutil
import sys
import tempfile
from argparse import ArgumentParser

from . import common


options = None


def main():
    global options

    parser = ArgumentParser(usage="%(prog)s [options]")
    common.setup_global_opts(parser)
    parser.add_argument("--git-repo",
                        default=os.path.join(os.getcwd(), 'binary_transparency'),
                        help="Path to the git repo to use as the log")
    parser.add_argument("-u", "--url", default='https://f-droid.org',
                        help="The base URL for the repo to log (default: https://f-droid.org)")
    parser.add_argument("--git-remote", default=None,
                        help="Create a repo signing key in a keystore")
    options = parser.parse_args()

    if options.verbose:
        logging.getLogger("requests").setLevel(logging.INFO)
        logging.getLogger("urllib3").setLevel(logging.INFO)
    else:
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

    if not os.path.exists(options.git_repo):
        logging.error('"' + options.git_repo + '/" does not exist! Create it, or use --git-repo')
        sys.exit(1)

    session = requests.Session()

    new_files = False
    repodirs = ('repo', 'archive')
    tempdirbase = tempfile.mkdtemp(prefix='.fdroid-btlog-')
    for repodir in repodirs:
        # TODO read HTTP headers for etag from git repo
        tempdir = os.path.join(tempdirbase, repodir)
        os.makedirs(tempdir, exist_ok=True)
        gitrepodir = os.path.join(options.git_repo, repodir)
        os.makedirs(gitrepodir, exist_ok=True)
        for f in ('index.jar', 'index.xml', 'index-v1.jar', 'index-v1.json'):
            dlfile = os.path.join(tempdir, f)
            dlurl = options.url + '/' + repodir + '/' + f
            http_headers_file = os.path.join(gitrepodir, f + '.HTTP-headers.json')

            headers = {
                'User-Agent': 'F-Droid 0.102.3'
            }
            if os.path.exists(http_headers_file):
                with open(http_headers_file) as fp:
                    etag = json.load(fp)['ETag']

            r = session.head(dlurl, headers=headers, allow_redirects=False)
            if r.status_code != 200:
                logging.debug('HTTP Response (' + str(r.status_code) + '), did not download ' + dlurl)
                continue
            if etag and etag == r.headers.get('ETag'):
                logging.debug('ETag matches, did not download ' + dlurl)
                continue

            r = session.get(dlurl, headers=headers, allow_redirects=False)
            if r.status_code == 200:
                with open(dlfile, 'wb') as f:
                    for chunk in r:
                        f.write(chunk)

                dump = dict()
                for k, v in r.headers.items():
                    dump[k] = v
                with open(http_headers_file, 'w') as fp:
                    json.dump(dump, fp, indent=2, sort_keys=True)
                new_files = True

    if new_files:
        os.chdir(tempdirbase)
        common.make_binary_transparency_log(repodirs, options.git_repo, options.url,
                                            'fdroid btlog')
    shutil.rmtree(tempdirbase, ignore_errors=True)

if __name__ == "__main__":
    main()
