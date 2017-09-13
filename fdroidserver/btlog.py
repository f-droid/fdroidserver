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


import collections
import git
import glob
import os
import json
import logging
import requests
import shutil
import tempfile
import xml.dom.minidom
import zipfile
from argparse import ArgumentParser

from . import _
from . import common
from . import server
from .exception import FDroidException


options = None


def make_binary_transparency_log(repodirs, btrepo='binary_transparency',
                                 url=None,
                                 commit_title='fdroid update'):
    '''Log the indexes in a standalone git repo to serve as a "binary
    transparency" log.

    see: https://www.eff.org/deeplinks/2014/02/open-letter-to-tech-companies

    '''

    logging.info('Committing indexes to ' + btrepo)
    if os.path.exists(os.path.join(btrepo, '.git')):
        gitrepo = git.Repo(btrepo)
    else:
        if not os.path.exists(btrepo):
            os.mkdir(btrepo)
        gitrepo = git.Repo.init(btrepo)

        if not url:
            url = common.config['repo_url'].rstrip('/')
        with open(os.path.join(btrepo, 'README.md'), 'w') as fp:
            fp.write("""
# Binary Transparency Log for %s

This is a log of the signed app index metadata.  This is stored in a
git repo, which serves as an imperfect append-only storage mechanism.
People can then check that any file that they received from that
F-Droid repository was a publicly released file.

For more info on this idea:
* https://wiki.mozilla.org/Security/Binary_Transparency
""" % url[:url.rindex('/')])  # strip '/repo'
        gitrepo.index.add(['README.md', ])
        gitrepo.index.commit('add README')

    for repodir in repodirs:
        cpdir = os.path.join(btrepo, repodir)
        if not os.path.exists(cpdir):
            os.mkdir(cpdir)
        for f in ('index.xml', 'index-v1.json'):
            repof = os.path.join(repodir, f)
            if not os.path.exists(repof):
                continue
            dest = os.path.join(cpdir, f)
            if f.endswith('.xml'):
                doc = xml.dom.minidom.parse(repof)
                output = doc.toprettyxml(encoding='utf-8')
                with open(dest, 'wb') as f:
                    f.write(output)
            elif f.endswith('.json'):
                with open(repof) as fp:
                    output = json.load(fp, object_pairs_hook=collections.OrderedDict)
                with open(dest, 'w') as fp:
                    json.dump(output, fp, indent=2)
            gitrepo.index.add([repof, ])
        for f in ('index.jar', 'index-v1.jar'):
            repof = os.path.join(repodir, f)
            if not os.path.exists(repof):
                continue
            dest = os.path.join(cpdir, f)
            jarin = zipfile.ZipFile(repof, 'r')
            jarout = zipfile.ZipFile(dest, 'w')
            for info in jarin.infolist():
                if info.filename.startswith('META-INF/'):
                    jarout.writestr(info, jarin.read(info.filename))
            jarout.close()
            jarin.close()
            gitrepo.index.add([repof, ])

        output_files = []
        for root, dirs, files in os.walk(repodir):
            for f in files:
                output_files.append(os.path.relpath(os.path.join(root, f), repodir))
        output = collections.OrderedDict()
        for f in sorted(output_files):
            repofile = os.path.join(repodir, f)
            stat = os.stat(repofile)
            output[f] = (
                stat.st_size,
                stat.st_ctime_ns,
                stat.st_mtime_ns,
                stat.st_mode,
                stat.st_uid,
                stat.st_gid,
            )
        fslogfile = os.path.join(cpdir, 'filesystemlog.json')
        with open(fslogfile, 'w') as fp:
            json.dump(output, fp, indent=2)
        gitrepo.index.add([os.path.join(repodir, 'filesystemlog.json'), ])

        for f in glob.glob(os.path.join(cpdir, '*.HTTP-headers.json')):
            gitrepo.index.add([os.path.join(repodir, os.path.basename(f)), ])

    gitrepo.index.commit(commit_title)


def main():
    global options

    parser = ArgumentParser(usage="%(prog)s [options]")
    common.setup_global_opts(parser)
    parser.add_argument("--git-repo",
                        default=os.path.join(os.getcwd(), 'binary_transparency'),
                        help=_("Path to the git repo to use as the log"))
    parser.add_argument("-u", "--url", default='https://f-droid.org',
                        help=_("The base URL for the repo to log (default: https://f-droid.org)"))
    parser.add_argument("--git-remote", default=None,
                        help=_("Push the log to this git remote repository"))
    options = parser.parse_args()

    if options.verbose:
        logging.getLogger("requests").setLevel(logging.INFO)
        logging.getLogger("urllib3").setLevel(logging.INFO)
    else:
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

    if not os.path.exists(options.git_repo):
        raise FDroidException(
            '"%s" does not exist! Create it, or use --git-repo' % options.git_repo)

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
            etag = None
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
        make_binary_transparency_log(repodirs, options.git_repo, options.url, 'fdroid btlog')
    if options.git_remote:
        server.push_binary_transparency(options.git_repo, options.git_remote)
    shutil.rmtree(tempdirbase, ignore_errors=True)


if __name__ == "__main__":
    main()
