#!/usr/bin/env python3

import io
import ipaddress
import json
import logging
import os
import socket
import subprocess
import sys
import zipfile
from argparse import ArgumentParser
from urllib.parse import urlparse

from . import _
from . import common
from . import net
from . import update

options = None


def main():
    global options

    parser = ArgumentParser(usage=_("%(prog)s [options] url"))
    common.setup_global_opts(parser)
    parser.add_argument("url", nargs='?', help=_("Base URL to mirror"))
    parser.add_argument("--archive", action='store_true', default=False,
                        help=_("Also mirror the full archive section"))
    parser.add_argument("--output-dir", default=os.getcwd(),
                        help=_("The directory to write the mirror to"))
    options = parser.parse_args()

    if options.url is None:
        logging.error(_('A URL is required as an argument!') + '\n')
        parser.print_help()
        sys.exit(1)

    baseurl = options.url
    basedir = options.output_dir

    url = urlparse(baseurl)
    hostname = url.netloc
    ip = None
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    if hostname == 'f-droid.org' \
       or (ip is not None and hostname in socket.gethostbyname_ex('f-droid.org')[2]):
        print(_('ERROR: this command should never be used to mirror f-droid.org!\n'
                'A full mirror of f-droid.org requires more than 200GB.'))
        sys.exit(1)

    path = url.path.rstrip('/')
    if path.endswith('repo') or path.endswith('archive'):
        logging.error(_('Do not include "{path}" in URL!').format(path=path.split('/')[-1]))
        sys.exit(1)
    elif not path.endswith('fdroid'):
        logging.warning(_('{url} does not end with "fdroid", check the URL path!')
                        .format(url=baseurl))

    icondirs = ['icons', ]
    for density in update.screen_densities:
        icondirs.append('icons-' + density)

    if options.archive:
        sections = ('repo', 'archive')
    else:
        sections = ('repo', )

    for section in sections:
        sectionurl = baseurl + '/' + section
        sectiondir = os.path.join(basedir, section)
        repourl = sectionurl + '/index-v1.jar'

        content, etag = net.http_get(repourl)
        with zipfile.ZipFile(io.BytesIO(content)) as zip:
            jsoncontents = zip.open('index-v1.json').read()

        os.makedirs(sectiondir, exist_ok=True)
        os.chdir(sectiondir)
        for icondir in icondirs:
            os.makedirs(os.path.join(sectiondir, icondir), exist_ok=True)

        data = json.loads(jsoncontents.decode('utf-8'))
        urls = ''
        for packageName, packageList in data['packages'].items():
            for package in packageList:
                to_fetch = []
                for k in ('apkName', 'srcname'):
                    if k in package:
                        to_fetch.append(package[k])
                    elif k == 'apkName':
                        logging.error(_('{appid} is missing {name}')
                                      .format(appid=package['packageName'], name=k))
                for f in to_fetch:
                    if not os.path.exists(f) \
                       or (f.endswith('.apk') and os.path.getsize(f) != package['size']):
                        url = sectionurl + '/' + f
                        urls += url + '\n'
                        urls += url + '.asc\n'

        for app in data['apps']:
            localized = app.get('localized')
            if localized:
                for locale, d in localized.items():
                    for k in update.GRAPHIC_NAMES:
                        f = d.get(k)
                        if f:
                            urls += '/'.join((sectionurl, locale, f)) + '\n'
                    for k in update.SCREENSHOT_DIRS:
                        filelist = d.get(k)
                        if filelist:
                            for f in filelist:
                                urls += '/'.join((sectionurl, locale, k, f)) + '\n'

        with open('.rsync-input-file', 'w') as fp:
            fp.write(urls)
        subprocess.call(['wget', '--continue', '--user-agent="fdroid mirror"',
                         '--input-file=.rsync-input-file'])
        os.remove('.rsync-input-file')

        urls = dict()
        for app in data['apps']:
            if 'icon' not in app:
                logging.error(_('no "icon" in {appid}').format(appid=app['packageName']))
                continue
            icon = app['icon']
            for icondir in icondirs:
                url = sectionurl + '/' + icondir + '/' + icon
                if icondir not in urls:
                    urls[icondir] = ''
                urls[icondir] += url + '\n'

        for icondir in icondirs:
            os.chdir(os.path.join(basedir, section, icondir))
            with open('.rsync-input-file', 'w') as fp:
                fp.write(urls[icondir])
            subprocess.call(['wget', '--continue', '--input-file=.rsync-input-file'])
            os.remove('.rsync-input-file')


if __name__ == "__main__":
    main()
