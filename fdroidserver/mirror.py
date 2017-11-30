#!/usr/bin/env python3

import ipaddress
import logging
import os
import posixpath
import socket
import subprocess
import sys
from argparse import ArgumentParser
import urllib.parse

from . import _
from . import common
from . import index
from . import update

options = None


def _run_wget(path, urls):
    if options.verbose:
        verbose = '--verbose'
    else:
        verbose = '--no-verbose'

    if not urls:
        return
    logging.debug(_('Running wget in {path}').format(path=path))
    os.makedirs(path, exist_ok=True)
    os.chdir(path)
    urls_file = '.fdroid-mirror-wget-input-file'
    with open(urls_file, 'w') as fp:
        for url in urls:
            fp.write(url.split('?')[0] + '\n')  # wget puts query string in the filename
    subprocess.call(['wget', verbose, '--continue', '--user-agent="fdroid mirror"',
                     '--input-file=' + urls_file])
    os.remove(urls_file)


def main():
    global options

    parser = ArgumentParser(usage=_("%(prog)s [options] url"))
    common.setup_global_opts(parser)
    parser.add_argument("url", nargs='?',
                        help=_('Base URL to mirror, can include the index signing key '
                               + 'using the query string: ?fingerprint='))
    parser.add_argument("--archive", action='store_true', default=False,
                        help=_("Also mirror the full archive section"))
    parser.add_argument("--output-dir", default=None,
                        help=_("The directory to write the mirror to"))
    options = parser.parse_args()

    if options.url is None:
        logging.error(_('A URL is required as an argument!') + '\n')
        parser.print_help()
        sys.exit(1)

    scheme, hostname, path, params, query, fragment = urllib.parse.urlparse(options.url)
    fingerprint = urllib.parse.parse_qs(query).get('fingerprint')

    def _append_to_url_path(*args):
        '''Append the list of path components to URL, keeping the rest the same'''
        newpath = posixpath.join(path, *args)
        return urllib.parse.urlunparse((scheme, hostname, newpath, params, query, fragment))

    if fingerprint:
        config = common.read_config(options)
        if not ('jarsigner' in config or 'apksigner' in config):
            logging.error(_('Java JDK not found! Install in standard location or set java_paths!'))
            sys.exit(1)

        def _get_index(section, etag=None):
            url = _append_to_url_path(section)
            return index.download_repo_index(url, etag=etag)
    else:
        def _get_index(section, etag=None):
            import io
            import json
            import zipfile
            from . import net
            url = _append_to_url_path(section, 'index-v1.jar')
            content, etag = net.http_get(url)
            with zipfile.ZipFile(io.BytesIO(content)) as zip:
                jsoncontents = zip.open('index-v1.json').read()
            data = json.loads(jsoncontents.decode('utf-8'))
            return data, etag

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

    path = path.rstrip('/')
    if path.endswith('repo') or path.endswith('archive'):
        logging.warning(_('Do not include "{path}" in URL!')
                        .format(path=path.split('/')[-1]))
    elif not path.endswith('fdroid'):
        logging.warning(_('{url} does not end with "fdroid", check the URL path!')
                        .format(url=options.url))

    icondirs = ['icons', ]
    for density in update.screen_densities:
        icondirs.append('icons-' + density)

    if options.output_dir:
        basedir = options.output_dir
    else:
        basedir = os.path.join(os.getcwd(), hostname, path.strip('/'))
        os.makedirs(basedir, exist_ok=True)

    if options.archive:
        sections = ('repo', 'archive')
    else:
        sections = ('repo', )

    for section in sections:
        sectiondir = os.path.join(basedir, section)

        data, etag = _get_index(section)

        os.makedirs(sectiondir, exist_ok=True)
        os.chdir(sectiondir)
        for icondir in icondirs:
            os.makedirs(os.path.join(sectiondir, icondir), exist_ok=True)

        urls = []
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
                        urls.append(_append_to_url_path(section, f))
                        urls.append(_append_to_url_path(section, f + '.asc'))
        _run_wget(sectiondir, urls)

        for app in data['apps']:
            localized = app.get('localized')
            if localized:
                for locale, d in localized.items():
                    urls = []
                    components = (section, app['packageName'], locale)
                    for k in update.GRAPHIC_NAMES:
                        f = d.get(k)
                        if f:
                            filepath_tuple = components + (f, )
                            urls.append(_append_to_url_path(*filepath_tuple))
                    _run_wget(os.path.join(basedir, *components), urls)
                    for k in update.SCREENSHOT_DIRS:
                        urls = []
                        filelist = d.get(k)
                        if filelist:
                            components = (section, app['packageName'], locale, k)
                            for f in filelist:
                                filepath_tuple = components + (f, )
                                urls.append(_append_to_url_path(*filepath_tuple))
                            _run_wget(os.path.join(basedir, *components), urls)

        urls = dict()
        for app in data['apps']:
            if 'icon' not in app:
                logging.error(_('no "icon" in {appid}').format(appid=app['packageName']))
                continue
            icon = app['icon']
            for icondir in icondirs:
                url = _append_to_url_path(section, icondir, icon)
                if icondir not in urls:
                    urls[icondir] = []
                urls[icondir].append(url)

        for icondir in icondirs:
            _run_wget(os.path.join(basedir, section, icondir), urls[icondir])


if __name__ == "__main__":
    main()
