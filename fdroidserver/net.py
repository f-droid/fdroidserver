#!/usr/bin/env python3
#
# net.py - part of the FDroid server tools
# Copyright (C) 2015 Hans-Christoph Steiner <hans@eds.org>
# Copyright (C) 2022 FC Stegerman <flx@obfusk.net>
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

import copy
import logging
import os
import random
import requests
import tempfile
import time
import urllib
import urllib3
from requests.adapters import HTTPAdapter, Retry

from . import _, common

logger = logging.getLogger(__name__)

HEADERS = {'User-Agent': 'F-Droid'}


def download_file(url, local_filename=None, dldir='tmp', retries=3, backoff_factor=0.1):
    """Try hard to download the file, including retrying on failures.

    This has two retry cycles, one inside of the requests session, the
    other provided by this function.  The requests retry logic applies
    to failed DNS lookups, socket connections and connection timeouts,
    never to requests where data has made it to the server. This
    handles ChunkedEncodingError during transfer in its own retry
    loop.  This can result in more retries than are specified in the
    retries parameter.

    """
    filename = urllib.parse.urlparse(url).path.split('/')[-1]
    if local_filename is None:
        local_filename = os.path.join(dldir, filename)
    for i in range(retries + 1):
        if retries:
            max_retries = Retry(total=retries - i, backoff_factor=backoff_factor)
            adapter = HTTPAdapter(max_retries=max_retries)
            session = requests.Session()
            session.mount('http://', adapter)
            session.mount('https://', adapter)
        else:
            session = requests
        # the stream=True parameter keeps memory usage low
        r = session.get(
            url, stream=True, allow_redirects=True, headers=HEADERS, timeout=300
        )
        r.raise_for_status()
        try:
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk:  # filter out keep-alive new chunks
                        f.write(chunk)
                        f.flush()
            return local_filename
        except requests.exceptions.ChunkedEncodingError as err:
            if i == retries:
                raise err
            logger.warning('Download interrupted, retrying...')
            time.sleep(backoff_factor * 2**i)
    raise ValueError("retries must be >= 0")


def download_using_mirrors(mirrors, local_filename=None):
    """Try to download the file from any working mirror.

    Download the file that all URLs in the mirrors list point to,
    trying all the tricks, starting with the most private methods
    first.  The list of mirrors is converted into a list of mirror
    configurations to try, in order that the should be attempted.

    This builds mirror_configs_to_try using all possible combos to
    try.  If a mirror is marked with worksWithoutSNI: True, then this
    logic will try it twice: first without SNI, then again with SNI.

    """
    mirrors = common.parse_mirrors_config(mirrors)
    mirror_configs_to_try = []
    for mirror in mirrors:
        mirror_configs_to_try.append(mirror)
        if mirror.get('worksWithoutSNI'):
            m = copy.deepcopy(mirror)
            del m['worksWithoutSNI']
            mirror_configs_to_try.append(m)

    if not local_filename:
        for mirror in mirrors:
            filename = urllib.parse.urlparse(mirror['url']).path.split('/')[-1]
            if filename:
                break
        if filename:
            local_filename = os.path.join(common.get_cachedir(), filename)
        else:
            local_filename = tempfile.mkstemp(prefix='fdroid-')

    timeouts = (2, 10, 100)
    last_exception = None
    for timeout in timeouts:
        for mirror in mirror_configs_to_try:
            last_exception = None
            urllib3.util.ssl_.HAS_SNI = not mirror.get('worksWithoutSNI')
            try:
                # the stream=True parameter keeps memory usage low
                r = requests.get(
                    mirror['url'],
                    stream=True,
                    allow_redirects=False,
                    headers=HEADERS,
                    # add jitter to the timeout to be less predictable
                    timeout=timeout + random.randint(0, timeout),  # nosec B311
                )
                if r.status_code != 200:
                    raise requests.exceptions.HTTPError(r.status_code, response=r)
                with open(local_filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=1024):
                        if chunk:  # filter out keep-alive new chunks
                            f.write(chunk)
                            f.flush()
                return local_filename
            except (
                ConnectionError,
                requests.exceptions.ChunkedEncodingError,
                requests.exceptions.ConnectionError,
                requests.exceptions.ContentDecodingError,
                requests.exceptions.HTTPError,
                requests.exceptions.SSLError,
                requests.exceptions.StreamConsumedError,
                requests.exceptions.Timeout,
                requests.exceptions.UnrewindableBodyError,
            ) as e:
                last_exception = e
                logger.debug(_('Retrying failed download: %s') % str(e))
    # if it hasn't succeeded by now, then give up and raise last exception
    if last_exception:
        raise last_exception


def http_get(url, etag=None, timeout=600):
    """Download the content from the given URL by making a GET request.

    If an ETag is given, it will do a HEAD request first, to see if the content changed.

    Parameters
    ----------
    url
      The URL to download from.
    etag
      The last ETag to be used for the request (optional).

    Returns
    -------
    A tuple consisting of:
      - The raw content that was downloaded or None if it did not change
      - The new eTag as returned by the HTTP request
    """
    # TODO disable TLS Session IDs and TLS Session Tickets
    #      (plain text cookie visible to anyone who can see the network traffic)
    if etag:
        r = requests.head(url, headers=HEADERS, timeout=timeout)
        r.raise_for_status()
        if 'ETag' in r.headers and etag == r.headers['ETag']:
            return None, etag

    r = requests.get(url, headers=HEADERS, timeout=timeout)
    r.raise_for_status()

    new_etag = None
    if 'ETag' in r.headers:
        new_etag = r.headers['ETag']

    return r.content, new_etag
