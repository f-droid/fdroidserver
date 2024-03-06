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

import logging
import os
import requests
import time
import urllib
from requests.adapters import HTTPAdapter, Retry
from requests.exceptions import ChunkedEncodingError

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
        except ChunkedEncodingError as err:
            if i == retries:
                raise err
            logging.warning('Download interrupted, retrying...')
            time.sleep(backoff_factor * 2**i)
    raise ValueError("retries must be >= 0")


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
