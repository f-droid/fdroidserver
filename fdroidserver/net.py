#!/usr/bin/env python3
#
# net.py - part of the FDroid server tools
# Copyright (C) 2015 Hans-Christoph Steiner <hans@eds.org>
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

import os

import requests


def download_file(url, local_filename=None, dldir='tmp'):
    filename = url.split('/')[-1]
    if local_filename is None:
        local_filename = os.path.join(dldir, filename)
    # the stream=True parameter keeps memory usage low
    r = requests.get(url, stream=True, allow_redirects=True)
    r.raise_for_status()
    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk:  # filter out keep-alive new chunks
                f.write(chunk)
                f.flush()
    return local_filename


def http_get(url, etag=None):
    """
    Downloads the content from the given URL by making a GET request.

    If an ETag is given, it will do a HEAD request first, to see if the content changed.

    :param url: The URL to download from.
    :param etag: The last ETag to be used for the request (optional).
    :return: A tuple consisting of:
        - The raw content that was downloaded or None if it did not change
        - The new eTag as returned by the HTTP request
    """
    headers = {'User-Agent': 'F-Droid'}
    # TODO disable TLS Session IDs and TLS Session Tickets
    #      (plain text cookie visible to anyone who can see the network traffic)
    if etag:
        r = requests.head(url, headers=headers)
        r.raise_for_status()
        if 'ETag' in r.headers and etag == r.headers['ETag']:
            return None, etag

    r = requests.get(url, headers=headers)
    r.raise_for_status()

    new_etag = None
    if 'ETag' in r.headers:
        new_etag = r.headers['ETag']

    return r.content, new_etag
