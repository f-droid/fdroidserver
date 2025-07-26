#!/usr/bin/env python3
#
# This generates a list of ISO_3166-1 alpha 2 country codes for use in lint.

import collections
import os
import re
import sys
import tempfile

import requests
import requests_cache


def main():
    # we want all the data
    url = 'https://api.worldbank.org/v2/country?format=json&per_page=500'
    r = requests.get(url, timeout=30)
    data = r.json()
    if data[0]['pages'] != 1:
        print(
            'ERROR: %d pages in data, this script only reads one page!'
            % data[0]['pages']
        )
        sys.exit(1)

    iso2Codes = set()
    ISO3166_1_alpha_2_codes = set()
    names = dict()
    regions = collections.defaultdict(set)
    for country in data[1]:
        iso2Code = country['iso2Code']
        iso2Codes.add(iso2Code)
        if country['region']['value'] == 'Aggregates':
            continue
        if re.match(r'[A-Z][A-Z]', iso2Code):
            ISO3166_1_alpha_2_codes.add(iso2Code)
            names[iso2Code] = country['name']
            regions[country['region']['value']].add(country['name'])
    for code in sorted(ISO3166_1_alpha_2_codes):
        print(f"    '{code}',  # " + names[code])


if __name__ == "__main__":
    requests_cache.install_cache(
        os.path.join(tempfile.gettempdir(), os.path.basename(__file__) + '.cache')
    )
    main()
