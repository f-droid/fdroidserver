#!/usr/bin/env python2
#
# This script is for updating the .pickle test files when there are changes to
# the default metadata, e.g. adding a new key/tag.

import glob
import pickle

for picklefile in glob.glob('*.pickle'):
    p = pickle.load(open(picklefile))

    for build in p['builds']:
        build['gradleprops'] = []

    pickle.dump(p, open(picklefile, 'w'))
