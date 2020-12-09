#!/usr/bin/env python3
#
# Test that the parsing of the .yml metadata format didn't change from last
# released version. This uses the commit ID of the release tags,
# rather than the release tag itself so that contributor forks do not
# need to include the tags in them for this test to work.
#
# This is for running manual tests when changing the metadata format.
# The idea is to test changes using all of the files in
# fdroiddata.git.  To run it, do:
#
#   cd fdroidserver/tests
#   cp dump_internal_metadata_format.py dump.py # since this isn't in old commits
#   git checkout 0.7.0  # or any old commit of your choosing
#   cd ../../fdroiddata
#   ../fdroidserver/tests/dump.py
#   mv metadata/dump metadata/dump_0.7.0
#   cd ../fdroidserver
#   git checkout master
#   cd ../fdroiddata
#   ../fdroidserver/tests/dump.py
#   meld metadata/dump_0.7.0 metadata/dump_0.7.0-179-ge85486a/

import git
import inspect
import optparse
import os
import sys
import yaml

localmodule = os.path.realpath(
    os.path.join(os.path.dirname(inspect.getfile(inspect.currentframe())), '..'))
if localmodule not in sys.path:
    sys.path.insert(0, localmodule)

import fdroidserver.common  # noqa
import fdroidserver.metadata  # noqa


def _build_yaml_representer(dumper, data):
    '''Creates a YAML representation of a Build instance'''
    if hasattr(data, 'append_flag'):
        # for 0.7.0 and earlier, before https://gitlab.com/fdroid/fdroidserver/merge_requests/210
        del(data._modified)
        readdict = data.__dict__
    else:
        readdict = data

    # these key names were all renamed in
    # https://gitlab.com/fdroid/fdroidserver/merge_requests/210
    output = dict()
    for k, v in readdict.items():
        if k == 'vercode':
            output['versionCode'] = v
        elif k == 'version':
            output['versionName'] = v
        elif k == 'update':
            output['androidupdate'] = v
        else:
            output[k] = v

    return dumper.represent_dict(output)


parser = optparse.OptionParser()
parser.add_option("-v", "--verbose", action="store_true", default=False,
                  help="Spew out even more information than normal")
(fdroidserver.common.options, args) = parser.parse_args(['--verbose'])

if not os.path.isdir('metadata'):
    print("This script must be run in an F-Droid data folder with a 'metadata' subdir!")
    sys.exit(1)

# these need to be set to prevent code running on None, only
# 'accepted_formats' is actually used in metadata.py
config = dict()
config['sdk_path'] = os.getenv('ANDROID_HOME') or '/opt/android-sdk'
config['ndk_paths'] = dict()
config['accepted_formats'] = ['yml']
fdroidserver.common.config = config

repo = git.Repo(localmodule)
savedir = os.path.join('metadata', 'dump_' + repo.git.describe())
if not os.path.isdir(savedir):
    os.mkdir(savedir)

apps = fdroidserver.metadata.read_metadata()
for appid, app in apps.items():
    savepath = os.path.join(savedir, appid + '.yaml')
    if hasattr(app, 'attr_to_field'):
        # for 0.7.0 and earlier, before https://gitlab.com/fdroid/fdroidserver/merge_requests/210
        app.__dict__['lastUpdated'] = app.__dict__['lastupdated']
        del(app.__dict__['lastupdated'])
        del(app._modified)
        frommeta = dict(app.__dict__)
    else:
        frommeta = dict(app)

    with open(savepath, 'w') as f:
        yaml.add_representer(fdroidserver.metadata.Build, _build_yaml_representer)
        yaml.dump(frommeta, f, default_flow_style=False)

    # if appid == 'at.tomtasche.reader':
    #     import pprint
    #     pprint.pprint(app)
    #     sys.exit(1)
