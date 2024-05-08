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
#   cd fdroidserver
#   git checkout <latest tag>
#   cd ../fdroiddata
#   ../fdroidserver/tests/dump_internal_metadata_format.py
#   cd ../fdroidserver
#   git checkout master
#   cd ../fdroiddata
#   ../fdroidserver/tests/dump_internal_metadata_format.py
#   diff -uw metadata/dump_*

import inspect
import os
import sys
from argparse import ArgumentParser

import git

import yaml

localmodule = os.path.realpath(
    os.path.join(os.path.dirname(inspect.getfile(inspect.currentframe())), '..')
)
if localmodule not in sys.path:
    sys.path.insert(0, localmodule)

import fdroidserver.common  # noqa
import fdroidserver.metadata  # noqa


def _build_yaml_representer(dumper, data):
    """Create a YAML representation of a Build instance."""
    # internal representation of keys were switched
    # to lists instead of strings concatenated by &&
    # https://gitlab.com/fdroid/fdroidserver/merge_requests/1185
    output = {}
    for k, v in data.items():
        if k in ("build", "init", "prebuild", "sudo"):
            output[k] = " && ".join(v)
        else:
            output[k] = v

    return dumper.represent_dict(output)


parser = ArgumentParser()
fdroidserver.common.setup_global_opts(parser)
fdroidserver.metadata.add_metadata_arguments(parser)
options = fdroidserver.common.parse_args(parser)
fdroidserver.metadata.warnings_action = options.W
fdroidserver.common.read_config()

if not os.path.isdir('metadata'):
    print("This script must be run in an F-Droid data folder with a 'metadata' subdir!")
    sys.exit(1)

repo = git.Repo(localmodule)
savedir = os.path.join('metadata', 'dump_' + repo.git.rev_parse('HEAD'))
if not os.path.isdir(savedir):
    os.mkdir(savedir)

apps = fdroidserver.metadata.read_metadata()
for appid, app in apps.items():
    savepath = os.path.join(savedir, appid + '.yaml')
    frommeta = dict(app)

    with open(savepath, "w", encoding="utf-8") as f:
        yaml.add_representer(fdroidserver.metadata.Build, _build_yaml_representer)
        yaml.dump(frommeta, f, default_flow_style=False)
