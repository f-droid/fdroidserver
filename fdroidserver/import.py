#!/usr/bin/env python3
#
# import.py - part of the FDroid server tools
# Copyright (C) 2010-13, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
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

import configparser
import git
import json
import os
import shutil
import sys
import yaml
from argparse import ArgumentParser
import logging

try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader

from . import _
from . import common
from . import metadata
from .exception import FDroidException


config = None
options = None


# WARNING!  This cannot be imported as a Python module, so reuseable functions need to go into common.py!

def clone_to_tmp_dir(app):
    tmp_dir = 'tmp'
    if not os.path.isdir(tmp_dir):
        logging.info(_("Creating temporary directory"))
        os.makedirs(tmp_dir)

    tmp_dir = os.path.join(tmp_dir, 'importer')
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
    vcs = common.getvcs(app.RepoType, app.Repo, tmp_dir)
    vcs.gotorevision(options.rev)

    return tmp_dir


def check_for_kivy_buildozer(tmp_importer_dir, app, build):
    versionCode = None
    buildozer_spec = os.path.join(tmp_importer_dir, 'buildozer.spec')
    if os.path.exists(buildozer_spec):
        config = configparser.ConfigParser()
        config.read(buildozer_spec)
        import pprint
        pprint.pprint(sorted(config['app'].keys()))
        app.id = config['app'].get('package.domain')
        print(app.id)
        app.AutoName = config['app'].get('package.name', app.AutoName)
        app.License = config['app'].get('license', app.License)
        app.Description = config['app'].get('description', app.Description)
        build.versionName = config['app'].get('version')
        build.output = 'bin/%s-$$VERSION$$-release-unsigned.apk' % app.AutoName
        build.ndk = 'r17c'
        build.srclibs = [
            'buildozer@586152c',
            'python-for-android@ccb0f8e1',
        ]
        build.sudo = [
            'apt-get update',
            'apt-get install -y build-essential libffi-dev libltdl-dev',
        ]
        build.prebuild = [
            'sed -iE "/^[# ]*android\\.(ant|ndk|sdk)_path[ =]/d" buildozer.spec',
            'sed -iE "/^[# ]*android.accept_sdk_license[ =]+.*/d" buildozer.spec',
            'sed -iE "/^[# ]*android.skip_update[ =]+.*/d" buildozer.spec',
            'sed -iE "/^[# ]*p4a.source_dir[ =]+.*/d" buildozer.spec',
            'sed -i "s,\\[app\\],[app]\\n\\nandroid.sdk_path = $$SDK$$\\nandroid.ndk_path = $$NDK$$\\np4a.source_dir = $$python-for-android$$\\nandroid.accept_sdk_license = False\\nandroid.skip_update = True\\nandroid.ant_path = /usr/bin/ant\\n," buildozer.spec',
            'pip3 install --user --upgrade $$buildozer$$ Cython==0.28.6',
        ]
        build.build = [
            'PATH="$HOME/.local/bin:$PATH" buildozer android release',
        ]
    return build.get('versionName'), versionCode, app.get('id')


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument("-u", "--url", default=None,
                        help=_("Project URL to import from."))
    parser.add_argument("-s", "--subdir", default=None,
                        help=_("Path to main Android project subdirectory, if not in root."))
    parser.add_argument("-c", "--categories", default=None,
                        help=_("Comma separated list of categories."))
    parser.add_argument("-l", "--license", default=None,
                        help=_("Overall license of the project."))
    parser.add_argument("--omit-disable", action="store_true", default=False,
                        help=_("Do not add 'disable:' to the generated build entries"))
    parser.add_argument("--rev", default=None,
                        help=_("Allows a different revision (or git branch) to be specified for the initial import"))
    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    metadata.warnings_action = options.W

    config = common.read_config(options)

    apps = metadata.read_metadata()
    app = None

    tmp_importer_dir = None

    local_metadata_files = common.get_local_metadata_files()
    if local_metadata_files != []:
        raise FDroidException(_("This repo already has local metadata: %s") % local_metadata_files[0])

    build = metadata.Build()
    if options.url is None and os.path.isdir('.git'):
        app = metadata.App()
        app.AutoName = os.path.basename(os.getcwd())
        app.RepoType = 'git'

        if os.path.exists('build.gradle') or os.path.exists('build.gradle.kts'):
            build.gradle = ['yes']

        git_repo = git.repo.Repo(os.getcwd())
        for remote in git.Remote.iter_items(git_repo):
            if remote.name == 'origin':
                url = git_repo.remotes.origin.url
                if url.startswith('https://git'):  # github, gitlab
                    app.SourceCode = url.rstrip('.git')
                app.Repo = url
                break
        write_local_file = True
    elif options.url:
        app = common.get_app_from_url(options.url)
        tmp_importer_dir = clone_to_tmp_dir(app)
        git_repo = git.repo.Repo(tmp_importer_dir)
        if not options.omit_disable:
            build.disable = 'Generated by import.py - check/set version fields and commit id'
        write_local_file = False
    else:
        raise FDroidException("Specify project url.")

    app.UpdateCheckMode = 'Tags'
    build.commit = common.get_head_commit_id(git_repo)

    versionName, versionCode, appid = check_for_kivy_buildozer(tmp_importer_dir, app, build)

    # Extract some information...
    paths = common.get_all_gradle_and_manifests(tmp_importer_dir)
    subdir = common.get_gradle_subdir(tmp_importer_dir, paths)
    if paths:
        versionName, versionCode, appid = common.parse_androidmanifests(paths, app)
        if not appid:
            raise FDroidException(_("Couldn't find Application ID"))
        if not versionName:
            logging.warning(_('Could not find latest version name'))
        if not versionCode:
            logging.warning(_('Could not find latest version code'))
    elif not appid:
        raise FDroidException(_("No gradle project could be found. Specify --subdir?"))

    # Make sure it's actually new...
    if appid in apps:
        raise FDroidException(_('Package "{appid}" already exists').format(appid=appid))

    # Create a build line...
    build.versionName = versionName or 'Unknown'
    build.versionCode = versionCode or '0'  # TODO heinous but this is still a str
    if options.subdir:
        build.subdir = options.subdir
        build.gradle = ['yes']
    elif subdir:
        build.subdir = subdir
        build.gradle = ['yes']

    if options.license:
        app.License = options.license
    if options.categories:
        app.Categories = options.categories.split(',')
    if os.path.exists(os.path.join(subdir, 'jni')):
        build.buildjni = ['yes']
    if os.path.exists(os.path.join(subdir, 'build.gradle')) \
       or os.path.exists(os.path.join(subdir, 'build.gradle')):
        build.gradle = ['yes']

    package_json = os.path.join(tmp_importer_dir, 'package.json')  # react-native
    pubspec_yaml = os.path.join(tmp_importer_dir, 'pubspec.yaml')  # flutter
    if os.path.exists(package_json):
        build.sudo = ['apt-get update || apt-get update', 'apt-get install -t stretch-backports npm', 'npm install -g react-native-cli']
        build.init = ['npm install']
        with open(package_json) as fp:
            data = json.load(fp)
        app.AutoName = data.get('name', app.AutoName)
        app.License = data.get('license', app.License)
        app.Description = data.get('description', app.Description)
        app.WebSite = data.get('homepage', app.WebSite)
        app_json = os.path.join(tmp_importer_dir, 'app.json')
        if os.path.exists(app_json):
            with open(app_json) as fp:
                data = json.load(fp)
            app.AutoName = data.get('name', app.AutoName)
    if os.path.exists(pubspec_yaml):
        with open(pubspec_yaml) as fp:
            data = yaml.load(fp, Loader=SafeLoader)
        app.AutoName = data.get('name', app.AutoName)
        app.License = data.get('license', app.License)
        app.Description = data.get('description', app.Description)
        build.srclibs = ['flutter@stable']
        build.output = 'build/app/outputs/apk/release/app-release.apk'
        build.build = [
            '$$flutter$$/bin/flutter config --no-analytics',
            '$$flutter$$/bin/flutter packages pub get',
            '$$flutter$$/bin/flutter build apk',
        ]

    git_modules = os.path.join(tmp_importer_dir, '.gitmodules')
    if os.path.exists(git_modules):
        build.submodules = True

    metadata.post_metadata_parse(app)

    app['Builds'].append(build)

    if write_local_file:
        metadata.write_metadata('.fdroid.yml', app)
    else:
        # Keep the repo directory to save bandwidth...
        if not os.path.exists('build'):
            os.mkdir('build')
        build_dir = os.path.join('build', appid)
        if os.path.exists(build_dir):
            logging.warning(_('{path} already exists, ignoring import results!')
                            .format(path=build_dir))
            sys.exit(1)
        elif tmp_importer_dir is not None:
            shutil.move(tmp_importer_dir, build_dir)
        with open('build/.fdroidvcs-' + appid, 'w') as f:
            f.write(app.RepoType + ' ' + app.Repo)

        metadatapath = os.path.join('metadata', appid + '.yml')
        metadata.write_metadata(metadatapath, app)
        logging.info("Wrote " + metadatapath)


if __name__ == "__main__":
    main()
