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

import git
import glob
import json
import os
import re
import shutil
import sys
import urllib.parse
import urllib.request
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

SETTINGS_GRADLE = re.compile(r'settings\.gradle(?:\.kts)?')
GRADLE_SUBPROJECT = re.compile(r'''['"]:([^'"]+)['"]''')


# Get the repo type and address from the given web page. The page is scanned
# in a rather naive manner for 'git clone xxxx', 'hg clone xxxx', etc, and
# when one of these is found it's assumed that's the information we want.
# Returns repotype, address, or None, reason
def getrepofrompage(url):
    if not url.startswith('http'):
        return (None, _('{url} does not start with "http"!'.format(url=url)))
    req = urllib.request.urlopen(url)  # nosec B310 non-http URLs are filtered out
    if req.getcode() != 200:
        return (None, 'Unable to get ' + url + ' - return code ' + str(req.getcode()))
    page = req.read().decode(req.headers.get_content_charset())

    # Works for BitBucket
    m = re.search('data-fetch-url="(.*)"', page)
    if m is not None:
        repo = m.group(1)

        if repo.endswith('.git'):
            return ('git', repo)

        return ('hg', repo)

    # Works for BitBucket (obsolete)
    index = page.find('hg clone')
    if index != -1:
        repotype = 'hg'
        repo = page[index + 9:]
        index = repo.find('<')
        if index == -1:
            return (None, _("Error while getting repo address"))
        repo = repo[:index]
        repo = repo.split('"')[0]
        return (repotype, repo)

    # Works for BitBucket (obsolete)
    index = page.find('git clone')
    if index != -1:
        repotype = 'git'
        repo = page[index + 10:]
        index = repo.find('<')
        if index == -1:
            return (None, _("Error while getting repo address"))
        repo = repo[:index]
        repo = repo.split('"')[0]
        return (repotype, repo)

    return (None, _("No information found.") + page)


config = None
options = None


def get_app_from_url(url):
    """Guess basic app metadata from the URL.

    The URL must include a network hostname, unless it is an lp:,
    file:, or git/ssh URL.  This throws ValueError on bad URLs to
    match urlparse().

    """

    parsed = urllib.parse.urlparse(url)
    invalid_url = False
    if not parsed.scheme or not parsed.path:
        invalid_url = True

    app = metadata.App()
    app.Repo = url
    if url.startswith('git://') or url.startswith('git@'):
        app.RepoType = 'git'
    elif parsed.netloc == 'github.com':
        app.RepoType = 'git'
        app.SourceCode = url
        app.IssueTracker = url + '/issues'
    elif parsed.netloc == 'gitlab.com':
        # git can be fussy with gitlab URLs unless they end in .git
        if url.endswith('.git'):
            url = url[:-4]
        app.Repo = url + '.git'
        app.RepoType = 'git'
        app.SourceCode = url
        app.IssueTracker = url + '/issues'
    elif parsed.netloc == 'notabug.org':
        if url.endswith('.git'):
            url = url[:-4]
        app.Repo = url + '.git'
        app.RepoType = 'git'
        app.SourceCode = url
        app.IssueTracker = url + '/issues'
    elif parsed.netloc == 'bitbucket.org':
        if url.endswith('/'):
            url = url[:-1]
        app.SourceCode = url + '/src'
        app.IssueTracker = url + '/issues'
        # Figure out the repo type and adddress...
        app.RepoType, app.Repo = getrepofrompage(url)
    elif url.startswith('https://') and url.endswith('.git'):
        app.RepoType = 'git'

    if not parsed.netloc and parsed.scheme in ('git', 'http', 'https', 'ssh'):
        invalid_url = True

    if invalid_url:
        raise ValueError(_('"{url}" is not a valid URL!'.format(url=url)))

    if not app.RepoType:
        raise FDroidException("Unable to determine vcs type. " + app.Repo)

    return app


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


def get_all_gradle_and_manifests(build_dir):
    paths = []
    for root, dirs, files in os.walk(build_dir):
        for f in sorted(files):
            if f == 'AndroidManifest.xml' \
               or f.endswith('.gradle') or f.endswith('.gradle.kts'):
                full = os.path.join(root, f)
                paths.append(full)
    return paths


def get_gradle_subdir(build_dir, paths):
    """get the subdir where the gradle build is based"""
    first_gradle_dir = None
    for path in paths:
        if not first_gradle_dir:
            first_gradle_dir = os.path.relpath(os.path.dirname(path), build_dir)
        if os.path.exists(path) and SETTINGS_GRADLE.match(os.path.basename(path)):
            with open(path) as fp:
                for m in GRADLE_SUBPROJECT.finditer(fp.read()):
                    for f in glob.glob(os.path.join(os.path.dirname(path), m.group(1), 'build.gradle*')):
                        with open(f) as fp:
                            while True:
                                line = fp.readline()
                                if not line:
                                    break
                                if common.ANDROID_PLUGIN_REGEX.match(line):
                                    return os.path.relpath(os.path.dirname(f), build_dir)
    if first_gradle_dir and first_gradle_dir != '.':
        return first_gradle_dir

    return ''


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
        app = get_app_from_url(options.url)
        tmp_importer_dir = clone_to_tmp_dir(app)
        git_repo = git.repo.Repo(tmp_importer_dir)
        build.disable = 'Generated by import.py - check/set version fields and commit id'
        write_local_file = False
    else:
        raise FDroidException("Specify project url.")

    app.UpdateCheckMode = 'Tags'
    build.commit = common.get_head_commit_id(git_repo)

    # Extract some information...
    paths = get_all_gradle_and_manifests(tmp_importer_dir)
    subdir = get_gradle_subdir(tmp_importer_dir, paths)
    if paths:
        versionName, versionCode, package = common.parse_androidmanifests(paths, app)
        if not package:
            raise FDroidException(_("Couldn't find package ID"))
        if not versionName:
            logging.warn(_("Couldn't find latest version name"))
        if not versionCode:
            logging.warn(_("Couldn't find latest version code"))
    else:
        raise FDroidException(_("No gradle project could be found. Specify --subdir?"))

    # Make sure it's actually new...
    if package in apps:
        raise FDroidException("Package " + package + " already exists")

    # Create a build line...
    build.versionName = versionName or 'Unknown'
    build.versionCode = versionCode or '0'  # TODO heinous but this is still a str
    if options.subdir:
        build.subdir = options.subdir
    elif subdir:
        build.subdir = subdir

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
        build.sudo = ['apt-get install npm', 'npm install -g react-native-cli']
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

    metadata.post_metadata_parse(app)

    app.builds.append(build)

    if write_local_file:
        metadata.write_metadata('.fdroid.yml', app)
    else:
        # Keep the repo directory to save bandwidth...
        if not os.path.exists('build'):
            os.mkdir('build')
        build_dir = os.path.join('build', package)
        if os.path.exists(build_dir):
            logging.warning(_('{path} already exists, ignoring import results!')
                            .format(path=build_dir))
            sys.exit(1)
        elif tmp_importer_dir is not None:
            shutil.move(tmp_importer_dir, build_dir)
        with open('build/.fdroidvcs-' + package, 'w') as f:
            f.write(app.RepoType + ' ' + app.Repo)

        metadatapath = os.path.join('metadata', package + '.yml')
        metadata.write_metadata(metadatapath, app)
        logging.info("Wrote " + metadatapath)


if __name__ == "__main__":
    main()
