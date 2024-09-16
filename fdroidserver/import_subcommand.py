#!/usr/bin/env python3
"""Extract application metadata from a source repository."""
#
# import_subcommand.py - part of the FDroid server tools
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

import json
import logging
import os
import re
import shutil
import stat
import sys
import urllib
from argparse import ArgumentParser
from pathlib import Path
from typing import Optional

import git
import yaml

try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader

from . import _, common, metadata
from .exception import FDroidException

config = None

SETTINGS_GRADLE_REGEX = re.compile(r'settings\.gradle(?:\.kts)?')
GRADLE_SUBPROJECT_REGEX = re.compile(r'''['"]:?([^'"]+)['"]''')
APPLICATION_ID_REGEX = re.compile(r'''\s*applicationId\s=?\s?['"].*['"]''')


def get_all_gradle_and_manifests(build_dir):
    paths = []
    for root, dirs, files in os.walk(build_dir):
        for f in sorted(files):
            if f == 'AndroidManifest.xml' or f.endswith(('.gradle', '.gradle.kts')):
                full = Path(root) / f
                paths.append(full)
    return paths


def get_gradle_subdir(build_dir, paths):
    """Get the subdir where the gradle build is based."""
    first_gradle_dir = None
    for path in paths:
        if not first_gradle_dir:
            first_gradle_dir = path.parent.relative_to(build_dir)
        if path.exists() and SETTINGS_GRADLE_REGEX.match(path.name):
            for m in GRADLE_SUBPROJECT_REGEX.finditer(path.read_text(encoding='utf-8')):
                for f in (path.parent / m.group(1)).glob('build.gradle*'):
                    with f.open(encoding='utf-8') as fp:
                        for line in fp:
                            if common.ANDROID_PLUGIN_REGEX.match(
                                line
                            ) or APPLICATION_ID_REGEX.match(line):
                                return f.parent.relative_to(build_dir)
    if first_gradle_dir and first_gradle_dir != Path('.'):
        return first_gradle_dir


def handle_retree_error_on_windows(function, path, excinfo):
    """Python can't remove a readonly file on Windows so chmod first."""
    if function in (os.unlink, os.rmdir, os.remove) and excinfo[0] == PermissionError:
        os.chmod(path, stat.S_IWRITE)
        function(path)


def clone_to_tmp_dir(app: metadata.App, rev=None) -> Path:
    """Clone the source repository of an app to a temporary directory for further processing.

    Parameters
    ----------
    app
        The App instance to clone the source of.

    Returns
    -------
    tmp_dir
        The (temporary) directory the apps source has been cloned into.

    """
    tmp_dir = Path('tmp')
    tmp_dir.mkdir(exist_ok=True)

    tmp_dir = tmp_dir / 'importer'

    if tmp_dir.exists():
        shutil.rmtree(str(tmp_dir), onerror=handle_retree_error_on_windows)
    vcs = common.getvcs(app.RepoType, app.Repo, tmp_dir)
    vcs.gotorevision(rev)

    return tmp_dir


def getrepofrompage(url: str) -> tuple[Optional[str], str]:
    """Get the repo type and address from the given web page.

    The page is scanned in a rather naive manner for 'git clone xxxx',
    'hg clone xxxx', etc, and when one of these is found it's assumed
    that's the information we want.  Returns repotype, address, or
    None, reason

    Parameters
    ----------
    url
        The url to look for repository information at.

    Returns
    -------
    repotype_or_none
        The found repository type or None if an error occured.
    address_or_reason
        The address to the found repository or the reason if an error occured.

    """
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
        repo = page[index + 9 :]
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
        repo = page[index + 10 :]
        index = repo.find('<')
        if index == -1:
            return (None, _("Error while getting repo address"))
        repo = repo[:index]
        repo = repo.split('"')[0]
        return (repotype, repo)

    return (None, _("No information found.") + page)


def get_app_from_url(url: str) -> metadata.App:
    """Guess basic app metadata from the URL.

    The URL must include a network hostname, unless it is an lp:,
    file:, or git/ssh URL.  This throws ValueError on bad URLs to
    match urlparse().

    Parameters
    ----------
    url
        The URL to look to look for app metadata at.

    Returns
    -------
    app
        App instance with the found metadata.

    Raises
    ------
    :exc:`~fdroidserver.exception.FDroidException`
        If the VCS type could not be determined.
    :exc:`ValueError`
        If the URL is invalid.

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
    elif parsed.netloc in ('gitlab.com', 'framagit.org'):
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
    elif parsed.netloc == 'codeberg.org':
        app.RepoType = 'git'
        app.SourceCode = url
        app.IssueTracker = url + '/issues'
    elif url.startswith('https://') and url.endswith('.git'):
        app.RepoType = 'git'

    if not parsed.netloc and parsed.scheme in ('git', 'http', 'https', 'ssh'):
        invalid_url = True

    if invalid_url:
        raise ValueError(_('"{url}" is not a valid URL!'.format(url=url)))

    if not app.RepoType:
        raise FDroidException("Unable to determine vcs type. " + app.Repo)

    return app


def main():
    """Extract app metadata and write it to a file.

    The behaviour of this function is influenced by the configuration file as
    well as command line parameters.

    Raises
    ------
    :exc:`~fdroidserver.exception.FDroidException`
        If the repository already has local metadata, no URL is specified and
        the current directory is not a Git repository, no application ID could
        be found, no Gradle project could be found or there is already metadata
        for the found application ID.

    """
    global config

    # Parse command line...
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument("-u", "--url", help=_("Project URL to import from."))
    parser.add_argument(
        "-s",
        "--subdir",
        help=_("Path to main Android project subdirectory, if not in root."),
    )
    parser.add_argument(
        "-c",
        "--categories",
        help=_("Comma separated list of categories."),
    )
    parser.add_argument("-l", "--license", help=_("Overall license of the project."))
    parser.add_argument(
        "--omit-disable",
        action="store_true",
        help=_("Do not add 'disable:' to the generated build entries"),
    )
    parser.add_argument(
        "--rev",
        help=_(
            "Allows a different revision (or git branch) to be specified for the initial import"
        ),
    )
    metadata.add_metadata_arguments(parser)
    options = common.parse_args(parser)
    metadata.warnings_action = options.W

    config = common.read_config()

    apps = metadata.read_metadata()
    app = None

    tmp_importer_dir = None

    local_metadata_files = common.get_local_metadata_files()
    if local_metadata_files:
        raise FDroidException(
            _("This repo already has local metadata: %s") % local_metadata_files[0]
        )

    build = metadata.Build()
    app = metadata.App()
    if options.url is None and Path('.git').is_dir():
        app.RepoType = 'git'
        tmp_importer_dir = Path.cwd()
        git_repo = git.Repo(tmp_importer_dir)
        for remote in git.Remote.iter_items(git_repo):
            if remote.name == 'origin':
                url = git_repo.remotes.origin.url
                app = get_app_from_url(url)
                break
        write_local_file = True
    elif options.url:
        app = get_app_from_url(options.url)
        tmp_importer_dir = clone_to_tmp_dir(app, options.rev)
        git_repo = git.Repo(tmp_importer_dir)

        if not options.omit_disable:
            build.disable = (
                'Generated by `fdroid import` - check version fields and commitid'
            )
        write_local_file = False
    else:
        raise FDroidException("Specify project url.")

    app.AutoUpdateMode = 'Version'
    app.UpdateCheckMode = 'Tags'
    build.commit = common.get_head_commit_id(git_repo)

    # Extract some information...
    paths = get_all_gradle_and_manifests(tmp_importer_dir)
    gradle_subdir = get_gradle_subdir(tmp_importer_dir, paths)
    if paths:
        versionName, versionCode, appid = common.parse_androidmanifests(paths, app)
        if not appid:
            raise FDroidException(_("Couldn't find Application ID"))
        if not versionName:
            logging.warning(_('Could not find latest version name'))
        if not versionCode:
            logging.warning(_('Could not find latest version code'))
    else:
        raise FDroidException(_("No gradle project could be found. Specify --subdir?"))

    # Make sure it's actually new...
    if appid in apps:
        raise FDroidException(_('Package "{appid}" already exists').format(appid=appid))

    # Create a build line...
    build.versionName = versionName or 'Unknown'
    app.CurrentVersion = build.versionName
    build.versionCode = versionCode or 0
    app.CurrentVersionCode = build.versionCode
    if options.subdir:
        build.subdir = options.subdir
    elif gradle_subdir:
        build.subdir = gradle_subdir.as_posix()
    # subdir might be None
    subdir = Path(tmp_importer_dir / build.subdir) if build.subdir else tmp_importer_dir

    if options.license:
        app.License = options.license
    if options.categories:
        app.Categories = options.categories.split(',')
    if (subdir / 'jni').exists():
        build.buildjni = ['yes']
    if (subdir / 'build.gradle').exists() or (subdir / 'build.gradle.kts').exists():
        build.gradle = ['yes']

    app.AutoName = common.fetch_real_name(subdir, build.gradle)

    package_json = tmp_importer_dir / 'package.json'  # react-native
    pubspec_yaml = tmp_importer_dir / 'pubspec.yaml'  # flutter
    if package_json.exists():
        build.sudo = [
            'sysctl fs.inotify.max_user_watches=524288 || true',
            'apt-get update',
            'apt-get install -y npm',
        ]
        build.init = ['npm install --build-from-source']
        with package_json.open() as fp:
            data = json.load(fp)
        app.AutoName = app.AutoName or data.get('name')
        app.License = data.get('license', app.License)
        app.Description = data.get('description', app.Description)
        app.WebSite = data.get('homepage', app.WebSite)
        app_json = tmp_importer_dir / 'app.json'
        build.scanignore = ['android/build.gradle']
        build.scandelete = ['node_modules']
        if app_json.exists():
            with app_json.open() as fp:
                data = json.load(fp)
            app.AutoName = app.AutoName or data.get('name')
    if pubspec_yaml.exists():
        with pubspec_yaml.open() as fp:
            data = yaml.load(fp, Loader=SafeLoader)
        app.AutoName = app.AutoName or data.get('name')
        app.License = data.get('license', app.License)
        app.Description = data.get('description', app.Description)
        app.UpdateCheckData = 'pubspec.yaml|version:\\s.+\\+(\\d+)|.|version:\\s(.+)\\+'
        build.srclibs = ['flutter@stable']
        build.output = 'build/app/outputs/flutter-apk/app-release.apk'
        build.subdir = None
        build.gradle = None
        build.prebuild = [
            'export PUB_CACHE=$(pwd)/.pub-cache',
            '$$flutter$$/bin/flutter config --no-analytics',
            '$$flutter$$/bin/flutter packages pub get',
        ]
        build.scandelete = [
            '.pub-cache',
        ]
        build.build = [
            'export PUB_CACHE=$(pwd)/.pub-cache',
            '$$flutter$$/bin/flutter build apk',
        ]

    git_modules = tmp_importer_dir / '.gitmodules'
    if git_modules.exists():
        build.submodules = True

    metadata.post_parse_yaml_metadata(app)

    app['Builds'].append(build)

    if write_local_file:
        metadata.write_metadata(Path('.fdroid.yml'), app)
    else:
        # Keep the repo directory to save bandwidth...
        Path('build').mkdir(exist_ok=True)
        build_dir = Path('build') / appid
        if build_dir.exists():
            logging.warning(
                _('{path} already exists, ignoring import results!').format(
                    path=build_dir
                )
            )
            sys.exit(1)
        elif tmp_importer_dir:
            # For Windows: Close the repo or a git.exe instance holds handles to repo
            try:
                git_repo.close()
            except AttributeError:  # Debian/stretch's version does not have close()
                pass
            shutil.move(tmp_importer_dir, build_dir)
        Path('build/.fdroidvcs-' + appid).write_text(app.RepoType + ' ' + app.Repo)

        metadatapath = Path('metadata') / (appid + '.yml')
        metadata.write_metadata(metadatapath, app)
        logging.info("Wrote " + str(metadatapath))


if __name__ == "__main__":
    main()
