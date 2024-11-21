#!/usr/bin/env python3
"""Check for updates to applications."""
#
# checkupdates.py - part of the FDroid server tools
# Copyright (C) 2010-2015, Ciaran Gultnieks, ciaran@ciarang.com
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
import os
import re
import urllib.request
import urllib.error
import time
import subprocess
import sys
from argparse import ArgumentParser
import traceback
import logging
import copy
import urllib.parse
from pathlib import Path
from typing import Optional

from . import _
from . import common
from . import metadata
from . import net
from .exception import VCSException, NoSubmodulesException, FDroidException, MetaDataException


# https://gitlab.com/fdroid/checkupdates-runner/-/blob/1861899262a62a4ed08fa24e5449c0368dfb7617/.gitlab-ci.yml#L36
BOT_EMAIL = 'fdroidci@bubu1.eu'


def check_http(app: metadata.App) -> tuple[Optional[str], Optional[int]]:
    """Check for a new version by looking at a document retrieved via HTTP.

    The app's UpdateCheckData field is used to provide the information
    required.

    Parameters
    ----------
    app
        The App instance to check for updates for.

    Returns
    -------
    version
        The found versionName or None if the versionName should be ignored
        according to UpdateCheckIgnore.
    vercode
        The found versionCode or None if the versionCode should be ignored
        according to UpdateCheckIgnore.

    Raises
    ------
    :exc:`~fdroidserver.exception.FDroidException`
        If UpdateCheckData is missing or is an invalid URL or if there is no
        match for the provided versionName or versionCode regex.
    """
    if not app.UpdateCheckData:
        raise FDroidException('Missing Update Check Data')

    urlcode, codeex, urlver, verex = app.UpdateCheckData.split('|')
    parsed = urllib.parse.urlparse(urlcode)
    if not parsed.netloc or not parsed.scheme or parsed.scheme != 'https':
        raise FDroidException(_('UpdateCheckData has invalid URL: {url}').format(url=urlcode))
    if urlver != '.':
        parsed = urllib.parse.urlparse(urlver)
        if not parsed.netloc or not parsed.scheme or parsed.scheme != 'https':
            raise FDroidException(_('UpdateCheckData has invalid URL: {url}').format(url=urlver))

    logging.debug("...requesting {0}".format(urlcode))
    req = urllib.request.Request(urlcode, None, headers=net.HEADERS)
    resp = urllib.request.urlopen(req, None, 20)  # nosec B310 scheme is filtered above
    page = resp.read().decode('utf-8')

    m = re.search(codeex, page)
    if not m:
        raise FDroidException("No RE match for version code")
    vercode = common.version_code_string_to_int(m.group(1).strip())

    if urlver != '.':
        logging.debug("...requesting {0}".format(urlver))
        req = urllib.request.Request(urlver, None)
        resp = urllib.request.urlopen(req, None, 20)  # nosec B310 scheme is filtered above
        page = resp.read().decode('utf-8')

    m = re.search(verex, page)
    if not m:
        raise FDroidException("No RE match for version")
    version = m.group(1)

    if app.UpdateCheckIgnore and re.search(app.UpdateCheckIgnore, version):
        logging.info("Version {version} for {appid} is ignored".format(version=version, appid=app.id))
        return (None, None)

    return (version, vercode)


def check_tags(app: metadata.App, pattern: str) -> tuple[str, int, str]:
    """Check for a new version by looking at the tags in the source repo.

    Whether this can be used reliably or not depends on
    the development procedures used by the project's developers. Use it with
    caution, because it's inappropriate for many projects.

    Parameters
    ----------
    app
        The App instance to check for updates for.
    pattern
        The pattern a tag needs to match to be considered.

    Returns
    -------
    versionName
        The highest found versionName.
    versionCode
        The highest found versionCode.
    ref
        The Git reference, commit hash or tag name, of the highest found
        versionName, versionCode.

    Raises
    ------
    :exc:`~fdroidserver.exception.MetaDataException`
        If this function is not suitable for the RepoType of the app or
        information is missing to perform this type of check.
    :exc:`~fdroidserver.exception.FDroidException`
        If no matching tags or no information whatsoever could be found.
    """
    if app.RepoType == 'srclib':
        build_dir = Path('build/srclib') / app.Repo
        repotype = common.getsrclibvcs(app.Repo)
    else:
        build_dir = Path('build') / app.id
        repotype = app.RepoType

    if repotype not in ('git', 'git-svn', 'hg', 'bzr'):
        raise MetaDataException(_('Tags update mode only works for git, hg, bzr and git-svn repositories currently'))

    if repotype == 'git-svn' and ';' not in app.Repo:
        raise MetaDataException(_('Tags update mode used in git-svn, but the repo was not set up with tags'))

    # Set up vcs interface and make sure we have the latest code...
    vcs = common.getvcs(app.RepoType, app.Repo, build_dir)

    vcs.gotorevision(None)

    last_build = get_last_build_from_app(app)

    try_init_submodules(app, last_build, vcs)

    htag = None
    hver = None
    hcode = 0

    tags = []
    if repotype == 'git':
        tags = vcs.latesttags()
    else:
        tags = vcs.gettags()
    if not tags:
        raise FDroidException(_('No tags found'))

    logging.debug("All tags: " + ','.join(tags))
    if pattern:
        pat = re.compile(pattern)
        tags = [tag for tag in tags if pat.match(tag)]
        if not tags:
            raise FDroidException(_('No matching tags found'))
        logging.debug("Matching tags: " + ','.join(tags))

    if len(tags) > 5 and repotype == 'git':
        tags = tags[:5]
        logging.debug("Latest tags: " + ','.join(tags))

    for tag in tags:
        logging.debug("Check tag: '{0}'".format(tag))
        vcs.gotorevision(tag)
        try_init_submodules(app, last_build, vcs)

        if app.UpdateCheckData:
            filecode, codeex, filever, verex = app.UpdateCheckData.split('|')

            if filecode:
                filecode = build_dir / filecode
                if not filecode.is_file():
                    logging.debug("UpdateCheckData file {0} not found in tag {1}".format(filecode, tag))
                    continue
                filecontent = filecode.read_text()
            else:
                filecontent = tag

            vercode = tag
            if codeex:
                m = re.search(codeex, filecontent)
                if not m:
                    logging.debug(f"UpdateCheckData regex {codeex} for version code"
                                  f" has no match in tag {tag}")
                    continue

                vercode = m.group(1).strip()

            if filever:
                if filever != '.':
                    filever = build_dir / filever
                    if filever.is_file():
                        filecontent = filever.read_text()
                    else:
                        logging.debug("UpdateCheckData file {0} not found in tag {1}".format(filever, tag))
            else:
                filecontent = tag

            version = tag
            if verex:
                m = re.search(verex, filecontent)
                if not m:
                    logging.debug(f"UpdateCheckData regex {verex} for version name"
                                  f" has no match in tag {tag}")
                    continue

                version = m.group(1)

            logging.debug("UpdateCheckData found version {0} ({1})"
                          .format(version, vercode))
            vercode = common.version_code_string_to_int(vercode)
            if vercode > hcode:
                htag = tag
                hcode = vercode
                hver = version
        else:
            for subdir in possible_subdirs(app):
                root_dir = build_dir / subdir
                paths = common.manifest_paths(root_dir, last_build.gradle)
                version, vercode, _package = common.parse_androidmanifests(paths, app)
                if version in ('Unknown', 'Ignore'):
                    version = tag
                if vercode:
                    logging.debug("Manifest exists in subdir '{0}'. Found version {1} ({2})"
                                  .format(subdir, version, vercode))
                    if vercode > hcode:
                        htag = tag
                        hcode = vercode
                        hver = version

    if hver:
        if htag != tags[0]:
            logging.warning(
                "{appid}: latest tag {tag} does not contain highest version {version}".format(
                    appid=app.id, tag=tags[0], version=hver
                )
            )
        try:
            commit = vcs.getref(htag)
            if commit:
                return (hver, hcode, commit)
        except VCSException:
            pass
        return (hver, hcode, htag)
    raise FDroidException(_("Couldn't find any version information"))


def check_repomanifest(app: metadata.App, branch: Optional[str] = None) -> tuple[str, int]:
    """Check for a new version by looking at the AndroidManifest.xml at the HEAD of the source repo.

    Whether this can be used reliably or not depends on
    the development procedures used by the project's developers. Use it with
    caution, because it's inappropriate for many projects.

    Parameters
    ----------
    app
        The App instance to check for updates for.
    branch
        The VCS branch where to search for versionCode, versionName.

    Returns
    -------
    versionName
        The highest found versionName.
    versionCode
        The highest found versionCode.

    Raises
    ------
    :exc:`~fdroidserver.exception.FDroidException`
        If no package id or no version information could be found.
    """
    if app.RepoType == 'srclib':
        build_dir = Path('build/srclib') / app.Repo
        repotype = common.getsrclibvcs(app.Repo)
    else:
        build_dir = Path('build') / app.id
        repotype = app.RepoType

    # Set up vcs interface and make sure we have the latest code...
    vcs = common.getvcs(app.RepoType, app.Repo, build_dir)

    if repotype == 'git':
        if branch:
            branch = 'origin/' + branch
        vcs.gotorevision(branch)
    elif repotype == 'git-svn':
        vcs.gotorevision(branch)
    elif repotype == 'hg':
        vcs.gotorevision(branch)
    elif repotype == 'bzr':
        vcs.gotorevision(None)

    last_build = get_last_build_from_app(app)
    try_init_submodules(app, last_build, vcs)

    hpak = None
    hver = None
    hcode = 0
    for subdir in possible_subdirs(app):
        root_dir = build_dir / subdir
        paths = common.manifest_paths(root_dir, last_build.gradle)
        version, vercode, package = common.parse_androidmanifests(paths, app)
        if vercode:
            logging.debug("Manifest exists in subdir '{0}'. Found version {1} ({2})"
                          .format(subdir, version, vercode))
            if vercode > hcode:
                hpak = package
                hcode = vercode
                hver = version

    if not hpak:
        raise FDroidException(_("Couldn't find package ID"))
    if hver:
        return (hver, hcode)
    raise FDroidException(_("Couldn't find any version information"))


def try_init_submodules(app: metadata.App, last_build: metadata.Build, vcs: common.vcs):
    """Try to init submodules if the last build entry uses them.

    They might have been removed from the app's repo in the meantime,
    so if we can't find any submodules we continue with the updates check.
    If there is any other error in initializing them then we stop the check.
    """
    if last_build.submodules:
        try:
            vcs.initsubmodules()
        except NoSubmodulesException:
            logging.info("No submodules present for {}".format(_getappname(app)))
        except VCSException:
            logging.info("submodule broken for {}".format(_getappname(app)))


def dirs_with_manifest(startdir: str):
    """Find directories containing a manifest file.

    Yield all directories under startdir that contain any of the manifest
    files, and thus are probably an Android project.

    Parameters
    ----------
    startdir
        Directory to be walked down for search

    Yields
    ------
    path : :class:`pathlib.Path` or None
        A directory that contains a manifest file of an Android project, None if
        no directory could be found
    """
    for root, _dirs, files in os.walk(startdir):
        if any(m in files for m in [
                'AndroidManifest.xml', 'pom.xml', 'build.gradle', 'build.gradle.kts']):
            yield Path(root)


def possible_subdirs(app: metadata.App):
    """Try to find a new subdir starting from the root build_dir.

    Yields said subdir relative to the build dir if found, None otherwise.

    Parameters
    ----------
    app
        The app to check for subdirs

    Yields
    ------
    subdir : :class:`pathlib.Path` or None
        A possible subdir, None if no subdir could be found
    """
    if app.RepoType == 'srclib':
        build_dir = Path('build/srclib') / app.Repo
    else:
        build_dir = Path('build') / app.id

    last_build = get_last_build_from_app(app)

    for d in dirs_with_manifest(build_dir):
        m_paths = common.manifest_paths(d, last_build.gradle)
        package = common.parse_androidmanifests(m_paths, app)[2]
        if package is not None or app.UpdateCheckName == "Ignore":
            subdir = d.relative_to(build_dir)
            logging.debug("Adding possible subdir %s" % subdir)
            yield subdir


def _getappname(app: metadata.App) -> str:
    return common.get_app_display_name(app)


def _getcvname(app: metadata.App) -> str:
    return '%s (%s)' % (app.CurrentVersion, app.CurrentVersionCode)


def fetch_autoname(app: metadata.App, tag: str) -> Optional[str]:
    """Fetch AutoName.

    Get the to be displayed name of an app from the source code and adjust the
    App instance in case it is different name has been found.

    Parameters
    ----------
    app
        The App instance to get the AutoName for.
    tag
        Tag to fetch AutoName at.

    Returns
    -------
    commitmsg
        Commit message about the name change.  None in case checking for the
        name is disabled, a VCSException occured or no name could be found.
    """
    if not app.RepoType or app.UpdateCheckMode in ('None', 'Static') \
       or app.UpdateCheckName == "Ignore":
        return None

    if app.RepoType == 'srclib':
        build_dir = Path('build/srclib') / app.Repo
    else:
        build_dir = Path('build') / app.id

    try:
        vcs = common.getvcs(app.RepoType, app.Repo, build_dir)
        vcs.gotorevision(tag)
    except VCSException:
        return None

    last_build = get_last_build_from_app(app)

    logging.debug("...fetch auto name from " + str(build_dir))
    new_name = None
    for subdir in possible_subdirs(app):
        root_dir = build_dir / subdir
        new_name = common.fetch_real_name(root_dir, last_build.gradle)
        if new_name is not None:
            break
    commitmsg = None
    if new_name:
        logging.debug("...got autoname '" + new_name + "'")
        if new_name != app.AutoName:
            app.AutoName = new_name
            if not commitmsg:
                commitmsg = "Set autoname of {0}".format(_getappname(app))
    else:
        logging.debug("...couldn't get autoname")

    return commitmsg


def operate_vercode(operation: str, vercode: int) -> int:
    """Calculate a new versionCode from a mathematical operation.

    Parameters
    ----------
    operation
        The operation to execute to get the new versionCode.
    vercode
        The versionCode for replacing "%c" in the operation.

    Returns
    -------
    vercode
        The new versionCode obtained by executing the operation.

    Raises
    ------
    :exc:`~fdroidserver.exception.MetaDataException`
        If the operation is invalid.
    """
    if not common.VERCODE_OPERATION_RE.match(operation):
        raise MetaDataException(_('Invalid VercodeOperation: {field}')
                                .format(field=operation))
    oldvercode = vercode
    op = operation.replace("%c", str(oldvercode))
    vercode = common.calculate_math_string(op)
    logging.debug("Applied vercode operation: %d -> %d" % (oldvercode, vercode))
    return vercode


def checkupdates_app(app: metadata.App, auto: bool, commit: bool = False) -> None:
    """Check for new versions and updated name of a single app.

    Also write back changes to the metadata file and create a Git commit if
    requested.

    Parameters
    ----------
    app
        The app to check for updates for.

    Raises
    ------
    :exc:`~fdroidserver.exception.MetaDataException`
        If the app has an invalid UpdateCheckMode or AutoUpdateMode.
    :exc:`~fdroidserver.exception.FDroidException`
        If no version information could be found, the current version is newer
        than the found version, auto-update was requested but an app has no
        CurrentVersionCode or (Git) commiting the changes failed.
    """
    # If a change is made, commitmsg should be set to a description of it.
    # Only if this is set, changes will be written back to the metadata.
    commitmsg = None

    tag = None
    mode = app.UpdateCheckMode
    if mode.startswith('Tags'):
        pattern = mode[5:] if len(mode) > 4 else None
        (version, vercode, tag) = check_tags(app, pattern)
    elif mode == 'RepoManifest':
        (version, vercode) = check_repomanifest(app)
    elif mode.startswith('RepoManifest/'):
        tag = mode[13:]
        (version, vercode) = check_repomanifest(app, tag)
    elif mode == 'HTTP':
        (version, vercode) = check_http(app)
    elif mode in ('None', 'Static'):
        logging.debug('Checking disabled')
        return
    else:
        raise MetaDataException(_('Invalid UpdateCheckMode: {mode}').format(mode=mode))

    if not version or not vercode:
        raise FDroidException(_('no version information found'))

    if app.VercodeOperation:
        vercodes = sorted([
            operate_vercode(operation, vercode) for operation in app.VercodeOperation
        ])
    else:
        vercodes = [vercode]

    updating = False
    if vercodes[-1] == app.CurrentVersionCode:
        logging.debug("...up to date")
    elif vercodes[-1] > app.CurrentVersionCode:
        logging.debug("...updating - old vercode={0}, new vercode={1}".format(
            app.CurrentVersionCode, vercodes[-1]))
        app.CurrentVersion = version
        app.CurrentVersionCode = vercodes[-1]
        updating = True
    else:
        raise FDroidException(
            _('current version is newer: old vercode={old}, new vercode={new}').format(
                old=app.CurrentVersionCode, new=vercodes[-1]
            )
        )

    commitmsg = fetch_autoname(app, tag)

    if updating:
        name = _getappname(app)
        ver = _getcvname(app)
        logging.info('...updating to version %s' % ver)
        commitmsg = 'Update CurrentVersion of %s to %s' % (name, ver)

    if auto:
        mode = app.AutoUpdateMode
        if not app.CurrentVersionCode:
            raise MetaDataException(
                _("Can't auto-update app with no CurrentVersionCode")
            )
        elif mode in ('None', 'Static'):
            pass
        elif mode.startswith('Version'):
            pattern = mode[8:]
            suffix = ''
            if pattern.startswith('+'):
                try:
                    suffix, pattern = pattern[1:].split(' ', 1)
                except ValueError as exc:
                    raise MetaDataException("Invalid AutoUpdateMode: " + mode) from exc

            gotcur = False
            latest = None
            builds = app.get('Builds', [])

            if builds:
                latest = builds[-1]
                if latest.versionCode == app.CurrentVersionCode:
                    gotcur = True
                elif latest.versionCode > app.CurrentVersionCode:
                    raise FDroidException(
                        _(
                            'latest build recipe is newer: '
                            'old vercode={old}, new vercode={new}'
                        ).format(old=latest.versionCode, new=app.CurrentVersionCode)
                    )

            if not gotcur:
                newbuilds = copy.deepcopy(builds[-len(vercodes):])

                # These are either built-in or invalid in newer system versions
                bookworm_blocklist = [
                    'apt-get install -y openjdk-11-jdk',
                    'apt-get install openjdk-11-jdk-headless',
                    'apt-get install -y openjdk-11-jdk-headless',
                    'apt-get install -t stretch-backports openjdk-11-jdk-headless openjdk-11-jre-headless',
                    'apt-get install -y -t stretch-backports openjdk-11-jdk-headless openjdk-11-jre-headless',
                    'apt-get install -y openjdk-17-jdk',
                    'apt-get install openjdk-17-jdk-headless',
                    'apt-get install -y openjdk-17-jdk-headless',
                    'update-alternatives --auto java',
                    'update-java-alternatives -a',
                ]

                for build in newbuilds:
                    if "sudo" in build:
                        if any("openjdk-11" in line for line in build["sudo"]) or any("openjdk-17" in line for line in build["sudo"]):
                            build["sudo"] = [line for line in build["sudo"] if line not in bookworm_blocklist]
                        if build["sudo"] == ['apt-get update']:
                            build["sudo"] = ''

                for b, v in zip(newbuilds, vercodes):
                    b.disable = False
                    b.versionCode = v
                    b.versionName = app.CurrentVersion + suffix.replace(
                        '%c', str(v)
                    )
                    logging.info("...auto-generating build for " + b.versionName)
                    if tag:
                        b.commit = tag
                    else:
                        commit = pattern.replace('%v', app.CurrentVersion)
                        commit = commit.replace('%c', str(v))
                        b.commit = commit

                app['Builds'].extend(newbuilds)

                name = _getappname(app)
                ver = _getcvname(app)
                commitmsg = "Update %s to %s" % (name, ver)
        else:
            raise MetaDataException(
                _('Invalid AutoUpdateMode: {mode}').format(mode=mode)
            )

    if commitmsg:
        metadata.write_metadata(app.metadatapath, app)
        if commit:
            logging.info("Commiting update for " + app.metadatapath)
            gitcmd = ["git", "commit", "-m", commitmsg]
            if 'auto_author' in config:
                gitcmd.extend(['--author', config['auto_author']])
            gitcmd.extend(["--", app.metadatapath])
            if subprocess.call(gitcmd) != 0:
                raise FDroidException("Git commit failed")


def get_last_build_from_app(app: metadata.App) -> metadata.Build:
    """Get the last build entry of an app."""
    if app.get('Builds'):
        return app['Builds'][-1]
    else:
        return metadata.Build()


def get_upstream_main_branch(git_repo):
    if len(git_repo.remotes.upstream.refs) == 1:
        return git_repo.remotes.upstream.refs[0].name
    for name in ('main', 'master'):
        if name in git_repo.remotes.upstream.refs:
            return f'upstream/{name}'
    try:
        with git_repo.config_reader() as reader:
            return 'upstream/%s' % reader.get_value('init', 'defaultBranch')
    except configparser.NoSectionError:
        return 'upstream/main'


def checkout_appid_branch(appid):
    """Prepare the working branch named after the appid.

    This sets up everything for checkupdates_app() to run and add
    commits.  If there is an existing branch named after the appid,
    and it has commits from users other than the checkupdates-bot,
    then this will return False.  Otherwise, it returns True.

    The checkupdates-runner must set the committer email address in
    the git config.  Then any commit with a committer or author that
    does not match that will be considered to have human edits.  That
    email address is currently set in:
    https://gitlab.com/fdroid/checkupdates-runner/-/blob/1861899262a62a4ed08fa24e5449c0368dfb7617/.gitlab-ci.yml#L36

    """
    logging.debug(f'Creating merge request branch for {appid}')
    git_repo = git.Repo.init('.')
    upstream_main = get_upstream_main_branch(git_repo)
    for remote in git_repo.remotes:
        remote.fetch()
    try:
        git_repo.remotes.origin.fetch(f'{appid}:refs/remotes/origin/{appid}')
    except Exception as e:
        logging.warning('"%s" branch not found on origin remote:\n\t%s', appid, e)
    if appid in git_repo.remotes.origin.refs:
        start_point = f"origin/{appid}"
        for commit in git_repo.iter_commits(
            f'{upstream_main}...{start_point}', right_only=True
        ):
            if commit.committer.email != BOT_EMAIL or commit.author.email != BOT_EMAIL:
                return False
    else:
        start_point = upstream_main
    git_repo.git.checkout('-B', appid, start_point)
    git_repo.git.rebase(upstream_main, strategy_option='ours', kill_after_timeout=120)
    return True


def get_changes_versus_ref(git_repo, ref, f):
    changes = []
    for m in re.findall(
        r"^[+-].*", git_repo.git.diff(f"{ref}", '--', f), flags=re.MULTILINE
    ):
        if not re.match(r"^(\+\+\+|---) ", m):
            changes.append(m)
    return changes


def push_commits(branch_name='checkupdates', verbose=False):
    """Make git branch then push commits as merge request.

    The appid is parsed from the actual file that was changed so that
    only the right branch is ever updated.

    This uses the appid as the standard branch name so that there is
    only ever one open merge request per-app.  If multiple apps are
    included in the branch, then 'checkupdates' is used as branch
    name.  This is to support the old way operating, e.g. in batches.

    This uses GitLab "Push Options" to create a merge request. Git
    Push Options are config data that can be sent via `git push
    --push-option=... origin foo`.

    References
    ----------
    * https://docs.gitlab.com/ee/user/project/push_options.html

    """
    git_repo = git.Repo.init('.')
    upstream_main = get_upstream_main_branch(git_repo)
    files = set()
    for commit in git_repo.iter_commits(f'{upstream_main}...HEAD', right_only=True):
        files.update(commit.stats.files.keys())

    files = list(files)
    if len(files) == 1:
        m = re.match(r'metadata/(\S+)\.yml', files[0])
        if m:
            branch_name = m.group(1)  # appid
    if not files:
        return

    remote = git_repo.remotes.origin
    if branch_name in remote.refs:
        if not get_changes_versus_ref(git_repo, f'origin/{branch_name}', files[0]):
            return

    git_repo.create_head(branch_name, force=True)
    push_options = [
        'merge_request.create',
        'merge_request.remove_source_branch',
        'merge_request.title=bot: ' + git_repo.branches[branch_name].commit.summary,
        'merge_request.description='
        + '~%s checkupdates-bot run %s' % (branch_name, os.getenv('CI_JOB_URL')),
    ]

    # mark as draft if there are only changes to CurrentVersion:
    current_version_only = True
    for m in get_changes_versus_ref(git_repo, upstream_main, files[0]):
        if not re.match(r"^[-+]CurrentVersion", m):
            current_version_only = False
            break
    if current_version_only:
        push_options.append('merge_request.draft')

    progress = None
    if verbose:
        import clint.textui

        progress_bar = clint.textui.progress.Bar()

        class MyProgressPrinter(git.RemoteProgress):
            def update(self, op_code, current, maximum=None, message=None):
                if isinstance(maximum, float):
                    progress_bar.show(current, maximum)

        progress = MyProgressPrinter()

    pushinfos = remote.push(
        branch_name,
        progress=progress,
        force=True,
        set_upstream=True,
        push_option=push_options,
    )

    for pushinfo in pushinfos:
        if pushinfo.flags & (
            git.remote.PushInfo.ERROR
            | git.remote.PushInfo.REJECTED
            | git.remote.PushInfo.REMOTE_FAILURE
            | git.remote.PushInfo.REMOTE_REJECTED
        ):
            # Show potentially useful messages from git remote
            if progress:
                for line in progress.other_lines:
                    if line.startswith('remote:'):
                        logging.debug(line)
            raise FDroidException(
                f'{remote.url} push failed: {pushinfo.flags} {pushinfo.summary}'
            )
        else:
            logging.debug(remote.url + ': ' + pushinfo.summary)


def prune_empty_appid_branches(git_repo=None, main_branch='main'):
    """Remove empty branches from checkupdates-bot git remote."""
    if git_repo is None:
        git_repo = git.Repo.init('.')
    upstream_main = get_upstream_main_branch(git_repo)
    main_branch = upstream_main.split('/')[1]

    remote = git_repo.remotes.origin
    remote.update(prune=True)
    merged_branches = git_repo.git().branch(remotes=True, merged=upstream_main).split()
    for remote_branch in merged_branches:
        if not remote_branch or '/' not in remote_branch:
            continue
        if remote_branch.split('/')[1] not in (main_branch, 'HEAD'):
            for ref in git_repo.remotes.origin.refs:
                if remote_branch == ref.name:
                    remote.push(':%s' % ref.remote_head, force=True)  # rm remote branch


def status_update_json(processed: list, failed: dict) -> None:
    """Output a JSON file with metadata about this run."""
    logging.debug(_('Outputting JSON'))
    output = common.setup_status_output(start_timestamp)
    if processed:
        output['processed'] = processed
    if failed:
        output['failed'] = failed
    common.write_status_json(output)


config = None
start_timestamp = time.gmtime()


def main():
    """Check for updates for one or more apps.

    The behaviour of this function is influenced by the configuration file as
    well as command line parameters.
    """
    global config

    # Parse command line...
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument("appid", nargs='*', help=_("application ID of file to operate on"))
    parser.add_argument("--auto", action="store_true", default=False,
                        help=_("Process auto-updates"))
    parser.add_argument("--autoonly", action="store_true", default=False,
                        help=_("Only process apps with auto-updates"))
    parser.add_argument("--commit", action="store_true", default=False,
                        help=_("Commit changes"))
    parser.add_argument("--merge-request", action="store_true", default=False,
                        help=_("Commit changes, push, then make a merge request"))
    parser.add_argument("--allow-dirty", action="store_true", default=False,
                        help=_("Run on git repo that has uncommitted changes"))
    metadata.add_metadata_arguments(parser)
    options = common.parse_args(parser)
    metadata.warnings_action = options.W

    config = common.read_config()

    if not options.allow_dirty:
        status = subprocess.check_output(['git', 'status', '--porcelain'])
        if status:
            logging.error(_('Build metadata git repo has uncommited changes!'))
            sys.exit(1)

    if options.merge_request and not (options.appid and len(options.appid) == 1):
        logging.error(_('--merge-request only runs on a single appid!'))
        sys.exit(1)

    apps = common.read_app_args(options.appid)

    processed = []
    failed = dict()
    exit_code = 0
    for appid, app in apps.items():

        if options.autoonly and app.AutoUpdateMode in ('None', 'Static'):
            logging.debug(_("Nothing to do for {appid}.").format(appid=appid))
            continue

        msg = _("Processing {appid}").format(appid=appid)
        logging.info(msg)

        try:
            if options.merge_request:
                if not checkout_appid_branch(appid):
                    msg = _("...checkupdate failed for {appid} : {error}").format(
                        appid=appid,
                        error='Open merge request with human edits, skipped.',
                    )
                    logging.warning(msg)
                    failed[appid] = msg
                    continue

            checkupdates_app(app, options.auto, options.commit or options.merge_request)
            processed.append(appid)
        except Exception as e:
            msg = _("...checkupdate failed for {appid} : {error}").format(appid=appid, error=e)
            logging.error(msg)
            logging.debug(traceback.format_exc())
            failed[appid] = str(e)
            exit_code = 1

    if options.appid and options.merge_request:
        push_commits(verbose=options.verbose)
        prune_empty_appid_branches()

    status_update_json(processed, failed)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
