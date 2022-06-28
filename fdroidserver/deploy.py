#!/usr/bin/env python3
#
# deploy.py - part of the FDroid server tools
# Copyright (C) 2010-15, Ciaran Gultnieks, ciaran@ciarang.com
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

import sys
import glob
import hashlib
import json
import os
import re
import subprocess
import time
import urllib
from typing import Dict, List
from git import Repo
import yaml
from argparse import ArgumentParser
import logging
import pathlib
import shutil
import git
import fdroidserver.github

from . import _
from . import common
from . import index
from .exception import FDroidException

config = None
start_timestamp = time.gmtime()

GIT_BRANCH = 'master'

BINARY_TRANSPARENCY_DIR = 'binary_transparency'

AUTO_S3CFG = '.fdroid-deploy-s3cfg'
USER_S3CFG = 's3cfg'
USER_RCLONE_CONF = None
REMOTE_HOSTNAME_REGEX = re.compile(r'\W*\w+\W+(\w+).*')


def _get_index_file_paths(base_dir):
    """Return the list of files to be synced last, since they finalize the deploy.

    The process of pushing all the new packages to the various
    services can take a while.  So the index files should be updated
    last.  That ensures that the package files are available when the
    client learns about them from the new index files.
    """
    return [os.path.join(base_dir, filename) for filename in common.INDEX_FILES]


def _get_index_excludes(base_dir):
    indexes = _get_index_file_paths(base_dir)
    index_excludes = []
    for f in indexes:
        index_excludes.append('--exclude')
        index_excludes.append(f)
    return index_excludes


def _get_index_includes(base_dir):
    indexes = _get_index_file_paths(base_dir)
    index_includes = []
    for f in indexes:
        index_includes.append('--include')
        index_includes.append(f)
    return index_includes


def _remove_missing_files(files: List[str]) -> List[str]:
    """Remove files that are missing from the file system."""
    existing = []
    for f in files:
        if os.path.exists(f):
            existing.append(f)
    return existing


def update_awsbucket(repo_section, is_index_only=False, verbose=False, quiet=False):
    """Upload the contents of the directory `repo_section` (including subdirectories) to the AWS S3 "bucket".

    The contents of that subdir of the
    bucket will first be deleted.

    Requires AWS credentials set in config.yml: awsaccesskeyid, awssecretkey
    """
    logging.debug(
        f'''Syncing "{repo_section}" to Amazon S3 bucket "{config['awsbucket']}"'''
    )

    if common.set_command_in_config('s3cmd') and common.set_command_in_config('rclone'):
        logging.info(
            'Both rclone and s3cmd are installed. Checking config.yml for preference.'
        )
        if config['s3cmd'] is not True and config['rclone'] is not True:
            logging.warning(
                'No syncing tool set in config.yml!. Defaulting to using s3cmd'
            )
            update_awsbucket_s3cmd(repo_section, is_index_only)
        if config['s3cmd'] is True and config['rclone'] is True:
            logging.warning(
                'Both syncing tools set in config.yml!. Defaulting to using s3cmd'
            )
            update_awsbucket_s3cmd(repo_section, is_index_only)
        if config['s3cmd'] is True and config['rclone'] is not True:
            update_awsbucket_s3cmd(repo_section, is_index_only)
        if config['rclone'] is True and config['s3cmd'] is not True:
            update_remote_storage_with_rclone(
                repo_section, is_index_only, verbose, quiet
            )

    elif common.set_command_in_config('s3cmd'):
        update_awsbucket_s3cmd(repo_section, is_index_only)
    elif common.set_command_in_config('rclone'):
        update_remote_storage_with_rclone(repo_section, is_index_only, verbose, quiet)
    else:
        update_awsbucket_libcloud(repo_section, is_index_only)


def update_awsbucket_s3cmd(repo_section, is_index_only=False):
    """Upload using the CLI tool s3cmd, which provides rsync-like sync.

    The upload is done in multiple passes to reduce the chance of
    interfering with an existing client-server interaction.  In the
    first pass, only new files are uploaded.  In the second pass,
    changed files are uploaded, overwriting what is on the server.  On
    the third/last pass, the indexes are uploaded, and any removed
    files are deleted from the server.  The last pass is the only pass
    to use a full MD5 checksum of all files to detect changes.
    """
    logging.debug(_('Using s3cmd to sync with: {url}').format(url=config['awsbucket']))

    if os.path.exists(USER_S3CFG):
        logging.info(_('Using "{path}" for configuring s3cmd.').format(path=USER_S3CFG))
        configfilename = USER_S3CFG
    else:
        fd = os.open(AUTO_S3CFG, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        logging.debug(
            _('Creating "{path}" for configuring s3cmd.').format(path=AUTO_S3CFG)
        )
        os.write(fd, '[default]\n'.encode('utf-8'))
        os.write(
            fd, ('access_key = ' + config['awsaccesskeyid'] + '\n').encode('utf-8')
        )
        os.write(fd, ('secret_key = ' + config['awssecretkey'] + '\n').encode('utf-8'))
        os.close(fd)
        configfilename = AUTO_S3CFG

    s3bucketurl = 's3://' + config['awsbucket']
    s3cmd = [config['s3cmd'], '--config=' + configfilename]
    if subprocess.call(s3cmd + ['info', s3bucketurl]) != 0:
        logging.warning(_('Creating new S3 bucket: {url}').format(url=s3bucketurl))
        if subprocess.call(s3cmd + ['mb', s3bucketurl]) != 0:
            logging.error(
                _('Failed to create S3 bucket: {url}').format(url=s3bucketurl)
            )
            raise FDroidException()

    s3cmd_sync = s3cmd + ['sync', '--acl-public']
    options = common.get_options()
    if options and options.verbose:
        s3cmd_sync += ['--verbose']
    if options and options.quiet:
        s3cmd_sync += ['--quiet']

    s3url = s3bucketurl + '/fdroid/'

    logging.debug(
        _('s3cmd sync indexes {path} to {url} and delete').format(
            path=repo_section, url=s3url
        )
    )

    if is_index_only:
        logging.debug(
            _('s3cmd syncs indexes from {path} to {url} and deletes removed').format(
                path=repo_section, url=s3url
            )
        )
        sync_indexes_flags = []
        sync_indexes_flags.extend(_get_index_includes(repo_section))
        sync_indexes_flags.append('--delete-removed')
        sync_indexes_flags.append('--delete-after')
        if options.no_checksum:
            sync_indexes_flags.append('--no-check-md5')
        else:
            sync_indexes_flags.append('--check-md5')
        returncode = subprocess.call(
            s3cmd_sync + sync_indexes_flags + [repo_section, s3url]
        )
        if returncode != 0:
            raise FDroidException()
    else:
        logging.debug('s3cmd sync new files in ' + repo_section + ' to ' + s3url)
        logging.debug(_('Running first pass with MD5 checking disabled'))
        excludes = _get_index_excludes(repo_section)
        returncode = subprocess.call(
            s3cmd_sync
            + excludes
            + ['--no-check-md5', '--skip-existing', repo_section, s3url]
        )
        if returncode != 0:
            raise FDroidException()
        logging.debug('s3cmd sync all files in ' + repo_section + ' to ' + s3url)
        returncode = subprocess.call(
            s3cmd_sync + excludes + ['--no-check-md5', repo_section, s3url]
        )
        if returncode != 0:
            raise FDroidException()

        logging.debug(
            _('s3cmd sync indexes {path} to {url} and delete').format(
                path=repo_section, url=s3url
            )
        )
        s3cmd_sync.append('--delete-removed')
        s3cmd_sync.append('--delete-after')
        if options.no_checksum:
            s3cmd_sync.append('--no-check-md5')
        else:
            s3cmd_sync.append('--check-md5')
        if subprocess.call(s3cmd_sync + [repo_section, s3url]) != 0:
            raise FDroidException()


def update_remote_storage_with_rclone(
    repo_section, is_index_only=False, verbose=False, quiet=False
):
    """
    Upload fdroid repo folder to remote storage using rclone sync.

    Rclone sync can send the files to any supported remote storage
    service once without numerous polling.
    If remote storage is s3 e.g aws s3, wasabi, filebase then path will be
    bucket_name/fdroid/repo where bucket_name will be an s3 bucket
    If remote storage is storage drive/sftp e.g google drive, rsync.net
    the new path will be bucket_name/fdroid/repo where bucket_name
    will be a folder

    Better than the s3cmd command as it does the syncing in one command
    Check https://rclone.org/docs/#config-config-file (optional config file)
    """
    logging.debug(_('Using rclone to sync with: {url}').format(url=config['awsbucket']))

    if config.get('path_to_custom_rclone_config') is not None:
        USER_RCLONE_CONF = config['path_to_custom_rclone_config']
        if os.path.exists(USER_RCLONE_CONF):
            logging.info("'path_to_custom_rclone_config' found in config.yml")
            logging.info(
                _('Using "{path}" for syncing with remote storage.').format(
                    path=USER_RCLONE_CONF
                )
            )
            configfilename = USER_RCLONE_CONF
        else:
            logging.info('Custom configuration not found.')
            logging.info(
                'Using default configuration at {}'.format(
                    subprocess.check_output(['rclone', 'config', 'file'], text=True)
                )
            )
            configfilename = None
    else:
        logging.warning("'path_to_custom_rclone_config' not found in config.yml")
        logging.info('Custom configuration not found.')
        logging.info(
            'Using default configuration at {}'.format(
                subprocess.check_output(['rclone', 'config', 'file'], text=True)
            )
        )
        configfilename = None

    upload_dir = 'fdroid/' + repo_section

    if not config.get('rclone_config') or not config.get('awsbucket'):
        raise FDroidException(
            _('To use rclone, rclone_config and awsbucket must be set in config.yml!')
        )

    if is_index_only:
        sources = _get_index_file_paths(repo_section)
        sources = _remove_missing_files(sources)
    else:
        sources = [repo_section]

    if isinstance(config['rclone_config'], str):
        rclone_config = [config['rclone_config']]
    else:
        rclone_config = config['rclone_config']

    for source in sources:
        for remote_config in rclone_config:
            complete_remote_path = f'{remote_config}:{config["awsbucket"]}/{upload_dir}'
            rclone_sync_command = ['rclone', 'sync', source, complete_remote_path]

            if verbose:
                rclone_sync_command += ['--verbose']
            elif quiet:
                rclone_sync_command += ['--quiet']

            if configfilename:
                rclone_sync_command += ['--config=' + configfilename]

            logging.debug(
                "rclone sync all files in " + source + ' to ' + complete_remote_path
            )

            if subprocess.call(rclone_sync_command) != 0:
                raise FDroidException()


def update_awsbucket_libcloud(repo_section, is_index_only=False):
    """No summary.

    Upload the contents of the directory `repo_section` (including
    subdirectories) to the AWS S3 "bucket".

    The contents of that subdir of the
    bucket will first be deleted.

    Requires AWS credentials set in config.yml: awsaccesskeyid, awssecretkey
    """
    logging.debug(
        _('using Apache libcloud to sync with {url}').format(url=config['awsbucket'])
    )

    import libcloud.security

    libcloud.security.VERIFY_SSL_CERT = True
    from libcloud.storage.types import Provider, ContainerDoesNotExistError
    from libcloud.storage.providers import get_driver

    if not config.get('awsaccesskeyid') or not config.get('awssecretkey'):
        raise FDroidException(
            _(
                'To use awsbucket, awssecretkey and awsaccesskeyid must also be set in config.yml!'
            )
        )
    awsbucket = config['awsbucket']

    if os.path.exists(USER_S3CFG):
        raise FDroidException(
            _('"{path}" exists but s3cmd is not installed!').format(path=USER_S3CFG)
        )

    cls = get_driver(Provider.S3)
    driver = cls(config['awsaccesskeyid'], config['awssecretkey'])
    try:
        container = driver.get_container(container_name=awsbucket)
    except ContainerDoesNotExistError:
        container = driver.create_container(container_name=awsbucket)
        logging.info(_('Created new container "{name}"').format(name=container.name))

    upload_dir = 'fdroid/' + repo_section
    objs = dict()
    for obj in container.list_objects():
        if obj.name.startswith(upload_dir + '/'):
            objs[obj.name] = obj

    if is_index_only:
        index_files = [
            f"{os.getcwd()}/{name}" for name in _get_index_file_paths(repo_section)
        ]
        files_to_upload = [
            os.path.join(root, name)
            for root, dirs, files in os.walk(os.path.join(os.getcwd(), repo_section))
            for name in files
        ]
        files_to_upload = list(set(files_to_upload) & set(index_files))
        files_to_upload = _remove_missing_files(files_to_upload)

    else:
        files_to_upload = [
            os.path.join(root, name)
            for root, dirs, files in os.walk(os.path.join(os.getcwd(), repo_section))
            for name in files
        ]

    for file_to_upload in files_to_upload:
        upload = False
        object_name = 'fdroid/' + os.path.relpath(file_to_upload, os.getcwd())
        if object_name not in objs:
            upload = True
        else:
            obj = objs.pop(object_name)
            if obj.size != os.path.getsize(file_to_upload):
                upload = True
            else:
                # if the sizes match, then compare by MD5
                md5 = hashlib.md5()  # nosec AWS uses MD5
                with open(file_to_upload, 'rb') as f:
                    while True:
                        data = f.read(8192)
                        if not data:
                            break
                        md5.update(data)
                if obj.hash != md5.hexdigest():
                    s3url = 's3://' + awsbucket + '/' + obj.name
                    logging.info(' deleting ' + s3url)
                    if not driver.delete_object(obj):
                        logging.warning('Could not delete ' + s3url)
                    upload = True

        if upload:
            logging.debug(' uploading "' + file_to_upload + '"...')
            extra = {'acl': 'public-read'}
            if file_to_upload.endswith('.sig'):
                extra['content_type'] = 'application/pgp-signature'
            elif file_to_upload.endswith('.asc'):
                extra['content_type'] = 'application/pgp-signature'
            path = os.path.relpath(file_to_upload)
            logging.info(f' uploading {path} to s3://{awsbucket}/{object_name}')
            with open(file_to_upload, 'rb') as iterator:
                obj = driver.upload_object_via_stream(
                    iterator=iterator,
                    container=container,
                    object_name=object_name,
                    extra=extra,
                )
    # delete the remnants in the bucket, they do not exist locally
    while objs:
        object_name, obj = objs.popitem()
        s3url = 's3://' + awsbucket + '/' + object_name
        if object_name.startswith(upload_dir):
            logging.warning(' deleting ' + s3url)
            driver.delete_object(obj)
        else:
            logging.info(' skipping ' + s3url)


def update_serverwebroot(serverwebroot, repo_section):
    """Deploy the index files to the serverwebroot using rsync.

    Upload the first time without the index files and delay the
    deletion as much as possible.  That keeps the repo functional
    while this update is running.  Then once it is complete, rerun the
    command again to upload the index files.  Always using the same
    target with rsync allows for very strict settings on the receiving
    server, you can literally specify the one rsync command that is
    allowed to run in ~/.ssh/authorized_keys.  (serverwebroot is
    guaranteed to have a trailing slash in common.py)

    It is possible to optionally use a checksum comparison for
    accurate comparisons on different filesystems, for example, FAT
    has a low resolution timestamp

    """
    try:
        subprocess.run(['rsync', '--version'], capture_output=True, check=True)
    except Exception as e:
        raise FDroidException(
            _('rsync is missing or broken: {error}').format(error=e)
        ) from e
    rsyncargs = ['rsync', '--archive', '--delete-after', '--safe-links']
    options = common.get_options()
    if not options or not options.no_checksum:
        rsyncargs.append('--checksum')
    if options and options.verbose:
        rsyncargs += ['--verbose']
    if options and options.quiet:
        rsyncargs += ['--quiet']
    if options and options.identity_file:
        rsyncargs += [
            '-e',
            'ssh -oBatchMode=yes -oIdentitiesOnly=yes -i ' + options.identity_file,
        ]
    elif config and config.get('identity_file'):
        rsyncargs += [
            '-e',
            'ssh -oBatchMode=yes -oIdentitiesOnly=yes -i ' + config['identity_file'],
        ]
    url = serverwebroot['url']
    is_index_only = serverwebroot.get('index_only', False)
    logging.info('rsyncing ' + repo_section + ' to ' + url)
    if is_index_only:
        files_to_upload = _get_index_file_paths(repo_section)
        files_to_upload = _remove_missing_files(files_to_upload)

        rsyncargs += files_to_upload
        rsyncargs += [f'{url}/{repo_section}/']
        logging.info(rsyncargs)
        if subprocess.call(rsyncargs) != 0:
            raise FDroidException()
    else:
        excludes = _get_index_excludes(repo_section)
        if subprocess.call(rsyncargs + excludes + [repo_section, url]) != 0:
            raise FDroidException()
        if subprocess.call(rsyncargs + [repo_section, url]) != 0:
            raise FDroidException()
        # upload "current version" symlinks if requested
        if (
            config
            and config.get('make_current_version_link')
            and repo_section == 'repo'
        ):
            links_to_upload = []
            for f in (
                glob.glob('*.apk') + glob.glob('*.apk.asc') + glob.glob('*.apk.sig')
            ):
                if os.path.islink(f):
                    links_to_upload.append(f)
            if len(links_to_upload) > 0:
                if subprocess.call(rsyncargs + links_to_upload + [url]) != 0:
                    raise FDroidException()


def update_serverwebroots(serverwebroots, repo_section, standardwebroot=True):
    for d in serverwebroots:
        # this supports both an ssh host:path and just a path
        serverwebroot = d['url']
        s = serverwebroot.rstrip('/').split(':')
        if len(s) == 1:
            fdroiddir = s[0]
        elif len(s) == 2:
            host, fdroiddir = s
        else:
            logging.error(_('Malformed serverwebroot line:') + ' ' + serverwebroot)
            sys.exit(1)
        repobase = os.path.basename(fdroiddir)
        if standardwebroot and repobase != 'fdroid':
            logging.error(
                _(
                    'serverwebroot: path does not end with "fdroid", perhaps you meant one of these:'
                )
                + '\n\t'
                + serverwebroot.rstrip('/')
                + '/fdroid\n\t'
                + serverwebroot.rstrip('/').rstrip(repobase)
                + 'fdroid'
            )
            sys.exit(1)
        update_serverwebroot(d, repo_section)


def sync_from_localcopy(repo_section, local_copy_dir):
    """Sync the repo from "local copy dir" filesystem to this box.

    In setups that use offline signing, this is the last step that
    syncs the repo from the "local copy dir" e.g. a thumb drive to the
    repo on the local filesystem.  That local repo is then used to
    push to all the servers that are configured.

    """
    logging.info('Syncing from local_copy_dir to this repo.')

    # trailing slashes have a meaning in rsync which is not needed here, so
    # make sure both paths have exactly one trailing slash
    common.local_rsync(
        common.get_options(),
        [os.path.join(local_copy_dir, repo_section).rstrip('/') + '/'],
        repo_section.rstrip('/') + '/',
    )

    offline_copy = os.path.join(local_copy_dir, BINARY_TRANSPARENCY_DIR)
    if os.path.exists(os.path.join(offline_copy, '.git')):
        online_copy = os.path.join(os.getcwd(), BINARY_TRANSPARENCY_DIR)
        push_binary_transparency(offline_copy, online_copy)


def update_localcopy(repo_section, local_copy_dir):
    """Copy data from offline to the "local copy dir" filesystem.

    This updates the copy of this repo used to shuttle data from an
    offline signing machine to the online machine, e.g. on a thumb
    drive.

    """
    # local_copy_dir is guaranteed to have a trailing slash in main() below
    common.local_rsync(common.get_options(), [repo_section], local_copy_dir)

    offline_copy = os.path.join(os.getcwd(), BINARY_TRANSPARENCY_DIR)
    if os.path.isdir(os.path.join(offline_copy, '.git')):
        online_copy = os.path.join(local_copy_dir, BINARY_TRANSPARENCY_DIR)
        push_binary_transparency(offline_copy, online_copy)


def _get_size(start_path='.'):
    """Get size of all files in a dir https://stackoverflow.com/a/1392549."""
    total_size = 0
    for root, dirs, files in os.walk(start_path):
        for f in files:
            fp = os.path.join(root, f)
            total_size += os.path.getsize(fp)
    return total_size


def update_servergitmirrors(servergitmirrors, repo_section):
    """Update repo mirrors stored in git repos.

    This is a hack to use public git repos as F-Droid repos.  It
    recreates the git repo from scratch each time, so that there is no
    history.  That keeps the size of the git repo small.  Services
    like GitHub or GitLab have a size limit of something like 1 gig.
    This git repo is only a git repo for the purpose of being hosted.
    For history, there is the archive section, and there is the binary
    transparency log.

    """
    from clint.textui import progress

    if config.get('local_copy_dir') and not config.get('sync_from_local_copy_dir'):
        logging.debug(
            _('Offline machine, skipping git mirror generation until `fdroid deploy`')
        )
        return

    options = common.get_options()
    workspace_dir = pathlib.Path(os.getcwd())

    # right now we support only 'repo' git-mirroring
    if repo_section == 'repo':
        git_mirror_path = workspace_dir / 'git-mirror'
        dotgit = os.path.join(git_mirror_path, '.git')
        git_fdroiddir = os.path.join(git_mirror_path, 'fdroid')
        git_repodir = os.path.join(git_fdroiddir, repo_section)
        if not os.path.isdir(git_repodir):
            os.makedirs(git_repodir)
        # github/gitlab use bare git repos, so only count the .git folder
        # test: generate giant APKs by including AndroidManifest.xml and and large
        # file from /dev/urandom, then sign it.  Then add those to the git repo.
        dotgit_size = _get_size(dotgit)
        dotgit_over_limit = dotgit_size > config['git_mirror_size_limit']
        if os.path.isdir(dotgit) and dotgit_over_limit:
            logging.warning(
                _(
                    'Deleting git-mirror history, repo is too big ({size} max {limit})'
                ).format(size=dotgit_size, limit=config['git_mirror_size_limit'])
            )
            shutil.rmtree(dotgit)
        if options.no_keep_git_mirror_archive and dotgit_over_limit:
            logging.warning(
                _('Deleting archive, repo is too big ({size} max {limit})').format(
                    size=dotgit_size, limit=config['git_mirror_size_limit']
                )
            )
            archive_path = os.path.join(git_mirror_path, 'fdroid', 'archive')
            shutil.rmtree(archive_path, ignore_errors=True)

        # use custom SSH command if identity_file specified
        ssh_cmd = 'ssh -oBatchMode=yes'
        if options.identity_file is not None:
            ssh_cmd += ' -oIdentitiesOnly=yes -i "%s"' % options.identity_file
        elif 'identity_file' in config:
            ssh_cmd += ' -oIdentitiesOnly=yes -i "%s"' % config['identity_file']

        if options.verbose:
            progressbar = progress.Bar()

            class MyProgressPrinter(git.RemoteProgress):
                def update(self, op_code, current, maximum=None, message=None):
                    if isinstance(maximum, float):
                        progressbar.show(current, maximum)

            progress = MyProgressPrinter()
        else:
            progress = None

        repo = git.Repo.init(git_mirror_path, initial_branch=GIT_BRANCH)

        enabled_remotes = []
        for d in servergitmirrors:
            is_index_only = d.get('index_only', False)

            # Use a separate branch for the index only mode as it needs a different set of files to commit
            if is_index_only:
                local_branch_name = 'index_only'
            else:
                local_branch_name = 'full'
            if local_branch_name in repo.heads:
                repo.git.switch(local_branch_name)
            else:
                repo.git.switch('--orphan', local_branch_name)

            # trailing slashes have a meaning in rsync which is not needed here, so
            # make sure both paths have exactly one trailing slash
            if is_index_only:
                files_to_sync = _get_index_file_paths(str(workspace_dir / repo_section))
                files_to_sync = _remove_missing_files(files_to_sync)
            else:
                files_to_sync = [str(workspace_dir / repo_section).rstrip('/') + '/']
            common.local_rsync(
                common.get_options(), files_to_sync, git_repodir.rstrip('/') + '/'
            )

            upload_to_servergitmirror(
                mirror_config=d,
                local_repo=repo,
                enabled_remotes=enabled_remotes,
                repo_section=repo_section,
                is_index_only=is_index_only,
                fdroid_dir=git_fdroiddir,
                git_mirror_path=str(git_mirror_path),
                ssh_cmd=ssh_cmd,
                progress=progress,
            )
        if progress:
            progressbar.done()


def upload_to_servergitmirror(
    mirror_config: Dict[str, str],
    local_repo: Repo,
    enabled_remotes: List[str],
    repo_section: str,
    is_index_only: bool,
    fdroid_dir: str,
    git_mirror_path: str,
    ssh_cmd: str,
    progress: git.RemoteProgress,
) -> None:
    remote_branch_name = GIT_BRANCH
    local_branch_name = local_repo.active_branch.name

    remote_url = mirror_config['url']
    name = REMOTE_HOSTNAME_REGEX.sub(r'\1', remote_url)
    enabled_remotes.append(name)
    r = git.remote.Remote(local_repo, name)
    if r in local_repo.remotes:
        r = local_repo.remote(name)
        if 'set_url' in dir(r):  # force remote URL if using GitPython 2.x
            r.set_url(remote_url)
    else:
        local_repo.create_remote(name, remote_url)
    logging.info('Mirroring to: ' + remote_url)

    if is_index_only:
        files_to_upload = _get_index_file_paths(
            os.path.join(local_repo.working_tree_dir, 'fdroid', repo_section)
        )
        files_to_upload = _remove_missing_files(files_to_upload)
        local_repo.index.add(files_to_upload)
    else:
        # sadly index.add don't allow the --all parameter
        logging.debug('Adding all files to git mirror')
        local_repo.git.add(all=True)

    logging.debug('Committing files into git mirror')
    local_repo.index.commit("fdroidserver git-mirror")

    # only deploy to GitLab Artifacts if too big for GitLab Pages
    if (
        is_index_only
        or common.get_dir_size(fdroid_dir) <= common.GITLAB_COM_PAGES_MAX_SIZE
    ):
        gitlab_ci_job_name = 'pages'
    else:
        gitlab_ci_job_name = 'GitLab Artifacts'
        logging.warning(
            _('Skipping GitLab Pages mirror because the repo is too large (>%.2fGB)!')
            % (common.GITLAB_COM_PAGES_MAX_SIZE / 1000000000)
        )

    # push. This will overwrite the git history
    remote = local_repo.remote(name)
    if remote.name == 'gitlab':
        logging.debug('Writing .gitlab-ci.yml to deploy to GitLab Pages')
        with open(os.path.join(git_mirror_path, ".gitlab-ci.yml"), "wt") as fp:
            yaml.dump(
                {
                    gitlab_ci_job_name: {
                        'script': [
                            'mkdir .public',
                            'cp -r * .public/',
                            'mv .public public',
                        ],
                        'artifacts': {'paths': ['public']},
                        'variables': {'GIT_DEPTH': 1},
                    }
                },
                fp,
                default_flow_style=False,
            )

        local_repo.index.add(['.gitlab-ci.yml'])
        local_repo.index.commit("fdroidserver git-mirror: Deploy to GitLab Pages")

    logging.debug(_('Pushing to {url}').format(url=remote.url))
    with local_repo.git.custom_environment(GIT_SSH_COMMAND=ssh_cmd):
        pushinfos = remote.push(
            f"{local_branch_name}:{remote_branch_name}",
            force=True,
            set_upstream=True,
            progress=progress,
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
                    remote.url
                    + ' push failed: '
                    + str(pushinfo.flags)
                    + ' '
                    + pushinfo.summary
                )
            else:
                logging.debug(remote.url + ': ' + pushinfo.summary)


def upload_to_android_observatory(repo_section):
    import requests

    requests  # stop unused import warning

    if common.get_options().verbose:
        logging.getLogger("requests").setLevel(logging.INFO)
        logging.getLogger("urllib3").setLevel(logging.INFO)
    else:
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

    if repo_section == 'repo':
        for f in sorted(glob.glob(os.path.join(repo_section, '*.apk'))):
            upload_apk_to_android_observatory(f)


def upload_apk_to_android_observatory(path):
    # depend on requests and lxml only if users enable AO
    import requests
    from . import net
    from lxml.html import fromstring

    apkfilename = os.path.basename(path)
    r = requests.post(
        'https://androidobservatory.org/',
        data={'q': common.sha256sum(path), 'searchby': 'hash'},
        headers=net.HEADERS,
        timeout=300,
    )
    if r.status_code == 200:
        # from now on XPath will be used to retrieve the message in the HTML
        # androidobservatory doesn't have a nice API to talk with
        # so we must scrape the page content
        tree = fromstring(r.text)

        href = None
        for element in tree.xpath("//html/body/div/div/table/tbody/tr/td/a"):
            a = element.attrib.get('href')
            if a:
                m = re.match(r'^/app/[0-9A-F]{40}$', a)
                if m:
                    href = m.group()

        page = 'https://androidobservatory.org'
        if href:
            message = _('Found {apkfilename} at {url}').format(
                apkfilename=apkfilename, url=(page + href)
            )
            logging.debug(message)
            return

    # upload the file with a post request
    logging.info(
        _('Uploading {apkfilename} to androidobservatory.org').format(
            apkfilename=apkfilename
        )
    )
    r = requests.post(
        'https://androidobservatory.org/upload',
        files={'apk': (apkfilename, open(path, 'rb'))},
        headers=net.HEADERS,
        allow_redirects=False,
        timeout=300,
    )


def upload_to_virustotal(repo_section, virustotal_apikey):
    import requests

    requests  # stop unused import warning

    if repo_section == 'repo':
        if not os.path.exists('virustotal'):
            os.mkdir('virustotal')

        if os.path.exists(os.path.join(repo_section, 'index-v1.json')):
            with open(os.path.join(repo_section, 'index-v1.json')) as fp:
                data = json.load(fp)
        else:
            local_jar = os.path.join(repo_section, 'index-v1.jar')
            data, _ignored, _ignored = index.get_index_from_jar(local_jar)

        for packageName, packages in data['packages'].items():
            for package in packages:
                upload_apk_to_virustotal(virustotal_apikey, **package)


def upload_apk_to_virustotal(
    virustotal_apikey, packageName, apkName, hash, versionCode, **kwargs
):
    import requests

    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    outputfilename = os.path.join(
        'virustotal', packageName + '_' + str(versionCode) + '_' + hash + '.json'
    )
    if os.path.exists(outputfilename):
        logging.debug(apkName + ' results are in ' + outputfilename)
        return outputfilename
    repofilename = os.path.join('repo', apkName)
    logging.info('Checking if ' + repofilename + ' is on virustotal')

    headers = {"User-Agent": "F-Droid"}
    if 'headers' in kwargs:
        for k, v in kwargs['headers'].items():
            headers[k] = v

    apikey = {
        'apikey': virustotal_apikey,
        'resource': hash,
    }
    needs_file_upload = False
    while True:
        report_url = (
            'https://www.virustotal.com/vtapi/v2/file/report?'
            + urllib.parse.urlencode(apikey)
        )
        r = requests.get(report_url, headers=headers, timeout=300)
        if r.status_code == 200:
            response = r.json()
            if response['response_code'] == 0:
                needs_file_upload = True
            else:
                response['filename'] = apkName
                response['packageName'] = packageName
                response['versionCode'] = versionCode
                if kwargs.get('versionName'):
                    response['versionName'] = kwargs.get('versionName')
                with open(outputfilename, 'w') as fp:
                    json.dump(response, fp, indent=2, sort_keys=True)

            if response.get('positives', 0) > 0:
                logging.warning(
                    _('{path} has been flagged by virustotal {count} times:').format(
                        path=repofilename, count=response['positives']
                    ),
                    +'\n\t' + response['permalink'],
                )
            break
        if r.status_code == 204:
            logging.warning(_('virustotal.com is rate limiting, waiting to retry...'))
            time.sleep(30)  # wait for public API rate limiting

    upload_url = None
    if needs_file_upload:
        manual_url = 'https://www.virustotal.com/'
        size = os.path.getsize(repofilename)
        if size > 200000000:
            # VirusTotal API 200MB hard limit
            logging.error(
                _('{path} more than 200MB, manually upload: {url}').format(
                    path=repofilename, url=manual_url
                )
            )
        elif size > 32000000:
            # VirusTotal API requires fetching a URL to upload bigger files
            query_url = (
                'https://www.virustotal.com/vtapi/v2/file/scan/upload_url?'
                + urllib.parse.urlencode(apikey)
            )
            r = requests.get(query_url, headers=headers, timeout=300)
            if r.status_code == 200:
                upload_url = r.json().get('upload_url')
            elif r.status_code == 403:
                logging.error(
                    _(
                        'VirusTotal API key cannot upload files larger than 32MB, '
                        + 'use {url} to upload {path}.'
                    ).format(path=repofilename, url=manual_url)
                )
            else:
                r.raise_for_status()
        else:
            upload_url = 'https://www.virustotal.com/vtapi/v2/file/scan'

    if upload_url:
        logging.info(
            _('Uploading {apkfilename} to virustotal').format(apkfilename=repofilename)
        )
        r = requests.post(
            upload_url,
            data=apikey,
            headers=headers,
            files={'file': (apkName, open(repofilename, 'rb'))},
            timeout=300,
        )
        logging.debug(
            _('If this upload fails, try manually uploading to {url}').format(
                url=manual_url
            )
        )
        r.raise_for_status()
        response = r.json()
        logging.info(response['verbose_msg'] + " " + response['permalink'])

    return outputfilename


def push_binary_transparency(git_repo_path, git_remote):
    """Push the binary transparency git repo to the specifed remote.

    If the remote is a local directory, make sure it exists, and is a
    git repo.  This is used to move this git repo from an offline
    machine onto a flash drive, then onto the online machine. Also,
    this pulls because pushing to a non-bare git repo is error prone.

    This is also used in offline signing setups, where it then also
    creates a "local copy dir" git repo that serves to shuttle the git
    data from the offline machine to the online machine.  In that
    case, git_remote is a dir on the local file system, e.g. a thumb
    drive.

    """
    logging.info(_('Pushing binary transparency log to {url}').format(url=git_remote))

    if os.path.isdir(os.path.dirname(git_remote)):
        # from offline machine to thumbdrive
        remote_path = os.path.abspath(git_repo_path)
        if not os.path.isdir(os.path.join(git_remote, '.git')):
            os.makedirs(git_remote, exist_ok=True)
            thumbdriverepo = git.Repo.init(git_remote, initial_branch=GIT_BRANCH)
            local = thumbdriverepo.create_remote('local', remote_path)
        else:
            thumbdriverepo = git.Repo(git_remote)
            local = git.remote.Remote(thumbdriverepo, 'local')
            if local in thumbdriverepo.remotes:
                local = thumbdriverepo.remote('local')
                if 'set_url' in dir(local):  # force remote URL if using GitPython 2.x
                    local.set_url(remote_path)
            else:
                local = thumbdriverepo.create_remote('local', remote_path)
        local.pull(GIT_BRANCH)
    else:
        # from online machine to remote on a server on the internet
        gitrepo = git.Repo(git_repo_path)
        origin = git.remote.Remote(gitrepo, 'origin')
        if origin in gitrepo.remotes:
            origin = gitrepo.remote('origin')
            if 'set_url' in dir(origin):  # added in GitPython 2.x
                origin.set_url(git_remote)
        else:
            origin = gitrepo.create_remote('origin', git_remote)
        for _i in range(3):
            try:
                origin.push(GIT_BRANCH)
            except git.GitCommandError as e:
                logging.error(e)
                continue
            break
        else:
            raise FDroidException(_("Pushing to remote server failed!"))


def find_release_infos(index_v2_path, repo_dir, package_names):
    """Find files, texts, etc. for uploading to a release page in index-v2.json.

    This function parses index-v2.json for file-paths elegible for deployment
    to release pages. (e.g. GitHub releases) It also groups these files by
    packageName and versionName. e.g. to get a list of files for all specific
    release of fdroid client you may call:

    find_binary_release_infos()['org.fdroid.fdroid']['0.19.2']

    All paths in the returned data-structure are of type pathlib.Path.
    """
    release_infos = {}
    with open(index_v2_path, 'r') as f:
        idx = json.load(f)
        for package_name in package_names:
            package = idx.get('packages', {}).get(package_name, {})
            for version in package.get('versions', {}).values():
                if package_name not in release_infos:
                    release_infos[package_name] = {}
                version_name = version['manifest']['versionName']
                version_path = repo_dir / version['file']['name'].lstrip("/")
                files = [version_path]
                asc_path = pathlib.Path(str(version_path) + '.asc')
                if asc_path.is_file():
                    files.append(asc_path)
                sig_path = pathlib.Path(str(version_path) + '.sig')
                if sig_path.is_file():
                    files.append(sig_path)
                release_infos[package_name][version_name] = {
                    'files': files,
                    'whatsNew': version.get('whatsNew', {}).get("en-US"),
                    'hasReleaseChannels': len(version.get('releaseChannels', [])) > 0,
                }
    return release_infos


def upload_to_github_releases(repo_section, gh_config, global_gh_token):
    repo_dir = pathlib.Path(repo_section)
    index_v2_path = repo_dir / 'index-v2.json'
    if not index_v2_path.is_file():
        logging.warning(
            _(
                "Error deploying 'github_releases', {} not present. (You might "
                "need to run `fdroid update` first.)"
            ).format(index_v2_path)
        )
        return

    package_names = []
    for repo_conf in gh_config:
        for package_name in repo_conf.get('packageNames', []):
            package_names.append(package_name)

    release_infos = fdroidserver.deploy.find_release_infos(
        index_v2_path, repo_dir, package_names
    )

    for repo_conf in gh_config:
        upload_to_github_releases_repo(repo_conf, release_infos, global_gh_token)


def upload_to_github_releases_repo(repo_conf, release_infos, global_gh_token):
    projectUrl = repo_conf.get("projectUrl")
    if not projectUrl:
        logging.warning(
            _(
                "One of the 'github_releases' config items is missing the "
                "'projectUrl' value. skipping ..."
            )
        )
        return
    token = repo_conf.get("token") or global_gh_token
    if not token:
        logging.warning(
            _(
                "One of the 'github_releases' config items is missing the "
                "'token' value. skipping ..."
            )
        )
        return
    conf_package_names = repo_conf.get("packageNames", [])
    if type(conf_package_names) == str:
        conf_package_names = [conf_package_names]
    if not conf_package_names:
        logging.warning(
            _(
                "One of the 'github_releases' config items is missing the "
                "'packageNames' value. skipping ..."
            )
        )
        return

    # lookup all versionNames (git tags) for all packages available in the
    # local fdroid repo
    all_local_versions = set()
    for package_name in conf_package_names:
        for version in release_infos.get(package_name, {}).keys():
            all_local_versions.add(version)

    gh = fdroidserver.github.GithubApi(token, projectUrl)
    unreleased_tags = gh.list_unreleased_tags()

    for version in all_local_versions:
        if version in unreleased_tags:
            # Making sure we're not uploading this version when releaseChannels
            # is set. (releaseChannels usually mean it's e.g. an alpha or beta
            # version)
            if (
                not release_infos.get(conf_package_names[0], {})
                .get(version, {})
                .get('hasReleaseChannels')
            ):
                # collect files associated with this github release
                files = []
                for package in conf_package_names:
                    files.extend(
                        release_infos.get(package, {}).get(version, {}).get('files', [])
                    )
                # always use the whatsNew text from the first app listed in
                # config.yml github_releases.packageNames
                text = (
                    release_infos.get(conf_package_names[0], {})
                    .get(version, {})
                    .get('whatsNew')
                    or ''
                )
                if 'release_notes_prepend' in repo_conf:
                    text = repo_conf['release_notes_prepend'] + "\n\n" + text
                # create new release on github and upload all associated files
                gh.create_release(version, files, text)


def main():
    global config

    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument(
        "-i",
        "--identity-file",
        default=None,
        help=_("Specify an identity file to provide to SSH for rsyncing"),
    )
    parser.add_argument(
        "--local-copy-dir",
        default=None,
        help=_("Specify a local folder to sync the repo to"),
    )
    parser.add_argument(
        "--no-checksum",
        action="store_true",
        default=False,
        help=_("Don't use rsync checksums"),
    )
    parser.add_argument(
        "--no-keep-git-mirror-archive",
        action="store_true",
        default=False,
        help=_("If a git mirror gets to big, allow the archive to be deleted"),
    )
    options = common.parse_args(parser)
    config = common.read_config()

    if config.get('nonstandardwebroot') is True:
        standardwebroot = False
    else:
        standardwebroot = True

    if options.local_copy_dir is not None:
        local_copy_dir = options.local_copy_dir
    elif config.get('local_copy_dir'):
        local_copy_dir = config['local_copy_dir']
    else:
        local_copy_dir = None
    if local_copy_dir is not None:
        fdroiddir = local_copy_dir.rstrip('/')
        if os.path.exists(fdroiddir) and not os.path.isdir(fdroiddir):
            logging.error(_('local_copy_dir must be directory, not a file!'))
            sys.exit(1)
        if not os.path.exists(os.path.dirname(fdroiddir)):
            logging.error(
                _('The root dir for local_copy_dir "{path}" does not exist!').format(
                    path=os.path.dirname(fdroiddir)
                )
            )
            sys.exit(1)
        if not os.path.isabs(fdroiddir):
            logging.error(_('local_copy_dir must be an absolute path!'))
            sys.exit(1)
        repobase = os.path.basename(fdroiddir)
        if standardwebroot and repobase != 'fdroid':
            logging.error(
                _(
                    'local_copy_dir does not end with "fdroid", '
                    + 'perhaps you meant: "{path}"'
                ).format(path=fdroiddir + '/fdroid')
            )
            sys.exit(1)
        if local_copy_dir[-1] != '/':
            local_copy_dir += '/'
        local_copy_dir = local_copy_dir.replace('//', '/')
        if not os.path.exists(fdroiddir):
            os.mkdir(fdroiddir)

    if (
        not config.get('awsbucket')
        and not config.get('serverwebroot')
        and not config.get('servergitmirrors')
        and not config.get('androidobservatory')
        and not config.get('binary_transparency_remote')
        and not config.get('virustotal_apikey')
        and not config.get('github_releases')
        and local_copy_dir is None
    ):
        logging.warning(
            _('No option set! Edit your config.yml to set at least one of these:')
            + '\nserverwebroot, servergitmirrors, local_copy_dir, awsbucket, '
            + 'virustotal_apikey, androidobservatory, github_releases '
            + 'or binary_transparency_remote'
        )
        sys.exit(1)

    repo_sections = ['repo']
    if config['archive_older'] != 0:
        repo_sections.append('archive')
        if not os.path.exists('archive'):
            os.mkdir('archive')
    if config['per_app_repos']:
        repo_sections += common.get_per_app_repos()

    if os.path.isdir('unsigned') or (
        local_copy_dir is not None
        and os.path.isdir(os.path.join(local_copy_dir, 'unsigned'))
    ):
        repo_sections.append('unsigned')

    for repo_section in repo_sections:
        if local_copy_dir is not None:
            if config['sync_from_local_copy_dir']:
                sync_from_localcopy(repo_section, local_copy_dir)
            else:
                update_localcopy(repo_section, local_copy_dir)
        if config.get('serverwebroot'):
            update_serverwebroots(
                config['serverwebroot'], repo_section, standardwebroot
            )
        if config.get('servergitmirrors'):
            # update_servergitmirrors will take care of multiple mirrors so don't need a foreach
            update_servergitmirrors(config['servergitmirrors'], repo_section)
        if config.get('awsbucket'):
            index_only = config.get('awsbucket_index_only')
            update_awsbucket(repo_section, index_only, options.verbose, options.quiet)
        if config.get('androidobservatory'):
            upload_to_android_observatory(repo_section)
        if config.get('virustotal_apikey'):
            upload_to_virustotal(repo_section, config.get('virustotal_apikey'))
        if config.get('github_releases'):
            upload_to_github_releases(
                repo_section, config.get('github_releases'), config.get('github_token')
            )

    binary_transparency_remote = config.get('binary_transparency_remote')
    if binary_transparency_remote:
        push_binary_transparency(BINARY_TRANSPARENCY_DIR, binary_transparency_remote)

    common.write_status_json(common.setup_status_output(start_timestamp))
    sys.exit(0)


if __name__ == "__main__":
    main()
