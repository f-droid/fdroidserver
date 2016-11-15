#!/usr/bin/env python3
#
# server.py - part of the FDroid server tools
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
import os
import paramiko
import pwd
import subprocess
from argparse import ArgumentParser
import logging

from . import common

config = None
options = None


def update_awsbucket(repo_section):
    '''
    Upload the contents of the directory `repo_section` (including
    subdirectories) to the AWS S3 "bucket". The contents of that subdir of the
    bucket will first be deleted.

    Requires AWS credentials set in config.py: awsaccesskeyid, awssecretkey
    '''

    logging.debug('Syncing "' + repo_section + '" to Amazon S3 bucket "'
                  + config['awsbucket'] + '"')

    import libcloud.security
    libcloud.security.VERIFY_SSL_CERT = True
    from libcloud.storage.types import Provider, ContainerDoesNotExistError
    from libcloud.storage.providers import get_driver

    if not config.get('awsaccesskeyid') or not config.get('awssecretkey'):
        logging.error('To use awsbucket, you must set awssecretkey and awsaccesskeyid in config.py!')
        sys.exit(1)
    awsbucket = config['awsbucket']

    cls = get_driver(Provider.S3)
    driver = cls(config['awsaccesskeyid'], config['awssecretkey'])
    try:
        container = driver.get_container(container_name=awsbucket)
    except ContainerDoesNotExistError:
        container = driver.create_container(container_name=awsbucket)
        logging.info('Created new container "' + container.name + '"')

    upload_dir = 'fdroid/' + repo_section
    objs = dict()
    for obj in container.list_objects():
        if obj.name.startswith(upload_dir + '/'):
            objs[obj.name] = obj

    for root, _, files in os.walk(os.path.join(os.getcwd(), repo_section)):
        for name in files:
            upload = False
            file_to_upload = os.path.join(root, name)
            object_name = 'fdroid/' + os.path.relpath(file_to_upload, os.getcwd())
            if object_name not in objs:
                upload = True
            else:
                obj = objs.pop(object_name)
                if obj.size != os.path.getsize(file_to_upload):
                    upload = True
                else:
                    # if the sizes match, then compare by MD5
                    md5 = hashlib.md5()
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
                            logging.warn('Could not delete ' + s3url)
                        upload = True

            if upload:
                logging.debug(' uploading "' + file_to_upload + '"...')
                extra = {'acl': 'public-read'}
                if file_to_upload.endswith('.sig'):
                    extra['content_type'] = 'application/pgp-signature'
                elif file_to_upload.endswith('.asc'):
                    extra['content_type'] = 'application/pgp-signature'
                logging.info(' uploading ' + os.path.relpath(file_to_upload)
                             + ' to s3://' + awsbucket + '/' + object_name)
                with open(file_to_upload, 'rb') as iterator:
                    obj = driver.upload_object_via_stream(iterator=iterator,
                                                          container=container,
                                                          object_name=object_name,
                                                          extra=extra)
    # delete the remnants in the bucket, they do not exist locally
    while objs:
        object_name, obj = objs.popitem()
        s3url = 's3://' + awsbucket + '/' + object_name
        if object_name.startswith(upload_dir):
            logging.warn(' deleting ' + s3url)
            driver.delete_object(obj)
        else:
            logging.info(' skipping ' + s3url)


def update_serverwebroot(serverwebroot, repo_section):
    # use a checksum comparison for accurate comparisons on different
    # filesystems, for example, FAT has a low resolution timestamp
    rsyncargs = ['rsync', '--archive', '--delete-after', '--safe-links']
    if not options.no_checksum:
        rsyncargs.append('--checksum')
    if options.verbose:
        rsyncargs += ['--verbose']
    if options.quiet:
        rsyncargs += ['--quiet']
    if options.identity_file is not None:
        rsyncargs += ['-e', 'ssh -i ' + options.identity_file]
    if 'identity_file' in config:
        rsyncargs += ['-e', 'ssh -i ' + config['identity_file']]
    indexxml = os.path.join(repo_section, 'index.xml')
    indexjar = os.path.join(repo_section, 'index.jar')
    # Upload the first time without the index files and delay the deletion as
    # much as possible, that keeps the repo functional while this update is
    # running.  Then once it is complete, rerun the command again to upload
    # the index files.  Always using the same target with rsync allows for
    # very strict settings on the receiving server, you can literally specify
    # the one rsync command that is allowed to run in ~/.ssh/authorized_keys.
    # (serverwebroot is guaranteed to have a trailing slash in common.py)
    logging.info('rsyncing ' + repo_section + ' to ' + serverwebroot)
    if subprocess.call(rsyncargs +
                       ['--exclude', indexxml, '--exclude', indexjar,
                        repo_section, serverwebroot]) != 0:
        sys.exit(1)
    if subprocess.call(rsyncargs + [repo_section, serverwebroot]) != 0:
        sys.exit(1)
    # upload "current version" symlinks if requested
    if config['make_current_version_link'] and repo_section == 'repo':
        links_to_upload = []
        for f in glob.glob('*.apk') \
                + glob.glob('*.apk.asc') + glob.glob('*.apk.sig'):
            if os.path.islink(f):
                links_to_upload.append(f)
        if len(links_to_upload) > 0:
            if subprocess.call(rsyncargs + links_to_upload + [serverwebroot]) != 0:
                sys.exit(1)


def _local_sync(fromdir, todir):
    rsyncargs = ['rsync', '--recursive', '--safe-links', '--times', '--perms',
                 '--one-file-system', '--delete', '--chmod=Da+rx,Fa-x,a+r,u+w']
    # use stricter rsync checking on all files since people using offline mode
    # are already prioritizing security above ease and speed
    if not options.no_checksum:
        rsyncargs.append('--checksum')
    if options.verbose:
        rsyncargs += ['--verbose']
    if options.quiet:
        rsyncargs += ['--quiet']
    logging.debug(' '.join(rsyncargs + [fromdir, todir]))
    if subprocess.call(rsyncargs + [fromdir, todir]) != 0:
        sys.exit(1)


def sync_from_localcopy(repo_section, local_copy_dir):
    logging.info('Syncing from local_copy_dir to this repo.')
    # trailing slashes have a meaning in rsync which is not needed here, so
    # make sure both paths have exactly one trailing slash
    _local_sync(os.path.join(local_copy_dir, repo_section).rstrip('/') + '/',
                repo_section.rstrip('/') + '/')


def update_localcopy(repo_section, local_copy_dir):
    # local_copy_dir is guaranteed to have a trailing slash in main() below
    _local_sync(repo_section, local_copy_dir)


def main():
    global config, options

    # Parse command line...
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument("command", help="command to execute, either 'init' or 'update'")
    parser.add_argument("-i", "--identity-file", default=None,
                        help="Specify an identity file to provide to SSH for rsyncing")
    parser.add_argument("--local-copy-dir", default=None,
                        help="Specify a local folder to sync the repo to")
    parser.add_argument("--sync-from-local-copy-dir", action="store_true", default=False,
                        help="Before uploading to servers, sync from local copy dir")
    parser.add_argument("--no-checksum", action="store_true", default=False,
                        help="Don't use rsync checksums")
    options = parser.parse_args()

    config = common.read_config(options)

    if options.command != 'init' and options.command != 'update':
        logging.critical("The only commands currently supported are 'init' and 'update'")
        sys.exit(1)

    if config.get('nonstandardwebroot') is True:
        standardwebroot = False
    else:
        standardwebroot = True

    for serverwebroot in config.get('serverwebroot', []):
        # this supports both an ssh host:path and just a path
        s = serverwebroot.rstrip('/').split(':')
        if len(s) == 1:
            fdroiddir = s[0]
        elif len(s) == 2:
            host, fdroiddir = s
        else:
            logging.error('Malformed serverwebroot line: ' + serverwebroot)
            sys.exit(1)
        repobase = os.path.basename(fdroiddir)
        if standardwebroot and repobase != 'fdroid':
            logging.error('serverwebroot path does not end with "fdroid", '
                          + 'perhaps you meant one of these:\n\t'
                          + serverwebroot.rstrip('/') + '/fdroid\n\t'
                          + serverwebroot.rstrip('/').rstrip(repobase) + 'fdroid')
            sys.exit(1)

    if options.local_copy_dir is not None:
        local_copy_dir = options.local_copy_dir
    elif config.get('local_copy_dir'):
        local_copy_dir = config['local_copy_dir']
    else:
        local_copy_dir = None
    if local_copy_dir is not None:
        fdroiddir = local_copy_dir.rstrip('/')
        if os.path.exists(fdroiddir) and not os.path.isdir(fdroiddir):
            logging.error('local_copy_dir must be directory, not a file!')
            sys.exit(1)
        if not os.path.exists(os.path.dirname(fdroiddir)):
            logging.error('The root dir for local_copy_dir "'
                          + os.path.dirname(fdroiddir)
                          + '" does not exist!')
            sys.exit(1)
        if not os.path.isabs(fdroiddir):
            logging.error('local_copy_dir must be an absolute path!')
            sys.exit(1)
        repobase = os.path.basename(fdroiddir)
        if standardwebroot and repobase != 'fdroid':
            logging.error('local_copy_dir does not end with "fdroid", '
                          + 'perhaps you meant: ' + fdroiddir + '/fdroid')
            sys.exit(1)
        if local_copy_dir[-1] != '/':
            local_copy_dir += '/'
        local_copy_dir = local_copy_dir.replace('//', '/')
        if not os.path.exists(fdroiddir):
            os.mkdir(fdroiddir)

    if not config.get('awsbucket') \
            and not config.get('serverwebroot') \
            and local_copy_dir is None:
        logging.warn('No serverwebroot, local_copy_dir, or awsbucket set!'
                     + 'Edit your config.py to set at least one.')
        sys.exit(1)

    repo_sections = ['repo']
    if config['archive_older'] != 0:
        repo_sections.append('archive')
        if not os.path.exists('archive'):
            os.mkdir('archive')
    if config['per_app_repos']:
        repo_sections += common.get_per_app_repos()

    if options.command == 'init':
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        for serverwebroot in config.get('serverwebroot', []):
            sshstr, remotepath = serverwebroot.rstrip('/').split(':')
            if sshstr.find('@') >= 0:
                username, hostname = sshstr.split('@')
            else:
                username = pwd.getpwuid(os.getuid())[0]  # get effective uid
                hostname = sshstr
            ssh.connect(hostname, username=username)
            sftp = ssh.open_sftp()
            if os.path.basename(remotepath) \
                    not in sftp.listdir(os.path.dirname(remotepath)):
                sftp.mkdir(remotepath, mode=0o755)
            for repo_section in repo_sections:
                repo_path = os.path.join(remotepath, repo_section)
                if os.path.basename(repo_path) \
                        not in sftp.listdir(remotepath):
                    sftp.mkdir(repo_path, mode=0o755)
            sftp.close()
            ssh.close()
    elif options.command == 'update':
        for repo_section in repo_sections:
            if local_copy_dir is not None:
                if config['sync_from_local_copy_dir'] and os.path.exists(repo_section):
                    sync_from_localcopy(repo_section, local_copy_dir)
                else:
                    update_localcopy(repo_section, local_copy_dir)
            for serverwebroot in config.get('serverwebroot', []):
                update_serverwebroot(serverwebroot, repo_section)
            if config.get('awsbucket'):
                update_awsbucket(repo_section)

    sys.exit(0)


if __name__ == "__main__":
    main()
