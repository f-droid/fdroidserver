#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# server.py - part of the FDroid server tools
# Copyright (C) 2010-13, Ciaran Gultnieks, ciaran@ciarang.com
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
import hashlib
import os
import subprocess
from optparse import OptionParser
import logging
import common

config = None
options = None


def update_awsbucket(repo_section):
    '''
    Upload the contents of the directory `repo_section` (including
    subdirectories) to the AWS S3 "bucket". The contents of that subdir of the
    bucket will first be deleted.

    Requires AWS credentials set in config.py: awsaccesskeyid, awssecretkey
    '''

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
                if options.verbose:
                    logging.info(' uploading "' + file_to_upload + '"...')
                extra = {'acl': 'public-read'}
                if file_to_upload.endswith('.sig'):
                    extra['content_type'] = 'application/pgp-signature'
                elif file_to_upload.endswith('.asc'):
                    extra['content_type'] = 'application/pgp-signature'
                logging.info(' uploading ' + os.path.relpath(file_to_upload)
                             + ' to s3://' + awsbucket + '/' + object_name)
                obj = driver.upload_object(file_path=file_to_upload,
                                           container=container,
                                           object_name=object_name,
                                           verify_hash=False,
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


def update_serverwebroot(repo_section):
    rsyncargs = ['rsync', '-u', '-r', '--delete']
    if options.verbose:
        rsyncargs += ['--verbose']
    if options.quiet:
        rsyncargs += ['--quiet']
    index = os.path.join(repo_section, 'index.xml')
    indexjar = os.path.join(repo_section, 'index.jar')
    # serverwebroot is guaranteed to have a trailing slash in common.py
    if subprocess.call(rsyncargs +
                       ['--exclude', index, '--exclude', indexjar,
                        repo_section, config['serverwebroot']]) != 0:
        sys.exit(1)
    if subprocess.call(rsyncargs +
                       [index, config['serverwebroot'] + repo_section]) != 0:
        sys.exit(1)
    if subprocess.call(rsyncargs +
                       [indexjar, config['serverwebroot'] + repo_section]) != 0:
        sys.exit(1)


def main():
    global config, options

    # Parse command line...
    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help="Spew out even more information than normal")
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help="Restrict output to warnings and errors")
    (options, args) = parser.parse_args()

    config = common.read_config(options)

    if len(args) != 1:
        logging.critical("Specify a single command")
        sys.exit(1)

    if args[0] != 'init' and args[0] != 'update':
        logging.critical("The only commands currently supported are 'init' and 'update'")
        sys.exit(1)

    if config.get('nonstandardwebroot') is True:
        standardwebroot = False
    else:
        standardwebroot = True

    if config.get('serverwebroot'):
        serverwebroot = config['serverwebroot']
        host, fdroiddir = serverwebroot.rstrip('/').split(':')
        serverrepobase = os.path.basename(fdroiddir)
        if serverrepobase != 'fdroid' and standardwebroot:
            logging.error('serverwebroot does not end with "fdroid", '
                          + 'perhaps you meant one of these:\n\t'
                          + serverwebroot.rstrip('/') + '/fdroid\n\t'
                          + serverwebroot.rstrip('/').rstrip(serverrepobase) + 'fdroid')
            sys.exit(1)
    elif not config.get('awsbucket'):
        logging.warn('No serverwebroot or awsbucket set! Edit your config.py to set one or both.')
        sys.exit(1)

    repo_sections = ['repo']
    if config['archive_older'] != 0:
        repo_sections.append('archive')

    if args[0] == 'init':
        if config.get('serverwebroot'):
            sshargs = ['ssh']
            if options.quiet:
                sshargs += ['-q']
            for repo_section in repo_sections:
                cmd = sshargs + [host, 'mkdir -p', fdroiddir + '/' + repo_section]
                if options.verbose:
                    # ssh -v produces different output than rsync -v, so this
                    # simulates rsync -v
                    logging.info(' '.join(cmd))
                if subprocess.call(cmd) != 0:
                    sys.exit(1)
    elif args[0] == 'update':
        for repo_section in repo_sections:
            if config.get('serverwebroot'):
                update_serverwebroot(repo_section)
            if config.get('awsbucket'):
                update_awsbucket(repo_section)

    sys.exit(0)

if __name__ == "__main__":
    main()
