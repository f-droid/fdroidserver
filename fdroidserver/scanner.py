#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# scanner.py - part of the FDroid server tools
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

import os
import re
import traceback
from argparse import ArgumentParser
import logging

import common
import metadata
from common import BuildException, VCSException

config = None
options = None


def init_mime_type():
    '''
    There are two incompatible versions of the 'magic' module, one
    that comes as part of libmagic, which is what Debian includes as
    python-magic, then another called python-magic that is a separate
    project that wraps libmagic.  The second is 'magic' on pypi, so
    both need to be supported.  Then on platforms where libmagic is
    not easily included, e.g. OSX and Windows, fallback to the
    built-in 'mimetypes' module so this will work without
    libmagic. Hence this function with the following hacks:
    '''

    init_path = ''
    method = ''
    ms = None

    def mime_from_file(path):
        try:
            return magic.from_file(path, mime=True)
        except UnicodeError:
            return None

    def mime_file(path):
        try:
            return ms.file(path)
        except UnicodeError:
            return None

    def mime_guess_type(path):
        return mimetypes.guess_type(path, strict=False)

    try:
        import magic
        try:
            ms = magic.open(magic.MIME_TYPE)
            ms.load()
            magic.from_file(init_path, mime=True)
            method = 'from_file'
        except AttributeError:
            ms.file(init_path)
            method = 'file'
    except ImportError:
        import mimetypes
        mimetypes.init()
        method = 'guess_type'

    logging.info("Using magic method " + method)
    if method == 'from_file':
        return mime_from_file
    if method == 'file':
        return mime_file
    if method == 'guess_type':
        return mime_guess_type

    logging.critical("unknown magic method!")


# Scan the source code in the given directory (and all subdirectories)
# and return the number of fatal problems encountered
def scan_source(build_dir, root_dir, thisbuild):

    count = 0

    # Common known non-free blobs (always lower case):
    usual_suspects = [
        re.compile(r'.*flurryagent', re.IGNORECASE),
        re.compile(r'.*paypal.*mpl', re.IGNORECASE),
        re.compile(r'.*google.*analytics', re.IGNORECASE),
        re.compile(r'.*admob.*sdk.*android', re.IGNORECASE),
        re.compile(r'.*google.*ad.*view', re.IGNORECASE),
        re.compile(r'.*google.*admob', re.IGNORECASE),
        re.compile(r'.*google.*play.*services', re.IGNORECASE),
        re.compile(r'.*crittercism', re.IGNORECASE),
        re.compile(r'.*heyzap', re.IGNORECASE),
        re.compile(r'.*jpct.*ae', re.IGNORECASE),
        re.compile(r'.*youtube.*android.*player.*api', re.IGNORECASE),
        re.compile(r'.*bugsense', re.IGNORECASE),
        re.compile(r'.*crashlytics', re.IGNORECASE),
        re.compile(r'.*ouya.*sdk', re.IGNORECASE),
        re.compile(r'.*libspen23', re.IGNORECASE),
    ]

    scanignore = common.getpaths(build_dir, thisbuild, 'scanignore')
    scandelete = common.getpaths(build_dir, thisbuild, 'scandelete')

    scanignore_worked = set()
    scandelete_worked = set()

    def toignore(fd):
        for p in scanignore:
            if fd.startswith(p):
                scanignore_worked.add(p)
                return True
        return False

    def todelete(fd):
        for p in scandelete:
            if fd.startswith(p):
                scandelete_worked.add(p)
                return True
        return False

    def ignoreproblem(what, fd, fp):
        logging.info('Ignoring %s at %s' % (what, fd))
        return 0

    def removeproblem(what, fd, fp):
        logging.info('Removing %s at %s' % (what, fd))
        os.remove(fp)
        return 0

    def warnproblem(what, fd):
        logging.warn('Found %s at %s' % (what, fd))

    def handleproblem(what, fd, fp):
        if toignore(fd):
            return ignoreproblem(what, fd, fp)
        if todelete(fd):
            return removeproblem(what, fd, fp)
        logging.error('Found %s at %s' % (what, fd))
        return 1

    get_mime_type = init_mime_type()

    # Iterate through all files in the source code
    for r, d, f in os.walk(build_dir, topdown=True):

        # It's topdown, so checking the basename is enough
        for ignoredir in ('.hg', '.git', '.svn', '.bzr'):
            if ignoredir in d:
                d.remove(ignoredir)

        for curfile in f:

            # Path (relative) to the file
            fp = os.path.join(r, curfile)
            fd = fp[len(build_dir) + 1:]

            mime = get_mime_type(fp)

            if mime == 'application/x-sharedlib':
                count += handleproblem('shared library', fd, fp)

            elif mime == 'application/x-archive':
                count += handleproblem('static library', fd, fp)

            elif mime == 'application/x-executable' or mime == 'application/x-mach-binary':
                count += handleproblem('binary executable', fd, fp)

            elif mime == 'application/x-java-applet':
                count += handleproblem('Java compiled class', fd, fp)

            elif mime in (
                    'application/jar',
                    'application/zip',
                    'application/java-archive',
                    'application/octet-stream',
                    'binary', ):

                if common.has_extension(fp, 'apk'):
                    removeproblem('APK file', fd, fp)

                elif common.has_extension(fp, 'jar'):

                    if any(suspect.match(curfile) for suspect in usual_suspects):
                        count += handleproblem('usual supect', fd, fp)
                    else:
                        warnproblem('JAR file', fd)

                elif common.has_extension(fp, 'zip'):
                    warnproblem('ZIP file', fd)

                else:
                    warnproblem('unknown compressed or binary file', fd)

            elif common.has_extension(fp, 'java'):
                if not os.path.isfile(fp):
                    continue
                for line in file(fp):
                    if 'DexClassLoader' in line:
                        count += handleproblem('DexClassLoader', fd, fp)
                        break

            elif common.has_extension(fp, 'gradle'):
                if not os.path.isfile(fp):
                    continue
                for i, line in enumerate(file(fp)):
                    i = i + 1
                    if any(suspect.match(line) for suspect in usual_suspects):
                        count += handleproblem('usual suspect at line %d' % i, fd, fp)
                        break

    for p in scanignore:
        if p not in scanignore_worked:
            logging.error('Unused scanignore path: %s' % p)
            count += 1

    for p in scandelete:
        if p not in scandelete_worked:
            logging.error('Unused scandelete path: %s' % p)
            count += 1

    # Presence of a jni directory without buildjni=yes might
    # indicate a problem (if it's not a problem, explicitly use
    # buildjni=no to bypass this check)
    if (os.path.exists(os.path.join(root_dir, 'jni')) and
            not thisbuild['buildjni']):
        logging.error('Found jni directory, but buildjni is not enabled. Set it to \'no\' to ignore.')
        count += 1

    return count


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser(usage="%(prog)s [options] [APPID[:VERCODE] [APPID[:VERCODE] ...]]")
    parser.add_argument("appid", nargs='*', help="app-id with optional versioncode in the form APPID[:VERCODE]")
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                        help="Spew out even more information than normal")
    parser.add_argument("-q", "--quiet", action="store_true", default=False,
                        help="Restrict output to warnings and errors")
    options = parser.parse_args()

    config = common.read_config(options)

    # Read all app and srclib metadata
    allapps = metadata.read_metadata()
    apps = common.read_app_args(options.appid, allapps, True)

    probcount = 0

    build_dir = 'build'
    if not os.path.isdir(build_dir):
        logging.info("Creating build directory")
        os.makedirs(build_dir)
    srclib_dir = os.path.join(build_dir, 'srclib')
    extlib_dir = os.path.join(build_dir, 'extlib')

    for appid, app in apps.iteritems():

        if app['Disabled']:
            logging.info("Skipping %s: disabled" % appid)
            continue
        if not app['builds']:
            logging.info("Skipping %s: no builds specified" % appid)
            continue

        logging.info("Processing " + appid)

        try:

            build_dir = 'build/' + appid

            # Set up vcs interface and make sure we have the latest code...
            vcs = common.getvcs(app['Repo Type'], app['Repo'], build_dir)

            for thisbuild in app['builds']:

                if thisbuild['disable']:
                    logging.info("...skipping version %s - %s" % (
                        thisbuild['version'], thisbuild.get('disable', thisbuild['commit'][1:])))
                else:
                    logging.info("...scanning version " + thisbuild['version'])

                    # Prepare the source code...
                    root_dir, _ = common.prepare_source(vcs, app, thisbuild,
                                                        build_dir, srclib_dir,
                                                        extlib_dir, False)

                    # Do the scan...
                    count = scan_source(build_dir, root_dir, thisbuild)
                    if count > 0:
                        logging.warn('Scanner found %d problems in %s (%s)' % (
                            count, appid, thisbuild['vercode']))
                        probcount += count

        except BuildException as be:
            logging.warn("Could not scan app %s due to BuildException: %s" % (
                appid, be))
            probcount += 1
        except VCSException as vcse:
            logging.warn("VCS error while scanning app %s: %s" % (appid, vcse))
            probcount += 1
        except Exception:
            logging.warn("Could not scan app %s due to unknown error: %s" % (
                appid, traceback.format_exc()))
            probcount += 1

    logging.info("Finished:")
    print "%d app(s) with problems" % probcount

if __name__ == "__main__":
    main()
