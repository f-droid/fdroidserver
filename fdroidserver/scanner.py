#!/usr/bin/env python3
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

from . import common
from . import metadata
from .exception import BuildException, VCSException

config = None
options = None


def get_gradle_compile_commands(build):
    compileCommands = ['compile', 'releaseCompile']
    if build.gradle and build.gradle != ['yes']:
        compileCommands += [flavor + 'Compile' for flavor in build.gradle]
        compileCommands += [flavor + 'ReleaseCompile' for flavor in build.gradle]

    return [re.compile(r'\s*' + c, re.IGNORECASE) for c in compileCommands]


def scan_source(build_dir, build):
    """Scan the source code in the given directory (and all subdirectories)
    and return the number of fatal problems encountered
    """

    count = 0

    # Common known non-free blobs (always lower case):
    usual_suspects = {
        exp: re.compile(r'.*' + exp, re.IGNORECASE) for exp in [
            r'flurryagent',
            r'paypal.*mpl',
            r'google.*analytics',
            r'admob.*sdk.*android',
            r'google.*ad.*view',
            r'google.*admob',
            r'google.*play.*services',
            r'crittercism',
            r'heyzap',
            r'jpct.*ae',
            r'youtube.*android.*player.*api',
            r'bugsense',
            r'crashlytics',
            r'ouya.*sdk',
            r'libspen23',
            r'firebase',
        ]
    }

    def suspects_found(s):
        for n, r in usual_suspects.items():
            if r.match(s):
                yield n

    gradle_mavenrepo = re.compile(r'maven *{ *(url)? *[\'"]?([^ \'"]*)[\'"]?')

    allowed_repos = [re.compile(r'^https?://' + re.escape(repo) + r'/*') for repo in [
        'repo1.maven.org/maven2',  # mavenCentral()
        'jcenter.bintray.com',     # jcenter()
        'jitpack.io',
        'repo.maven.apache.org/maven2',
        'oss.jfrog.org/artifactory/oss-snapshot-local',
        'oss.sonatype.org/content/repositories/snapshots',
        'oss.sonatype.org/content/repositories/releases',
        'oss.sonatype.org/content/groups/public',
        'clojars.org/repo',  # Clojure free software libs
        's3.amazonaws.com/repo.commonsware.com',  # CommonsWare
        'plugins.gradle.org/m2',  # Gradle plugin repo
        'maven.google.com',  # Google Maven Repo, https://developer.android.com/studio/build/dependencies.html#google-maven
        ]
    ]

    scanignore = common.getpaths_map(build_dir, build.scanignore)
    scandelete = common.getpaths_map(build_dir, build.scandelete)

    scanignore_worked = set()
    scandelete_worked = set()

    def toignore(fd):
        for k, paths in scanignore.items():
            for p in paths:
                if fd.startswith(p):
                    scanignore_worked.add(k)
                    return True
        return False

    def todelete(fd):
        for k, paths in scandelete.items():
            for p in paths:
                if fd.startswith(p):
                    scandelete_worked.add(k)
                    return True
        return False

    def ignoreproblem(what, fd):
        logging.info('Ignoring %s at %s' % (what, fd))
        return 0

    def removeproblem(what, fd, fp):
        logging.info('Removing %s at %s' % (what, fd))
        os.remove(fp)
        return 0

    def warnproblem(what, fd):
        if toignore(fd):
            return
        logging.warn('Found %s at %s' % (what, fd))

    def handleproblem(what, fd, fp):
        if toignore(fd):
            return ignoreproblem(what, fd)
        if todelete(fd):
            return removeproblem(what, fd, fp)
        logging.error('Found %s at %s' % (what, fd))
        return 1

    def is_executable(path):
        return os.path.exists(path) and os.access(path, os.X_OK)

    textchars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})

    def is_binary(path):
        d = None
        with open(path, 'rb') as f:
            d = f.read(1024)
        return bool(d.translate(None, textchars))

    # False positives patterns for files that are binary and executable.
    safe_paths = [re.compile(r) for r in [
        r".*/drawable[^/]*/.*\.png$",  # png drawables
        r".*/mipmap[^/]*/.*\.png$",    # png mipmaps
        ]
    ]

    def safe_path(path):
        for sp in safe_paths:
            if sp.match(path):
                return True
        return False

    gradle_compile_commands = get_gradle_compile_commands(build)

    def is_used_by_gradle(line):
        return any(command.match(line) for command in gradle_compile_commands)

    # Iterate through all files in the source code
    for dirpath, dirnames, filenames in os.walk(build_dir, topdown=True):

        # It's topdown, so checking the basename is enough
        for ignoredir in ('.hg', '.git', '.svn', '.bzr'):
            if ignoredir in dirnames:
                dirnames.remove(ignoredir)

        for curfile in filenames:

            if curfile in ['.DS_Store']:
                continue

            # Path (relative) to the file
            fp = os.path.join(dirpath, curfile)

            if os.path.islink(fp):
                continue

            fd = fp[len(build_dir) + 1:]
            _, ext = common.get_extension(fd)

            if ext == 'so':
                count += handleproblem('shared library', fd, fp)
            elif ext == 'a':
                count += handleproblem('static library', fd, fp)
            elif ext == 'class':
                count += handleproblem('Java compiled class', fd, fp)
            elif ext == 'apk':
                removeproblem('APK file', fd, fp)

            elif ext == 'jar':
                for name in suspects_found(curfile):
                    count += handleproblem('usual supect \'%s\'' % name, fd, fp)
                warnproblem('JAR file', fd)

            elif ext == 'java':
                if not os.path.isfile(fp):
                    continue
                with open(fp, 'r', encoding='utf8', errors='replace') as f:
                    for line in f:
                        if 'DexClassLoader' in line:
                            count += handleproblem('DexClassLoader', fd, fp)
                            break

            elif ext == 'gradle':
                if not os.path.isfile(fp):
                    continue
                with open(fp, 'r', encoding='utf8', errors='replace') as f:
                    lines = f.readlines()
                for i, line in enumerate(lines):
                    if is_used_by_gradle(line):
                        for name in suspects_found(line):
                            count += handleproblem('usual supect \'%s\' at line %d' % (name, i + 1), fd, fp)
                noncomment_lines = [l for l in lines if not common.gradle_comment.match(l)]
                joined = re.sub(r'[\n\r\s]+', ' ', ' '.join(noncomment_lines))
                for m in gradle_mavenrepo.finditer(joined):
                    url = m.group(2)
                    if not any(r.match(url) for r in allowed_repos):
                        count += handleproblem('unknown maven repo \'%s\'' % url, fd, fp)

            elif ext in ['', 'bin', 'out', 'exe']:
                if is_binary(fp):
                    count += handleproblem('binary', fd, fp)

            elif is_executable(fp):
                if is_binary(fp) and not safe_path(fd):
                    warnproblem('possible binary', fd)

    for p in scanignore:
        if p not in scanignore_worked:
            logging.error('Unused scanignore path: %s' % p)
            count += 1

    for p in scandelete:
        if p not in scandelete_worked:
            logging.error('Unused scandelete path: %s' % p)
            count += 1

    return count


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser(usage="%(prog)s [options] [APPID[:VERCODE] [APPID[:VERCODE] ...]]")
    common.setup_global_opts(parser)
    parser.add_argument("appid", nargs='*', help="app-id with optional versionCode in the form APPID[:VERCODE]")
    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    metadata.warnings_action = options.W

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

    for appid, app in apps.items():

        if app.Disabled:
            logging.info("Skipping %s: disabled" % appid)
            continue
        if not app.builds:
            logging.info("Skipping %s: no builds specified" % appid)
            continue

        logging.info("Processing " + appid)

        try:

            if app.RepoType == 'srclib':
                build_dir = os.path.join('build', 'srclib', app.Repo)
            else:
                build_dir = os.path.join('build', appid)

            # Set up vcs interface and make sure we have the latest code...
            vcs = common.getvcs(app.RepoType, app.Repo, build_dir)

            for build in app.builds:

                if build.disable:
                    logging.info("...skipping version %s - %s" % (
                        build.versionName, build.get('disable', build.commit[1:])))
                else:
                    logging.info("...scanning version " + build.versionName)

                    # Prepare the source code...
                    common.prepare_source(vcs, app, build,
                                          build_dir, srclib_dir,
                                          extlib_dir, False)

                    # Do the scan...
                    count = scan_source(build_dir, build)
                    if count > 0:
                        logging.warn('Scanner found %d problems in %s (%s)' % (
                            count, appid, build.versionCode))
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
    print("%d problems found" % probcount)


if __name__ == "__main__":
    main()
