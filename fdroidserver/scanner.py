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

from . import _
from . import common
from . import metadata
from .exception import BuildException, VCSException

config = None
options = None


def get_gradle_compile_commands(build):
    compileCommands = ['compile',
                       'provided'
                       'apk'
                       'implementation'
                       'api'
                       'compileOnly'
                       'runtimeOnly',
                       'releaseCompile'
                       'releaseProvided'
                       'releaseApk'
                       'releaseImplementation'
                       'releaseApi'
                       'releaseCompileOnly'
                       'releaseRuntimeOnly']
    if build.gradle and build.gradle != ['yes']:
        compileCommands += [flavor + 'Compile' for flavor in build.gradle]
        compileCommands += [flavor + 'ReleaseCompile' for flavor in build.gradle]

    return [re.compile(r'\s*' + c, re.IGNORECASE) for c in compileCommands]


def scan_source(build_dir, build=metadata.Build()):
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

    whitelisted = [
        'firebase-jobdispatcher',  # https://github.com/firebase/firebase-jobdispatcher-android/blob/master/LICENSE
        'com.firebaseui',          # https://github.com/firebase/FirebaseUI-Android/blob/master/LICENSE
        'geofire-android'          # https://github.com/firebase/geofire-java/blob/master/LICENSE
    ]

    def is_whitelisted(s):
        return any(wl in s for wl in whitelisted)

    def suspects_found(s):
        for n, r in usual_suspects.items():
            if r.match(s) and not is_whitelisted(s):
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

    def toignore(path_in_build_dir):
        for k, paths in scanignore.items():
            for p in paths:
                if path_in_build_dir.startswith(p):
                    scanignore_worked.add(k)
                    return True
        return False

    def todelete(path_in_build_dir):
        for k, paths in scandelete.items():
            for p in paths:
                if path_in_build_dir.startswith(p):
                    scandelete_worked.add(k)
                    return True
        return False

    def ignoreproblem(what, path_in_build_dir):
        logging.info('Ignoring %s at %s' % (what, path_in_build_dir))
        return 0

    def removeproblem(what, path_in_build_dir, filepath):
        logging.info('Removing %s at %s' % (what, path_in_build_dir))
        os.remove(filepath)
        return 0

    def warnproblem(what, path_in_build_dir):
        if toignore(path_in_build_dir):
            return
        logging.warn('Found %s at %s' % (what, path_in_build_dir))

    def handleproblem(what, path_in_build_dir, filepath):
        if toignore(path_in_build_dir):
            return ignoreproblem(what, path_in_build_dir)
        if todelete(path_in_build_dir):
            return removeproblem(what, path_in_build_dir, filepath)
        logging.error('Found %s at %s' % (what, path_in_build_dir))
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
    for root, dirs, files in os.walk(build_dir, topdown=True):

        # It's topdown, so checking the basename is enough
        for ignoredir in ('.hg', '.git', '.svn', '.bzr'):
            if ignoredir in dirs:
                dirs.remove(ignoredir)

        for curfile in files:

            if curfile in ['.DS_Store']:
                continue

            # Path (relative) to the file
            filepath = os.path.join(root, curfile)

            if os.path.islink(filepath):
                continue

            path_in_build_dir = os.path.relpath(filepath, build_dir)
            _ignored, ext = common.get_extension(path_in_build_dir)

            if ext == 'so':
                count += handleproblem('shared library', path_in_build_dir, filepath)
            elif ext == 'a':
                count += handleproblem('static library', path_in_build_dir, filepath)
            elif ext == 'class':
                count += handleproblem('Java compiled class', path_in_build_dir, filepath)
            elif ext == 'apk':
                removeproblem('APK file', path_in_build_dir, filepath)

            elif ext == 'jar':
                for name in suspects_found(curfile):
                    count += handleproblem('usual suspect \'%s\'' % name, path_in_build_dir, filepath)
                if curfile == 'gradle-wrapper.jar':
                    removeproblem('gradle-wrapper.jar', path_in_build_dir, filepath)
                else:
                    warnproblem('JAR file', path_in_build_dir)

            elif ext == 'aar':
                warnproblem('AAR file', path_in_build_dir)

            elif ext == 'java':
                if not os.path.isfile(filepath):
                    continue
                with open(filepath, 'r', encoding='utf8', errors='replace') as f:
                    for line in f:
                        if 'DexClassLoader' in line:
                            count += handleproblem('DexClassLoader', path_in_build_dir, filepath)
                            break

            elif ext == 'gradle':
                if not os.path.isfile(filepath):
                    continue
                with open(filepath, 'r', encoding='utf8', errors='replace') as f:
                    lines = f.readlines()
                for i, line in enumerate(lines):
                    if is_used_by_gradle(line):
                        for name in suspects_found(line):
                            count += handleproblem('usual suspect \'%s\' at line %d' % (name, i + 1), path_in_build_dir, filepath)
                noncomment_lines = [l for l in lines if not common.gradle_comment.match(l)]
                joined = re.sub(r'[\n\r\s]+', ' ', ' '.join(noncomment_lines))
                for m in gradle_mavenrepo.finditer(joined):
                    url = m.group(2)
                    if not any(r.match(url) for r in allowed_repos):
                        count += handleproblem('unknown maven repo \'%s\'' % url, path_in_build_dir, filepath)

            elif ext in ['', 'bin', 'out', 'exe']:
                if is_binary(filepath):
                    count += handleproblem('binary', path_in_build_dir, filepath)

            elif is_executable(filepath):
                if is_binary(filepath) and not safe_path(path_in_build_dir):
                    warnproblem('possible binary', path_in_build_dir)

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
    parser.add_argument("appid", nargs='*', help=_("applicationId with optional versionCode in the form APPID[:VERCODE]"))
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
            logging.info(_("Skipping {appid}: disabled").format(appid=appid))
            continue

        try:
            if app.RepoType == 'srclib':
                build_dir = os.path.join('build', 'srclib', app.Repo)
            else:
                build_dir = os.path.join('build', appid)

            if app.builds:
                logging.info(_("Processing {appid}").format(appid=appid))
            else:
                logging.info(_("{appid}: no builds specified, running on current source state")
                             .format(appid=appid))
                count = scan_source(build_dir)
                if count > 0:
                    logging.warn(_('Scanner found {count} problems in {appid}:')
                                 .format(count=count, appid=appid))
                    probcount += count
                continue

            # Set up vcs interface and make sure we have the latest code...
            vcs = common.getvcs(app.RepoType, app.Repo, build_dir)

            for build in app.builds:

                if build.disable:
                    logging.info("...skipping version %s - %s" % (
                        build.versionName, build.get('disable', build.commit[1:])))
                    continue

                logging.info("...scanning version " + build.versionName)
                # Prepare the source code...
                common.prepare_source(vcs, app, build,
                                      build_dir, srclib_dir,
                                      extlib_dir, False)

                count = scan_source(build_dir, build)
                if count > 0:
                    logging.warn(_('Scanner found {count} problems in {appid}:{versionCode}:')
                                 .format(count=count, appid=appid, versionCode=build.versionCode))
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

    logging.info(_("Finished"))
    print(_("%d problems found") % probcount)


if __name__ == "__main__":
    main()
