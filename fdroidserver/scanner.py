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

import imghdr
import itertools
import json
import logging
import os
import re
import sys
import traceback
import urllib.parse
import urllib.request
import zipfile
from argparse import ArgumentParser
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta
from enum import IntEnum
from pathlib import Path
from tempfile import TemporaryDirectory

from . import _, common, metadata, scanner
from .exception import BuildException, ConfigurationException, VCSException


@dataclass
class MessageStore:
    infos: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


MAVEN_URL_REGEX = re.compile(
    r"""\smaven\s*(?:{.*?(?:setUrl|url)|\(\s*(?:url)?)\s*=?\s*(?:uri|URI|Uri\.create)?\(?\s*["']?([^\s"']+)["']?[^})]*[)}]""",
    re.DOTALL,
)

DEPFILE = {
    "Cargo.toml": ["Cargo.lock"],
    "pubspec.yaml": ["pubspec.lock"],
    "package.json": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
}

SCANNER_CACHE_VERSION = 1


class ExitCode(IntEnum):
    NONFREE_CODE = 1


def get_gradle_compile_commands(build):
    compileCommands = [
        'api',
        'apk',
        'classpath',
        'compile',
        'compileOnly',
        'id',
        'implementation',
        'provided',
        'runtimeOnly',
    ]
    buildTypes = ['', 'release']
    flavors = ['']
    if build.gradle and build.gradle != ['yes']:
        flavors += build.gradle

    commands = [
        ''.join(c) for c in itertools.product(flavors, buildTypes, compileCommands)
    ]
    return [re.compile(r'\s*' + c, re.IGNORECASE) for c in commands]


def get_embedded_classes(apkfile, depth=0):
    """
    Get the list of Java classes embedded into all DEX files.

    :return: set of Java classes names as string
    """
    if depth > 10:  # zipbomb protection
        return {_('Max recursion depth in ZIP file reached: %s') % apkfile}

    archive_regex = re.compile(r'.*\.(aab|aar|apk|apks|jar|war|xapk|zip)$')
    class_regex = re.compile(r'classes.*\.dex')
    classes = set()

    try:
        with TemporaryDirectory() as tmp_dir, zipfile.ZipFile(apkfile, 'r') as apk_zip:
            for info in apk_zip.infolist():
                # apk files can contain apk files, again
                with apk_zip.open(info) as apk_fp:
                    if zipfile.is_zipfile(apk_fp):
                        classes = classes.union(get_embedded_classes(apk_fp, depth + 1))
                        if not archive_regex.search(info.filename):
                            classes.add(
                                'ZIP file without proper file extension: %s'
                                % info.filename
                            )
                        continue

                with apk_zip.open(info.filename) as fp:
                    file_magic = fp.read(3)
                if file_magic == b'dex':
                    if not class_regex.search(info.filename):
                        classes.add('DEX file with fake name: %s' % info.filename)
                    apk_zip.extract(info, tmp_dir)
                    run = common.SdkToolsPopen(
                        ["dexdump", '{}/{}'.format(tmp_dir, info.filename)],
                        output=False,
                    )
                    classes = classes.union(
                        set(re.findall(r'[A-Z]+((?:\w+\/)+\w+)', run.output))
                    )
    except zipfile.BadZipFile as ex:
        return {_('Problem with ZIP file: %s, error %s') % (apkfile, ex)}

    return classes


def _datetime_now():
    """Get datetime.now(), using this funciton allows mocking it for testing."""
    return datetime.utcnow()


def _scanner_cachedir():
    """Get `Path` to fdroidserver cache dir."""
    cfg = common.get_config()
    if not cfg:
        raise ConfigurationException('config not initialized')
    if "cachedir_scanner" not in cfg:
        raise ConfigurationException("could not load 'cachedir_scanner' from config")
    cachedir = Path(cfg["cachedir_scanner"])
    cachedir.mkdir(exist_ok=True, parents=True)
    return cachedir


class SignatureDataMalformedException(Exception):
    pass


class SignatureDataOutdatedException(Exception):
    pass


class SignatureDataCacheMissException(Exception):
    pass


class SignatureDataNoDefaultsException(Exception):
    pass


class SignatureDataVersionMismatchException(Exception):
    pass


class SignatureDataController:
    def __init__(self, name, filename, url):
        self.name = name
        self.filename = filename
        self.url = url
        # by default we assume cache is valid indefinitely
        self.cache_duration = timedelta(days=999999)
        self.data = {}

    def check_data_version(self):
        if self.data.get("version") != SCANNER_CACHE_VERSION:
            raise SignatureDataVersionMismatchException()

    def check_last_updated(self):
        """
        Check if the last_updated value is ok and raise an exception if expired or inaccessible.

        :raises SignatureDataMalformedException: when timestamp value is
                                                 inaccessible or not parse-able
        :raises SignatureDataOutdatedException: when timestamp is older then
                                                `self.cache_duration`
        """
        last_updated = self.data.get("last_updated", None)
        if last_updated:
            try:
                last_updated = datetime.fromtimestamp(last_updated)
            except ValueError as e:
                raise SignatureDataMalformedException() from e
            except TypeError as e:
                raise SignatureDataMalformedException() from e
            delta = (last_updated + self.cache_duration) - scanner._datetime_now()
            if delta > timedelta(seconds=0):
                logging.debug(
                    _('next {name} cache update due in {time}').format(
                        name=self.filename, time=delta
                    )
                )
            else:
                raise SignatureDataOutdatedException()

    def fetch(self):
        try:
            self.fetch_signatures_from_web()
            self.write_to_cache()
        except Exception as e:
            raise Exception(
                _("downloading scanner signatures from '{}' failed").format(self.url)
            ) from e

    def load(self):
        try:
            try:
                self.load_from_cache()
                self.verify_data()
                self.check_last_updated()
            except SignatureDataCacheMissException:
                self.load_from_defaults()
        except (SignatureDataOutdatedException, SignatureDataNoDefaultsException):
            self.fetch_signatures_from_web()
            self.write_to_cache()
        except (
            SignatureDataMalformedException,
            SignatureDataVersionMismatchException,
        ) as e:
            logging.critical(
                _(
                    "scanner cache is malformed! You can clear it with: '{clear}'"
                ).format(
                    clear='rm -r {}'.format(common.get_config()['cachedir_scanner'])
                )
            )
            raise e

    def load_from_defaults(self):
        raise SignatureDataNoDefaultsException()

    def load_from_cache(self):
        sig_file = scanner._scanner_cachedir() / self.filename
        if not sig_file.exists():
            raise SignatureDataCacheMissException()
        with open(sig_file) as f:
            self.set_data(json.load(f))

    def write_to_cache(self):
        sig_file = scanner._scanner_cachedir() / self.filename
        with open(sig_file, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        logging.debug("write '{}' to cache".format(self.filename))

    def verify_data(self):
        """
        Clean and validate `self.data`.

        Right now this function does just a basic key sanitation.
        """
        self.check_data_version()
        valid_keys = [
            'timestamp',
            'last_updated',
            'version',
            'signatures',
            'cache_duration',
        ]

        for k in list(self.data.keys()):
            if k not in valid_keys:
                del self.data[k]

    def set_data(self, new_data):
        self.data = new_data
        if 'cache_duration' in new_data:
            self.cache_duration = timedelta(seconds=new_data['cache_duration'])

    def fetch_signatures_from_web(self):
        if not self.url.startswith("https://"):
            raise Exception(_("can't open non-https url: '{};".format(self.url)))
        logging.debug(_("downloading '{}'").format(self.url))
        with urllib.request.urlopen(self.url) as f:  # nosec B310 scheme filtered above
            self.set_data(json.load(f))
        self.data['last_updated'] = scanner._datetime_now().timestamp()


class ExodusSignatureDataController(SignatureDataController):
    def __init__(self):
        super().__init__(
            'Exodus signatures',
            'exodus.json',
            'https://reports.exodus-privacy.eu.org/api/trackers',
        )
        self.cache_duration = timedelta(days=1)  # refresh exodus cache after one day
        self.has_trackers_json_key = True

    def fetch_signatures_from_web(self):
        logging.debug(_("downloading '{}'").format(self.url))

        data = {
            "signatures": {},
            "timestamp": scanner._datetime_now().timestamp(),
            "last_updated": scanner._datetime_now().timestamp(),
            "version": SCANNER_CACHE_VERSION,
        }

        if not self.url.startswith("https://"):
            raise Exception(_("can't open non-https url: '{};".format(self.url)))
        with urllib.request.urlopen(self.url) as f:  # nosec B310 scheme filtered above
            trackerlist = json.load(f)
            if self.has_trackers_json_key:
                trackerlist = trackerlist["trackers"].values()
            for tracker in trackerlist:
                if tracker.get('code_signature'):
                    data["signatures"][tracker["name"]] = {
                        "name": tracker["name"],
                        "warn_code_signatures": [tracker["code_signature"]],
                        # exodus also provides network signatures, unused atm.
                        # "network_signatures": [tracker["network_signature"]],
                        "AntiFeatures": ["Tracking"],  # TODO
                        "license": "NonFree",  # We assume all trackers in exodus
                        # are non-free, although free
                        # trackers like piwik, acra,
                        # etc. might be listed by exodus
                        # too.
                    }
        self.set_data(data)


class EtipSignatureDataController(ExodusSignatureDataController):
    def __init__(self):
        super().__init__()
        self.name = 'ETIP signatures'
        self.filename = 'etip.json'
        self.url = 'https://etip.exodus-privacy.eu.org/api/trackers/?format=json'
        self.has_trackers_json_key = False


class SUSSDataController(SignatureDataController):
    def __init__(self):
        super().__init__(
            'SUSS', 'suss.json', 'https://fdroid.gitlab.io/fdroid-suss/suss.json'
        )

    def load_from_defaults(self):
        self.set_data(json.loads(SUSS_DEFAULT))


class ScannerTool:
    def __init__(self):
        # we could add support for loading additional signature source
        # definitions from config.yml here

        self.scanner_data_lookup()

        options = common.get_options()
        options_refresh_scanner = (
            hasattr(options, "refresh_scanner") and options.refresh_scanner
        )
        if options_refresh_scanner or common.get_config().get('refresh_scanner'):
            self.refresh()

        self.load()
        self.compile_regexes()

    def scanner_data_lookup(self):
        sigsources = common.get_config().get('scanner_signature_sources', [])
        logging.debug(
            "scanner is configured to use signature data from: '{}'".format(
                "', '".join(sigsources)
            )
        )
        self.sdcs = []
        for i, source_url in enumerate(sigsources):
            if source_url.lower() == 'suss':
                self.sdcs.append(SUSSDataController())
            elif source_url.lower() == 'exodus':
                self.sdcs.append(ExodusSignatureDataController())
            elif source_url.lower() == 'etip':
                self.sdcs.append(EtipSignatureDataController())
            else:
                u = urllib.parse.urlparse(source_url)
                if u.scheme != 'https' or u.path == "":
                    raise ConfigurationException(
                        "Invalid 'scanner_signature_sources' configuration: '{}'. "
                        "Has to be a valid HTTPS-URL or match a predefined "
                        "constants: 'suss', 'exodus'".format(source_url)
                    )
                self.sdcs.append(
                    SignatureDataController(
                        source_url,
                        '{}_{}'.format(i, os.path.basename(u.path)),
                        source_url,
                    )
                )

    def load(self):
        for sdc in self.sdcs:
            sdc.load()

    def compile_regexes(self):
        self.regexs = {
            'err_code_signatures': {},
            'err_gradle_signatures': {},
            'warn_code_signatures': {},
            'warn_gradle_signatures': {},
        }
        for sdc in self.sdcs:
            for signame, sigdef in sdc.data.get('signatures', {}).items():
                for sig in sigdef.get('code_signatures', []):
                    self.regexs['err_code_signatures'][sig] = re.compile(
                        '.*' + sig, re.IGNORECASE
                    )
                for sig in sigdef.get('gradle_signatures', []):
                    self.regexs['err_gradle_signatures'][sig] = re.compile(
                        '.*' + sig, re.IGNORECASE
                    )
                for sig in sigdef.get('warn_code_signatures', []):
                    self.regexs['warn_code_signatures'][sig] = re.compile(
                        '.*' + sig, re.IGNORECASE
                    )
                for sig in sigdef.get('warn_gradle_signatures', []):
                    self.regexs['warn_gradle_signatures'][sig] = re.compile(
                        '.*' + sig, re.IGNORECASE
                    )

    def refresh(self):
        for sdc in self.sdcs:
            sdc.fetch_signatures_from_web()
            sdc.write_to_cache()

    def add(self, new_controller: SignatureDataController):
        self.sdcs.append(new_controller)
        self.compile_regexes()


# TODO: change this from singleton instance to dependency injection
# use `_get_tool()` instead of accessing this directly
_SCANNER_TOOL = None


def _get_tool():
    """
    Lazy loading function for getting a ScannerTool instance.

    ScannerTool initialization need to access `common.config` values. Those are only available after initialization through `common.read_config()`. So this factory assumes config was called at an erlier point in time.
    """
    if not scanner._SCANNER_TOOL:
        scanner._SCANNER_TOOL = ScannerTool()
    return scanner._SCANNER_TOOL


def scan_binary(apkfile):
    """Scan output of dexdump for known non-free classes."""
    logging.info(_('Scanning APK with dexdump for known non-free classes.'))
    result = get_embedded_classes(apkfile)
    problems, warnings = 0, 0
    for classname in result:
        for suspect, regexp in _get_tool().regexs['warn_code_signatures'].items():
            if regexp.match(classname):
                logging.debug("Warning: found class '%s'" % classname)
                warnings += 1
        for suspect, regexp in _get_tool().regexs['err_code_signatures'].items():
            if regexp.match(classname):
                logging.debug("Problem: found class '%s'" % classname)
                problems += 1
    if warnings:
        logging.warning(
            _("Found {count} warnings in {filename}").format(
                count=warnings, filename=apkfile
            )
        )
    if problems:
        logging.critical(
            _("Found {count} problems in {filename}").format(
                count=problems, filename=apkfile
            )
        )
    return problems


def scan_source(build_dir, build=metadata.Build(), json_per_build=None):
    """Scan the source code in the given directory (and all subdirectories).

    Returns
    -------
    the number of fatal problems encountered.
    """
    count = 0

    if not json_per_build:
        json_per_build = MessageStore()

    def suspects_found(s):
        for n, r in _get_tool().regexs['err_gradle_signatures'].items():
            if r.match(s):
                yield n

    allowed_repos = [
        re.compile(r'^https://' + re.escape(repo) + r'/*')
        for repo in [
            'repo1.maven.org/maven2',  # mavenCentral()
            'jcenter.bintray.com',  # jcenter()
            'jitpack.io',
            'www.jitpack.io',
            'repo.maven.apache.org/maven2',
            'oss.jfrog.org/artifactory/oss-snapshot-local',
            'oss.sonatype.org/content/repositories/snapshots',
            'oss.sonatype.org/content/repositories/releases',
            'oss.sonatype.org/content/groups/public',
            'oss.sonatype.org/service/local/staging/deploy/maven2',
            's01.oss.sonatype.org/content/repositories/snapshots',
            's01.oss.sonatype.org/content/repositories/releases',
            's01.oss.sonatype.org/content/groups/public',
            's01.oss.sonatype.org/service/local/staging/deploy/maven2',
            'clojars.org/repo',  # Clojure free software libs
            'repo.clojars.org',  # Clojure free software libs
            's3.amazonaws.com/repo.commonsware.com',  # CommonsWare
            'plugins.gradle.org/m2',  # Gradle plugin repo
            'maven.google.com',  # google()
        ]
    ] + [
        re.compile(r'^file://' + re.escape(repo) + r'/*')
        for repo in [
            '/usr/share/maven-repo',  # local repo on Debian installs
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

    def ignoreproblem(what, path_in_build_dir, json_per_build):
        """No summary.

        Parameters
        ----------
        what: string
          describing the problem, will be printed in log messages
        path_in_build_dir
          path to the file relative to `build`-dir

        Returns
        -------
        0 as we explicitly ignore the file, so don't count an error
        """
        msg = 'Ignoring %s at %s' % (what, path_in_build_dir)
        logging.info(msg)
        if json_per_build is not None:
            json_per_build.infos.append([msg, path_in_build_dir])
        return 0

    def removeproblem(what, path_in_build_dir, filepath, json_per_build):
        """No summary.

        Parameters
        ----------
        what: string
          describing the problem, will be printed in log messages
        path_in_build_dir
          path to the file relative to `build`-dir
        filepath
          Path (relative to our current path) to the file

        Returns
        -------
        0 as we deleted the offending file
        """
        msg = 'Removing %s at %s' % (what, path_in_build_dir)
        logging.info(msg)
        if json_per_build is not None:
            json_per_build.infos.append([msg, path_in_build_dir])
        try:
            os.remove(filepath)
        except FileNotFoundError:
            # File is already gone, nothing to do.
            # This can happen if we find multiple problems in one file that is setup for scandelete
            # I.e. build.gradle files containig multiple unknown maven repos.
            pass
        return 0

    def warnproblem(what, path_in_build_dir, json_per_build):
        """No summary.

        Parameters
        ----------
        what: string
          describing the problem, will be printed in log messages
        path_in_build_dir
          path to the file relative to `build`-dir

        Returns
        -------
        0, as warnings don't count as errors
        """
        if toignore(path_in_build_dir):
            return 0
        logging.warning('Found %s at %s' % (what, path_in_build_dir))
        if json_per_build is not None:
            json_per_build.warnings.append([what, path_in_build_dir])
        return 0

    def handleproblem(what, path_in_build_dir, filepath, json_per_build):
        """Dispatches to problem handlers (ignore, delete, warn).

        Or returns 1 for increasing the error count.

        Parameters
        ----------
        what: string
          describing the problem, will be printed in log messages
        path_in_build_dir
          path to the file relative to `build`-dir
        filepath
          Path (relative to our current path) to the file

        Returns
        -------
        0 if the problem was ignored/deleted/is only a warning, 1 otherwise
        """
        options = common.get_options()
        if toignore(path_in_build_dir):
            return ignoreproblem(what, path_in_build_dir, json_per_build)
        if todelete(path_in_build_dir):
            return removeproblem(what, path_in_build_dir, filepath, json_per_build)
        if 'src/test' in path_in_build_dir or '/test/' in path_in_build_dir:
            return warnproblem(what, path_in_build_dir, json_per_build)
        if options and 'json' in vars(options) and options.json:
            json_per_build.errors.append([what, path_in_build_dir])
        if options and (
            options.verbose or not ('json' in vars(options) and options.json)
        ):
            logging.error('Found %s at %s' % (what, path_in_build_dir))
        return 1

    def is_executable(path):
        return os.path.exists(path) and os.access(path, os.X_OK)

    textchars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})  # fmt: skip

    def is_binary(path):
        d = None
        with open(path, 'rb') as f:
            d = f.read(1024)
        return bool(d.translate(None, textchars))

    # False positives patterns for files that are binary and executable.
    safe_paths = [
        re.compile(r)
        for r in [
            r".*/drawable[^/]*/.*\.png$",  # png drawables
            r".*/mipmap[^/]*/.*\.png$",  # png mipmaps
        ]
    ]

    def is_image_file(path):
        if imghdr.what(path) is not None:
            return True

    def safe_path(path_in_build_dir):
        for sp in safe_paths:
            if sp.match(path_in_build_dir):
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

            if curfile in ('gradle-wrapper.jar', 'gradlew', 'gradlew.bat'):
                removeproblem(curfile, path_in_build_dir, filepath, json_per_build)
            elif curfile.endswith('.apk'):
                removeproblem(
                    _('Android APK file'), path_in_build_dir, filepath, json_per_build
                )

            elif curfile.endswith('.a'):
                count += handleproblem(
                    _('static library'), path_in_build_dir, filepath, json_per_build
                )
            elif curfile.endswith('.aar'):
                count += handleproblem(
                    _('Android AAR library'),
                    path_in_build_dir,
                    filepath,
                    json_per_build,
                )
            elif curfile.endswith('.class'):
                count += handleproblem(
                    _('Java compiled class'),
                    path_in_build_dir,
                    filepath,
                    json_per_build,
                )
            elif curfile.endswith('.dex'):
                count += handleproblem(
                    _('Android DEX code'), path_in_build_dir, filepath, json_per_build
                )
            elif curfile.endswith('.gz') or curfile.endswith('.tgz'):
                count += handleproblem(
                    _('gzip file archive'), path_in_build_dir, filepath, json_per_build
                )
            # We use a regular expression here to also match versioned shared objects like .so.0.0.0
            elif re.match(r'.*\.so(\..+)*$', curfile):
                count += handleproblem(
                    _('shared library'), path_in_build_dir, filepath, json_per_build
                )
            elif curfile.endswith('.zip'):
                count += handleproblem(
                    _('ZIP file archive'), path_in_build_dir, filepath, json_per_build
                )
            elif curfile.endswith('.jar'):
                for name in suspects_found(curfile):
                    count += handleproblem(
                        'usual suspect \'%s\'' % name,
                        path_in_build_dir,
                        filepath,
                        json_per_build,
                    )
                count += handleproblem(
                    _('Java JAR file'), path_in_build_dir, filepath, json_per_build
                )

            elif curfile.endswith('.java'):
                if not os.path.isfile(filepath):
                    continue
                with open(filepath, 'r', errors='replace') as f:
                    for line in f:
                        if 'DexClassLoader' in line:
                            count += handleproblem(
                                'DexClassLoader',
                                path_in_build_dir,
                                filepath,
                                json_per_build,
                            )
                            break

            elif curfile.endswith('.gradle') or curfile.endswith('.gradle.kts'):
                if not os.path.isfile(filepath):
                    continue
                with open(filepath, 'r', errors='replace') as f:
                    lines = f.readlines()
                for i, line in enumerate(lines):
                    if is_used_by_gradle(line):
                        for name in suspects_found(line):
                            count += handleproblem(
                                "usual suspect '%s'" % (name),
                                path_in_build_dir,
                                filepath,
                                json_per_build,
                            )
                noncomment_lines = [
                    line for line in lines if not common.gradle_comment.match(line)
                ]
                no_comments = re.sub(
                    r'/\*.*?\*/', '', ''.join(noncomment_lines), flags=re.DOTALL
                )
                for url in MAVEN_URL_REGEX.findall(no_comments):
                    if not any(r.match(url) for r in allowed_repos):
                        count += handleproblem(
                            'unknown maven repo \'%s\'' % url,
                            path_in_build_dir,
                            filepath,
                            json_per_build,
                        )

            elif os.path.splitext(path_in_build_dir)[1] in ['', '.bin', '.out', '.exe']:
                if is_binary(filepath):
                    count += handleproblem(
                        'binary', path_in_build_dir, filepath, json_per_build
                    )

            elif curfile in DEPFILE:
                d = root
                while d.startswith(str(build_dir)):
                    for lockfile in DEPFILE[curfile]:
                        if os.path.isfile(os.path.join(d, lockfile)):
                            break
                    else:
                        d = os.path.dirname(d)
                        continue
                    break
                else:
                    count += handleproblem(
                        _('dependency file without lock'),
                        path_in_build_dir,
                        filepath,
                        json_per_build,
                    )

            elif is_executable(filepath):
                if is_binary(filepath) and not (
                    safe_path(path_in_build_dir) or is_image_file(filepath)
                ):
                    warnproblem(
                        _('executable binary, possibly code'),
                        path_in_build_dir,
                        json_per_build,
                    )

    for p in scanignore:
        if p not in scanignore_worked:
            logging.error(_('Unused scanignore path: %s') % p)
            count += 1

    for p in scandelete:
        if p not in scandelete_worked:
            logging.error(_('Unused scandelete path: %s') % p)
            count += 1

    return count


def main():
    parser = ArgumentParser(
        usage="%(prog)s [options] [(APPID[:VERCODE] | path/to.apk) ...]"
    )
    common.setup_global_opts(parser)
    parser.add_argument(
        "appid",
        nargs='*',
        help=_("application ID with optional versionCode in the form APPID[:VERCODE]"),
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        default=False,
        help=_("Force scan of disabled apps and builds."),
    )
    parser.add_argument(
        "--json", action="store_true", default=False, help=_("Output JSON to stdout.")
    )
    parser.add_argument(
        "-r",
        "--refresh",
        dest="refresh_scanner",
        action="store_true",
        default=False,
        help=_("fetch the latest version of signatures from the web"),
    )
    parser.add_argument(
        "-e",
        "--exit-code",
        action="store_true",
        default=False,
        help=_("Exit with a non-zero code if problems were found"),
    )
    metadata.add_metadata_arguments(parser)
    options = common.parse_args(parser)
    metadata.warnings_action = options.W

    json_output = dict()
    if options.json:
        if options.verbose:
            logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
        else:
            logging.getLogger().setLevel(logging.ERROR)

    # initialize/load configuration values
    common.get_config()

    probcount = 0

    appids = []
    for apk in options.appid:
        if os.path.isfile(apk):
            count = scanner.scan_binary(apk)
            if count > 0:
                logging.warning(
                    _('Scanner found {count} problems in {apk}').format(
                        count=count, apk=apk
                    )
                )
                probcount += count
        else:
            appids.append(apk)

    if not appids:
        if options.exit_code and probcount > 0:
            sys.exit(ExitCode.NONFREE_CODE)
        if options.refresh_scanner:
            _get_tool()
        return

    # Read all app and srclib metadata

    allapps = metadata.read_metadata()
    apps = common.read_app_args(appids, allapps, True)

    build_dir = 'build'
    if not os.path.isdir(build_dir):
        logging.info("Creating build directory")
        os.makedirs(build_dir)
    srclib_dir = os.path.join(build_dir, 'srclib')
    extlib_dir = os.path.join(build_dir, 'extlib')

    for appid, app in apps.items():
        json_per_appid = dict()

        if app.Disabled and not options.force:
            logging.info(_("Skipping {appid}: disabled").format(appid=appid))
            json_per_appid['disabled'] = MessageStore().infos.append(
                'Skipping: disabled'
            )
            continue

        try:
            if app.RepoType == 'srclib':
                build_dir = os.path.join('build', 'srclib', app.Repo)
            else:
                build_dir = os.path.join('build', appid)

            if app.get('Builds'):
                logging.info(_("Processing {appid}").format(appid=appid))
                # Set up vcs interface and make sure we have the latest code...
                vcs = common.getvcs(app.RepoType, app.Repo, build_dir)
            else:
                logging.info(
                    _(
                        "{appid}: no builds specified, running on current source state"
                    ).format(appid=appid)
                )
                json_per_build = MessageStore()
                json_per_appid['current-source-state'] = json_per_build
                count = scan_source(build_dir, json_per_build=json_per_build)
                if count > 0:
                    logging.warning(
                        _('Scanner found {count} problems in {appid}:').format(
                            count=count, appid=appid
                        )
                    )
                    probcount += count
                app['Builds'] = []

            for build in app.get('Builds', []):
                json_per_build = MessageStore()
                json_per_appid[build.versionCode] = json_per_build

                if build.disable and not options.force:
                    logging.info(
                        "...skipping version %s - %s"
                        % (build.versionName, build.get('disable', build.commit[1:]))
                    )
                    continue

                logging.info("...scanning version " + build.versionName)
                # Prepare the source code...
                common.prepare_source(
                    vcs, app, build, build_dir, srclib_dir, extlib_dir, False
                )

                count = scan_source(build_dir, build, json_per_build=json_per_build)
                if count > 0:
                    logging.warning(
                        _(
                            'Scanner found {count} problems in {appid}:{versionCode}:'
                        ).format(
                            count=count, appid=appid, versionCode=build.versionCode
                        )
                    )
                    probcount += count

        except BuildException as be:
            logging.warning(
                'Could not scan app %s due to BuildException: %s' % (appid, be)
            )
            probcount += 1
        except VCSException as vcse:
            logging.warning('VCS error while scanning app %s: %s' % (appid, vcse))
            probcount += 1
        except Exception:
            logging.warning(
                'Could not scan app %s due to unknown error: %s'
                % (appid, traceback.format_exc())
            )
            probcount += 1

        for k, v in json_per_appid.items():
            if len(v.errors) or len(v.warnings) or len(v.infos):
                json_output[appid] = {
                    k: dict((field.name, getattr(v, field.name)) for field in fields(v))
                    for k, v in json_per_appid.items()
                }
                break

    logging.info(_("Finished"))
    if options.json:
        print(json.dumps(json_output))
    else:
        print(_("%d problems found") % probcount)


if __name__ == "__main__":
    main()


SUSS_DEFAULT = r'''{
  "cache_duration": 86400,
  "signatures": {
    "com.amazon.device.ads": {
      "anti_features": [
        "Ads",
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/amazon/device/ads"
      ],
      "description": "an interface for views used to retrieve and display Amazon ads.",
      "license": "NonFree"
    },
    "com.amazon.device.associates": {
      "anti_features": [
        "Ads",
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/amazon/device/associates"
      ],
      "description": "library for Amazon\u2019s affiliate marketing program.",
      "license": "NonFree"
    },
    "com.amazon.device.iap": {
      "anti_features": [
        "NonFreeComp",
        "NonFreeNet"
      ],
      "code_signatures": [
        "com/amazon/device/iap"
      ],
      "description": "allows an app to present, process, and fulfill purchases of digital content and subscriptions within your app.",
      "license": "NonFree"
    },
    "com.amazonaws": {
      "code_signatures": [
        "com/amazonaws/AbortedException",
        "com/amazonaws/AmazonClientException",
        "com/amazonaws/AmazonServiceException$ErrorType",
        "com/amazonaws/AmazonServiceException",
        "com/amazonaws/AmazonWebServiceClient",
        "com/amazonaws/AmazonWebServiceRequest",
        "com/amazonaws/AmazonWebServiceResponse",
        "com/amazonaws/async",
        "com/amazonaws/auth",
        "com/amazonaws/ClientConfiguration",
        "com/amazonaws/cognito",
        "com/amazonaws/DefaultRequest",
        "com/amazonaws/event",
        "com/amazonaws/handlers",
        "com/amazonaws/http",
        "com/amazonaws/HttpMethod",
        "com/amazonaws/internal",
        "com/amazonaws/logging",
        "com/amazonaws/metrics",
        "com/amazonaws/mobile",
        "com/amazonaws/mobileconnectors",
        "com/amazonaws/Protocol",
        "com/amazonaws/regions",
        "com/amazonaws/RequestClientOptions$Marker",
        "com/amazonaws/RequestClientOptions",
        "com/amazonaws/Request",
        "com/amazonaws/ResponseMetadata",
        "com/amazonaws/Response",
        "com/amazonaws/retry",
        "com/amazonaws/SDKGlobalConfiguration",
        "com/amazonaws/ServiceNameFactory",
        "com/amazonaws/services",
        "com/amazonaws/transform",
        "com/amazonaws/util"
      ],
      "gradle_signatures": [
        "com.amazonaws:amazon-kinesis-aggregator",
        "com.amazonaws:amazon-kinesis-connectors",
        "com.amazonaws:amazon-kinesis-deaggregator",
        "com.amazonaws:aws-android-sdk-apigateway-core",
        "com.amazonaws:aws-android-sdk-auth-core",
        "com.amazonaws:aws-android-sdk-auth-facebook",
        "com.amazonaws:aws-android-sdk-auth-google",
        "com.amazonaws:aws-android-sdk-auth-ui",
        "com.amazonaws:aws-android-sdk-auth-userpools",
        "com.amazonaws:aws-android-sdk-cognito",
        "com.amazonaws:aws-android-sdk-cognitoauth",
        "com.amazonaws:aws-android-sdk-cognitoidentityprovider-asf",
        "com.amazonaws:aws-android-sdk-comprehend",
        "com.amazonaws:aws-android-sdk-core",
        "com.amazonaws:aws-android-sdk-ddb",
        "com.amazonaws:aws-android-sdk-ddb-document",
        "com.amazonaws:aws-android-sdk-iot",
        "com.amazonaws:aws-android-sdk-kinesis",
        "com.amazonaws:aws-android-sdk-kinesisvideo",
        "com.amazonaws:aws-android-sdk-kinesisvideo-archivedmedia",
        "com.amazonaws:aws-android-sdk-kms",
        "com.amazonaws:aws-android-sdk-lambda",
        "com.amazonaws:aws-android-sdk-lex",
        "com.amazonaws:aws-android-sdk-location",
        "com.amazonaws:aws-android-sdk-logs",
        "com.amazonaws:aws-android-sdk-mobileanalytics",
        "com.amazonaws:aws-android-sdk-mobile-client",
        "com.amazonaws:aws-android-sdk-pinpoint",
        "com.amazonaws:aws-android-sdk-polly",
        "com.amazonaws:aws-android-sdk-rekognition",
        "com.amazonaws:aws-android-sdk-s3",
        "com.amazonaws:aws-android-sdk-ses",
        "com.amazonaws:aws-android-sdk-sns",
        "com.amazonaws:aws-android-sdk-sqs",
        "com.amazonaws:aws-android-sdk-textract",
        "com.amazonaws:aws-android-sdk-transcribe",
        "com.amazonaws:aws-android-sdk-translate",
        "com.amazonaws:dynamodb-key-diagnostics-library",
        "com.amazonaws:DynamoDBLocal",
        "com.amazonaws:dynamodb-lock-client",
        "com.amazonaws:ivs-broadcast",
        "com.amazonaws:ivs-player",
        "com.amazonaws:kinesis-storm-spout"
      ],
      "license": "NonFree",
      "name": "AmazonAWS"
    },
    "com.android.billingclient": {
      "code_signatures": [
        "com/android/billingclient"
      ],
      "documentation": [
        "https://developer.android.com/google/play/billing/integrate"
      ],
      "gradle_signatures": [
        "com.android.billingclient",
        "com.google.androidbrowserhelper:billing",
        "com.anjlab.android.iab.v3:library",
        "com.github.penn5:donations",
        "me.proton.core:payment-iap"
      ],
      "license": "NonFree",
      "name": "BillingClient"
    },
    "com.android.installreferrer": {
      "anti_features": [
        "NonFreeDep",
        "NonFreeNet"
      ],
      "code_signatures": [
        "com/android/installreferrer"
      ],
      "documentation": [
        "https://developer.android.com/google/play/installreferrer/library"
      ],
      "gradle_signatures": [
        "com.android.installreferrer"
      ],
      "license": "NonFree",
      "name": "Play Install Referrer Library"
    },
    "com.anychart": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/anychart"
      ],
      "description": "a data visualization library for easily creating interactive charts in Android apps.",
      "license": "NonFree"
    },
    "com.appboy": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/appboy"
      ],
      "description": "Targets customers based on personal interests, location, past purchases, and more; profiles users, segments audiences, and utilizes analytics for targeted advertisements.",
      "license": "NonFree"
    },
    "com.appbrain": {
      "anti_features": [
        "Ads",
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/appbrain"
      ],
      "description": "See <a rel='nofollow' href='https://reports.exodus-privacy.eu.org/en/trackers/136/'>Exodus Privacy</a>.",
      "license": "NonFree"
    },
    "com.applause.android": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/applause/android"
      ],
      "description": "crowd-sourced testing. See <a rel='nofollow' href='https://www.crunchbase.com/organization/applause'>Crunchbase</a> and <a href='https://reports.exodus-privacy.eu.org/en/trackers/132/'>Exodus Privacy</a>.",
      "license": "NonFree"
    },
    "com.applovin": {
      "anti_features": [
        "Ads"
      ],
      "code_signatures": [
        "com/applovin"
      ],
      "description": "a mobile advertising technology company that enables brands to create mobile marketing campaigns that are fueled by data. Primary targets games.",
      "license": "NonFree"
    },
    "com.appsflyer": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/appsflyer"
      ],
      "description": "a mobile & attribution analytics platform.",
      "license": "NonFree"
    },
    "com.apptentive": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/apptentive"
      ],
      "description": "See <a href='https://reports.exodus-privacy.eu.org/en/trackers/115/'>Exodus Privacy</a>.",
      "license": "NonFree"
    },
    "com.apptimize": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/apptimize"
      ],
      "description": "See <a href='https://reports.exodus-privacy.eu.org/en/trackers/135/'>Exodus Privacy</a> and <a rel='nofollow' href='https://www.crunchbase.com/organization/apptimize'>Crunchbase</a>.",
      "license": "NonFree"
    },
    "com.askingpoint": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/askingpoint"
      ],
      "description": "complete mobile user engagement solution (power local, In-application evaluations and audits, input, user support, mobile reviews and informing).",
      "license": "NonFree"
    },
    "com.baidu.mobstat": {
      "code_signatures": [
        "com/baidu/mobstat"
      ],
      "documentation": [
        "https://mtj.baidu.com/web/sdk/index"
      ],
      "gradle_signatures": [
        "com.baidu.mobstat"
      ],
      "license": "NonFree",
      "name": "\u767e\u5ea6\u79fb\u52a8\u7edf\u8ba1SDK"
    },
    "com.batch": {
      "anti_features": [
        "Ads",
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/batch"
      ],
      "description": "mobile engagement platform to execute CRM tactics over iOS, Android & mobile websites.",
      "license": "NonFree"
    },
    "com.bosch.mtprotocol": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/bosch/mtprotocol"
      ],
      "description": "simplify and manage use of Bosch GLM and PLR laser rangefinders with Bluetooth connectivity.",
      "license": "NonFree"
    },
    "com.bugsee.library.Bugsee": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/bugsee/library/Bugsee"
      ],
      "description": "see video, network and logs that led to bugs and crashes in live apps. No need to reproduce intermittent bugs. With Bugsee, all the crucial data is always there.",
      "license": "NonFree"
    },
    "com.bugsense": {
      "code_signatures": [
        "com/bugsense"
      ],
      "documentation": [
        "https://github.com/bugsense/docs/blob/master/android.md"
      ],
      "gradle_signatures": [
        "com.bugsense"
      ],
      "license": "NonFree",
      "name": "BugSense"
    },
    "com.chartboost.sdk": {
      "anti_features": [
        "Ads",
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/chartboost/sdk"
      ],
      "description": "create customized interstitial and video ads, promote new games, and swap traffic with one another. For more details, see <a href='https://en.wikipedia.org/wiki/Chartboost'>Wikipedia</a>.",
      "license": "NonFree"
    },
    "com.cloudrail": {
      "code_signature": [
        "com/cloudrail"
      ],
      "documentation": [
        "https://cloudrail.com/"
      ],
      "gradle_signatures": [
        "com.cloudrail"
      ],
      "license": "NonFree",
      "name": "CloudRail"
    },
    "com.comscore.analytics": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/comscore"
      ],
      "description": "See <a href='https://en.wikipedia.org/wiki/Comscore'>Wikipedia</a> for details.",
      "license": "NonFree"
    },
    "com.crashlytics.sdk.android": {
      "code_signatures": [
        "com/crashlytics"
      ],
      "documentation": [
        "https://firebase.google.com/docs/crashlytics"
      ],
      "gradle_signatures": [
        "crashlytics"
      ],
      "license": "NonFree",
      "name": "Firebase Crashlytics"
    },
    "com.crittercism": {
      "code_signatures": [
        "com/crittercism"
      ],
      "documentation": [
        "https://github.com/crittercism/crittercism-unity-android"
      ],
      "gradle_signatures": [
        "com.crittercism"
      ],
      "license": "NonFree",
      "name": "Crittercism Plugin for Unity Crash Reporting"
    },
    "com.criware": {
      "anti_features": [
        "NonFreeComp",
        "NonFreeAssets"
      ],
      "code_signatures": [
        "com/criware"
      ],
      "description": "audio and video solutions that can be integrated with popular game engines.",
      "license": "NonFree"
    },
    "com.deezer.sdk": {
      "anti_features": [
        "NonFreeComp",
        "NonFreeNet"
      ],
      "code_signatures": [
        "com/deezer/sdk"
      ],
      "description": "a closed-source API for the Deezer music streaming service.",
      "license": "NonFree"
    },
    "com.dynamicyield": {
      "anti_features": [
        "Ads",
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/dynamicyield"
      ],
      "description": "targeted advertising. Tracks user via location (GPS, WiFi, location data). Collects PII, profiling. See <a href='https://reports.exodus-privacy.eu.org/en/trackers/152/'>Exodus Privacy</a> for more details.",
      "license": "NonFree"
    },
    "com.dynatrace.android.app": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/dynatrace/android/app"
      ],
      "description": "See <a rel='nofollow' href='https://www.crunchbase.com/organization/dynatrace-software'>Crunchbase</a> and <a href='https://reports.exodus-privacy.eu.org/en/trackers/137/'>Exodus Privacy</a>.",
      "license": "NonFree"
    },
    "com.ensighten": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/ensighten"
      ],
      "description": "organizations can leverage first-party customer data and profiles to fuel omni-channel action and insight using their existing technology investments. See <a rel='nofollow' href='https://www.crunchbase.com/organization/ensighten'>Crunchbase</a> and <a href='https://reports.exodus-privacy.eu.org/en/trackers/151/'>Exodus Privacy</a>.",
      "license": "NonFree"
    },
    "com.epicgames.mobile.eossdk": {
      "anti_features": [
        "NonFreeComp",
        "NonFreeNet"
      ],
      "code_signatures": [
        "com/epicgames/mobile/eossdk"
      ],
      "description": "integrate games with Epic Account Services and Epic Games Store",
      "license": "NonFree"
    },
    "com.facebook.android": {
      "code_signatures": [
        "com/facebook/AccessToken",
        "com/facebook/AccessTokenCache",
        "com/facebook/AccessTokenManager",
        "com/facebook/AccessTokenSource",
        "com/facebook/AccessTokenTracker",
        "com/facebook/all/All",
        "com/facebook/appevents/aam/MetadataIndexer",
        "com/facebook/appevents/aam/MetadataMatcher",
        "com/facebook/appevents/aam/MetadataRule",
        "com/facebook/appevents/aam/MetadataViewObserver",
        "com/facebook/appevents/AccessTokenAppIdPair",
        "com/facebook/appevents/AnalyticsUserIDStore",
        "com/facebook/appevents/AppEvent",
        "com/facebook/appevents/AppEventCollection",
        "com/facebook/appevents/AppEventDiskStore",
        "com/facebook/appevents/AppEventQueue",
        "com/facebook/appevents/AppEventsConstants",
        "com/facebook/appevents/AppEventsLogger",
        "com/facebook/appevents/AppEventsLoggerImpl",
        "com/facebook/appevents/AppEventsManager",
        "com/facebook/appevents/AppEventStore",
        "com/facebook/appevents/cloudbridge/AppEventsCAPIManager",
        "com/facebook/appevents/cloudbridge/AppEventsConversionsAPITransformer",
        "com/facebook/appevents/cloudbridge/AppEventsConversionsAPITransformerWebRequests",
        "com/facebook/appevents/codeless/CodelessLoggingEventListener",
        "com/facebook/appevents/codeless/CodelessManager",
        "com/facebook/appevents/codeless/CodelessMatcher",
        "com/facebook/appevents/codeless/internal/Constants",
        "com/facebook/appevents/codeless/internal/EventBinding",
        "com/facebook/appevents/codeless/internal/ParameterComponent",
        "com/facebook/appevents/codeless/internal/PathComponent",
        "com/facebook/appevents/codeless/internal/SensitiveUserDataUtils",
        "com/facebook/appevents/codeless/internal/UnityReflection",
        "com/facebook/appevents/codeless/internal/ViewHierarchy",
        "com/facebook/appevents/codeless/RCTCodelessLoggingEventListener",
        "com/facebook/appevents/codeless/ViewIndexer",
        "com/facebook/appevents/codeless/ViewIndexingTrigger",
        "com/facebook/appevents/eventdeactivation/EventDeactivationManager",
        "com/facebook/appevents/FacebookSDKJSInterface",
        "com/facebook/appevents/FlushReason",
        "com/facebook/appevents/FlushResult",
        "com/facebook/appevents/FlushStatistics",
        "com/facebook/appevents/iap/InAppPurchaseActivityLifecycleTracker",
        "com/facebook/appevents/iap/InAppPurchaseAutoLogger",
        "com/facebook/appevents/iap/InAppPurchaseBillingClientWrapper",
        "com/facebook/appevents/iap/InAppPurchaseEventManager",
        "com/facebook/appevents/iap/InAppPurchaseLoggerManager",
        "com/facebook/appevents/iap/InAppPurchaseManager",
        "com/facebook/appevents/iap/InAppPurchaseSkuDetailsWrapper",
        "com/facebook/appevents/iap/InAppPurchaseUtils",
        "com/facebook/appevents/integrity/BlocklistEventsManager",
        "com/facebook/appevents/integrity/IntegrityManager",
        "com/facebook/appevents/integrity/MACARuleMatchingManager",
        "com/facebook/appevents/integrity/ProtectedModeManager",
        "com/facebook/appevents/integrity/RedactedEventsManager",
        "com/facebook/appevents/internal/ActivityLifecycleTracker",
        "com/facebook/appevents/InternalAppEventsLogger",
        "com/facebook/appevents/internal/AppEventsLoggerUtility",
        "com/facebook/appevents/internal/AppEventUtility",
        "com/facebook/appevents/internal/AutomaticAnalyticsLogger",
        "com/facebook/appevents/internal/Constants",
        "com/facebook/appevents/internal/FileDownloadTask",
        "com/facebook/appevents/internal/HashUtils",
        "com/facebook/appevents/internal/SessionInfo",
        "com/facebook/appevents/internal/SessionLogger",
        "com/facebook/appevents/internal/SourceApplicationInfo",
        "com/facebook/appevents/internal/ViewHierarchyConstants",
        "com/facebook/appevents/ml/Model",
        "com/facebook/appevents/ml/ModelManager",
        "com/facebook/appevents/ml/MTensor",
        "com/facebook/appevents/ml/Operator",
        "com/facebook/appevents/ml/Utils",
        "com/facebook/appevents/ondeviceprocessing/OnDeviceProcessingManager",
        "com/facebook/appevents/ondeviceprocessing/RemoteServiceParametersHelper",
        "com/facebook/appevents/ondeviceprocessing/RemoteServiceWrapper",
        "com/facebook/appevents/PersistedEvents",
        "com/facebook/appevents/restrictivedatafilter/RestrictiveDataManager",
        "com/facebook/appevents/SessionEventsState",
        "com/facebook/appevents/suggestedevents/FeatureExtractor",
        "com/facebook/appevents/suggestedevents/PredictionHistoryManager",
        "com/facebook/appevents/suggestedevents/SuggestedEventsManager",
        "com/facebook/appevents/suggestedevents/SuggestedEventViewHierarchy",
        "com/facebook/appevents/suggestedevents/ViewObserver",
        "com/facebook/appevents/suggestedevents/ViewOnClickListener",
        "com/facebook/appevents/UserDataStore",
        "com/facebook/applinks/AppLinkData",
        "com/facebook/applinks/AppLinks",
        "com/facebook/applinks/FacebookAppLinkResolver",
        "com/facebook/AuthenticationToken",
        "com/facebook/AuthenticationTokenCache",
        "com/facebook/AuthenticationTokenClaims",
        "com/facebook/AuthenticationTokenHeader",
        "com/facebook/AuthenticationTokenManager",
        "com/facebook/AuthenticationTokenTracker",
        "com/facebook/bolts/AggregateException",
        "com/facebook/bolts/AndroidExecutors",
        "com/facebook/bolts/AppLink",
        "com/facebook/bolts/AppLinkResolver",
        "com/facebook/bolts/AppLinks",
        "com/facebook/bolts/BoltsExecutors",
        "com/facebook/bolts/CancellationToken",
        "com/facebook/bolts/CancellationTokenRegistration",
        "com/facebook/bolts/CancellationTokenSource",
        "com/facebook/bolts/Continuation",
        "com/facebook/bolts/ExecutorException",
        "com/facebook/bolts/Task",
        "com/facebook/bolts/TaskCompletionSource",
        "com/facebook/bolts/UnobservedErrorNotifier",
        "com/facebook/bolts/UnobservedTaskException",
        "com/facebook/CallbackManager",
        "com/facebook/common/Common",
        "com/facebook/core/Core",
        "com/facebook/CurrentAccessTokenExpirationBroadcastReceiver",
        "com/facebook/CustomTabActivity",
        "com/facebook/CustomTabMainActivity",
        "com/facebook/devicerequests/internal/DeviceRequestsHelper",
        "com/facebook/FacebookActivity",
        "com/facebook/FacebookAuthorizationException",
        "com/facebook/FacebookBroadcastReceiver",
        "com/facebook/FacebookButtonBase",
        "com/facebook/FacebookCallback",
        "com/facebook/FacebookContentProvider",
        "com/facebook/FacebookDialog",
        "com/facebook/FacebookDialogException",
        "com/facebook/FacebookException",
        "com/facebook/FacebookGraphResponseException",
        "com/facebook/FacebookOperationCanceledException",
        "com/facebook/FacebookRequestError",
        "com/facebook/FacebookSdk",
        "com/facebook/FacebookSdkNotInitializedException",
        "com/facebook/FacebookSdkVersion",
        "com/facebook/FacebookServiceException",
        "com/facebook/gamingservices/cloudgaming/AppToUserNotificationSender",
        "com/facebook/gamingservices/cloudgaming/CloudGameLoginHandler",
        "com/facebook/gamingservices/cloudgaming/DaemonReceiver",
        "com/facebook/gamingservices/cloudgaming/DaemonRequest",
        "com/facebook/gamingservices/cloudgaming/GameFeaturesLibrary",
        "com/facebook/gamingservices/cloudgaming/InAppAdLibrary",
        "com/facebook/gamingservices/cloudgaming/InAppPurchaseLibrary",
        "com/facebook/gamingservices/cloudgaming/internal/SDKAnalyticsEvents",
        "com/facebook/gamingservices/cloudgaming/internal/SDKConstants",
        "com/facebook/gamingservices/cloudgaming/internal/SDKLogger",
        "com/facebook/gamingservices/cloudgaming/internal/SDKMessageEnum",
        "com/facebook/gamingservices/cloudgaming/internal/SDKShareIntentEnum",
        "com/facebook/gamingservices/cloudgaming/PlayableAdsLibrary",
        "com/facebook/gamingservices/ContextChooseDialog",
        "com/facebook/gamingservices/ContextCreateDialog",
        "com/facebook/gamingservices/ContextSwitchDialog",
        "com/facebook/gamingservices/CustomUpdate",
        "com/facebook/gamingservices/FriendFinderDialog",
        "com/facebook/gamingservices/GameRequestDialog",
        "com/facebook/gamingservices/GamingContext",
        "com/facebook/gamingservices/GamingGroupIntegration",
        "com/facebook/gamingservices/GamingImageUploader",
        "com/facebook/gamingservices/GamingPayload",
        "com/facebook/gamingservices/GamingServices",
        "com/facebook/gamingservices/GamingVideoUploader",
        "com/facebook/gamingservices/internal/DateFormatter",
        "com/facebook/gamingservices/internal/GamingMediaUploader",
        "com/facebook/gamingservices/internal/TournamentJoinDialogURIBuilder",
        "com/facebook/gamingservices/internal/TournamentScoreType",
        "com/facebook/gamingservices/internal/TournamentShareDialogURIBuilder",
        "com/facebook/gamingservices/internal/TournamentSortOrder",
        "com/facebook/gamingservices/model/ContextChooseContent",
        "com/facebook/gamingservices/model/ContextCreateContent",
        "com/facebook/gamingservices/model/ContextSwitchContent",
        "com/facebook/gamingservices/model/CustomUpdateContent",
        "com/facebook/gamingservices/OpenGamingMediaDialog",
        "com/facebook/gamingservices/Tournament",
        "com/facebook/gamingservices/TournamentConfig",
        "com/facebook/gamingservices/TournamentFetcher",
        "com/facebook/gamingservices/TournamentJoinDialog",
        "com/facebook/gamingservices/TournamentShareDialog",
        "com/facebook/gamingservices/TournamentUpdater",
        "com/facebook/GraphRequest",
        "com/facebook/GraphRequestAsyncTask",
        "com/facebook/GraphRequestBatch",
        "com/facebook/GraphResponse",
        "com/facebook/HttpMethod",
        "com/facebook/internal/AnalyticsEvents",
        "com/facebook/internal/AppCall",
        "com/facebook/internal/AttributionIdentifiers",
        "com/facebook/internal/BoltsMeasurementEventListener",
        "com/facebook/internal/BundleJSONConverter",
        "com/facebook/internal/CallbackManagerImpl",
        "com/facebook/internal/CollectionMapper",
        "com/facebook/internal/CustomTab",
        "com/facebook/internal/CustomTabUtils",
        "com/facebook/internal/DialogFeature",
        "com/facebook/internal/DialogPresenter",
        "com/facebook/internal/FacebookDialogBase",
        "com/facebook/internal/FacebookDialogFragment",
        "com/facebook/internal/FacebookGamingAction",
        "com/facebook/internal/FacebookInitProvider",
        "com/facebook/internal/FacebookRequestErrorClassification",
        "com/facebook/internal/FacebookSignatureValidator",
        "com/facebook/internal/FacebookWebFallbackDialog",
        "com/facebook/internal/FeatureManager",
        "com/facebook/internal/FetchedAppGateKeepersManager",
        "com/facebook/internal/FetchedAppSettings",
        "com/facebook/internal/FetchedAppSettingsManager",
        "com/facebook/internal/FileLruCache",
        "com/facebook/internal/FragmentWrapper",
        "com/facebook/internal/gatekeeper/GateKeeper",
        "com/facebook/internal/gatekeeper/GateKeeperRuntimeCache",
        "com/facebook/internal/ImageDownloader",
        "com/facebook/internal/ImageRequest",
        "com/facebook/internal/ImageResponse",
        "com/facebook/internal/ImageResponseCache",
        "com/facebook/internal/InstagramCustomTab",
        "com/facebook/internal/InstallReferrerUtil",
        "com/facebook/internal/instrument/anrreport/ANRDetector",
        "com/facebook/internal/instrument/anrreport/ANRHandler",
        "com/facebook/internal/instrument/crashreport/CrashHandler",
        "com/facebook/internal/instrument/crashshield/AutoHandleExceptions",
        "com/facebook/internal/instrument/crashshield/CrashShieldHandler",
        "com/facebook/internal/instrument/crashshield/NoAutoExceptionHandling",
        "com/facebook/internal/instrument/errorreport/ErrorReportData",
        "com/facebook/internal/instrument/errorreport/ErrorReportHandler",
        "com/facebook/internal/instrument/ExceptionAnalyzer",
        "com/facebook/internal/instrument/InstrumentData",
        "com/facebook/internal/instrument/InstrumentManager",
        "com/facebook/internal/instrument/InstrumentUtility",
        "com/facebook/internal/instrument/threadcheck/ThreadCheckHandler",
        "com/facebook/internal/InternalSettings",
        "com/facebook/internal/LockOnGetVariable",
        "com/facebook/internal/Logger",
        "com/facebook/internal/logging/dumpsys/EndToEndDumper",
        "com/facebook/internal/Mutable",
        "com/facebook/internal/NativeAppCallAttachmentStore",
        "com/facebook/internal/NativeProtocol",
        "com/facebook/internal/PlatformServiceClient",
        "com/facebook/internal/ProfileInformationCache",
        "com/facebook/internal/qualityvalidation/Excuse",
        "com/facebook/internal/qualityvalidation/ExcusesForDesignViolations",
        "com/facebook/internal/security/CertificateUtil",
        "com/facebook/internal/security/OidcSecurityUtil",
        "com/facebook/internal/ServerProtocol",
        "com/facebook/internal/SmartLoginOption",
        "com/facebook/internal/UrlRedirectCache",
        "com/facebook/internal/Utility",
        "com/facebook/internal/Validate",
        "com/facebook/internal/WebDialog",
        "com/facebook/internal/WorkQueue",
        "com/facebook/LegacyTokenHelper",
        "com/facebook/LoggingBehavior",
        "com/facebook/login/CodeChallengeMethod",
        "com/facebook/login/CustomTabLoginMethodHandler",
        "com/facebook/login/CustomTabPrefetchHelper",
        "com/facebook/login/DefaultAudience",
        "com/facebook/login/DeviceAuthDialog",
        "com/facebook/login/DeviceAuthMethodHandler",
        "com/facebook/login/DeviceLoginManager",
        "com/facebook/login/GetTokenClient",
        "com/facebook/login/GetTokenLoginMethodHandler",
        "com/facebook/login/InstagramAppLoginMethodHandler",
        "com/facebook/login/KatanaProxyLoginMethodHandler",
        "com/facebook/login/Login",
        "com/facebook/login/LoginBehavior",
        "com/facebook/login/LoginClient",
        "com/facebook/login/LoginConfiguration",
        "com/facebook/login/LoginFragment",
        "com/facebook/login/LoginLogger",
        "com/facebook/login/LoginManager",
        "com/facebook/login/LoginMethodHandler",
        "com/facebook/login/LoginResult",
        "com/facebook/login/LoginStatusClient",
        "com/facebook/login/LoginTargetApp",
        "com/facebook/login/NativeAppLoginMethodHandler",
        "com/facebook/login/NonceUtil",
        "com/facebook/login/PKCEUtil",
        "com/facebook/login/StartActivityDelegate",
        "com/facebook/LoginStatusCallback",
        "com/facebook/login/WebLoginMethodHandler",
        "com/facebook/login/WebViewLoginMethodHandler",
        "com/facebook/login/widget/DeviceLoginButton",
        "com/facebook/login/widget/LoginButton",
        "com/facebook/login/widget/ProfilePictureView",
        "com/facebook/login/widget/ToolTipPopup",
        "com/facebook/messenger/Messenger",
        "com/facebook/messenger/MessengerThreadParams",
        "com/facebook/messenger/MessengerUtils",
        "com/facebook/messenger/ShareToMessengerParams",
        "com/facebook/messenger/ShareToMessengerParamsBuilder",
        "com/facebook/Profile",
        "com/facebook/ProfileCache",
        "com/facebook/ProfileManager",
        "com/facebook/ProfileTracker",
        "com/facebook/ProgressNoopOutputStream",
        "com/facebook/ProgressOutputStream",
        "com/facebook/RequestOutputStream",
        "com/facebook/RequestProgress",
        "com/facebook/share/internal/CameraEffectFeature",
        "com/facebook/share/internal/CameraEffectJSONUtility",
        "com/facebook/share/internal/GameRequestValidation",
        "com/facebook/share/internal/LegacyNativeDialogParameters",
        "com/facebook/share/internal/MessageDialogFeature",
        "com/facebook/share/internal/NativeDialogParameters",
        "com/facebook/share/internal/ResultProcessor",
        "com/facebook/share/internal/ShareConstants",
        "com/facebook/share/internal/ShareContentValidation",
        "com/facebook/share/internal/ShareDialogFeature",
        "com/facebook/share/internal/ShareFeedContent",
        "com/facebook/share/internal/ShareInternalUtility",
        "com/facebook/share/internal/ShareStoryFeature",
        "com/facebook/share/internal/VideoUploader",
        "com/facebook/share/internal/WebDialogParameters",
        "com/facebook/share/model/AppGroupCreationContent",
        "com/facebook/share/model/CameraEffectArguments",
        "com/facebook/share/model/CameraEffectTextures",
        "com/facebook/share/model/GameRequestContent",
        "com/facebook/share/model/ShareCameraEffectContent",
        "com/facebook/share/model/ShareContent",
        "com/facebook/share/model/ShareHashtag",
        "com/facebook/share/model/ShareLinkContent",
        "com/facebook/share/model/ShareMedia",
        "com/facebook/share/model/ShareMediaContent",
        "com/facebook/share/model/ShareMessengerActionButton",
        "com/facebook/share/model/ShareMessengerURLActionButton",
        "com/facebook/share/model/ShareModel",
        "com/facebook/share/model/ShareModelBuilder",
        "com/facebook/share/model/SharePhoto",
        "com/facebook/share/model/SharePhotoContent",
        "com/facebook/share/model/ShareStoryContent",
        "com/facebook/share/model/ShareVideo",
        "com/facebook/share/model/ShareVideoContent",
        "com/facebook/share/Share",
        "com/facebook/share/ShareApi",
        "com/facebook/share/ShareBuilder",
        "com/facebook/share/Sharer",
        "com/facebook/share/widget/GameRequestDialog",
        "com/facebook/share/widget/MessageDialog",
        "com/facebook/share/widget/SendButton",
        "com/facebook/share/widget/ShareButton",
        "com/facebook/share/widget/ShareButtonBase",
        "com/facebook/share/widget/ShareDialog",
        "com/facebook/UserSettingsManager",
        "com/facebook/WebDialog"
      ],
      "documentation": [
        "https://developers.facebook.com/docs/android"
      ],
      "gradle_signatures": [
        "com.facebook.android"
      ],
      "license": "NonFree",
      "name": "Facebook Android SDK"
    },
    "com.flurry.android": {
      "code_signature": [
        "com/flurry"
      ],
      "documentation": [
        "https://www.flurry.com/"
      ],
      "gradle_signatures": [
        "com.flurry.android"
      ],
      "license": "NonFree",
      "name": "Flurry Android SDK"
    },
    "com.garmin.android.connectiq": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/garmin/android/apps/connectmobile/connectiq"
      ],
      "description": "SDK to build unique wearable experiences leveraging Garmin device sensors and features.",
      "license": "NonFree"
    },
    "com.garmin.connectiq": {
      "code_signatures": [
        "com/garmin/android/connectiq"
      ],
      "documentation": [
        "https://developer.garmin.com/connect-iq/core-topics/mobile-sdk-for-android/"
      ],
      "gradle_signatures": [
        "com.garmin.connectiq:ciq-companion-app-sdk"
      ],
      "license": "NonFree",
      "name": "Connect IQ Mobile SDK for Android"
    },
    "com.garmin.fit": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/garmin/fit"
      ],
      "description": "SDK to access the Garmin Fit.",
      "license": "NonFree"
    },
    "com.geetest": {
      "code_signatures": [
        "com/geetest"
      ],
      "documentation": [
        "https://docs.geetest.com/"
      ],
      "gradle_signatures": [
        "com.geetest"
      ],
      "license": "NonFree",
      "name": "GeeTest"
    },
    "com.github.junrar": {
      "code_signatures": [
        "com/github/junrar"
      ],
      "documentation": [
        "https://github.com/junrar/junrar"
      ],
      "gradle_signatures": [
        "com.github.junrar:junrar"
      ],
      "license": "NonFree",
      "name": "Junrar"
    },
    "com.github.omicronapps.7-Zip-JBinding-4Android": {
      "documentation": [
        "https://github.com/omicronapps/7-Zip-JBinding-4Android"
      ],
      "gradle_signatures": [
        "com.github.omicronapps:7-Zip-JBinding-4Android"
      ],
      "license": "NonFree",
      "name": "7-Zip-JBinding-4Android"
    },
    "com.google.ads": {
      "code_signatures": [
        "com/google/ads"
      ],
      "documentation": [
        "https://developers.google.com/interactive-media-ads/docs/sdks/android/client-side"
      ],
      "gradle_signatures": [
        "com.google.ads",
        "com.google.android.exoplayer:extension-ima",
        "androidx.media3:media3-exoplayer-ima"
      ],
      "license": "NonFree",
      "name": "IMA SDK for Android"
    },
    "com.google.android.apps.auto.sdk": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/google/android/apps/auto/sdk"
      ],
      "description": "Framework to develop apps for Android Auto",
      "license": "NonFree"
    },
    "com.google.android.gcm": {
      "anti_features": [
        "NonFreeComp",
        "NonFreeNet"
      ],
      "code_signatures": [
        "com/google/android/gcm"
      ],
      "description": "<a href='https://en.wikipedia.org/wiki/Google_Cloud_Messaging' target='_blank'>Google Cloud Messaging</a> is a mobile notification service developed by Google that enables third-party application developers to send notification data or information from developer-run servers to app.",
      "license": "NonFree"
    },
    "com.google.android.gms": {
      "code_signatures": [
        "com/google/android/gms"
      ],
      "documentation": [
        "https://www.android.com/gms/"
      ],
      "gradle_signatures": [
        "com.google.android.gms(?!.oss-licenses-plugin)",
        "com.google.android.ump",
        "androidx.core:core-google-shortcuts",
        "androidx.credentials:credentials",
        "androidx.credentials:credentials-play-services-auth",
        "androidx.media3:media3-cast",
        "androidx.media3:media3-datasource-cronet",
        "androidx.work:work-gcm",
        "com.google.android.exoplayer:extension-cast",
        "com.google.android.exoplayer:extension-cronet",
        "com.evernote:android-job",
        "com.cloudinary:cloudinary-android.*:2\\.[12]\\.",
        "com.pierfrancescosoffritti.androidyoutubeplayer:chromecast-sender",
        "com.yayandroid:locationmanager",
        "play-services",
        "xyz.belvi.mobilevision:barcodescanner",
        "com.google.api-client:google-api-client-android"
      ],
      "license": "NonFree",
      "name": "Google Mobile Services"
    },
    "com.google.android.gms.analytics": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/google/android/apps/analytics"
      ],
      "description": "a web analytics service offered by Google that tracks and reports. 'NoAnalytics' srclib will provide stubs for these classes.",
      "license": "NonFree"
    },
    "com.google.android.libraries": {
      "code_signatures": [
        "com/google/android/libraries"
      ],
      "gradle_signatures": [
        "com.google.android.libraries(?!.mapsplatform.secrets-gradle-plugin)"
      ],
      "gradle_signatures_negative_examples": [
        "classpath \"com.google.android.libraries.mapsplatform.secrets-gradle-plugin:secrets-gradle-plugin:2.0.1\""
      ],
      "license": "NonFree",
      "name": "Google Android Libraries"
    },
    "com.google.android.mediahome.video": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/google/android/mediahome/video"
      ],
      "description": "integrate video content with <a href='https://developer.android.com/training/home-channels' target='_blank' rel='nofollow'>Home channels for mobile apps</a>.",
      "license": "NonFree"
    },
    "com.google.android.play": {
      "anti_features": [
        "NonFreeDep",
        "NonFreeNet"
      ],
      "code_signatures": [
        "com/google/android/play/core"
      ],
      "documentation": [
        "https://developer.android.com/guide/playcore"
      ],
      "gradle_signatures": [
        "com.google.android.play:app-update",
        "com.google.android.play:asset-delivery",
        "com.google.android.play:core.*",
        "com.google.android.play:feature-delivery",
        "com.google.android.play:review",
        "androidx.navigation:navigation-dynamic-features",
        "com.github.SanojPunchihewa:InAppUpdater",
        "com.suddenh4x.ratingdialog:awesome-app-rating"
      ],
      "license": "NonFree",
      "name": "Google Play Core"
    },
    "com.google.android.play.appupdate": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/google/android/play/appupdate"
      ],
      "description": "manages operations that allow an app to initiate its own updates.",
      "license": "NonFree"
    },
    "com.google.android.play.integrity": {
      "anti_features": [
        "NonFreeComp",
        "NonFreeNet"
      ],
      "code_signatures": [
        "com/google/android/play/integrity"
      ],
      "description": "helps you check that interactions and server requests are coming from your genuine app binary running on a genuine Android device.",
      "license": "NonFree"
    },
    "com.google.android.play.review": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/google/android/play/review"
      ],
      "description": "lets you prompt users to submit Play Store ratings and reviews without the inconvenience of leaving your app or game.",
      "license": "NonFree"
    },
    "com.google.android.vending": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/google/android/vending/(?!licensing|expansion)"
      ],
      "description": "the Google Play Store app and its libaries, parts are FOSS and get vendored in libs as they are",
      "documentation": [
        "https://github.com/google/play-licensing/tree/master/lvl_library/src/main",
        "https://github.com/googlearchive/play-apk-expansion/tree/master/zip_file/src/com/google/android/vending/expansion/zipfile",
        "https://github.com/googlearchive/play-apk-expansion/tree/master/apkx_library/src/com/google/android/vending/expansion/downloader"
      ],
      "license": "NonFree"
    },
    "com.google.android.wearable": {
      "code_signatures": [
        "com/google/android/wearable/(?!compat/WearableActivityController)"
      ],
      "description": "an API for the Android Wear platform, note that androidx.wear:wear has a stub https://android.googlesource.com/platform/frameworks/support/+/refs/heads/androidx-master-release/wear/wear/src/androidTest/java/com/google/android/wearable/compat/WearableActivityController.java#26",
      "gradle_signatures": [
        "com.google.android.support:wearable",
        "com.google.android.wearable:wearable"
      ],
      "license": "NonFree"
    },
    "com.google.android.youtube.player": {
      "anti_features": [
        "NonFreeComp",
        "NonFreeNet"
      ],
      "code_signatures": [
        "com/google/android/youtube/player"
      ],
      "description": "enables you to easily play YouTube videos and display thumbnails of YouTube videos in your Android application.",
      "license": "NonFree"
    },
    "com.google.mlkit": {
      "code_signatures": [
        "com/google/mlkit"
      ],
      "documentation": [
        "https://developers.google.com/ml-kit"
      ],
      "gradle_signatures": [
        "com.google.mlkit"
      ],
      "license": "NonFree",
      "name": "ML Kit"
    },
    "com.google.vr": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/google/vr"
      ],
      "description": "enables Daydream and Cardboard app development on Android.",
      "license": "NonFree"
    },
    "com.heapanalytics": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/heapanalytics"
      ],
      "description": "automatically captures every web, mobile, and cloud interaction: clicks, submits, transactions, emails, and more. Retroactively analyze your data without writing code.",
      "license": "NonFree"
    },
    "com.heyzap": {
      "code_signatures": [
        "com/heyzap"
      ],
      "documentation": [
        "https://www.digitalturbine.com/"
      ],
      "license": "NonFree",
      "name": "Heyzap"
    },
    "com.huawei.hms": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/huawei/hms"
      ],
      "description": "Huawei's pendant to GMS (Google Mobile Services)",
      "license": "NonFree"
    },
    "com.hypertrack": {
      "code_signatures": [
        "com/hypertrack/(?!hyperlog)"
      ],
      "documentation": [
        "https://github.com/hypertrack/sdk-android"
      ],
      "gradle_signatures": [
        "com.hypertrack(?!:hyperlog)"
      ],
      "gradle_signatures_negative_examples": [
        "com.hypertrack:hyperlog"
      ],
      "license": "NonFree",
      "name": "HyperTrack SDK for Android"
    },
    "com.instabug": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/instabug"
      ],
      "description": "In-App Feedback and Bug Reporting for Mobile Apps.",
      "license": "NonFree"
    },
    "com.kiddoware.kidsplace.sdk": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/kiddoware/kidsplace/sdk"
      ],
      "description": "parental control",
      "license": "NonFree"
    },
    "com.kochava.android.tracker": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/kochava/android/tracker"
      ],
      "description": "provides holistic, unbiased measurement for precise, real-time visualization of app performance through the funnel. See <a rel='nofollow' href='https://www.crunchbase.com/organization/kochava'>Crunchbase</a> and <a href='https://reports.exodus-privacy.eu.org/en/trackers/127/'>Exodus Privacy</a>.",
      "license": "NonFree"
    },
    "com.mapbox": {
      "MaintainerNotes": "It seems that all libs in https://github.com/mapbox/mapbox-java is fully FOSS\nsince 3.0.0.\n",
      "documentation": [
        "https://docs.mapbox.com/android/java/overview/",
        "https://github.com/mapbox/mapbox-java"
      ],
      "gradle_signatures": [
        "com\\.mapbox(?!\\.mapboxsdk:mapbox-sdk-(services|geojson|turf):([3-5]))"
      ],
      "gradle_signatures_negative_examples": [
        "com.mapbox.mapboxsdk:mapbox-sdk-services:5.0.0",
        "com.github.johan12345:mapbox-events-android:a21c324501",
        "implementation(\"com.github.johan12345.AnyMaps:anymaps-mapbox:$anyMapsVersion\")"
      ],
      "gradle_signatures_positive_examples": [
        "com.mapbox.mapboxsdk:mapbox-android-plugin-annotation-v7:0.6.0",
        "com.mapbox.mapboxsdk:mapbox-android-plugin-annotation-v8:0.7.0",
        "com.mapbox.mapboxsdk:mapbox-android-plugin-localization-v7:0.7.0",
        "com.mapbox.mapboxsdk:mapbox-android-plugin-locationlayer:0.4.0",
        "com.mapbox.mapboxsdk:mapbox-android-plugin-markerview-v8:0.3.0",
        "com.mapbox.mapboxsdk:mapbox-android-plugin-places-v8:0.9.0",
        "com.mapbox.mapboxsdk:mapbox-android-plugin-scalebar-v8:0.2.0",
        "com.mapbox.mapboxsdk:mapbox-android-sdk:7.3.0"
      ],
      "license": "NonFree",
      "name": "Mapbox Java SDK"
    },
    "com.microblink": {
      "anti_features": [
        "NonFreeComp",
        "NonFreeNet",
        "Tracking"
      ],
      "code_signatures": [
        "com/microblink"
      ],
      "description": "verify users at scale and automate your document-based workflow with computer vision tech built for a remote world.",
      "license": "NonFree"
    },
    "com.microsoft.band": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/microsoft/band"
      ],
      "description": "library to access the Microsoft Band smartwatch.",
      "license": "NonFree"
    },
    "com.mopub.mobileads": {
      "anti_features": [
        "Ads",
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/mopub/mobileads"
      ],
      "description": "ad framework run by Twitter until 1/2022, then sold to AppLovin.",
      "license": "NonFree"
    },
    "com.newrelic.agent": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/newrelic/agent"
      ],
      "description": "delivering full-stack visibility and analytics to enterprises around the world. See <a rel='nofollow' href='https://www.crunchbase.com/organization/new-relic'>Crunchbase</a> and <a href='https://reports.exodus-privacy.eu.org/en/trackers/130/'>Exodus Privacy</a>.",
      "license": "NonFree"
    },
    "com.onesignal": {
      "code_signatures": [
        "com/onesignal"
      ],
      "documentation": [
        "https://github.com/OneSignal/OneSignal-Android-SDK"
      ],
      "gradle_signatures": [
        "com.onesignal:OneSignal"
      ],
      "license": "NonFree",
      "name": "OneSignal Android Push Notification Plugin"
    },
    "com.optimizely": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/optimizely"
      ],
      "description": "part of the comScore, Inc. market research community, a leading global market research effort that studies and reports on Internet trends and behavior.",
      "license": "NonFree"
    },
    "com.paypal.sdk": {
      "code_signatures": [
        "com/paypal"
      ],
      "documentation": [
        "https://github.com/paypal/PayPal-Android-SDK",
        "https://github.com/paypal/android-checkout-sdk"
      ],
      "gradle_signatures": [
        "com.paypal"
      ],
      "license": "NonFree",
      "name": "PayPal Android SDK"
    },
    "com.pushwoosh": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/pushwoosh"
      ],
      "description": "mobile analytics under the cover of push messaging.",
      "license": "NonFree"
    },
    "com.quantcast.measurement.service": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/quantcast/measurement/service"
      ],
      "description": "processes real-time data at the intersection of commerce and culture, providing useful, actionable insights for brands and publishers. See <a rel='nofollow' href='https://www.crunchbase.com/organization/quantcast'>Crunchbase</a> and <a href='https://reports.exodus-privacy.eu.org/en/trackers/133/'>Exodus Privacy</a>.",
      "license": "NonFree"
    },
    "com.samsung.accessory": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/samsung/accessory"
      ],
      "description": "provides a stable environment in which you can use a variety features by connecting accessories to your mobile device.",
      "license": "NonFree"
    },
    "com.samsung.android.sdk.look": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/samsung/android/sdk/look"
      ],
      "description": "offers specialized widgets and service components for extended functions of the Samsung Android devices.",
      "license": "NonFree"
    },
    "com.sendbird.android": {
      "anti_features": [
        "NonFreeComp",
        "NonFreeNet",
        "Tracking"
      ],
      "code_signatures": [
        "com/sendbird/android"
      ],
      "description": "an easy-to-use Chat API, native Chat SDKs, and a fully-managed chat platform on the backend means faster time-to-market.",
      "license": "NonFree"
    },
    "com.smaato.soma": {
      "anti_features": [
        "Ads",
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/smaato/soma"
      ],
      "description": "a mobile ad platform that includes video ads.",
      "license": "NonFree"
    },
    "com.spotify.sdk": {
      "anti_features": [
        "NonFreeComp",
        "NonFreeNet"
      ],
      "code_signatures": [
        "com/spotify/sdk"
      ],
      "description": "allows your application to interact with the Spotify app service. (Note that while the SDK repo claims Apache license, the code is not available there)",
      "license": "NonFree"
    },
    "com.startapp.android": {
      "anti_features": [
        "Ads",
        "Tracking",
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/startapp"
      ],
      "description": "partly quite intrusive ad network.",
      "license": "NonFree"
    },
    "com.telerik.android": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/telerik/android"
      ],
      "description": "offers high quality Xamarin Forms UI components and Visual Studio item templates to enable every developer.",
      "license": "NonFree"
    },
    "com.tencent.bugly": {
      "code_signatures": [
        "com/tencent/bugly"
      ],
      "documentation": [
        "https://bugly.qq.com/"
      ],
      "gradle_signatures": [
        "com.tencent.bugly"
      ],
      "license": "NonFree",
      "name": "Bugly Android SDK"
    },
    "com.tencent.mapsdk": {
      "anti_features": [
        "NonFreeNet"
      ],
      "code_signatures": [
        "com/tencent/tencentmap"
      ],
      "description": "giving access to <a href='https://en.wikipedia.org/wiki/Tencent_Maps' target='_blank'>Tencent Maps</a>.",
      "license": "NonFree"
    },
    "com.tenjin.android.TenjinSDK": {
      "anti_features": [
        "Tracking"
      ],
      "code_signatures": [
        "com/tenjin/android/TenjinSDK"
      ],
      "description": "a marketing platform designed for mobile that features analytics, automated aggregation, and direct data visualization with direct SQL access.",
      "license": "NonFree"
    },
    "com.umeng.umsdk": {
      "code_signatures": [
        "com/umeng"
      ],
      "documentation": [
        "https://developer.umeng.com/docs/119267/detail/118584"
      ],
      "gradle_signatures": [
        "com.umeng"
      ],
      "license": "NonFree",
      "name": "Umeng SDK"
    },
    "com.wei.android.lib": {
      "code_signatures": [
        "com/wei/android/lib/fingerprintidentify"
      ],
      "documentation": [
        "https://github.com/uccmawei/FingerprintIdentify"
      ],
      "gradle_signatures": [
        "com.wei.android.lib:fingerprintidentify",
        "com.github.uccmawei:FingerprintIdentify"
      ],
      "license": "NonFree",
      "name": "FingerprintIdentify"
    },
    "com.yandex.android": {
      "code_signatures": [
        "com/yandex/android/(?!:authsdk)"
      ],
      "gradle_signatures": [
        "com\\.yandex\\.android(?!:authsdk)"
      ],
      "gradle_signatures_negative_examples": [
        "com.yandex.android:authsdk"
      ],
      "license": "NonFree",
      "name": "Yandex SDK"
    },
    "com.yandex.metrica": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "com/yandex/metrica"
      ],
      "description": "a mobile attribution and analytics platform developed by Yandex. It is free, real-time and has no data limits restriction. See <a rel='nofollow' href='https://www.crunchbase.com/organization/appmetrica'>Crunchbase</a> and <a href='https://reports.exodus-privacy.eu.org/en/trackers/140/'>Exodus Privacy</a>.",
      "license": "NonFree"
    },
    "com.yandex.mobile.ads": {
      "anti_features": [
        "Ads",
        "NonFreeComp"
      ],
      "code_signatures": [
        "com/yandex/mobile/ads"
      ],
      "description": "See <a href='https://reports.exodus-privacy.eu.org/en/trackers/124/'>Exodus Privacy</a>.",
      "license": "NonFree"
    },
    "de.epgpaid": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "de/epgpaid"
      ],
      "description": "access paid <a href='https://en.wikipedia.org/wiki/EPG' target='_blank'>EPG</a> (Electronic Program Guide, for TV) data (after payment, of course). Part of <a href='https://github.com/ds10git/tvbrowserandroid' target='_blank' rel='nofollow'>TVBrowser</a>.",
      "license": "NonFree"
    },
    "de.innosystec.unrar": {
      "code_signatures": [
        "de/innosystec/unrar"
      ],
      "description": "java unrar util",
      "license": "NonFree"
    },
    "firebase": {
      "code_signatures": [
        "com/google/firebase"
      ],
      "documentation": [
        "https://www.firebase.com"
      ],
      "gradle_signatures": [
        "com(\\.google)?\\.firebase[.:](?!firebase-jobdispatcher|geofire-java)",
        "com.microsoft.appcenter:appcenter-push"
      ],
      "gradle_signatures_negative_examples": [
        "    compile 'com.firebase:firebase-jobdispatcher:0.8.4'",
        "implementation 'com.firebase:geofire-java:3.0.0'",
        "    compile 'com.firebaseui:firebase-ui-auth:3.1.3'",
        "com.firebaseui:firebase-ui-database",
        "com.firebaseui:firebase-ui-storage",
        "com.github.axet:android-firebase-fake",
        "com.github.b3er.rxfirebase:firebase-database",
        "com.github.b3er.rxfirebase:firebase-database-kotlin",
        "com.segment.analytics.android.integrations:firebase"
      ],
      "gradle_signatures_positive_examples": [
        "\tcompile 'com.google.firebase:firebase-crash:11.0.8'",
        "\tcompile 'com.google.firebase:firebase-core:11.0.8'",
        "com.firebase:firebase-client-android:2.5.2",
        "com.google.firebase.crashlytics",
        "com.google.firebase.firebase-perf",
        "com.google.firebase:firebase-ads",
        "com.google.firebase:firebase-analytics",
        "com.google.firebase:firebase-appindexing",
        "com.google.firebase:firebase-auth",
        "com.google.firebase:firebase-config",
        "com.google.firebase:firebase-core",
        "com.google.firebase:firebase-crash",
        "com.google.firebase:firebase-crashlytics",
        "com.google.firebase:firebase-database",
        "com.google.firebase:firebase-dynamic-links",
        "com.google.firebase:firebase-firestore",
        "com.google.firebase:firebase-inappmessaging",
        "com.google.firebase:firebase-inappmessaging-display",
        "com.google.firebase:firebase-messaging",
        "com.google.firebase:firebase-ml-natural-language",
        "com.google.firebase:firebase-ml-natural-language-smart-reply-model",
        "com.google.firebase:firebase-ml-vision",
        "com.google.firebase:firebase-perf",
        "com.google.firebase:firebase-plugins",
        "com.google.firebase:firebase-storage"
      ],
      "license": "NonFree",
      "name": "Firebase"
    },
    "google-maps": {
      "anti_features": [
        "NonFreeDep",
        "NonFreeNet"
      ],
      "api_key_ids": [
        "com\\.google\\.android\\.geo\\.API_KEY",
        "com\\.google\\.android\\.maps\\.v2\\.API_KEY"
      ],
      "documentation": [
        "https://developers.google.com/maps/documentation/android-sdk/overview"
      ],
      "license": "NonFree",
      "name": "Google Maps"
    },
    "io.fabric.sdk.android": {
      "anti_features": [
        "NonFreeComp",
        "Tracking"
      ],
      "code_signatures": [
        "io/fabric/sdk/android"
      ],
      "description": "Framework to integrate services. Provides e.g. crash reports and analytics. <a rel='nofollow' href='http://fabric.io/blog/fabric-joins-google/' target='_blank' rel='nofollow'>Aquired by Google in 2017</a>.",
      "license": "NonFree"
    },
    "io.github.sinaweibosdk": {
      "code_signatures": [
        "com/sina"
      ],
      "documentation": [
        "https://github.com/sinaweibosdk/weibo_android_sdk"
      ],
      "gradle_signatures": [
        "io.github.sinaweibosdk"
      ],
      "license": "NonFree",
      "name": "SinaWeiboSDK"
    },
    "io.intercom": {
      "anti_features": [
        "NonFreeComp",
        "NonFreeNet"
      ],
      "code_signatures": [
        "io/intercom"
      ],
      "description": "engage customers with email, push, and in\u2011app messages and support them with an integrated knowledge base and help desk.",
      "license": "NonFree"
    },
    "io.objectbox": {
      "code_signatures": [
        "io/objectbox"
      ],
      "documentation": [
        "https://objectbox.io/faq/#license-pricing"
      ],
      "gradle_signatures": [
        "io.objectbox:objectbox-gradle-plugin"
      ],
      "license": "NonFree",
      "name": "ObjectBox Database"
    },
    "me.pushy": {
      "code_signatures": [
        "me/pushy"
      ],
      "documentation": [
        "https://pushy.me/"
      ],
      "gradle_signatures": [
        "me.pushy"
      ],
      "license": "NonFree",
      "name": "Pushy"
    },
    "org.mariuszgromada.math": {
      "code_signatures": [
        "org/mariuszgromada/math/mxparser/parsertokens/SyntaxStringBuilder",
        "org/mariuszgromada/math/mxparser/CalcStepRecord",
        "org/mariuszgromada/math/mxparser/CalcStepsRegister",
        "org/mariuszgromada/math/mxparser/License",
        "org/mariuszgromada/math/mxparser/CloneCache",
        "org/mariuszgromada/math/mxparser/ElementAtTheEnd",
        "org/mariuszgromada/math/mxparser/CompilationDetails",
        "org/mariuszgromada/math/mxparser/CompiledElement"
      ],
      "documentation": [
        "https://mathparser.org",
        "https://mathparser.org/mxparser-license/"
      ],
      "gradle_signatures": [
        "org.mariuszgromada.math:MathParser.org-mXparser:[5-9]"
      ],
      "license": "NonFree",
      "name": "mXparser"
    },
    "tornaco.android.sec": {
      "anti_features": [
        "NonFreeComp"
      ],
      "code_signatures": [
        "tornaco/android/sec"
      ],
      "description": "proprietary part of the <a href='https://github.com/Tornaco/Thanox' target='_blank' rel='nofollow noopener'>Thanox</a> application",
      "license": "NonFree"
    }
  },
  "timestamp": 1725205987.66681,
  "version": 1,
  "last_updated": 1725950235.569432
}'''
