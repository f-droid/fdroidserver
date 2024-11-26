#!/usr/bin/env python3
#
# common.py - part of the FDroid server tools
#
# Copyright (C) 2010-2016, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013-2017, Daniel Martí <mvdan@mvdan.cc>
# Copyright (C) 2013-2021, Hans-Christoph Steiner <hans@eds.org>
# Copyright (C) 2017-2018, Torsten Grote <t@grobox.de>
# Copyright (C) 2017, tobiasKaminsky <tobias@kaminsky.me>
# Copyright (C) 2017-2021, Michael Pöhn <michael.poehn@fsfe.org>
# Copyright (C) 2017,2021, mimi89999 <michel@lebihan.pl>
# Copyright (C) 2019-2021, Jochen Sprickerhof <git@jochen.sprickerhof.de>
# Copyright (C) 2021, Felix C. Stegerman <flx@obfusk.net>
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

# common.py is imported by all modules, so do not import third-party
# libraries here as they will become a requirement for all commands.

import copy
import difflib
from typing import List
import git
import glob
import io
import os
import sys
import re
import ast
import gzip
import shutil
import stat
import subprocess
import time
import operator
import logging
import hashlib
import socket
import base64
import yaml
import zipfile
import tempfile
import json
from pathlib import Path

import defusedxml.ElementTree as XMLElementTree

from argparse import BooleanOptionalAction
from asn1crypto import cms
from base64 import urlsafe_b64encode
from binascii import hexlify
from datetime import datetime, timedelta, timezone
from queue import Queue
from urllib.parse import urlparse, urlsplit, urlunparse
from zipfile import ZipFile

import fdroidserver.metadata
import fdroidserver.lint
from fdroidserver import _
from fdroidserver.exception import FDroidException, VCSException, NoSubmodulesException, \
    BuildException, VerificationException, MetaDataException
from .asynchronousfilereader import AsynchronousFileReader
from .looseversion import LooseVersion

from . import apksigcopier, common


# The path to this fdroidserver distribution
FDROID_PATH = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))

# There needs to be a default, and this is the most common for software.
DEFAULT_LOCALE = 'en-US'

# this is the build-tools version, aapt has a separate version that
# has to be manually set in test_aapt_version()
MINIMUM_AAPT_BUILD_TOOLS_VERSION = '26.0.0'
# 31.0.0 is the first version to support --v4-signing-enabled.
# we only require 30.0.0 for now as that's the version in buster-backports, see also signindex.py
# 26.0.2 is the first version recognizing md5 based signatures as valid again
# (as does android, so we want that)
MINIMUM_APKSIGNER_BUILD_TOOLS_VERSION = '30.0.0'

VERCODE_OPERATION_RE = re.compile(r'^([ 0-9/*+-]|%c)+$')

# A signature block file with a .DSA, .RSA, or .EC extension
SIGNATURE_BLOCK_FILE_REGEX = re.compile(r'^META-INF/.*\.(DSA|EC|RSA)$')
APK_NAME_REGEX = re.compile(r'^([a-zA-Z][\w.]*)_(-?[0-9]+)_?([0-9a-f]{7})?\.apk')
APK_ID_TRIPLET_REGEX = re.compile(r"^package: name='(\w[^']*)' versionCode='([^']+)' versionName='([^']*)'")
STANDARD_FILE_NAME_REGEX = re.compile(r'^(\w[\w.]*)_(-?[0-9]+)\.\w+')
FDROID_PACKAGE_NAME_REGEX = re.compile(r'''^[a-f0-9]+$''', re.IGNORECASE)
STRICT_APPLICATION_ID_REGEX = re.compile(r'''(?:^[a-zA-Z]+(?:\d*[a-zA-Z_]*)*)(?:\.[a-zA-Z]+(?:\d*[a-zA-Z_]*)*)+$''')
VALID_APPLICATION_ID_REGEX = re.compile(r'''(?:^[a-z_]+(?:\d*[a-zA-Z_]*)*)(?:\.[a-z_]+(?:\d*[a-zA-Z_]*)*)*$''',
                                        re.IGNORECASE)
ANDROID_PLUGIN_REGEX = re.compile(r'''\s*(:?apply plugin:|id)\(?\s*['"](android|com\.android\.application)['"]\s*\)?''')

MAX_VERSION_CODE = 0x7fffffff  # Java's Integer.MAX_VALUE (2147483647)

XMLNS_ANDROID = '{http://schemas.android.com/apk/res/android}'

# https://docs.gitlab.com/ee/user/gitlab_com/#gitlab-pages
GITLAB_COM_PAGES_MAX_SIZE = 1000000000

# the names used for things that are configured per-repo
ANTIFEATURES_CONFIG_NAME = 'antiFeatures'
CATEGORIES_CONFIG_NAME = 'categories'
CONFIG_CONFIG_NAME = 'config'
MIRRORS_CONFIG_NAME = 'mirrors'
RELEASECHANNELS_CONFIG_NAME = "releaseChannels"
CONFIG_NAMES = (
    ANTIFEATURES_CONFIG_NAME,
    CATEGORIES_CONFIG_NAME,
    CONFIG_CONFIG_NAME,
    MIRRORS_CONFIG_NAME,
    RELEASECHANNELS_CONFIG_NAME,
)


config = None
options = None
env = None
orig_path = None


def get_default_cachedir():
    """Get a cachedir, using platformdirs for cross-platform, but works without.

    Once platformdirs is installed everywhere, this function can be
    removed.

    """
    appname = __name__.split('.')[0]
    try:
        import platformdirs

        return platformdirs.user_cache_dir(appname, 'F-Droid')
    except ImportError:
        return str(Path.home() / '.cache' / appname)


# All paths in the config must be strings, never pathlib.Path instances
default_config = {
    'sdk_path': "$ANDROID_HOME",
    'ndk_paths': {},
    'cachedir': get_default_cachedir(),
    'java_paths': None,
    'scan_binary': False,
    'ant': "ant",
    'mvn3': "mvn",
    'gradle': os.path.join(FDROID_PATH, 'gradlew-fdroid'),
    'sync_from_local_copy_dir': False,
    'allow_disabled_algorithms': False,
    'keep_when_not_allowed': False,
    'per_app_repos': False,
    'make_current_version_link': False,
    'current_version_name_source': 'Name',
    'deploy_process_logs': False,
    'repo_maxage': 0,
    'build_server_always': False,
    'keystore': 'keystore.p12',
    'smartcardoptions': [],
    'char_limits': {
        'author': 256,
        'name': 50,
        'summary': 80,
        'description': 4000,
        'video': 256,
        'whatsNew': 500,
    },
    'keyaliases': {},
    'repo_url': "https://MyFirstFDroidRepo.org/fdroid/repo",
    'repo_name': "My First F-Droid Repo Demo",
    'repo_icon': "icon.png",
    'repo_description': _("""This is a repository of apps to be used with F-Droid. Applications in this repository are either official binaries built by the original application developers, or are binaries built from source by the admin of f-droid.org using the tools on https://gitlab.com/fdroid."""),  # type: ignore
    'archive_name': 'My First F-Droid Archive Demo',
    'archive_description': _('These are the apps that have been archived from the main repo.'),  # type: ignore
    'archive_older': 0,
    'lint_licenses': fdroidserver.lint.APPROVED_LICENSES,  # type: ignore
    'git_mirror_size_limit': 10000000000,
    'scanner_signature_sources': ['suss'],
}


def get_options():
    """Return options as set up by parse_args().

    This provides an easy way to get the global instance without
    having to think about very confusing import and submodule
    visibility.  The code should be probably refactored so it does not
    need this.  If each individual option value was always passed to
    functions as args, for example.

    https://docs.python.org/3/reference/import.html#submodules

    """
    return fdroidserver.common.options


def parse_args(parser):
    """Call parser.parse_args(), store result in module-level variable and return it.

    This is needed to set up the copy of the options instance in the
    fdroidserver.common module.  A subcommand only needs to call this
    if it uses functions from fdroidserver.common that expect the
    "options" variable to be initialized.

    """
    fdroidserver.common.options = parser.parse_args()
    return fdroidserver.common.options


def setup_global_opts(parser):
    try:  # the buildserver VM might not have PIL installed
        from PIL import PngImagePlugin

        logger = logging.getLogger(PngImagePlugin.__name__)
        logger.setLevel(logging.INFO)  # tame the "STREAM" debug messages
    except ImportError:
        pass

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help=_("Spew out even more information than normal"),
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help=_("Restrict output to warnings and errors"),
    )
    parser.add_argument(
        "--color",
        action=BooleanOptionalAction,
        default=None,
        help=_("Color the log output"),
    )


class ColorFormatter(logging.Formatter):

    def __init__(self, msg):
        logging.Formatter.__init__(self, msg)

        bright_black = "\x1b[90;20m"
        yellow = "\x1b[33;20m"
        red = "\x1b[31;20m"
        bold_red = "\x1b[31;1m"
        reset = "\x1b[0m"

        self.FORMATS = {
            logging.DEBUG: bright_black + msg + reset,
            logging.INFO: reset + msg + reset,  # use default color
            logging.WARNING: yellow + msg + reset,
            logging.ERROR: red + msg + reset,
            logging.CRITICAL: bold_red + msg + reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def set_console_logging(verbose=False, color=False):
    """Globally set logging to output nicely to the console."""

    class _StdOutFilter(logging.Filter):
        def filter(self, record):
            return record.levelno < logging.ERROR

    if verbose:
        level = logging.DEBUG
    else:
        level = logging.ERROR

    if color or (color is None and sys.stdout.isatty()):
        formatter = ColorFormatter
    else:
        formatter = logging.Formatter

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.addFilter(_StdOutFilter())
    stdout_handler.setFormatter(formatter('%(message)s'))

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.ERROR)
    stderr_handler.setFormatter(formatter(_('ERROR: %(message)s')))

    logging.basicConfig(
        force=True, level=level, handlers=[stdout_handler, stderr_handler]
    )


def _add_java_paths_to_config(pathlist, thisconfig):
    def path_version_key(s):
        versionlist = []
        for u in re.split('[^0-9]+', s):
            try:
                versionlist.append(int(u))
            except ValueError:
                pass
        return versionlist

    for d in sorted(pathlist, key=path_version_key):
        if os.path.islink(d):
            continue
        j = os.path.basename(d)
        # the last one found will be the canonical one, so order appropriately
        for regex in [
                r'^1\.([126-9][0-9]?)\.0\.jdk$',  # OSX
                r'^jdk1\.([126-9][0-9]?)\.0_[0-9]+.jdk$',  # OSX and Oracle tarball
                r'^jdk1\.([126-9][0-9]?)\.0_[0-9]+$',  # Oracle Windows
                r'^jdk([126-9][0-9]?)-openjdk$',  # Arch
                r'^java-([126-9][0-9]?)-openjdk$',  # Arch
                r'^java-([126-9][0-9]?)-jdk$',  # Arch (oracle)
                r'^java-1\.([126-9][0-9]?)\.0-.*$',  # RedHat
                r'^java-([126-9][0-9]?)-oracle$',  # Debian WebUpd8
                r'^jdk-([126-9][0-9]?)-oracle-.*$',  # Debian make-jpkg
                r'^java-([126-9][0-9]?)-openjdk-.*$',  # Debian
                r'^oracle-jdk-bin-1\.([126-9][0-9]?).*$',  # Gentoo (oracle)
                r'^icedtea-bin-([126-9][0-9]?).*$',  # Gentoo (openjdk)
                ]:
            m = re.match(regex, j)
            if not m:
                continue
            for p in [d, os.path.join(d, 'Contents', 'Home')]:
                if os.path.exists(os.path.join(p, 'bin', 'javac')):
                    thisconfig['java_paths'][m.group(1)] = p


def fill_config_defaults(thisconfig):
    """Fill in the global config dict with relevant defaults.

    For config values that have a path that can be expanded, e.g. an
    env var or a ~/, this will store the original value using "_orig"
    appended to the key name so that if the config gets written out,
    it will preserve the original, unexpanded string.

    """
    for k, v in default_config.items():
        if k not in thisconfig:
            if isinstance(v, dict) or isinstance(v, list):
                thisconfig[k] = v.copy()
            else:
                thisconfig[k] = v

    # Expand paths (~users and $vars)
    def expand_path(path):
        if path is None:
            return None
        orig = path
        path = os.path.expanduser(path)
        path = os.path.expandvars(path)
        if orig == path:
            return None
        return path

    for k in ['sdk_path', 'ant', 'mvn3', 'gradle', 'keystore']:
        v = thisconfig[k]
        exp = expand_path(v)
        if exp is not None:
            thisconfig[k] = exp
            thisconfig[k + '_orig'] = v

    # find all installed JDKs for keytool, jarsigner, and JAVA[6-9]_HOME env vars
    if thisconfig['java_paths'] is None:
        thisconfig['java_paths'] = dict()
        pathlist = []
        pathlist += glob.glob('/usr/lib/jvm/j*[126-9]*')
        pathlist += glob.glob('/usr/java/jdk1.[126-9]*')
        pathlist += glob.glob('/System/Library/Java/JavaVirtualMachines/1.[126-9][0-9]?.0.jdk')
        pathlist += glob.glob('/Library/Java/JavaVirtualMachines/*jdk*[0-9]*')
        pathlist += glob.glob('/opt/oracle-jdk-*1.[0-9]*')
        pathlist += glob.glob('/opt/icedtea-*[0-9]*')
        if os.getenv('JAVA_HOME') is not None:
            pathlist.append(os.getenv('JAVA_HOME'))
        if os.getenv('PROGRAMFILES') is not None:
            pathlist += glob.glob(os.path.join(os.getenv('PROGRAMFILES'), 'Java', 'jdk1.[126-9][0-9]?.*'))
        _add_java_paths_to_config(pathlist, thisconfig)

    for java_version in range(29, 6, -1):
        java_version = str(java_version)
        if java_version not in thisconfig['java_paths']:
            continue
        java_home = thisconfig['java_paths'][java_version]
        jarsigner = os.path.join(java_home, 'bin', 'jarsigner')
        if os.path.exists(jarsigner):
            thisconfig['jarsigner'] = jarsigner
            thisconfig['keytool'] = os.path.join(java_home, 'bin', 'keytool')
            break

    if 'jarsigner' not in thisconfig and shutil.which('jarsigner'):
        thisconfig['jarsigner'] = shutil.which('jarsigner')
    if 'keytool' not in thisconfig and shutil.which('keytool'):
        thisconfig['keytool'] = shutil.which('keytool')

    # enable apksigner by default so v2/v3 APK signatures validate
    find_apksigner(thisconfig)
    if not thisconfig.get('apksigner'):
        logging.warning(_('apksigner not found! Cannot sign or verify modern APKs'))

    if 'ipfs_cid' not in thisconfig and shutil.which('ipfs_cid'):
        thisconfig['ipfs_cid'] = shutil.which('ipfs_cid')
    cmd = sys.argv[1] if len(sys.argv) >= 2 else ''
    if cmd == 'update' and not thisconfig.get('ipfs_cid'):
        logging.debug(_("ipfs_cid not found, skipping CIDv1 generation"))

    for k in ['ndk_paths', 'java_paths']:
        d = thisconfig[k]
        for k2 in d.copy():
            v = d[k2]
            exp = expand_path(v)
            if exp is not None:
                thisconfig[k][k2] = exp
                thisconfig[k][k2 + '_orig'] = v

    ndk_paths = thisconfig.get('ndk_paths', {})

    ndk_bundle = os.path.join(thisconfig['sdk_path'], 'ndk-bundle')
    if os.path.exists(ndk_bundle):
        version = get_ndk_version(ndk_bundle)
        if version not in ndk_paths:
            ndk_paths[version] = ndk_bundle

    ndk_dir = os.path.join(thisconfig['sdk_path'], 'ndk')
    if os.path.exists(ndk_dir):
        for ndk in glob.glob(os.path.join(ndk_dir, '*')):
            version = get_ndk_version(ndk)
            if version not in ndk_paths:
                ndk_paths[version] = ndk

    if 'cachedir_scanner' not in thisconfig:
        thisconfig['cachedir_scanner'] = str(Path(thisconfig['cachedir']) / 'scanner')
    if 'gradle_version_dir' not in thisconfig:
        thisconfig['gradle_version_dir'] = str(Path(thisconfig['cachedir']) / 'gradle')


def get_config():
    """Get the initalized, singleton config instance.

    config and options are intertwined in read_config(), so they have
    to be here too.  In the current ugly state of things, there are
    multiple potential instances of config and options in use:

    * global
    * module-level in the subcommand module (e.g. fdroidserver/build.py)
    * module-level in fdroidserver.common

    There are some insane parts of the code that are probably
    referring to multiple instances of these at different points.
    This can be super confusing and maddening.

    The current intermediate refactoring step is to move all
    subcommands to always get/set config and options via this function
    so that there is no longer a distinction between the global and
    module-level instances.  Then there can be only one module-level
    instance in fdroidserver.common.

    """
    global config

    if config is not None:
        return config

    read_config()

    # make sure these values are available in common.py even if they didn't
    # declare global in a scope
    common.config = config

    return config


def get_cachedir():
    cachedir = config and config.get('cachedir')
    if cachedir and os.path.exists(cachedir):
        return Path(cachedir)
    else:
        return Path(tempfile.mkdtemp())


def regsub_file(pattern, repl, path):
    with open(path, 'rb') as f:
        text = f.read()
    text = re.sub(bytes(pattern, 'utf8'), bytes(repl, 'utf8'), text)
    with open(path, 'wb') as f:
        f.write(text)


def config_type_check(path, data):
    if Path(path).name == 'mirrors.yml':
        expected_type = list
    else:
        expected_type = dict
    if expected_type == dict:
        if not isinstance(data, dict):
            msg = _('{path} is not "key: value" dict, but a {datatype}!')
            raise TypeError(msg.format(path=path, datatype=type(data).__name__))
    elif not isinstance(data, expected_type):
        msg = _('{path} is not {expected_type}, but a {datatype}!')
        raise TypeError(
            msg.format(
                path=path,
                expected_type=expected_type.__name__,
                datatype=type(data).__name__,
            )
        )


def read_config():
    """Read the repository config.

    The config is read from config_file, which is in the current
    directory when any of the repo management commands are used. If
    there is a local metadata file in the git repo, then the config is
    not required, just use defaults.

    config.yml is the preferred form because no code is executed when
    reading it.  config.py is deprecated and supported for backwards
    compatibility.

    config.yml requires ASCII or UTF-8 encoding because this code does
    not auto-detect the file's encoding.  That is left up to the YAML
    library.  YAML allows ASCII, UTF-8, UTF-16, and UTF-32 encodings.
    Since it is a good idea to manage config.yml (WITHOUT PASSWORDS!)
    in git, it makes sense to use a globally standard encoding.

    """
    global config

    if config is not None:
        return config

    config = {}
    config_file = 'config.yml'
    old_config_file = 'config.py'

    if os.path.exists(config_file) and os.path.exists(old_config_file):
        logging.error(_("""Conflicting config files! Using {newfile}, ignoring {oldfile}!""")
                      .format(oldfile=old_config_file, newfile=config_file))

    if os.path.exists(config_file):
        logging.debug(_("Reading '{config_file}'").format(config_file=config_file))
        with open(config_file, encoding='utf-8') as fp:
            config = yaml.safe_load(fp)
        if not config:
            config = {}
        config_type_check(config_file, config)
    elif os.path.exists(old_config_file):
        logging.warning(_("""{oldfile} is deprecated, use {newfile}""")
                        .format(oldfile=old_config_file, newfile=config_file))
        with io.open(old_config_file, "rb") as fp:
            code = compile(fp.read(), old_config_file, 'exec')
            exec(code, None, config)  # nosec TODO automatically migrate

        for k in ('mirrors', 'install_list', 'uninstall_list', 'serverwebroot', 'servergitroot'):
            if k in config:
                if not type(config[k]) in (str, list, tuple):
                    logging.warning(
                        _("'{field}' will be in random order! Use () or [] brackets if order is important!")
                        .format(field=k))

    # smartcardoptions must be a list since its command line args for Popen
    smartcardoptions = config.get('smartcardoptions')
    if isinstance(smartcardoptions, str):
        sco_items = re.sub(r'\s+', r' ', config['smartcardoptions']).split(' ')
        config['smartcardoptions'] = [i.strip() for i in sco_items if i]
    elif not smartcardoptions and 'keystore' in config and config['keystore'] == 'NONE':
        # keystore='NONE' means use smartcard, these are required defaults
        config['smartcardoptions'] = ['-storetype', 'PKCS11', '-providerName',
                                      'SunPKCS11-OpenSC', '-providerClass',
                                      'sun.security.pkcs11.SunPKCS11',
                                      '-providerArg', 'opensc-fdroid.cfg']

    if any(k in config for k in ["keystore", "keystorepass", "keypass"]):
        if os.path.exists(config_file):
            f = config_file
        elif os.path.exists(old_config_file):
            f = old_config_file
        st = os.stat(f)
        if st.st_mode & stat.S_IRWXG or st.st_mode & stat.S_IRWXO:
            logging.warning(_("unsafe permissions on '{config_file}' (should be 0600)!")
                            .format(config_file=f))

    fill_config_defaults(config)

    if 'serverwebroot' in config:
        roots = parse_mirrors_config(config['serverwebroot'])
        rootlist = []
        for d in roots:
            # since this is used with rsync, where trailing slashes have
            # meaning, ensure there is always a trailing slash
            rootstr = d['url']
            if rootstr[-1] != '/':
                rootstr += '/'
            d['url'] = rootstr.replace('//', '/')
            rootlist.append(d)
        config['serverwebroot'] = rootlist

    if 'servergitmirrors' in config:
        config['servergitmirrors'] = parse_mirrors_config(config['servergitmirrors'])

        limit = config['git_mirror_size_limit']
        config['git_mirror_size_limit'] = parse_human_readable_size(limit)

    if 'repo_url' in config:
        if not config['repo_url'].endswith('/repo'):
            raise FDroidException(_('repo_url needs to end with /repo'))

    if 'archive_url' in config:
        if not config['archive_url'].endswith('/archive'):
            raise FDroidException(_('archive_url needs to end with /archive'))

    confignames_to_delete = set()
    for configname, dictvalue in config.items():
        if configname == 'java_paths':
            new = dict()
            for k, v in dictvalue.items():
                new[str(k)] = v
            config[configname] = new
        elif configname in ('ndk_paths', 'java_paths', 'char_limits', 'keyaliases'):
            continue
        elif isinstance(dictvalue, dict):
            for k, v in dictvalue.items():
                if k == 'env':
                    env = os.getenv(v)
                    if env:
                        config[configname] = env
                    else:
                        confignames_to_delete.add(configname)
                        logging.error(_('Environment variable {var} from {configname} is not set!')
                                      .format(var=k, configname=configname))
                else:
                    confignames_to_delete.add(configname)
                    logging.error(_('Unknown entry {key} in {configname}')
                                  .format(key=k, configname=configname))

    for configname in confignames_to_delete:
        del config[configname]

    return config


def parse_mirrors_config(mirrors):
    """Mirrors can be specified as a string, list of strings, or dictionary map."""
    if isinstance(mirrors, str):
        return [{"url": mirrors}]
    elif all(isinstance(item, str) for item in mirrors):
        return [{'url': i} for i in mirrors]
    elif all(isinstance(item, dict) for item in mirrors):
        return mirrors
    else:
        raise TypeError(_('only accepts strings, lists, and tuples'))


def get_mirrors(url, filename=None):
    """Get list of dict entries for mirrors, appending filename if provided."""
    # TODO use cached index if it exists
    if isinstance(url, str):
        url = urlsplit(url)

    if url.netloc == 'f-droid.org':
        mirrors = FDROIDORG_MIRRORS
    else:
        mirrors = parse_mirrors_config(url.geturl())

    if filename:
        return append_filename_to_mirrors(filename, mirrors)
    else:
        return mirrors


def append_filename_to_mirrors(filename, mirrors):
    """Append the filename to all "url" entries in the mirrors dict."""
    appended = copy.deepcopy(mirrors)
    for mirror in appended:
        parsed = urlparse(mirror['url'])
        mirror['url'] = urlunparse(
            parsed._replace(path=os.path.join(parsed.path, filename))
        )
    return appended


def file_entry(filename, hash_value=None):
    meta = {}
    meta["name"] = "/" + Path(filename).as_posix().split("/", 1)[1]
    meta["sha256"] = hash_value or sha256sum(filename)
    meta["size"] = os.stat(filename).st_size
    return meta


def load_localized_config(name, repodir):
    """Load localized config files and put them into internal dict format.

    This will maintain the order as came from the data files, e.g
    YAML.  The locale comes from unsorted paths on the filesystem, so
    that is separately sorted.

    """
    ret = dict()
    found_config_file = False
    for f in Path().glob("config/**/{name}.yml".format(name=name)):
        found_config_file = True
        locale = f.parts[1]
        if len(f.parts) == 2:
            locale = DEFAULT_LOCALE
        with open(f, encoding="utf-8") as fp:
            elem = yaml.safe_load(fp)
            if not isinstance(elem, dict):
                msg = _('{path} is not "key: value" dict, but a {datatype}!')
                raise TypeError(msg.format(path=f, datatype=type(elem).__name__))
            for afname, field_dict in elem.items():
                if afname not in ret:
                    ret[afname] = dict()
                for key, value in field_dict.items():
                    if key not in ret[afname]:
                        ret[afname][key] = dict()
                    if key == "icon":
                        icons_dir = os.path.join(repodir, 'icons')
                        if not os.path.exists(icons_dir):
                            os.makedirs(icons_dir, exist_ok=True)
                        shutil.copy(os.path.join("config", value), icons_dir)
                        ret[afname][key][locale] = file_entry(
                            os.path.join(icons_dir, value)
                        )
                    else:
                        ret[afname][key][locale] = value

    if not found_config_file:
        for f in Path().glob("config/*.yml"):
            if f.stem not in CONFIG_NAMES:
                msg = _('{path} is not a standard config file!').format(path=f)
                m = difflib.get_close_matches(f.stem, CONFIG_NAMES, 1)
                if m:
                    msg += ' '
                    msg += _('Did you mean config/{name}.yml?').format(name=m[0])
                logging.error(msg)

    for elem in ret.values():
        for afname in elem:
            elem[afname] = {locale: v for locale, v in sorted(elem[afname].items())}
    return ret


def parse_human_readable_size(size):
    units = {
        'b': 1,
        'kb': 1000, 'mb': 1000**2, 'gb': 1000**3, 'tb': 1000**4,
        'kib': 1024, 'mib': 1024**2, 'gib': 1024**3, 'tib': 1024**4,
    }
    try:
        return int(float(size))
    except (ValueError, TypeError) as exc:
        if type(size) != str:
            raise ValueError(_('Could not parse size "{size}", wrong type "{type}"')
                             .format(size=size, type=type(size))) from exc
        s = size.lower().replace(' ', '')
        m = re.match(r'^(?P<value>[0-9][0-9.]*) *(?P<unit>' + r'|'.join(units.keys()) + r')$', s)
        if not m:
            raise ValueError(_('Not a valid size definition: "{}"').format(size)) from exc
        return int(float(m.group("value")) * units[m.group("unit")])


def get_dir_size(path_or_str):
    """Get the total size of all files in the given directory."""
    if isinstance(path_or_str, str):
        path_or_str = Path(path_or_str)
    return sum(f.stat().st_size for f in path_or_str.glob('**/*') if f.is_file())


def assert_config_keystore(config):
    """Check weather keystore is configured correctly and raise exception if not."""
    nosigningkey = False
    if 'repo_keyalias' not in config:
        nosigningkey = True
        logging.critical(_("'repo_keyalias' not found in config.yml!"))
    if 'keystore' not in config:
        nosigningkey = True
        logging.critical(_("'keystore' not found in config.yml!"))
    elif config['keystore'] == 'NONE':
        if not config.get('smartcardoptions'):
            nosigningkey = True
            logging.critical(_("'keystore' is NONE and 'smartcardoptions' is blank!"))
    elif not os.path.exists(config['keystore']):
        nosigningkey = True
        logging.critical("'" + config['keystore'] + "' does not exist!")
    if 'keystorepass' not in config:
        nosigningkey = True
        logging.critical(_("'keystorepass' not found in config.yml!"))
    if 'keypass' not in config and config.get('keystore') != 'NONE':
        nosigningkey = True
        logging.critical(_("'keypass' not found in config.yml!"))
    if nosigningkey:
        raise FDroidException("This command requires a signing key, "
                              + "you can create one using: fdroid update --create-key")


def find_apksigner(config):
    """Search for the best version apksigner and adds it to the config.

    Returns the best version of apksigner following this algorithm:

    * use config['apksigner'] if set
    * try to find apksigner in path
    * find apksigner in build-tools starting from newest installed
      going down to MINIMUM_APKSIGNER_BUILD_TOOLS_VERSION

    Returns
    -------
    str
        path to apksigner or None if no version is found

    """
    command = 'apksigner'
    if command in config:
        return

    tmp = find_command(command)
    if tmp is not None:
        config[command] = tmp
        return

    build_tools_path = os.path.join(config.get('sdk_path', ''), 'build-tools')
    if not os.path.isdir(build_tools_path):
        return
    for f in sorted(os.listdir(build_tools_path), reverse=True):
        if not os.path.isdir(os.path.join(build_tools_path, f)):
            continue
        try:
            if LooseVersion(f) < LooseVersion(MINIMUM_APKSIGNER_BUILD_TOOLS_VERSION):
                logging.debug("Local Android SDK only has outdated apksigner versions")
                return
        except TypeError:
            continue
        if os.path.exists(os.path.join(build_tools_path, f, 'apksigner')):
            apksigner = os.path.join(build_tools_path, f, 'apksigner')
            logging.info("Using %s " % apksigner)
            config['apksigner'] = apksigner
            return


def find_sdk_tools_cmd(cmd):
    """Find a working path to a tool from the Android SDK."""
    tooldirs = []
    if config is not None and 'sdk_path' in config and os.path.exists(config['sdk_path']):
        # try to find a working path to this command, in all the recent possible paths
        build_tools = os.path.join(config['sdk_path'], 'build-tools')
        if os.path.isdir(build_tools):
            for f in sorted(os.listdir(build_tools), reverse=True):
                if os.path.isdir(os.path.join(build_tools, f)):
                    tooldirs.append(os.path.join(build_tools, f))
        sdk_tools = os.path.join(config['sdk_path'], 'tools')
        if os.path.exists(sdk_tools):
            tooldirs.append(sdk_tools)
            tooldirs.append(os.path.join(sdk_tools, 'bin'))
        sdk_platform_tools = os.path.join(config['sdk_path'], 'platform-tools')
        if os.path.exists(sdk_platform_tools):
            tooldirs.append(sdk_platform_tools)
    sdk_build_tools = glob.glob(os.path.join(config['sdk_path'], 'build-tools', '*.*'))
    if sdk_build_tools:
        tooldirs.append(sorted(sdk_build_tools)[-1])  # use most recent version
    if os.path.exists('/usr/bin'):
        tooldirs.append('/usr/bin')
    for d in tooldirs:
        path = os.path.join(d, cmd)
        if not os.path.isfile(path):
            path += '.exe'
        if os.path.isfile(path):
            if cmd == 'aapt':
                test_aapt_version(path)
            return path
    # did not find the command, exit with error message
    test_sdk_exists(config)  # ignore result so None is never returned
    raise FDroidException(_("Android SDK tool {cmd} not found!").format(cmd=cmd))


def test_aapt_version(aapt):
    """Check whether the version of aapt is new enough."""
    output = subprocess.check_output([aapt, 'version'], universal_newlines=True)
    if output is None or output == '':
        logging.error(_("'{path}' failed to execute!").format(path=aapt))
    else:
        m = re.match(r'.*v([0-9]+)\.([0-9]+)[.-]?([0-9.-]*)', output)
        if m:
            major = m.group(1)
            minor = m.group(2)
            bugfix = m.group(3)
            # the Debian package has the version string like "v0.2-23.0.2"
            too_old = False
            if '.' in bugfix:
                if LooseVersion(bugfix) < LooseVersion(MINIMUM_AAPT_BUILD_TOOLS_VERSION):
                    too_old = True
            elif LooseVersion('.'.join((major, minor, bugfix))) < LooseVersion('0.2.4062713'):
                too_old = True
            if too_old:
                logging.warning(_("'{aapt}' is too old, fdroid requires build-tools-{version} or newer!")
                                .format(aapt=aapt, version=MINIMUM_AAPT_BUILD_TOOLS_VERSION))
        else:
            logging.warning(_('Unknown version of aapt, might cause problems: ') + output)


def test_sdk_exists(thisconfig):
    if 'sdk_path' not in thisconfig:
        # check the 'apksigner' value in the config to see if its new enough
        f = thisconfig.get('apksigner', '')
        if os.path.isfile(f):
            sdk_path = os.path.dirname(os.path.dirname(os.path.dirname(f)))
            tmpconfig = {'sdk_path': sdk_path}
            find_apksigner(tmpconfig)
            if os.path.exists(tmpconfig.get('apksigner', '')):
                return True
        logging.error(_("'sdk_path' not set in config.yml!"))
        return False
    if thisconfig['sdk_path'] == default_config['sdk_path']:
        logging.error(_('No Android SDK found!'))
        logging.error(_('You can use ANDROID_HOME to set the path to your SDK, i.e.:'))
        logging.error('\texport ANDROID_HOME=/opt/android-sdk')
        return False
    if not os.path.exists(thisconfig['sdk_path']):
        logging.critical(_("Android SDK path '{path}' does not exist!")
                         .format(path=thisconfig['sdk_path']))
        return False
    if not os.path.isdir(thisconfig['sdk_path']):
        logging.critical(_("Android SDK path '{path}' is not a directory!")
                         .format(path=thisconfig['sdk_path']))
        return False
    find_apksigner(thisconfig)
    if not os.path.exists(thisconfig.get('apksigner', '')):
        return False
    return True


def get_local_metadata_files():
    """Get any metadata files local to an app's source repo.

    This tries to ignore anything that does not count as app metdata,
    including emacs cruft ending in ~

    """
    return glob.glob('.fdroid.[a-jl-z]*[a-rt-z]')


def read_pkg_args(appid_versionCode_pairs, allow_version_codes=False):
    """No summary.

    Parameters
    ----------
    appids
        arguments in the form of multiple appid:[versionCode] strings

    Returns
    -------
    a dictionary with the set of vercodes specified for each package
    """
    vercodes = {}
    if not appid_versionCode_pairs:
        return vercodes

    error = False
    apk_regex = re.compile(r'_(\d+)\.apk$')
    for p in appid_versionCode_pairs:
        # Convert the apk name to a appid:versioncode pair
        p = apk_regex.sub(r':\1', p)
        if allow_version_codes and ':' in p:
            package, vercode = p.split(':')
            try:
                vercode = version_code_string_to_int(vercode)
            except ValueError as e:
                logging.error('"%s": %s' % (p, str(e)))
                error = True
        else:
            package, vercode = p, None
        if package not in vercodes:
            vercodes[package] = [vercode] if vercode else []
            continue
        elif vercode and vercode not in vercodes[package]:
            vercodes[package] += [vercode] if vercode else []

    if error:
        raise FDroidException(_("Found invalid versionCodes for some apps"))

    return vercodes


def get_metadata_files(vercodes):
    """
    Build a list of metadata files and raise an exception for invalid appids.

    Parameters
    ----------
    vercodes
        version codes as returned by read_pkg_args()

    Returns
    -------
    List
        a list of corresponding metadata/*.yml files
    """
    found_invalid = False
    metadatafiles = []
    for appid in vercodes.keys():
        f = Path('metadata') / ('%s.yml' % appid)
        if f.exists():
            metadatafiles.append(f)
        else:
            found_invalid = True
            logging.critical(_("No such package: %s") % appid)
    if found_invalid:
        raise FDroidException(_("Found invalid appids in arguments"))
    return metadatafiles


def read_app_args(appid_versionCode_pairs, allow_version_codes=False, sort_by_time=False):
    """Build a list of App instances for processing.

    On top of what read_pkg_args does, this returns the whole app
    metadata, but limiting the builds list to the builds matching the
    appid_versionCode_pairs and vercodes specified.  If no
    appid_versionCode_pairs are specified, then all App and Build instances are
    returned.

    """
    vercodes = read_pkg_args(appid_versionCode_pairs, allow_version_codes)
    allapps = fdroidserver.metadata.read_metadata(vercodes, sort_by_time)

    if not vercodes:
        return allapps

    apps = {}
    for appid, app in allapps.items():
        if appid in vercodes:
            apps[appid] = app

    if not apps:
        raise FDroidException(_("No packages specified"))

    error = False
    for appid, app in apps.items():
        vc = vercodes[appid]
        if not vc:
            continue
        app['Builds'] = [b for b in app.get('Builds', []) if b.versionCode in vc]
        if len(app.get('Builds', [])) != len(vercodes[appid]):
            error = True
            allvcs = [b.versionCode for b in app.get('Builds', [])]
            for v in vercodes[appid]:
                if v not in allvcs:
                    logging.critical(_("No such versionCode {versionCode} for app {appid}")
                                     .format(versionCode=v, appid=appid))

    if error:
        raise FDroidException(_("Found invalid versionCodes for some apps"))

    return apps


def get_extension(filename):
    """Get name and extension of filename, with extension always lower case."""
    base, ext = os.path.splitext(filename)
    if not ext:
        return base, ''
    return base, ext.lower()[1:]


publish_name_regex = re.compile(r"^(.+)_([0-9]+)\.(apk|zip)$")


def publishednameinfo(filename):
    filename = os.path.basename(filename)
    m = publish_name_regex.match(filename)
    try:
        result = (m.group(1), int(m.group(2)))
    except AttributeError as exc:
        raise FDroidException(_("Invalid name for published file: %s") % filename) from exc
    return result


apk_release_filename = re.compile(r'(?P<appid>[a-zA-Z0-9_\.]+)_(?P<vercode>[0-9]+)\.apk')
apk_release_filename_with_sigfp = re.compile(r'(?P<appid>[a-zA-Z0-9_\.]+)_(?P<vercode>[0-9]+)_(?P<sigfp>[0-9a-f]{7})\.apk')


def apk_parse_release_filename(apkname):
    """Parse the name of an APK file according the F-Droids APK naming scheme.

    WARNING: Returned values don't necessarily represent the APKs actual
    properties, the are just paresed from the file name.

    Returns
    -------
    Tuple
        A triplet containing (appid, versionCode, signer), where appid
        should be the package name, versionCode should be the integer
        represion of the APKs version and signer should be the first 7 hex
        digists of the sha256 signing key fingerprint which was used to sign
        this APK.
    """
    m = apk_release_filename_with_sigfp.match(apkname)
    if m:
        return m.group('appid'), int(m.group('vercode')), m.group('sigfp')
    m = apk_release_filename.match(apkname)
    if m:
        return m.group('appid'), int(m.group('vercode')), None
    return None, None, None


def get_release_filename(app, build, extension=None):
    if extension:
        return "%s_%s.%s" % (app.id, build.versionCode, extension)
    if build.output and get_file_extension(build.output):
        return "%s_%s.%s" % (app.id, build.versionCode, get_file_extension(build.output))
    else:
        return "%s_%s.apk" % (app.id, build.versionCode)


def get_toolsversion_logname(app, build):
    return "%s_%s_toolsversion.log" % (app.id, build.versionCode)


def getsrcname(app, build):
    return "%s_%s_src.tar.gz" % (app.id, build.versionCode)


def get_build_dir(app):
    """Get the dir that this app will be built in."""
    if app.RepoType == 'srclib':
        return Path('build/srclib') / app.Repo

    return Path('build') / app.id


class Encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return sorted(obj)
        return super().default(obj)


def setup_status_output(start_timestamp):
    """Create the common output dictionary for public status updates."""
    output = {
        'commandLine': sys.argv,
        'startTimestamp': int(time.mktime(start_timestamp) * 1000),
        'subcommand': sys.argv[0].split()[1],
    }
    if os.path.isdir('.git'):
        git_repo = git.repo.Repo(os.getcwd())
        output['fdroiddata'] = {
            'commitId': get_head_commit_id(git_repo),
            'isDirty': git_repo.is_dirty(),
            'modifiedFiles': git_repo.git().ls_files(modified=True).split(),
            'untrackedFiles': git_repo.untracked_files,
        }
    fdroidserver_dir = os.path.dirname(sys.argv[0])
    if os.path.isdir(os.path.join(fdroidserver_dir, '.git')):
        git_repo = git.repo.Repo(fdroidserver_dir)
        output['fdroidserver'] = {
            'commitId': get_head_commit_id(git_repo),
            'isDirty': git_repo.is_dirty(),
            'modifiedFiles': git_repo.git().ls_files(modified=True).split(),
            'untrackedFiles': git_repo.untracked_files,
        }
    etc_issue_net = '/etc/issue.net'
    if os.path.exists(etc_issue_net):
        with open(etc_issue_net) as fp:
            output[etc_issue_net] = fp.read(100).strip()
    write_running_status_json(output)
    return output


def write_running_status_json(output):
    write_status_json(output, pretty=True, name='running')


def write_status_json(output, pretty=False, name=None):
    """Write status out as JSON, and rsync it to the repo server."""
    status_dir = os.path.join('repo', 'status')
    if not os.path.exists(status_dir):
        os.makedirs(status_dir)
    if not name:
        output['endTimestamp'] = int(datetime.now(timezone.utc).timestamp() * 1000)
        names = ['running', sys.argv[0].split()[1]]  # fdroid subcommand
    else:
        names = [name]

    for fname in names:
        path = os.path.join(status_dir, fname + '.json')
        with open(path, "w", encoding="utf-8") as fp:
            if pretty:
                json.dump(output, fp, sort_keys=True, cls=Encoder, indent=2)
            else:
                json.dump(output, fp, sort_keys=True, cls=Encoder, separators=(',', ':'))
        rsync_status_file_to_repo(path, repo_subdir='status')


def get_head_commit_id(git_repo):
    """Get git commit ID for HEAD as a str."""
    try:
        return git_repo.head.commit.hexsha
    except ValueError:
        return "None"


def setup_vcs(app):
    """Checkout code from VCS and return instance of vcs and the build dir."""
    build_dir = get_build_dir(app)

    # Set up vcs interface and make sure we have the latest code...
    logging.debug("Getting {0} vcs interface for {1}"
                  .format(app.RepoType, app.Repo))
    if app.RepoType == 'git' and os.path.exists('.fdroid.yml'):
        remote = os.getcwd()
    else:
        remote = app.Repo
    vcs = getvcs(app.RepoType, remote, build_dir)

    return vcs, build_dir


def getvcs(vcstype, remote, local):
    """Return a vcs instance based on the arguments.

    remote and local can be either a string or a pathlib.Path

    """
    if vcstype == 'git':
        return vcs_git(remote, local)
    if vcstype == 'git-svn':
        return vcs_gitsvn(remote, local)
    if vcstype == 'hg':
        return vcs_hg(remote, local)
    if vcstype == 'bzr':
        return vcs_bzr(remote, local)
    if vcstype == 'srclib':
        if str(local) != os.path.join('build', 'srclib', str(remote)):
            raise VCSException("Error: srclib paths are hard-coded!")
        return getsrclib(remote, os.path.join('build', 'srclib'), raw=True)
    if vcstype == 'svn':
        raise VCSException("Deprecated vcs type 'svn' - please use 'git-svn' instead")
    raise VCSException("Invalid vcs type " + vcstype)


def getsrclibvcs(name):
    if name not in fdroidserver.metadata.srclibs:
        raise VCSException("Missing srclib " + name)
    return fdroidserver.metadata.srclibs[name]['RepoType']


class vcs:

    def __init__(self, remote, local):

        # svn, git-svn and bzr may require auth
        self.username = None
        if self.repotype() in ('git-svn', 'bzr'):
            if '@' in remote:
                if self.repotype == 'git-svn':
                    raise VCSException("Authentication is not supported for git-svn")
                self.username, remote = remote.split('@')
                if ':' not in self.username:
                    raise VCSException(_("Password required with username"))
                self.username, self.password = self.username.split(':')

        self.remote = remote
        self.local = local
        self.clone_failed = False
        self.refreshed = False
        self.srclib = None

    def _gettags(self):
        raise NotImplementedError

    def repotype(self):
        return None

    def clientversion(self):
        versionstr = FDroidPopen(self.clientversioncmd()).output
        return versionstr[0:versionstr.find('\n')]

    def clientversioncmd(self):
        return None

    def gotorevision(self, rev, refresh=True):
        """Take the local repository to a clean version of the given revision.

        Take the local repository to a clean version of the given
        revision, which is specificed in the VCS's native
        format. Beforehand, the repository can be dirty, or even
        non-existent. If the repository does already exist locally, it
        will be updated from the origin, but only once in the lifetime
        of the vcs object.  None is acceptable for 'rev' if you know
        you are cloning a clean copy of the repo - otherwise it must
        specify a valid revision.
        """
        if self.clone_failed:
            raise VCSException(_("Downloading the repository already failed once, not trying again."))

        # The .fdroidvcs-id file for a repo tells us what VCS type
        # and remote that directory was created from, allowing us to drop it
        # automatically if either of those things changes.
        fdpath = os.path.join(self.local, '..',
                              '.fdroidvcs-' + os.path.basename(self.local))
        fdpath = os.path.normpath(fdpath)
        cdata = self.repotype() + ' ' + self.remote
        writeback = True
        deleterepo = False
        if os.path.exists(self.local):
            if os.path.exists(fdpath):
                with open(fdpath, 'r') as f:
                    fsdata = f.read().strip()
                if fsdata == cdata:
                    writeback = False
                else:
                    deleterepo = True
                    logging.info("Repository details for %s changed - deleting" % (
                        self.local))
            else:
                deleterepo = True
                logging.info("Repository details for %s missing - deleting" % (
                    self.local))
        if deleterepo:
            shutil.rmtree(self.local)

        exc = None
        if not refresh:
            self.refreshed = True

        try:
            self.gotorevisionx(rev)
        except FDroidException as e:
            exc = e

        # If necessary, write the .fdroidvcs file.
        if writeback and not self.clone_failed:
            os.makedirs(os.path.dirname(fdpath), exist_ok=True)
            with open(fdpath, 'w+') as f:
                f.write(cdata)

        if exc is not None:
            raise exc

    def gotorevisionx(self, rev):  # pylint: disable=unused-argument
        """No summary.

        Derived classes need to implement this.

        It's called once basic checking has been performed.
        """
        raise VCSException("This VCS type doesn't define gotorevisionx")

    # Initialise and update submodules
    def initsubmodules(self):
        raise VCSException('Submodules not supported for this vcs type')

    # Deinitialise and update submodules
    def deinitsubmodules(self):
        pass

    # Get a list of all known tags
    def gettags(self):
        if not self._gettags:
            raise VCSException('gettags not supported for this vcs type')
        rtags = []
        for tag in self._gettags():
            if re.match('[-A-Za-z0-9_. /]+$', tag):
                rtags.append(tag)
        return rtags

    def latesttags(self):
        """Get a list of all the known tags, sorted from newest to oldest."""
        raise VCSException('latesttags not supported for this vcs type')

    def getref(self, revname=None):
        """Get current commit reference (hash, revision, etc)."""
        raise VCSException('getref not supported for this vcs type')

    def getsrclib(self):
        """Return the srclib (name, path) used in setting up the current revision, or None."""
        return self.srclib


class vcs_git(vcs):

    def repotype(self):
        return 'git'

    def clientversioncmd(self):
        return ['git', '--version']

    def git(self, args, envs=dict(), cwd=None, output=True):
        """Prevent git fetch/clone/submodule from hanging at the username/password prompt.

        While fetch/pull/clone respect the command line option flags,
        it seems that submodule commands do not.  They do seem to
        follow whatever is in env vars, if the version of git is new
        enough.  So we just throw the kitchen sink at it to see what
        sticks.

        Also, because of CVE-2017-1000117, block all SSH URLs.
        """
        #
        # supported in git >= 2.3
        git_config = [
            '-c', 'core.askpass=/bin/true',
            '-c', 'core.sshCommand=/bin/false',
            '-c', 'url.https://.insteadOf=ssh://',
        ]
        for domain in ('bitbucket.org', 'github.com', 'gitlab.com', 'codeberg.org'):
            git_config.append('-c')
            git_config.append('url.https://u:p@' + domain + '/.insteadOf=git@' + domain + ':')
            git_config.append('-c')
            git_config.append('url.https://u:p@' + domain + '.insteadOf=git://' + domain)
            git_config.append('-c')
            git_config.append('url.https://u:p@' + domain + '.insteadOf=https://' + domain)
        envs.update({
            'GIT_TERMINAL_PROMPT': '0',
            'GIT_ASKPASS': '/bin/true',
            'SSH_ASKPASS': '/bin/true',
            'GIT_SSH': '/bin/false',  # for git < 2.3
        })
        return FDroidPopen(['git', ] + git_config + args,
                           envs=envs, cwd=cwd, output=output)

    def checkrepo(self):
        """No summary.

        If the local directory exists, but is somehow not a git repository,
        git will traverse up the directory tree until it finds one
        that is (i.e.  fdroidserver) and then we'll proceed to destroy
        it!  This is called as a safety check.

        """
        p = FDroidPopen(['git', 'rev-parse', '--show-toplevel'], cwd=self.local, output=False)
        result = p.output.rstrip()
        if Path(result) != Path(self.local).resolve():
            raise VCSException('Repository mismatch')

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            # Brand new checkout
            p = self.git(['clone', '--', self.remote, str(self.local)])
            if p.returncode != 0:
                self.clone_failed = True
                raise VCSException("Git clone failed", p.output)
            self.checkrepo()
        else:
            self.checkrepo()
            # Discard any working tree changes
            p = FDroidPopen(['git', 'submodule', 'foreach', '--recursive',
                             'git', 'reset', '--hard'], cwd=self.local, output=False)
            if p.returncode != 0:
                logging.debug("Git submodule reset failed (ignored) {output}".format(output=p.output))
            p = FDroidPopen(['git', 'reset', '--hard'], cwd=self.local, output=False)
            if p.returncode != 0:
                raise VCSException(_("Git reset failed"), p.output)
            # Remove untracked files now, in case they're tracked in the target
            # revision (it happens!)
            p = FDroidPopen(['git', 'submodule', 'foreach', '--recursive',
                             'git', 'clean', '-dffx'], cwd=self.local, output=False)
            if p.returncode != 0:
                logging.debug("Git submodule cleanup failed (ignored) {output}".format(output=p.output))
            p = FDroidPopen(['git', 'clean', '-dffx'], cwd=self.local, output=False)
            if p.returncode != 0:
                raise VCSException(_("Git clean failed"), p.output)
            if not self.refreshed:
                # Get latest commits and tags from remote
                p = self.git(['fetch', '--prune', '--prune-tags', '--force', 'origin'], cwd=self.local)
                if p.returncode != 0:
                    raise VCSException(_("Git fetch failed"), p.output)
                p = self.git(['fetch', '--prune', '--tags', '--force', 'origin'], output=False, cwd=self.local)
                if p.returncode != 0:
                    raise VCSException(_("Git fetch failed"), p.output)
                # Recreate origin/HEAD as git clone would do it, in case it disappeared
                p = FDroidPopen(['git', 'remote', 'set-head', 'origin', '--auto'], cwd=self.local, output=False)
                if p.returncode != 0:
                    lines = p.output.splitlines()
                    if 'Multiple remote HEAD branches' not in lines[0]:
                        logging.warning(_("Git remote set-head failed: \"%s\"") % p.output.strip())
                    else:
                        branch = lines[1].split(' ')[-1]
                        p2 = FDroidPopen(['git', 'remote', 'set-head', 'origin', '--', branch],
                                         cwd=self.local, output=False)
                        if p2.returncode != 0:
                            logging.warning(_("Git remote set-head failed: \"%s\"")
                                            % p.output.strip() + '\n' + p2.output.strip())
                self.refreshed = True
        # origin/HEAD is the HEAD of the remote, e.g. the "default branch" on
        # a github repo. Most of the time this is the same as origin/master.
        rev = rev or 'origin/HEAD'
        p = FDroidPopen(['git', 'checkout', '-f', rev], cwd=self.local, output=False)
        if p.returncode != 0:
            raise VCSException(_("Git checkout of '%s' failed") % rev, p.output)
        # Get rid of any uncontrolled files left behind
        p = FDroidPopen(['git', 'clean', '-dffx'], cwd=self.local, output=False)
        if p.returncode != 0:
            raise VCSException(_("Git clean failed"), p.output)

    def initsubmodules(self):
        self.checkrepo()
        submfile = os.path.join(self.local, '.gitmodules')
        if not os.path.isfile(submfile):
            raise NoSubmodulesException(_("No git submodules available"))

        # fix submodules not accessible without an account and public key auth
        with open(submfile, 'r') as f:
            lines = f.readlines()
        with open(submfile, 'w') as f:
            for line in lines:
                for domain in ('bitbucket.org', 'github.com', 'gitlab.com'):
                    line = re.sub('git@' + domain + ':', 'https://u:p@' + domain + '/', line)
                f.write(line)

        p = FDroidPopen(['git', 'submodule', 'sync'], cwd=self.local, output=False)
        if p.returncode != 0:
            raise VCSException(_("Git submodule sync failed"), p.output)
        p = self.git(['submodule', 'update', '--init', '--force', '--recursive'], cwd=self.local)
        if p.returncode != 0:
            raise VCSException(_("Git submodule update failed"), p.output)

    def deinitsubmodules(self):
        self.checkrepo()
        p = FDroidPopen(['git', 'submodule', 'deinit', '--all', '--force'], cwd=self.local, output=False)
        if p.returncode != 0:
            raise VCSException(_("Git submodule deinit failed"), p.output)

    def _gettags(self):
        self.checkrepo()
        p = FDroidPopen(['git', 'tag'], cwd=self.local, output=False)
        return p.output.splitlines()

    def latesttags(self):
        """Return a list of latest tags."""
        self.checkrepo()
        return [tag.name for tag in sorted(
            git.Repo(self.local).tags,
            key=lambda t: t.commit.committed_date,
            reverse=True
        )]

    def getref(self, revname='HEAD'):
        self.checkrepo()
        repo = git.Repo(self.local)
        try:
            return repo.commit(revname).hexsha
        except git.BadName:
            return None


class vcs_gitsvn(vcs):

    def repotype(self):
        return 'git-svn'

    def clientversioncmd(self):
        return ['git', 'svn', '--version']

    def checkrepo(self):
        """No summary.

        If the local directory exists, but is somehow not a git repository,
        git will traverse up the directory tree until it finds one that
        is (i.e.  fdroidserver) and then we'll proceed to destory it!
        This is called as a safety check.

        """
        p = FDroidPopen(['git', 'rev-parse', '--show-toplevel'], cwd=self.local, output=False)
        result = p.output.rstrip()
        if Path(result) != Path(self.local).resolve():
            raise VCSException('Repository mismatch')

    def git(self, args, envs=dict(), cwd=None, output=True):
        """Prevent git fetch/clone/submodule from hanging at the username/password prompt.

        AskPass is set to /bin/true to let the process try to connect
        without a username/password.

        The SSH command is set to /bin/false to block all SSH URLs
        (supported in git >= 2.3).  This protects against
        CVE-2017-1000117.

        """
        git_config = [
            '-c', 'core.askpass=/bin/true',
            '-c', 'core.sshCommand=/bin/false',
        ]
        envs.update({
            'GIT_TERMINAL_PROMPT': '0',
            'GIT_ASKPASS': '/bin/true',
            'SSH_ASKPASS': '/bin/true',
            'GIT_SSH': '/bin/false',  # for git < 2.3
            'SVN_SSH': '/bin/false',
        })
        return FDroidPopen(['git', ] + git_config + args,
                           envs=envs, cwd=cwd, output=output)

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            # Brand new checkout
            gitsvn_args = ['svn', 'clone']
            remote = None
            if ';' in self.remote:
                remote_split = self.remote.split(';')
                for i in remote_split[1:]:
                    if i.startswith('trunk='):
                        gitsvn_args.extend(['-T', i[6:]])
                    elif i.startswith('tags='):
                        gitsvn_args.extend(['-t', i[5:]])
                    elif i.startswith('branches='):
                        gitsvn_args.extend(['-b', i[9:]])
                remote = remote_split[0]
            else:
                remote = self.remote

            if not remote.startswith('https://'):
                raise VCSException(_('HTTPS must be used with Subversion URLs!'))

            # git-svn sucks at certificate validation, this throws useful errors:
            try:
                import requests
                r = requests.head(remote, timeout=300)
                r.raise_for_status()
            except Exception as e:
                raise VCSException('SVN certificate pre-validation failed: ' + str(e)) from e
            location = r.headers.get('location')
            if location and not location.startswith('https://'):
                raise VCSException(_('Invalid redirect to non-HTTPS: {before} -> {after} ')
                                   .format(before=remote, after=location))

            gitsvn_args.extend(['--', remote, str(self.local)])
            p = self.git(gitsvn_args)
            if p.returncode != 0:
                self.clone_failed = True
                raise VCSException(_('git svn clone failed'), p.output)
            self.checkrepo()
        else:
            self.checkrepo()
            # Discard any working tree changes
            p = self.git(['reset', '--hard'], cwd=self.local, output=False)
            if p.returncode != 0:
                raise VCSException("Git reset failed", p.output)
            # Remove untracked files now, in case they're tracked in the target
            # revision (it happens!)
            p = self.git(['clean', '-dffx'], cwd=self.local, output=False)
            if p.returncode != 0:
                raise VCSException("Git clean failed", p.output)
            if not self.refreshed:
                # Get new commits, branches and tags from repo
                p = self.git(['svn', 'fetch'], cwd=self.local, output=False)
                if p.returncode != 0:
                    raise VCSException("Git svn fetch failed")
                p = self.git(['svn', 'rebase'], cwd=self.local, output=False)
                if p.returncode != 0:
                    raise VCSException("Git svn rebase failed", p.output)
                self.refreshed = True

        rev = rev or 'master'
        if rev:
            nospaces_rev = rev.replace(' ', '%20')
            # Try finding a svn tag
            for treeish in ['origin/', '']:
                p = self.git(['checkout', treeish + 'tags/' + nospaces_rev], cwd=self.local, output=False)
                if p.returncode == 0:
                    break
            if p.returncode != 0:
                # No tag found, normal svn rev translation
                # Translate svn rev into git format
                rev_split = rev.split('/')

                p = None
                for treeish in ['origin/', '']:
                    if len(rev_split) > 1:
                        treeish += rev_split[0]
                        svn_rev = rev_split[1]

                    else:
                        # if no branch is specified, then assume trunk (i.e. 'master' branch):
                        treeish += 'master'
                        svn_rev = rev

                    svn_rev = svn_rev if svn_rev[0] == 'r' else 'r' + svn_rev

                    p = self.git(['svn', 'find-rev', '--before', svn_rev, treeish], cwd=self.local, output=False)
                    git_rev = p.output.rstrip()

                    if p.returncode == 0 and git_rev:
                        break

                if p.returncode != 0 or not git_rev:
                    # Try a plain git checkout as a last resort
                    p = self.git(['checkout', rev], cwd=self.local, output=False)
                    if p.returncode != 0:
                        raise VCSException("No git treeish found and direct git checkout of '%s' failed" % rev, p.output)
                else:
                    # Check out the git rev equivalent to the svn rev
                    p = self.git(['checkout', git_rev], cwd=self.local, output=False)
                    if p.returncode != 0:
                        raise VCSException(_("Git checkout of '%s' failed") % rev, p.output)

        # Get rid of any uncontrolled files left behind
        p = self.git(['clean', '-dffx'], cwd=self.local, output=False)
        if p.returncode != 0:
            raise VCSException(_("Git clean failed"), p.output)

    def _gettags(self):
        self.checkrepo()
        for treeish in ['origin/', '']:
            d = os.path.join(self.local, '.git', 'svn', 'refs', 'remotes', treeish, 'tags')
            if os.path.isdir(d):
                return os.listdir(d)

    def getref(self, revname='HEAD'):
        self.checkrepo()
        p = FDroidPopen(['git', 'svn', 'find-rev', revname], cwd=self.local, output=False)
        if p.returncode != 0:
            return None
        return p.output.strip()


class vcs_hg(vcs):

    def repotype(self):
        return 'hg'

    def clientversioncmd(self):
        return ['hg', '--version']

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            p = FDroidPopen(['hg', 'clone', '--ssh', '/bin/false', '--', self.remote, str(self.local)],
                            output=False)
            if p.returncode != 0:
                self.clone_failed = True
                raise VCSException("Hg clone failed", p.output)
        else:
            p = FDroidPopen(['hg', 'status', '-uiS'], cwd=self.local, output=False)
            if p.returncode != 0:
                raise VCSException("Hg status failed", p.output)
            for line in p.output.splitlines():
                if not line.startswith('? ') and not line.startswith('I '):
                    raise VCSException("Unexpected output from hg status -uS: " + line)
                FDroidPopen(['rm', '-rf', '--', line[2:]], cwd=self.local, output=False)
            if not self.refreshed:
                p = FDroidPopen(['hg', 'pull', '--ssh', '/bin/false'], cwd=self.local, output=False)
                if p.returncode != 0:
                    raise VCSException("Hg pull failed", p.output)
                self.refreshed = True

        rev = rev or 'default'
        if not rev:
            return
        p = FDroidPopen(['hg', 'update', '-C', '--', rev], cwd=self.local, output=False)
        if p.returncode != 0:
            raise VCSException("Hg checkout of '%s' failed" % rev, p.output)

    def _gettags(self):
        p = FDroidPopen(['hg', 'tags', '-q'], cwd=self.local, output=False)
        return p.output.splitlines()[1:]


class vcs_bzr(vcs):

    def repotype(self):
        return 'bzr'

    def clientversioncmd(self):
        return ['bzr', '--version']

    def bzr(self, args, envs=dict(), cwd=None, output=True):
        """Prevent bzr from ever using SSH to avoid security vulns."""
        envs.update({
            'BZR_SSH': 'false',
        })
        return FDroidPopen(['bzr', ] + args, envs=envs, cwd=cwd, output=output)

    def gotorevisionx(self, rev):
        if not os.path.exists(self.local):
            p = self.bzr(['branch', self.remote, str(self.local)], output=False)
            if p.returncode != 0:
                self.clone_failed = True
                raise VCSException("Bzr branch failed", p.output)
        else:
            p = self.bzr(['clean-tree', '--force', '--unknown', '--ignored'], cwd=self.local, output=False)
            if p.returncode != 0:
                raise VCSException("Bzr revert failed", p.output)
            if not self.refreshed:
                p = self.bzr(['pull'], cwd=self.local, output=False)
                if p.returncode != 0:
                    raise VCSException("Bzr update failed", p.output)
                self.refreshed = True

        revargs = list(['-r', rev] if rev else [])
        p = self.bzr(['revert'] + revargs, cwd=self.local, output=False)
        if p.returncode != 0:
            raise VCSException("Bzr revert of '%s' failed" % rev, p.output)

    def _gettags(self):
        p = self.bzr(['tags'], cwd=self.local, output=False)
        return [tag.split('   ')[0].strip() for tag in
                p.output.splitlines()]


def unescape_string(string):
    if len(string) < 2:
        return string
    if string[0] == '"' and string[-1] == '"':
        return string[1:-1]

    return string.replace("\\'", "'")


def retrieve_string(app_dir, string, xmlfiles=None):

    if string.startswith('@string/'):
        name = string[len('@string/'):]
    elif string.startswith('${'):
        return ''  # Gradle variable
    else:
        return unescape_string(string)

    if xmlfiles is None:
        xmlfiles = []
        for res_dir in [
            os.path.join(app_dir, 'res'),
            os.path.join(app_dir, 'src', 'main', 'res'),
        ]:
            for root, dirs, files in os.walk(res_dir):
                if os.path.basename(root) == 'values':
                    xmlfiles += [os.path.join(root, x) for x in files if x.endswith('.xml')]

    def element_content(element):
        if element.text is None:
            return ""
        s = XMLElementTree.tostring(element, encoding='utf-8', method='text')
        return s.decode('utf-8').strip()

    for path in sorted(xmlfiles):
        if not os.path.isfile(path):
            continue
        try:
            xml = parse_xml(path)
        except (XMLElementTree.ParseError, ValueError):
            logging.warning(_("Problem with xml at '{path}'").format(path=path))
            continue
        element = xml.find('string[@name="' + name + '"]')
        if element is not None:
            content = element_content(element)
            return retrieve_string(app_dir, content, xmlfiles)

    return ''


def retrieve_string_singleline(app_dir, string, xmlfiles=None):
    return retrieve_string(app_dir, string, xmlfiles).replace('\n', ' ').strip()


def manifest_paths(app_dir, flavours):
    """Return list of existing files that will be used to find the highest vercode."""
    possible_manifests = \
        [Path(app_dir) / 'AndroidManifest.xml',
         Path(app_dir) / 'src/main/AndroidManifest.xml',
         Path(app_dir) / 'src/AndroidManifest.xml',
         Path(app_dir) / 'build.gradle',
         Path(app_dir) / 'build-extras.gradle',
         Path(app_dir) / 'build.gradle.kts']

    for flavour in flavours:
        if flavour == 'yes':
            continue
        possible_manifests.append(
            Path(app_dir) / 'src' / flavour / 'AndroidManifest.xml')

    return [path for path in possible_manifests if path.is_file()]


def fetch_real_name(app_dir, flavours):
    """Retrieve the package name. Returns the name, or None if not found."""
    for path in manifest_paths(app_dir, flavours):
        if not path.suffix == '.xml' or not path.is_file():
            continue
        logging.debug("fetch_real_name: Checking manifest at %s" % path)
        try:
            xml = parse_xml(path)
        except (XMLElementTree.ParseError, ValueError):
            logging.warning(_("Problem with xml at '{path}'").format(path=path))
            continue
        app = xml.find('application')
        if app is None:
            continue
        if XMLNS_ANDROID + "label" not in app.attrib:
            continue
        label = app.attrib[XMLNS_ANDROID + "label"]
        result = retrieve_string_singleline(app_dir, label)
        if result:
            result = result.strip()
        return result
    return None


def get_library_references(root_dir):
    libraries = []
    proppath = os.path.join(root_dir, 'project.properties')
    if not os.path.isfile(proppath):
        return libraries
    with open(proppath, 'r', encoding='iso-8859-1') as f:
        for line in f:
            if not line.startswith('android.library.reference.'):
                continue
            path = line.split('=')[1].strip()
            relpath = os.path.join(root_dir, path)
            if not os.path.isdir(relpath):
                continue
            logging.debug("Found subproject at %s" % path)
            libraries.append(path)
    return libraries


def ant_subprojects(root_dir):
    subprojects = get_library_references(root_dir)
    for subpath in subprojects:
        subrelpath = os.path.join(root_dir, subpath)
        for p in get_library_references(subrelpath):
            relp = os.path.normpath(os.path.join(subpath, p))
            if relp not in subprojects:
                subprojects.insert(0, relp)
    return subprojects


def remove_debuggable_flags(root_dir):
    # Remove forced debuggable flags
    logging.debug("Removing debuggable flags from %s" % root_dir)
    for root, dirs, files in os.walk(root_dir):
        if 'AndroidManifest.xml' in files and os.path.isfile(os.path.join(root, 'AndroidManifest.xml')):
            regsub_file(r'android:debuggable="[^"]*"',
                        '',
                        os.path.join(root, 'AndroidManifest.xml'))


vcsearch_g = re.compile(r'''\b[Vv]ersionCode\s*=?\s*["'(]*([0-9][0-9_]*)["')]*''').search
vnsearch_g = re.compile(r'''\b[Vv]ersionName\s*=?\s*\(?(["'])((?:(?=(\\?))\3.)*?)\1''').search
vnssearch_g = re.compile(r'''\b[Vv]ersionNameSuffix\s*=?\s*(["'])((?:(?=(\\?))\3.)*?)\1''').search
psearch_g = re.compile(r'''\b(packageName|applicationId|namespace)\s*=*\s*["']([^"']+)["']''').search
fsearch_g = re.compile(r'''\b(applicationIdSuffix)\s*=*\s*["']([^"']+)["']''').search


def app_matches_packagename(app, package):
    if not package:
        return False
    appid = app.UpdateCheckName or app.id
    if appid is None or appid == "Ignore":
        return True
    return appid == package


def parse_androidmanifests(paths, app):
    """Extract some information from the AndroidManifest.xml at the given path.

    Returns (version, vercode, package), any or all of which might be None.
    All values returned are strings.

    Android Studio recommends "you use UTF-8 encoding whenever possible", so
    this code assumes the files use UTF-8.
    https://sites.google.com/a/android.com/tools/knownissues/encoding
    """
    ignoreversions = app.UpdateCheckIgnore
    ignoresearch = re.compile(ignoreversions).search if ignoreversions else None

    if not paths:
        return (None, None, None)

    max_version = None
    max_vercode = None
    max_package = None

    def vnsearch(line):
        matches = vnsearch_g(line)
        if matches and not any(
            matches.group(2).startswith(s)
            for s in [
                '${',  # Gradle variable names
                '@string/',  # Strings we could not resolve
            ]
        ):
            return matches.group(2)
        return None

    for path in paths:
        if not path.is_file():
            continue

        logging.debug(_("Parsing manifest at '{path}'").format(path=path))
        version = None
        vercode = None
        package = None

        flavours = None
        temp_app_id = None
        temp_version_name = None
        if len(app.get('Builds', [])) > 0 and 'gradle' in app['Builds'][-1] and app['Builds'][-1].gradle:
            flavours = app['Builds'][-1].gradle

        if path.suffix == '.gradle' or path.name.endswith('.gradle.kts'):
            with open(path, 'r', encoding='utf-8') as f:
                android_plugin_file = False
                inside_flavour_group = 0
                inside_required_flavour = 0
                for line in f:
                    if gradle_comment.match(line):
                        continue

                    if "applicationId" in line and not temp_app_id:
                        matches = psearch_g(line)
                        if matches:
                            temp_app_id = matches.group(2)

                    if "versionName" in line and not temp_version_name:
                        matches = vnsearch(line)
                        if matches:
                            temp_version_name = matches

                    if inside_flavour_group > 0:
                        if inside_required_flavour > 1:
                            matches = psearch_g(line)
                            if matches:
                                s = matches.group(2)
                                if app_matches_packagename(app, s):
                                    package = s
                            else:
                                # If build.gradle contains applicationIdSuffix add it to the end of package name
                                matches = fsearch_g(line)
                                if matches and temp_app_id:
                                    suffix = matches.group(2)
                                    temp_app_id = temp_app_id + suffix
                                    if app_matches_packagename(app, temp_app_id):
                                        package = temp_app_id

                            matches = vnsearch(line)
                            if matches:
                                version = matches

                            else:
                                # If build.gradle contains applicationNameSuffix add it to the end of version name
                                matches = vnssearch_g(line)
                                if matches and temp_version_name:
                                    name_suffix = matches.group(2)
                                    version = temp_version_name + name_suffix

                            matches = vcsearch_g(line)
                            if matches:
                                vercode = version_code_string_to_int(matches.group(1))

                        if inside_required_flavour > 0:
                            if '{' in line:
                                inside_required_flavour += 1
                            if '}' in line:
                                inside_required_flavour -= 1
                                if inside_required_flavour == 1:
                                    inside_required_flavour -= 1
                        elif flavours:
                            for flavour in flavours:
                                if re.match(r'.*[\'"\s]{flavour}[\'"\s].*\{{.*'.format(flavour=flavour), line):
                                    inside_required_flavour = 2
                                    break
                                if re.match(r'.*[\'"\s]{flavour}[\'"\s].*'.format(flavour=flavour), line):
                                    inside_required_flavour = 1
                                    break

                        if '{' in line:
                            inside_flavour_group += 1
                        if '}' in line:
                            inside_flavour_group -= 1
                    else:
                        if "productFlavors" in line:
                            inside_flavour_group = 1
                        if not package:
                            matches = psearch_g(line)
                            if matches:
                                s = matches.group(2)
                                if app_matches_packagename(app, s):
                                    package = s
                        if not version:
                            matches = vnsearch(line)
                            if matches:
                                version = matches
                        if not vercode:
                            matches = vcsearch_g(line)
                            if matches:
                                vercode = version_code_string_to_int(matches.group(1))
                    if not android_plugin_file and ANDROID_PLUGIN_REGEX.match(line):
                        android_plugin_file = True
            if android_plugin_file:
                if package:
                    max_package = package
                if version:
                    max_version = version
                if vercode:
                    max_vercode = vercode
                if max_package and max_version and max_vercode:
                    break
        else:
            try:
                xml = parse_xml(path)
            except (XMLElementTree.ParseError, ValueError):
                logging.warning(_("Problem with xml at '{path}'").format(path=path))
                continue
            if "package" in xml.attrib:
                s = xml.attrib["package"]
                if app_matches_packagename(app, s):
                    package = s
            if XMLNS_ANDROID + "versionName" in xml.attrib:
                version = xml.attrib[XMLNS_ANDROID + "versionName"]
                base_dir = os.path.dirname(path)
                version = retrieve_string_singleline(base_dir, version)
            if XMLNS_ANDROID + "versionCode" in xml.attrib:
                vercode = version_code_string_to_int(
                    xml.attrib[XMLNS_ANDROID + "versionCode"])

        # Remember package name, may be defined separately from version+vercode
        if package is None:
            package = max_package

        logging.debug("..got package={0}, version={1}, vercode={2}"
                      .format(package, version, vercode))

        # Always grab the package name and version name in case they are not
        # together with the highest version code
        if max_package is None and package is not None:
            max_package = package
        if max_version is None and version is not None:
            max_version = version

        if vercode is not None \
           and (max_vercode is None or vercode > max_vercode):
            if version and (not ignoresearch or not ignoresearch(version)):
                if version is not None:
                    max_version = version
                if vercode is not None:
                    max_vercode = vercode
                if package is not None:
                    max_package = package
            else:
                max_version = "Ignore"

    if max_version is None:
        max_version = "Unknown"

    if max_package:
        msg = _("Invalid application ID {appid}").format(appid=max_package)
        if not is_valid_package_name(max_package):
            raise FDroidException(msg)
        elif not is_strict_application_id(max_package):
            logging.warning(msg)

    return (max_version, max_vercode, max_package)


def is_valid_package_name(name):
    """Check whether name is a valid fdroid package name.

    APKs and manually defined package names must use a valid Java
    Package Name.  Automatically generated package names for non-APK
    files use the SHA-256 sum.

    """
    return VALID_APPLICATION_ID_REGEX.match(name) is not None \
        or FDROID_PACKAGE_NAME_REGEX.match(name) is not None


def is_strict_application_id(name):
    """Check whether name is a valid Android Application ID.

    The Android ApplicationID is basically a Java Package Name, but
    with more restrictive naming rules:

    * It must have at least two segments (one or more dots).
    * Each segment must start with a letter.
    * All characters must be alphanumeric or an underscore [a-zA-Z0-9_].

    References
    ----------
    https://developer.android.com/studio/build/application-id

    """
    return STRICT_APPLICATION_ID_REGEX.match(name) is not None \
        and '.' in name


def parse_srclib_spec(spec):

    if type(spec) != str:
        raise MetaDataException(_("can not parse scrlib spec "
                                  "(not a string): '{}'")
                                .format(spec))

    tokens = spec.split('@', 1)
    if not tokens[0]:
        raise MetaDataException(
            _("could not parse srclib spec (no name specified): '{}'").format(spec)
        )
    if len(tokens) < 2 or not tokens[1]:
        raise MetaDataException(
            _("could not parse srclib spec (no ref specified): '{}'").format(spec)
        )

    name = tokens[0]
    ref = tokens[1]
    number = None
    subdir = None

    if ':' in name:
        number, name = name.split(':', 1)
    if '/' in name:
        name, subdir = name.split('/', 1)

    return (name, ref, number, subdir)


def getsrclib(spec, srclib_dir, basepath=False,
              raw=False, prepare=True, preponly=False, refresh=True,
              build=None):
    """Get the specified source library.

    Return the path to it. Normally this is the path to be used when
    referencing it, which may be a subdirectory of the actual project. If
    you want the base directory of the project, pass 'basepath=True'.

    spec and srclib_dir are both strings, not pathlib.Path.
    """
    number = None
    subdir = None
    if not isinstance(spec, str):
        spec = str(spec)
    if not isinstance(srclib_dir, str):
        spec = str(srclib_dir)
    if raw:
        name = spec
        ref = None
    else:
        name, ref, number, subdir = parse_srclib_spec(spec)

    if name not in fdroidserver.metadata.srclibs:
        raise VCSException('srclib ' + name + ' not found.')

    srclib = fdroidserver.metadata.srclibs[name]

    sdir = os.path.join(srclib_dir, name)

    if not preponly:
        vcs = getvcs(srclib["RepoType"], srclib["Repo"], sdir)
        vcs.srclib = (name, number, sdir)
        if ref:
            vcs.gotorevision(ref, refresh)

        if raw:
            return vcs

    libdir = None
    if subdir:
        libdir = os.path.join(sdir, subdir)
    elif srclib["Subdir"]:
        for subdir in srclib["Subdir"]:
            libdir_candidate = os.path.join(sdir, subdir)
            if os.path.exists(libdir_candidate):
                libdir = libdir_candidate
                break

    if libdir is None:
        libdir = sdir

    remove_signing_keys(sdir)
    remove_debuggable_flags(sdir)

    if prepare:

        if srclib["Prepare"]:
            cmd = replace_config_vars("; ".join(srclib["Prepare"]), build)

            p = FDroidPopen(['bash', '-e', '-u', '-o', 'pipefail', '-x', '-c', '--', cmd], cwd=libdir)
            if p.returncode != 0:
                raise BuildException("Error running prepare command for srclib %s"
                                     % name, p.output)

    if basepath:
        libdir = sdir

    return (name, number, libdir)


gradle_version_regex = re.compile(r"[^/]*'com\.android\.tools\.build:gradle:([^\.]+\.[^\.]+).*'.*")


def prepare_source(vcs, app, build, build_dir, srclib_dir, extlib_dir, onserver=False, refresh=True):
    """Prepare the source code for a particular build.

    Parameters
    ----------
    vcs
        the appropriate vcs object for the application
    app
        the application details from the metadata
    build
        the build details from the metadata
    build_dir
        the path to the build directory, usually 'build/app.id'
    srclib_dir
        the path to the source libraries directory, usually 'build/srclib'
    extlib_dir
        the path to the external libraries directory, usually 'build/extlib'

    Returns
    -------
    root
        is the root directory, which may be the same as 'build_dir' or may
        be a subdirectory of it.
    srclibpaths
        is information on the srclibs being used
    """
    # Optionally, the actual app source can be in a subdirectory
    if build.subdir:
        root_dir = os.path.join(build_dir, build.subdir)
    else:
        root_dir = build_dir

    # Get a working copy of the right revision
    logging.info("Getting source for revision " + build.commit)
    vcs.gotorevision(build.commit, refresh)

    # Initialise submodules if required
    if build.submodules:
        logging.info(_("Initialising submodules"))
        vcs.initsubmodules()
    else:
        vcs.deinitsubmodules()

    # Check that a subdir (if we're using one) exists. This has to happen
    # after the checkout, since it might not exist elsewhere
    if not os.path.exists(root_dir):
        raise BuildException('Missing subdir ' + root_dir)

    # Run an init command if one is required
    if build.init:
        cmd = replace_config_vars("; ".join(build.init), build)
        logging.info("Running 'init' commands in %s" % root_dir)

        p = FDroidPopen(['bash', '-e', '-u', '-o', 'pipefail', '-x', '-c', '--', cmd], cwd=root_dir)
        if p.returncode != 0:
            raise BuildException("Error running init command for %s:%s" %
                                 (app.id, build.versionName), p.output)

    # Apply patches if any
    if build.patch:
        logging.info("Applying patches")
        for patch in build.patch:
            patch = patch.strip()
            logging.info("Applying " + patch)
            patch_path = os.path.join('metadata', app.id, patch)
            p = FDroidPopen(['patch', '-p1', '-i', os.path.abspath(patch_path)], cwd=build_dir)
            if p.returncode != 0:
                raise BuildException("Failed to apply patch %s" % patch_path)

    # Get required source libraries
    srclibpaths = []
    if build.srclibs:
        logging.info("Collecting source libraries")
        for lib in build.srclibs:
            srclibpaths.append(getsrclib(lib, srclib_dir, preponly=onserver,
                                         refresh=refresh, build=build))

    for name, number, libpath in srclibpaths:
        place_srclib(root_dir, int(number) if number else None, libpath)

    basesrclib = vcs.getsrclib()
    # If one was used for the main source, add that too.
    if basesrclib:
        srclibpaths.append(basesrclib)

    # Update the local.properties file
    localprops = [os.path.join(build_dir, 'local.properties')]
    if build.subdir:
        parts = build.subdir.split(os.sep)
        cur = build_dir
        for d in parts:
            cur = os.path.join(cur, d)
            localprops += [os.path.join(cur, 'local.properties')]
    for path in localprops:
        props = ""
        if os.path.isfile(path):
            logging.info("Updating local.properties file at %s" % path)
            with open(path, 'r', encoding='iso-8859-1') as f:
                props += f.read()
            props += '\n'
        else:
            logging.info("Creating local.properties file at %s" % path)
        # Fix old-fashioned 'sdk-location' by copying
        # from sdk.dir, if necessary
        if build.oldsdkloc:
            sdkloc = re.match(r".*^sdk.dir=(\S+)$.*", props,
                              re.S | re.M).group(1)
            props += "sdk-location=%s\n" % sdkloc
        else:
            props += "sdk.dir=%s\n" % config['sdk_path']
            props += "sdk-location=%s\n" % config['sdk_path']
        ndk_path = build.ndk_path()
        # if for any reason the path isn't valid or the directory
        # doesn't exist, some versions of Gradle will error with a
        # cryptic message (even if the NDK is not even necessary).
        # https://gitlab.com/fdroid/fdroidserver/issues/171
        if ndk_path and os.path.exists(ndk_path):
            # Add ndk location
            props += "ndk.dir=%s\n" % ndk_path
            props += "ndk-location=%s\n" % ndk_path
        # Add java.encoding if necessary
        if build.encoding:
            props += "java.encoding=%s\n" % build.encoding
        with open(path, 'w', encoding='iso-8859-1') as f:
            f.write(props)

    flavours = []
    if build.build_method() == 'gradle':
        flavours = build.gradle

        if build.target:
            n = build.target.split('-')[1]
            build_gradle = os.path.join(root_dir, "build.gradle")
            build_gradle_kts = build_gradle + ".kts"
            if os.path.exists(build_gradle):
                gradlefile = build_gradle
            elif os.path.exists(build_gradle_kts):
                gradlefile = build_gradle_kts
            else:
                raise BuildException("No gradle file found")
            regsub_file(r'compileSdkVersion[ =]+[0-9]+',
                        r'compileSdkVersion %s' % n,
                        gradlefile)

    # Remove forced debuggable flags
    remove_debuggable_flags(root_dir)

    # Insert version code and number into the manifest if necessary
    if build.forceversion:
        logging.info("Changing the version name")
        for path in manifest_paths(root_dir, flavours):
            if not os.path.isfile(path):
                continue
            if path.suffix == '.xml':
                regsub_file(r'android:versionName="[^"]*"',
                            r'android:versionName="%s"' % build.versionName,
                            path)
            elif path.suffix == '.gradle':
                regsub_file(r"""(\s*)versionName[\s'"=]+.*""",
                            r"""\1versionName '%s'""" % build.versionName,
                            path)

    if build.forcevercode:
        logging.info("Changing the version code")
        for path in manifest_paths(root_dir, flavours):
            if not path.is_file():
                continue
            if path.suffix == '.xml':
                regsub_file(r'android:versionCode="[^"]*"',
                            r'android:versionCode="%s"' % build.versionCode,
                            path)
            elif path.suffix == '.gradle':
                regsub_file(r'versionCode[ =]+[0-9]+',
                            r'versionCode %s' % build.versionCode,
                            path)

    # Delete unwanted files
    if build.rm:
        logging.info(_("Removing specified files"))
        for part in getpaths(build_dir, build.rm):
            dest = os.path.join(build_dir, part)
            logging.info("Removing {0}".format(part))
            if os.path.lexists(dest):
                # rmtree can only handle directories that are not symlinks, so catch anything else
                if not os.path.isdir(dest) or os.path.islink(dest):
                    os.remove(dest)
                else:
                    shutil.rmtree(dest)
            else:
                logging.info("...but it didn't exist")

    remove_signing_keys(build_dir)

    # Add required external libraries
    if build.extlibs:
        logging.info("Collecting prebuilt libraries")
        libsdir = os.path.join(root_dir, 'libs')
        if not os.path.exists(libsdir):
            os.mkdir(libsdir)
        for lib in build.extlibs:
            lib = lib.strip()
            logging.info("...installing extlib {0}".format(lib))
            libf = os.path.basename(lib)
            libsrc = os.path.join(extlib_dir, lib)
            if not os.path.exists(libsrc):
                raise BuildException("Missing extlib file {0}".format(libsrc))
            shutil.copyfile(libsrc, os.path.join(libsdir, libf))
            # Add extlibs to scanignore (this is relative to the build dir root, *sigh*)
            if build.subdir:
                scanignorepath = os.path.join(build.subdir, 'libs', libf)
            else:
                scanignorepath = os.path.join('libs', libf)
            if scanignorepath not in build.scanignore:
                build.scanignore.append(scanignorepath)

    # Run a pre-build command if one is required
    if build.prebuild:
        logging.info("Running 'prebuild' commands in %s" % root_dir)

        cmd = replace_config_vars("; ".join(build.prebuild), build)

        # Substitute source library paths into prebuild commands
        for name, number, libpath in srclibpaths:
            cmd = cmd.replace('$$' + name + '$$', os.path.join(os.getcwd(), libpath))

        p = FDroidPopen(['bash', '-e', '-u', '-o', 'pipefail', '-x', '-c', '--', cmd], cwd=root_dir)
        if p.returncode != 0:
            raise BuildException("Error running prebuild command for %s:%s" %
                                 (app.id, build.versionName), p.output)

    # Generate (or update) the ant build file, build.xml...
    if build.build_method() == 'ant' and build.androidupdate != ['no']:
        parms = ['android', 'update', 'lib-project']
        lparms = ['android', 'update', 'project']

        if build.target:
            parms += ['-t', build.target]
            lparms += ['-t', build.target]
        if build.androidupdate:
            update_dirs = build.androidupdate
        else:
            update_dirs = ant_subprojects(root_dir) + ['.']

        for d in update_dirs:
            subdir = os.path.join(root_dir, d)
            if d == '.':
                logging.debug("Updating main project")
                cmd = parms + ['-p', d]
            else:
                logging.debug("Updating subproject %s" % d)
                cmd = lparms + ['-p', d]
            p = SdkToolsPopen(cmd, cwd=root_dir)
            # Check to see whether an error was returned without a proper exit
            # code (this is the case for the 'no target set or target invalid'
            # error)
            if p.returncode != 0 or p.output.startswith("Error: "):
                raise BuildException("Failed to update project at %s" % d, p.output)
            # Clean update dirs via ant
            if d != '.':
                logging.info("Cleaning subproject %s" % d)
                p = FDroidPopen(['ant', 'clean'], cwd=subdir)

    return (root_dir, srclibpaths)


def getpaths_map(build_dir, globpaths):
    """Extend via globbing the paths from a field and return them as a map from original path to resulting paths."""
    paths = dict()
    not_found_paths = []
    for p in globpaths:
        p = p.strip()
        full_path = os.path.join(build_dir, p)
        full_path = os.path.normpath(full_path)
        paths[p] = [r[len(str(build_dir)) + 1:] for r in glob.glob(full_path)]
        if not paths[p]:
            not_found_paths.append(p)
    if not_found_paths:
        raise FDroidException(
            "Some glob paths did not match any files/dirs:\n"
            + "\n".join(not_found_paths)
        )
    return paths


def getpaths(build_dir, globpaths):
    """Extend via globbing the paths from a field and return them as a set."""
    paths_map = getpaths_map(build_dir, globpaths)
    paths = set()
    for k, v in paths_map.items():
        for p in v:
            paths.add(p)
    return paths


def natural_key(s):
    return [int(sp) if sp.isdigit() else sp for sp in re.split(r'(\d+)', s)]


def check_system_clock(dt_obj, path):
    """Check if system clock is updated based on provided date.

    If an APK has files newer than the system time, suggest updating
    the system clock.  This is useful for offline systems, used for
    signing, which do not have another source of clock sync info. It
    has to be more than 24 hours newer because ZIP/APK files do not
    store timezone info

    """
    checkdt = dt_obj - timedelta(1)
    if datetime.today() < checkdt:
        logging.warning(_('System clock is older than date in {path}!').format(path=path)
                        + '\n' + _('Set clock to that time using:') + '\n'
                        + 'sudo date -s "' + str(dt_obj) + '"')


class KnownApks:
    """Permanent store of existing APKs with the date they were added.

    This is currently the only way to permanently store the "updated"
    date of APKs.
    """

    def __init__(self):
        """Load filename/date info about previously seen APKs.

        Since the appid and date strings both will never have spaces,
        this is parsed as a list from the end to allow the filename to
        have any combo of spaces.
        """
        self.apks = {}
        for part in ('repo', 'archive'):
            path = os.path.join(part, 'index-v2.json')
            if os.path.isfile(path):
                with open(path, 'r', encoding='utf-8') as f:
                    index = json.load(f)
                    for appid, data in index["packages"].items():
                        for version in data["versions"].values():
                            filename = version["file"]["name"][1:]
                            date = datetime.fromtimestamp(version["added"] // 1000, tz=timezone.utc)
                            self.apks[filename] = date

    def recordapk(self, apkName, default_date=None):
        """
        Record an APK (if it's new, otherwise does nothing).

        Returns
        -------
        datetime
          the date it was added as a datetime instance.
        """
        if apkName not in self.apks:
            if default_date is None:
                default_date = datetime.now(timezone.utc)
            self.apks[apkName] = default_date
        return self.apks[apkName]


def get_file_extension(filename):
    """Get the normalized file extension, can be blank string but never None."""
    if isinstance(filename, bytes):
        filename = filename.decode('utf-8')
    return os.path.splitext(filename)[1].lower()[1:]


def _androguard_logging_level(level=logging.ERROR):
    """Tames androguard's default debug output.

    There should be no debug output when the functions are being used
    via the API.  Otherwise, the output is controlled by the --verbose
    flag.

    To get coverage across the full range of androguard >= 3.3.5, this
    includes all known logger names that are relevant.  So some of
    these names might not be present in the version of androguard
    currently in use.

    """
    if options and options.verbose:
        level = logging.WARNING

    for name in (
        'androguard.apk',
        'androguard.axml',
        'androguard.core.api_specific_resources',
        'androguard.core.apk',
        'androguard.core.axml',
    ):
        logging.getLogger(name).setLevel(level)

    # some parts of androguard 4.x use loguru instead of logging
    try:
        from loguru import logger
        logger.remove()
    except ImportError:
        pass


def get_androguard_APK(apkfile, skip_analysis=False):
    try:
        # these were moved in androguard 4.0
        from androguard.core.apk import APK
    except ImportError:
        from androguard.core.bytecodes.apk import APK
    _androguard_logging_level()

    return APK(apkfile, skip_analysis=skip_analysis)


def ensure_final_value(packageName, arsc, value):
    """Ensure incoming value is always the value, not the resid.

    androguard will sometimes return the Android "resId" aka
    Resource ID instead of the actual value.  This checks whether
    the value is actually a resId, then performs the Android
    Resource lookup as needed.
    """
    if value:
        returnValue = value
        if value[0] == '@':
            try:  # can be a literal value or a resId
                res_id = int('0x' + value[1:], 16)
                res_id = arsc.get_id(packageName, res_id)[1]
                returnValue = arsc.get_string(packageName, res_id)[1]
            except (ValueError, TypeError):
                pass
        return returnValue
    return ''


def is_debuggable_or_testOnly(apkfile):
    """Return True if the given file is an APK and is debuggable or testOnly.

    These two settings should never be enabled in release builds. This
    parses <application android:debuggable="" android:testOnly="">
    from the APK and nothing else to run fast, since it is run on
    every APK as part of update.

    Parameters
    ----------
    apkfile
        full path to the APK to check

    """
    if get_file_extension(apkfile) != 'apk':
        return False
    try:
        # these were moved in androguard 4.0
        from androguard.core.axml import AXMLParser, format_value, START_TAG
    except ImportError:
        from androguard.core.bytecodes.axml import AXMLParser, format_value, START_TAG
    _androguard_logging_level()

    with ZipFile(apkfile) as apk:
        with apk.open('AndroidManifest.xml') as manifest:
            axml = AXMLParser(manifest.read())
            while axml.is_valid():
                _type = next(axml)
                if _type == START_TAG and axml.getName() == 'application':
                    for i in range(0, axml.getAttributeCount()):
                        name = axml.getAttributeName(i)
                        if name in ('debuggable', 'testOnly'):
                            _type = axml.getAttributeValueType(i)
                            _data = axml.getAttributeValueData(i)
                            value = format_value(_type, _data, lambda _: axml.getAttributeValue(i))
                            if value == 'true':
                                return True
                            else:
                                return False
                    break
    return False


def get_apk_id(apkfile):
    """Extract identification information from APK.

    Androguard is preferred since it is more reliable and a lot
    faster.  Occasionally, when androguard can't get the info from the
    APK, aapt still can.  So aapt is also used as the final fallback
    method.

    Parameters
    ----------
    apkfile
        path to an APK file.

    Returns
    -------
    appid
    version code
    version name

    """
    try:
        return get_apk_id_androguard(apkfile)
    except zipfile.BadZipFile as e:
        if config and 'aapt' in config:
            logging.error(apkfile + ': ' + str(e))
            return get_apk_id_aapt(apkfile)
        else:
            raise e


def get_apk_id_androguard(apkfile):
    """Read (appid, versionCode, versionName) from an APK.

    This first tries to do quick binary XML parsing to just get the
    values that are needed.  It will fallback to full androguard
    parsing, which is slow, if it can't find the versionName value or
    versionName is set to a Android String Resource (e.g. an integer
    hex value that starts with @).

    This function is part of androguard as get_apkid(), so this
    vendored and modified to return versionCode as an integer.

    """
    if not os.path.exists(apkfile):
        raise FDroidException(_("Reading packageName/versionCode/versionName failed, APK invalid: '{apkfilename}'")
                              .format(apkfilename=apkfile))

    try:
        # these were moved in androguard 4.0
        from androguard.core.axml import AXMLParser, format_value, START_TAG, END_TAG, TEXT, END_DOCUMENT
    except ImportError:
        from androguard.core.bytecodes.axml import AXMLParser, format_value, START_TAG, END_TAG, TEXT, END_DOCUMENT
    _androguard_logging_level()

    appid = None
    versionCode = None
    versionName = None
    with zipfile.ZipFile(apkfile) as apk:
        with apk.open('AndroidManifest.xml') as manifest:
            axml = AXMLParser(manifest.read())
            count = 0
            while axml.is_valid():
                _type = next(axml)
                count += 1
                if _type == START_TAG:
                    for i in range(0, axml.getAttributeCount()):
                        name = axml.getAttributeName(i)
                        _type = axml.getAttributeValueType(i)
                        _data = axml.getAttributeValueData(i)
                        value = format_value(_type, _data, lambda _: axml.getAttributeValue(i))
                        if appid is None and name == 'package':
                            appid = value
                        elif versionCode is None and name == 'versionCode':
                            if value.startswith('0x'):
                                versionCode = int(value, 16)
                            else:
                                versionCode = int(value)
                        elif versionName is None and name == 'versionName':
                            versionName = value

                    if axml.getName() == 'manifest':
                        break
                elif _type in (END_TAG, TEXT, END_DOCUMENT):
                    raise RuntimeError('{path}: <manifest> must be the first element in AndroidManifest.xml'
                                       .format(path=apkfile))

    if not versionName or versionName[0] == '@':
        a = get_androguard_APK(apkfile)
        versionName = ensure_final_value(a.package, a.get_android_resources(), a.get_androidversion_name())
    if not versionName:
        versionName = ''  # versionName is expected to always be a str

    return appid, versionCode, versionName.strip('\0')


def get_apk_id_aapt(apkfile):
    """Read (appid, versionCode, versionName) from an APK."""
    p = SdkToolsPopen(['aapt', 'dump', 'badging', apkfile], output=False)
    m = APK_ID_TRIPLET_REGEX.match(p.output[0:p.output.index('\n')])
    if m:
        return m.group(1), int(m.group(2)), m.group(3)
    raise FDroidException(_(
        "Reading packageName/versionCode/versionName failed,"
        "APK invalid: '{apkfilename}'"
    ).format(apkfilename=apkfile))


def get_native_code(apkfile):
    """Aapt checks if there are architecture folders under the lib/ folder.

    We are simulating the same behaviour.
    """
    arch_re = re.compile("^lib/(.*)/.*$")
    archset = set()
    with ZipFile(apkfile) as apk:
        for filename in apk.namelist():
            m = arch_re.match(filename)
            if m:
                archset.add(m.group(1))
    return sorted(list(archset))


class PopenResult:
    def __init__(self, returncode=None, output=None):
        self.returncode = returncode
        self.output = output


def SdkToolsPopen(commands, cwd=None, output=True):
    cmd = commands[0]
    if cmd not in config:
        config[cmd] = find_sdk_tools_cmd(commands[0])
    abscmd = config[cmd]
    if abscmd is None:
        raise FDroidException(_("Could not find '{command}' on your system").format(command=cmd))
    if cmd == 'aapt':
        test_aapt_version(config['aapt'])
    return FDroidPopen([abscmd] + commands[1:],
                       cwd=cwd, output=output)


def FDroidPopenBytes(commands, cwd=None, envs=None, output=True, stderr_to_stdout=True):
    """
    Run a command and capture the possibly huge output as bytes.

    Parameters
    ----------
    commands
        command and argument list like in subprocess.Popen
    cwd
        optionally specifies a working directory
    envs
        a optional dictionary of environment variables and their values

    Returns
    -------
    A PopenResult.
    """
    global env
    if env is None:
        set_FDroidPopen_env()

    process_env = env.copy()
    if envs is not None and len(envs) > 0:
        process_env.update(envs)

    if cwd:
        cwd = os.path.normpath(cwd)
        logging.debug("Directory: %s" % cwd)
    logging.debug("> %s" % ' '.join(commands))

    stderr_param = subprocess.STDOUT if stderr_to_stdout else subprocess.PIPE
    result = PopenResult()
    p = None
    try:
        p = subprocess.Popen(commands, cwd=cwd, shell=False, env=process_env,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=stderr_param)
    except OSError as e:
        raise BuildException("OSError while trying to execute "
                             + ' '.join(commands) + ': ' + str(e)) from e

    # TODO are these AsynchronousFileReader threads always exiting?
    if not stderr_to_stdout and options.verbose:
        stderr_queue = Queue()
        stderr_reader = AsynchronousFileReader(p.stderr, stderr_queue)

        while not stderr_reader.eof():
            while not stderr_queue.empty():
                line = stderr_queue.get()
                sys.stderr.buffer.write(line)
                sys.stderr.flush()

            time.sleep(0.1)

    stdout_queue = Queue()
    stdout_reader = AsynchronousFileReader(p.stdout, stdout_queue)
    buf = io.BytesIO()

    # Check the queue for output (until there is no more to get)
    while not stdout_reader.eof():
        while not stdout_queue.empty():
            line = stdout_queue.get()
            if output and options and options.verbose:
                # Output directly to console
                sys.stderr.buffer.write(line)
                sys.stderr.flush()
            buf.write(line)

        time.sleep(0.1)

    result.returncode = p.wait()
    result.output = buf.getvalue()
    buf.close()
    # make sure all filestreams of the subprocess are closed
    for streamvar in ['stdin', 'stdout', 'stderr']:
        if hasattr(p, streamvar):
            stream = getattr(p, streamvar)
            if stream:
                stream.close()
    return result


def FDroidPopen(commands, cwd=None, envs=None, output=True, stderr_to_stdout=True):
    """
    Run a command and capture the possibly huge output as a str.

    Parameters
    ----------
    commands
        command and argument list like in subprocess.Popen
    cwd
        optionally specifies a working directory
    envs
        a optional dictionary of environment variables and their values

    Returns
    -------
    A PopenResult.
    """
    result = FDroidPopenBytes(commands, cwd, envs, output, stderr_to_stdout)
    result.output = result.output.decode('utf-8', 'ignore')
    return result


gradle_comment = re.compile(r'[ ]*//')
gradle_signing_configs = re.compile(r'^[\t ]*signingConfigs[ \t]*{[ \t]*$')
gradle_line_matches = [
    re.compile(r'^[\t ]*signingConfig\s*[= ]\s*[^ ]*$'),
    re.compile(r'.*android\.signingConfigs\.[^{]*$'),
    re.compile(r'.*release\.signingConfig *= *'),
]


def remove_signing_keys(build_dir):
    for root, dirs, files in os.walk(build_dir):
        gradlefile = None
        if 'build.gradle' in files:
            gradlefile = "build.gradle"
        elif 'build.gradle.kts' in files:
            gradlefile = "build.gradle.kts"
        if gradlefile:
            path = os.path.join(root, gradlefile)
            with open(path, "r") as o:
                lines = o.readlines()

            changed = False

            opened = 0
            i = 0
            with open(path, "w") as o:
                while i < len(lines):
                    line = lines[i]
                    i += 1
                    while line.endswith('\\\n'):
                        line = line.rstrip('\\\n') + lines[i]
                        i += 1

                    if gradle_comment.match(line):
                        o.write(line)
                        continue

                    if opened > 0:
                        opened += line.count('{')
                        opened -= line.count('}')
                        continue

                    if gradle_signing_configs.match(line):
                        changed = True
                        opened += 1
                        continue

                    if any(s.match(line) for s in gradle_line_matches):
                        changed = True
                        continue

                    if opened == 0:
                        o.write(line)

            if changed:
                logging.info("Cleaned %s of keysigning configs at %s" % (gradlefile, path))

        for propfile in [
                'project.properties',
                'build.properties',
                'default.properties',
                'ant.properties', ]:
            if propfile in files:
                path = os.path.join(root, propfile)

                with open(path, "r", encoding='iso-8859-1') as o:
                    lines = o.readlines()

                changed = False

                with open(path, "w", encoding='iso-8859-1') as o:
                    for line in lines:
                        if any(line.startswith(s) for s in ('key.store', 'key.alias')):
                            changed = True
                            continue

                        o.write(line)

                if changed:
                    logging.info("Cleaned %s of keysigning configs at %s" % (propfile, path))


def set_FDroidPopen_env(build=None):
    """Set up the environment variables for the build environment.

    There is only a weak standard, the variables used by gradle, so also set
    up the most commonly used environment variables for SDK and NDK.  Also, if
    there is no locale set, this will set the locale (e.g. LANG) to en_US.UTF-8.
    """
    global env, orig_path

    if env is None:
        env = os.environ
        orig_path = env['PATH']
        if config:
            if config.get('sdk_path'):
                for n in ['ANDROID_HOME', 'ANDROID_SDK', 'ANDROID_SDK_ROOT']:
                    env[n] = config['sdk_path']
            for k, v in config.get('java_paths', {}).items():
                env['JAVA%s_HOME' % k] = v

    missinglocale = True
    for k, v in env.items():
        if k == 'LANG' and v != 'C':
            missinglocale = False
        elif k == 'LC_ALL':
            missinglocale = False
    if missinglocale:
        env['LANG'] = 'en_US.UTF-8'

    if build is not None:
        path = build.ndk_path()
        paths = orig_path.split(os.pathsep)
        if path and path not in paths:
            paths = [path] + paths
            env['PATH'] = os.pathsep.join(paths)
        for n in ['ANDROID_NDK', 'NDK', 'ANDROID_NDK_HOME']:
            env[n] = build.ndk_path()


def replace_build_vars(cmd, build):
    cmd = cmd.replace('$$COMMIT$$', build.commit)
    cmd = cmd.replace('$$VERSION$$', build.versionName)
    cmd = cmd.replace('$$VERCODE$$', str(build.versionCode))
    return cmd


def replace_config_vars(cmd, build):
    cmd = cmd.replace('$$SDK$$', config['sdk_path'])
    cmd = cmd.replace('$$NDK$$', build.ndk_path())
    if build is not None:
        cmd = replace_build_vars(cmd, build)
    return cmd


def place_srclib(root_dir, number, libpath):
    if not number:
        return
    relpath = os.path.relpath(libpath, root_dir)
    proppath = os.path.join(root_dir, 'project.properties')

    lines = []
    if os.path.isfile(proppath):
        with open(proppath, "r", encoding='iso-8859-1') as o:
            lines = o.readlines()

    with open(proppath, "w", encoding='iso-8859-1') as o:
        placed = False
        for line in lines:
            if line.startswith('android.library.reference.%d=' % number):
                o.write('android.library.reference.%d=%s\n' % (number, relpath))
                placed = True
            else:
                o.write(line)
        if not placed:
            o.write('android.library.reference.%d=%s\n' % (number, relpath))


APK_SIGNATURE_FILES = re.compile(r'META-INF/[0-9A-Za-z_\-]+\.(SF|RSA|DSA|EC)')


def signer_fingerprint_short(cert_encoded):
    """Obtain shortened sha256 signing-key fingerprint for pkcs7 DER certficate.

    Extracts the first 7 hexadecimal digits of sha256 signing-key fingerprint
    for a given pkcs7 signature.

    Parameters
    ----------
    cert_encoded
        Contents of an APK signing certificate.

    Returns
    -------
    shortened signing-key fingerprint.
    """
    return signer_fingerprint(cert_encoded)[:7]


def signer_fingerprint(cert_encoded):
    """Return SHA-256 signer fingerprint for PKCS#7 DER-encoded signature.

    Parameters
    ----------
    Contents of an APK signature.

    Returns
    -------
    Standard SHA-256 signer fingerprint.

    """
    return hashlib.sha256(cert_encoded).hexdigest()


def get_first_signer_certificate(apkpath):
    """Get the first signing certificate from the APK, DER-encoded.

    JAR and APK Signatures allow for multiple signers, though it is
    rarely used, and this is poorly documented.  So this method only
    fetches the first certificate, and errors out if there are more.

    Starting with targetSdkVersion 30, APK v2 Signatures are required.
    https://developer.android.com/about/versions/11/behavior-changes-11#minimum-signature-scheme

    When a APK v2+ signature is present, the JAR signature is not
    verified.  The verifier parses the signers from the v2+ signature
    and does not seem to look at the JAR signature.
    https://source.android.com/docs/security/features/apksigning/v2#apk-signature-scheme-v2-block
    https://android.googlesource.com/platform/tools/apksig/+/refs/tags/android-13.0.0_r3/src/main/java/com/android/apksig/ApkVerifier.java#270

    apksigner checks that the signers from all the APK signatures match:
    https://android.googlesource.com/platform/tools/apksig/+/refs/tags/android-13.0.0_r3/src/main/java/com/android/apksig/ApkVerifier.java#383

    apksigner verifies each signer's signature block file
    .(RSA|DSA|EC) against the corresponding signature file .SF
    https://android.googlesource.com/platform/tools/apksig/+/refs/tags/android-13.0.0_r3/src/main/java/com/android/apksig/internal/apk/v1/V1SchemeVerifier.java#280

    NoOverwriteDict is a workaround for:
    https://github.com/androguard/androguard/issues/1030

    Lots more discusion here:
    https://gitlab.com/fdroid/fdroidserver/-/issues/1128

    """

    class NoOverwriteDict(dict):
        def __setitem__(self, k, v):
            if k not in self:
                super().__setitem__(k, v)

    cert_encoded = None
    found_certs = []
    apkobject = get_androguard_APK(apkpath)
    apkobject._v2_blocks = NoOverwriteDict()
    certs_v3 = apkobject.get_certificates_der_v3()
    if certs_v3:
        cert_v3 = certs_v3[0]
        found_certs.append(cert_v3)
        if not cert_encoded:
            logging.debug(_('Using APK Signature v3'))
            cert_encoded = cert_v3

    certs_v2 = apkobject.get_certificates_der_v2()
    if certs_v2:
        cert_v2 = certs_v2[0]
        found_certs.append(cert_v2)
        if not cert_encoded:
            logging.debug(_('Using APK Signature v2'))
            cert_encoded = cert_v2

    if get_min_sdk_version(apkobject) < 24 or (
        not (certs_v3 or certs_v2) and get_effective_target_sdk_version(apkobject) < 30
    ):
        with zipfile.ZipFile(apkpath, 'r') as apk:
            cert_files = [
                n for n in apk.namelist() if SIGNATURE_BLOCK_FILE_REGEX.match(n)
            ]
            if len(cert_files) > 1:
                logging.error(
                    _("Found multiple JAR Signature Block Files in {path}").format(
                        path=apkpath
                    )
                )
                return
            elif len(cert_files) == 1:
                signature_block_file = cert_files[0]
                signature_file = (
                    cert_files[0][: signature_block_file.rindex('.')] + '.SF'
                )
                cert_v1 = get_certificate(
                    apk.read(signature_block_file),
                    apk.read(signature_file),
                )
                found_certs.append(cert_v1)
                if not cert_encoded:
                    logging.debug(_('Using JAR Signature'))
                    cert_encoded = cert_v1

    if not cert_encoded:
        logging.error(_("No signing certificates found in {path}").format(path=apkpath))
        return

    if not all(cert == found_certs[0] for cert in found_certs):
        logging.error(
            _("APK signatures have different certificates in {path}:").format(
                path=apkpath
            )
        )
        return

    return cert_encoded


def apk_signer_fingerprint(apk_path):
    """Get SHA-256 fingerprint string for the first signer from given APK.

    Parameters
    ----------
    apk_path
        path to APK

    Returns
    -------
    Standard SHA-256 signer fingerprint

    """
    cert_encoded = get_first_signer_certificate(apk_path)
    if not cert_encoded:
        return None
    return signer_fingerprint(cert_encoded)


def apk_signer_fingerprint_short(apk_path):
    """Get 7 hex digit SHA-256 fingerprint string for the first signer from given APK.

    Parameters
    ----------
    apk_path
        path to APK

    Returns
    -------
    first 7 chars of the standard SHA-256 signer fingerprint

    """
    return apk_signer_fingerprint(apk_path)[:7]


def metadata_get_sigdir(appid, vercode=None):
    """Get signature directory for app."""
    if vercode:
        return os.path.join('metadata', appid, 'signatures', str(vercode))
    else:
        return os.path.join('metadata', appid, 'signatures')


def metadata_find_developer_signature(appid, vercode=None):
    """Try to find the developer signature for given appid.

    This picks the first signature file found in metadata an returns its
    signature.

    Returns
    -------
    sha256 signing key fingerprint of the developer signing key.
    None in case no signature can not be found.
    """
    # fetch list of dirs for all versions of signatures
    appversigdirs = []
    if vercode:
        appversigdirs.append(metadata_get_sigdir(appid, vercode))
    else:
        appsigdir = metadata_get_sigdir(appid)
        if os.path.isdir(appsigdir):
            numre = re.compile('[0-9]+')
            for ver in os.listdir(appsigdir):
                if numre.match(ver):
                    appversigdir = os.path.join(appsigdir, ver)
                    appversigdirs.append(appversigdir)

    for sigdir in appversigdirs:
        signature_block_files = (
            glob.glob(os.path.join(sigdir, '*.DSA'))
            + glob.glob(os.path.join(sigdir, '*.EC'))
            + glob.glob(os.path.join(sigdir, '*.RSA'))
        )
        if len(signature_block_files) > 1:
            raise FDroidException('ambiguous signatures, please make sure there is only one signature in \'{}\'. (The signature has to be the App maintainers signature for version of the APK.)'.format(sigdir))
        for signature_block_file in signature_block_files:
            with open(signature_block_file, 'rb') as f:
                return signer_fingerprint(get_certificate(f.read()))
    return None


def metadata_find_signing_files(appid, vercode):
    """Get a list of signed manifests and signatures.

    Parameters
    ----------
    appid
        app id string
    vercode
        app version code

    Returns
    -------
    List
        of 4-tuples for each signing key with following paths:
        (signature_file, signature_block_file, manifest, v2_files), where v2_files
        is either a (apk_signing_block_offset_file, apk_signing_block_file) pair or None

    References
    ----------
    * https://docs.oracle.com/javase/tutorial/deployment/jar/intro.html
    * https://source.android.com/security/apksigning/v2
    * https://source.android.com/security/apksigning/v3
    """
    ret = []
    sigdir = metadata_get_sigdir(appid, vercode)
    signature_block_files = (
        glob.glob(os.path.join(sigdir, '*.DSA'))
        + glob.glob(os.path.join(sigdir, '*.EC'))
        + glob.glob(os.path.join(sigdir, '*.RSA'))
    )
    signature_block_pat = re.compile(r'(\.DSA|\.EC|\.RSA)$')
    apk_signing_block = os.path.join(sigdir, "APKSigningBlock")
    apk_signing_block_offset = os.path.join(sigdir, "APKSigningBlockOffset")
    if os.path.isfile(apk_signing_block) and os.path.isfile(apk_signing_block_offset):
        v2_files = apk_signing_block, apk_signing_block_offset
    else:
        v2_files = None
    for signature_block_file in signature_block_files:
        signature_file = signature_block_pat.sub('.SF', signature_block_file)
        if os.path.isfile(signature_file):
            manifest = os.path.join(sigdir, 'MANIFEST.MF')
            if os.path.isfile(manifest):
                ret.append((signature_block_file, signature_file, manifest, v2_files))
    return ret


def metadata_find_developer_signing_files(appid, vercode):
    """Get developer signature files for specified app from metadata.

    Returns
    -------
    List
        of 4-tuples for each signing key with following paths:
        (signature_file, signature_block_file, manifest, v2_files), where v2_files
        is either a (apk_signing_block_offset_file, apk_signing_block_file) pair or None

    """
    allsigningfiles = metadata_find_signing_files(appid, vercode)
    if allsigningfiles and len(allsigningfiles) == 1:
        return allsigningfiles[0]
    else:
        return None


class ClonedZipInfo(zipfile.ZipInfo):
    """Hack to allow fully cloning ZipInfo instances.

    The zipfile library has some bugs that prevent it from fully
    cloning ZipInfo entries.  https://bugs.python.org/issue43547

    """

    def __init__(self, zinfo):
        super().__init__()
        self.original = zinfo
        for k in self.__slots__:
            try:
                setattr(self, k, getattr(zinfo, k))
            except AttributeError:
                pass

    def __getattribute__(self, name):
        if name in ("date_time", "external_attr", "flag_bits"):
            return getattr(self.original, name)
        return object.__getattribute__(self, name)


def apk_has_v1_signatures(apkfile):
    """Test whether an APK has v1 signature files."""
    with ZipFile(apkfile, 'r') as apk:
        for info in apk.infolist():
            if APK_SIGNATURE_FILES.match(info.filename):
                return True
    return False


def apk_strip_v1_signatures(signed_apk, strip_manifest=False):
    """Remove signatures from APK.

    Parameters
    ----------
    signed_apk
        path to APK file.
    strip_manifest
        when set to True also the manifest file will be removed from the APK.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_apk = os.path.join(tmpdir, 'tmp.apk')
        shutil.move(signed_apk, tmp_apk)
        with ZipFile(tmp_apk, 'r') as in_apk:
            with ZipFile(signed_apk, 'w') as out_apk:
                for info in in_apk.infolist():
                    if not APK_SIGNATURE_FILES.match(info.filename):
                        if strip_manifest:
                            if info.filename != 'META-INF/MANIFEST.MF':
                                buf = in_apk.read(info.filename)
                                out_apk.writestr(ClonedZipInfo(info), buf)
                        else:
                            buf = in_apk.read(info.filename)
                            out_apk.writestr(ClonedZipInfo(info), buf)


def apk_implant_signatures(apkpath, outpath, manifest):
    """Implant a signature from metadata into an APK.

    Note: this changes there supplied APK in place. So copy it if you
    need the original to be preserved.

    Parameters
    ----------
    apkpath
        location of the unsigned apk
    outpath
        location of the output apk

    References
    ----------
    * https://docs.oracle.com/javase/tutorial/deployment/jar/intro.html
    * https://source.android.com/security/apksigning/v2
    * https://source.android.com/security/apksigning/v3

    """
    sigdir = os.path.dirname(manifest)  # FIXME
    apksigcopier.do_patch(sigdir, apkpath, outpath, v1_only=None,
                          exclude=apksigcopier.exclude_meta)


def apk_extract_signatures(apkpath, outdir):
    """Extract a signature files from APK and puts them into target directory.

    Parameters
    ----------
    apkpath
        location of the apk
    outdir
        older where the extracted signature files will be stored

    References
    ----------
    * https://docs.oracle.com/javase/tutorial/deployment/jar/intro.html
    * https://source.android.com/security/apksigning/v2
    * https://source.android.com/security/apksigning/v3

    """
    apksigcopier.do_extract(apkpath, outdir, v1_only=None)


def get_min_sdk_version(apk):
    """Wrap the androguard function to always return an integer.

    Fall back to 1 if we can't get a valid minsdk version.

    Parameters
    ----------
    apk
        androguard APK object

    Returns
    -------
    minSdkVersion: int
    """
    try:
        return int(apk.get_min_sdk_version())
    except TypeError:
        return 1


def get_effective_target_sdk_version(apk):
    """Wrap the androguard function to always return an integer.

    Parameters
    ----------
    apk
        androguard APK object

    Returns
    -------
    targetSdkVersion: int
    """
    try:
        return int(apk.get_effective_target_sdk_version())
    except TypeError:
        return get_min_sdk_version(apk)


def get_apksigner_smartcardoptions(smartcardoptions):
    if '-providerName' in smartcardoptions.copy():
        pos = smartcardoptions.index('-providerName')
        # remove -providerName and it's argument
        del smartcardoptions[pos]
        del smartcardoptions[pos]
    replacements = {'-storetype': '--ks-type',
                    '-providerClass': '--provider-class',
                    '-providerArg': '--provider-arg'}
    return [replacements.get(n, n) for n in smartcardoptions]


def sign_apk(unsigned_path, signed_path, keyalias):
    """Sign an unsigned APK, then save to a new file, deleting the unsigned.

    NONE is a Java keyword used to configure smartcards as the
    keystore.  Otherwise, the keystore is a local file.
    https://docs.oracle.com/javase/7/docs/technotes/guides/security/p11guide.html#KeyToolJarSigner

    When using smartcards, apksigner does not use the same options has
    Java/keytool/jarsigner (-providerName, -providerClass,
    -providerArg, -storetype).  apksigner documents the options as
    --ks-provider-class and --ks-provider-arg.  Those seem to be
    accepted but fail when actually making a signature with weird
    internal exceptions. We use the options that actually work.  From:
    https://geoffreymetais.github.io/code/key-signing/#scripting

    """
    if config['keystore'] == 'NONE':
        signing_args = get_apksigner_smartcardoptions(config['smartcardoptions'])
    else:
        signing_args = ['--key-pass', 'env:FDROID_KEY_PASS']
    apksigner = config.get('apksigner', '')
    if not shutil.which(apksigner):
        raise BuildException(_("apksigner not found, it's required for signing!"))
    cmd = [apksigner, 'sign',
           '--ks', config['keystore'],
           '--ks-pass', 'env:FDROID_KEY_STORE_PASS']
    cmd += signing_args
    cmd += ['--ks-key-alias', keyalias,
            '--in', unsigned_path,
            '--out', signed_path]
    p = FDroidPopen(cmd, envs={
        'FDROID_KEY_STORE_PASS': config['keystorepass'],
        'FDROID_KEY_PASS': config.get('keypass', "")})
    if p.returncode != 0:
        if os.path.exists(signed_path):
            os.remove(signed_path)
        raise BuildException(_("Failed to sign application"), p.output)
    os.remove(unsigned_path)


def verify_apks(signed_apk, unsigned_apk, tmp_dir, v1_only=None):
    """Verify that two apks are the same.

    One of the inputs is signed, the other is unsigned. The signature metadata
    is transferred from the signed to the unsigned apk, and then apksigner is
    used to verify that the signature from the signed APK is also valid for
    the unsigned one.  If the APK given as unsigned actually does have a
    signature, it will be stripped out and ignored.

    Parameters
    ----------
    signed_apk
        Path to a signed APK file
    unsigned_apk
        Path to an unsigned APK file expected to match it
    tmp_dir
        Path to directory for temporary files
    v1_only
        True for v1-only signatures, False for v1 and v2 signatures,
        or None for autodetection

    Returns
    -------
    None if the verification is successful, otherwise a string describing what went wrong.
    """
    if not verify_apk_signature(signed_apk):
        logging.info('...NOT verified - {0}'.format(signed_apk))
        return 'verification of signed APK failed'

    if not os.path.isfile(signed_apk):
        return 'can not verify: file does not exists: {}'.format(signed_apk)
    if not os.path.isfile(unsigned_apk):
        return 'can not verify: file does not exists: {}'.format(unsigned_apk)

    tmp_apk = os.path.join(tmp_dir, 'sigcp_' + os.path.basename(unsigned_apk))

    try:
        apksigcopier.do_copy(signed_apk, unsigned_apk, tmp_apk, v1_only=v1_only,
                             exclude=apksigcopier.exclude_meta)
    except apksigcopier.APKSigCopierError as e:
        logging.info('...NOT verified - {0}'.format(tmp_apk))
        error = 'signature copying failed: {}'.format(str(e))
        result = compare_apks(signed_apk, unsigned_apk, tmp_dir,
                              os.path.dirname(unsigned_apk))
        if result is not None:
            error += '\nComparing reference APK to unsigned APK...\n' + result
        return error

    if not verify_apk_signature(tmp_apk):
        logging.info('...NOT verified - {0}'.format(tmp_apk))
        error = 'verification of APK with copied signature failed'
        result = compare_apks(signed_apk, tmp_apk, tmp_dir,
                              os.path.dirname(unsigned_apk))
        if result is not None:
            error += '\nComparing reference APK to APK with copied signature...\n' + result
        return error

    logging.info('...successfully verified')
    return None


def verify_jar_signature(jar):
    """Verify the signature of a given JAR file.

    jarsigner is very shitty: unsigned JARs pass as "verified"! So
    this has to turn on -strict then check for result 4, since this
    does not expect the signature to be from a CA-signed certificate.

    Raises
    ------
    VerificationException
        If the JAR's signature could not be verified.

    """
    error = _('JAR signature failed to verify: {path}').format(path=jar)
    try:
        output = subprocess.check_output(
            [config['jarsigner'], '-strict', '-verify', jar], stderr=subprocess.STDOUT
        )
        raise VerificationException(error + '\n' + output.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        if e.returncode == 4:
            logging.debug(_('JAR signature verified: {path}').format(path=jar))
        else:
            raise VerificationException(error + '\n' + e.output.decode('utf-8')) from e


def verify_deprecated_jar_signature(jar):
    """Verify the signature of a given JAR file, allowing deprecated algorithms.

    index.jar (v0) and index-v1.jar are both signed by MD5/SHA1 by
    definition, so this method provides a way to verify those.  Also,
    apksigner has different deprecation rules than jarsigner, so this
    is our current hack to try to represent the apksigner rules when
    executing jarsigner.

    jarsigner is very shitty: unsigned JARs pass as "verified"! So
    this has to turn on -strict then check for result 4, since this
    does not expect the signature to be from a CA-signed certificate.

    Also used to verify the signature on an archived APK, supporting deprecated
    algorithms.

    F-Droid aims to keep every single binary that it ever published.  Therefore,
    it needs to be able to verify APK signatures that include deprecated/removed
    algorithms.  For example, jarsigner treats an MD5 signature as unsigned.

    jarsigner passes unsigned APKs as "verified"! So this has to turn
    on -strict then check for result 4.

    Just to be safe, this never reuses the file, and locks down the
    file permissions while in use.  That should prevent a bad actor
    from changing the settings during operation.

    Raises
    ------
    VerificationException
        If the JAR's signature could not be verified.

    """
    error = _('JAR signature failed to verify: {path}').format(path=jar)
    with tempfile.TemporaryDirectory() as tmpdir:
        java_security = os.path.join(tmpdir, 'java.security')
        with open(java_security, 'w') as fp:
            fp.write('jdk.jar.disabledAlgorithms=MD2, RSA keySize < 1024')
        os.chmod(java_security, 0o400)

        try:
            cmd = [
                config['jarsigner'],
                '-J-Djava.security.properties=' + java_security,
                '-strict', '-verify', jar
            ]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            raise VerificationException(error + '\n' + output.decode('utf-8'))
        except subprocess.CalledProcessError as e:
            if e.returncode == 4:
                logging.debug(_('JAR signature verified: {path}').format(path=jar))
            else:
                raise VerificationException(error + '\n' + e.output.decode('utf-8')) from e


def verify_apk_signature(apk, min_sdk_version=None):
    """Verify the signature on an APK.

    Try to use apksigner whenever possible since jarsigner is very
    shitty: unsigned APKs pass as "verified"!  Warning, this does
    not work on JARs with apksigner >= 0.7 (build-tools 26.0.1)

    Returns
    -------
    Boolean
        whether the APK was verified
    """
    if set_command_in_config('apksigner'):
        args = [config['apksigner'], 'verify']
        if min_sdk_version:
            args += ['--min-sdk-version=' + min_sdk_version]
        if options.verbose:
            args += ['--verbose']
        try:
            output = subprocess.check_output(args + [apk])
            if options.verbose:
                logging.debug(apk + ': ' + output.decode('utf-8'))
            return True
        except subprocess.CalledProcessError as e:
            logging.error('\n' + apk + ': ' + e.output.decode('utf-8'))
    else:
        if not config.get('jarsigner_warning_displayed'):
            config['jarsigner_warning_displayed'] = True
            logging.warning(_("Using Java's jarsigner, not recommended for verifying APKs! Use apksigner"))
        try:
            verify_deprecated_jar_signature(apk)
            return True
        except Exception as e:
            logging.error(e)
    return False


apk_badchars = re.compile('''[/ :;'"]''')


def compare_apks(apk1, apk2, tmp_dir, log_dir=None):
    """Compare two apks.

    Returns
    -------
    None if the APK content is the same (apart from the signing key),
    otherwise a string describing what's different, or what went wrong when
    trying to do the comparison.
    """
    if not log_dir:
        log_dir = tmp_dir

    absapk1 = os.path.abspath(apk1)
    absapk2 = os.path.abspath(apk2)

    if set_command_in_config('diffoscope'):
        logfilename = os.path.join(log_dir, os.path.basename(absapk1))
        htmlfile = logfilename + '.diffoscope.html'
        textfile = logfilename + '.diffoscope.txt'
        if subprocess.call([config['diffoscope'],
                            '--max-report-size', '12345678', '--max-diff-block-lines', '128',
                            '--html', htmlfile, '--text', textfile,
                            absapk1, absapk2]) != 0:
            return "Failed to run diffoscope " + apk1

    apk1dir = os.path.join(tmp_dir, apk_badchars.sub('_', apk1[0:-4]))  # trim .apk
    apk2dir = os.path.join(tmp_dir, apk_badchars.sub('_', apk2[0:-4]))  # trim .apk
    for d in [apk1dir, apk2dir]:
        if os.path.exists(d):
            shutil.rmtree(d)
        os.mkdir(d)
        os.mkdir(os.path.join(d, 'content'))

    # extract APK contents for comparision
    with ZipFile(absapk1, 'r') as f:
        f.extractall(path=os.path.join(apk1dir, 'content'))
    with ZipFile(absapk2, 'r') as f:
        f.extractall(path=os.path.join(apk2dir, 'content'))

    if set_command_in_config('apktool'):
        if subprocess.call([config['apktool'], 'd', absapk1, '--output', 'apktool'],
                           cwd=apk1dir) != 0:
            return "Failed to run apktool " + apk1
        if subprocess.call([config['apktool'], 'd', absapk2, '--output', 'apktool'],
                           cwd=apk2dir) != 0:
            return "Failed to run apktool " + apk2

    p = FDroidPopen(['diff', '-r', apk1dir, apk2dir], output=False)
    lines = p.output.splitlines()
    if len(lines) != 1 or 'META-INF' not in lines[0]:
        if set_command_in_config('meld'):
            p = FDroidPopen([config['meld'], apk1dir, apk2dir], output=False)
        return "Unexpected diff output:\n" + p.output.replace("\r", "^M")

    # since everything verifies, delete the comparison to keep cruft down
    shutil.rmtree(apk1dir)
    shutil.rmtree(apk2dir)

    # If we get here, it seems like they're the same!
    return None


def set_command_in_config(command):
    """Try to find specified command in the path, if it hasn't been manually set in config.yml.

    If found, it is added to the config
    dict.  The return value says whether the command is available.

    """
    if command in config:
        return True
    else:
        tmp = find_command(command)
        if tmp is not None:
            config[command] = tmp
            return True
    return False


def find_command(command):
    """Find the full path of a command, or None if it can't be found in the PATH."""
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(command)
    if fpath:
        if is_exe(command):
            return command
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, command)
            if is_exe(exe_file):
                return exe_file

    return None


def genpassword():
    """Generate a random password for when generating keys."""
    h = hashlib.sha256()
    h.update(os.urandom(16))  # salt
    h.update(socket.getfqdn().encode('utf-8'))
    passwd = base64.b64encode(h.digest()).strip()
    return passwd.decode('utf-8')


def genkeystore(localconfig):
    """Generate a new key with password provided in localconfig and add it to new keystore.

    Parameters
    ----------
    localconfig

    Returns
    -------
    hexed public key, public key fingerprint
    """
    logging.info('Generating a new key in "' + localconfig['keystore'] + '"...')
    keystoredir = os.path.dirname(localconfig['keystore'])
    if keystoredir is None or keystoredir == '':
        keystoredir = os.path.join(os.getcwd(), keystoredir)
    if not os.path.exists(keystoredir):
        os.makedirs(keystoredir, mode=0o700)

    env_vars = {'LC_ALL': 'C.UTF-8',
                'FDROID_KEY_STORE_PASS': localconfig['keystorepass'],
                'FDROID_KEY_PASS': localconfig.get('keypass', "")}

    cmd = [config['keytool'], '-genkey',
           '-keystore', localconfig['keystore'],
           '-alias', localconfig['repo_keyalias'],
           '-keyalg', 'RSA', '-keysize', '4096',
           '-sigalg', 'SHA256withRSA',
           '-validity', '10000',
           '-storetype', 'pkcs12',
           '-storepass:env', 'FDROID_KEY_STORE_PASS',
           '-dname', localconfig['keydname'],
           '-J-Duser.language=en']
    if localconfig['keystore'] == "NONE":
        cmd += localconfig['smartcardoptions']
    else:
        cmd += '-keypass:env', 'FDROID_KEY_PASS'
    p = FDroidPopen(cmd, envs=env_vars)
    if p.returncode != 0:
        raise BuildException("Failed to generate key", p.output)
    if localconfig['keystore'] != "NONE":
        os.chmod(localconfig['keystore'], 0o0600)
    if not options.quiet:
        # now show the lovely key that was just generated
        p = FDroidPopen([config['keytool'], '-list', '-v',
                         '-keystore', localconfig['keystore'],
                         '-alias', localconfig['repo_keyalias'],
                         '-storepass:env', 'FDROID_KEY_STORE_PASS', '-J-Duser.language=en']
                        + config['smartcardoptions'], envs=env_vars)
        logging.info(p.output.strip() + '\n\n')
    # get the public key
    p = FDroidPopenBytes([config['keytool'], '-exportcert',
                          '-keystore', localconfig['keystore'],
                          '-alias', localconfig['repo_keyalias'],
                          '-storepass:env', 'FDROID_KEY_STORE_PASS']
                         + config['smartcardoptions'],
                         envs=env_vars, output=False, stderr_to_stdout=False)
    if p.returncode != 0 or len(p.output) < 20:
        raise BuildException("Failed to get public key", p.output)
    pubkey = p.output
    fingerprint = get_cert_fingerprint(pubkey)
    return hexlify(pubkey), fingerprint


def get_cert_fingerprint(pubkey):
    """Generate a certificate fingerprint the same way keytool does it (but with slightly different formatting)."""
    digest = hashlib.sha256(pubkey).digest()
    ret = [' '.join("%02X" % b for b in bytearray(digest))]
    return " ".join(ret)


def get_certificate(signature_block_file, signature_file=None):
    """Extract a single DER certificate from JAR Signature's "Signature Block File".

    If there is more than one signer certificate, this exits with an
    error, unless the signature_file is provided.  If that is set, it
    will return the certificate that matches the Signature File, for
    example, if there is a certificate chain, like TLS does.  In the
    fdroidserver use cases, there should always be a single signer.
    But rarely, some APKs include certificate chains.

    This could be replaced by androguard's APK.get_certificate_der()
    provided the cert chain fix was merged there.  Maybe in 4.1.2?
    https://github.com/androguard/androguard/pull/1038

    https://docs.oracle.com/en/java/javase/21/docs/specs/man/jarsigner.html#the-signed-jar-file

    Parameters
    ----------
    signature_block_file
        Bytes representing the PKCS#7 signer certificate and
        signature, as read directly out of the JAR/APK, e.g. CERT.RSA.

    signature_file
        Bytes representing the manifest signed by the Signature Block
        File, e.g. CERT.SF.  If this is not given, the assumption is
        there will be only a single certificate in
        signature_block_file, otherwise it is an error.

    Returns
    -------
    A binary representation of the certificate's public key,
    or None in case of error

    """
    pkcs7obj = cms.ContentInfo.load(signature_block_file)
    certificates = pkcs7obj['content']['certificates']
    if len(certificates) == 1:
        return certificates[0].chosen.dump()
    elif not signature_file:
        logging.error(_('Found multiple Signer Certificates!'))
        return
    certificate = get_jar_signer_certificate(pkcs7obj, signature_file)
    if certificate:
        return certificate.chosen.dump()


def _find_matching_certificate(signer_info, certificate):
    """Find the certificates that matches signer_info using issuer and serial number.

    https://android.googlesource.com/platform/tools/apksig/+/refs/tags/android-13.0.0_r3/src/main/java/com/android/apksig/internal/apk/v1/V1SchemeVerifier.java#590
    https://android.googlesource.com/platform/tools/apksig/+/refs/tags/android-13.0.0_r3/src/main/java/com/android/apksig/internal/x509/Certificate.java#55

    """
    certificate_serial = certificate.chosen['tbs_certificate']['serial_number']
    expected_issuer_serial = signer_info['sid'].chosen
    return (
        expected_issuer_serial['issuer'] == certificate.chosen.issuer
        and expected_issuer_serial['serial_number'] == certificate_serial
    )


def get_jar_signer_certificate(pkcs7obj: cms.ContentInfo, signature_file: bytes):
    """Return the one certificate in a chain that actually signed the manifest.

    PKCS#7-signed data can include certificate chains for use cases
    where an Certificate Authority (CA) is used.  Android does not
    validate the certificate chain on APK signatures, so neither does
    this.
    https://android.googlesource.com/platform/tools/apksig/+/refs/tags/android-13.0.0_r3/src/main/java/com/android/apksig/internal/apk/v1/V1SchemeVerifier.java#512

    Some useful fodder for understanding all this:
    https://docs.oracle.com/javase/tutorial/deployment/jar/intro.html
    https://technotes.shemyak.com/posts/jar-signature-block-file-format/
    https://docs.oracle.com/en/java/javase/21/docs/specs/man/jarsigner.html#the-signed-jar-file
    https://qistoph.blogspot.com/2012/01/manual-verify-pkcs7-signed-data-with.html

    """
    import oscrypto.asymmetric
    import oscrypto.errors

    # Android attempts to verify all SignerInfos and then picks the first verified SignerInfo.
    first_verified_signer_info = None
    first_verified_signer_info_signing_certificate = None
    for signer_info in pkcs7obj['content']['signer_infos']:
        signature = signer_info['signature'].contents
        digest_algorithm = signer_info["digest_algorithm"]["algorithm"].native
        public_key = None
        for certificate in pkcs7obj['content']['certificates']:
            if _find_matching_certificate(signer_info, certificate):
                public_key = oscrypto.asymmetric.load_public_key(certificate.chosen.public_key)
                break
        if public_key is None:
            logging.info('No certificate found that matches signer info!')
            continue

        signature_algo = signer_info['signature_algorithm'].signature_algo
        if signature_algo == 'rsassa_pkcs1v15':
            # ASN.1 - 1.2.840.113549.1.1.1
            verify_func = oscrypto.asymmetric.rsa_pkcs1v15_verify
        elif signature_algo == 'rsassa_pss':
            # ASN.1 - 1.2.840.113549.1.1.10
            verify_func = oscrypto.asymmetric.rsa_pss_verify
        elif signature_algo == 'dsa':
            # ASN.1 - 1.2.840.10040.4.1
            verify_func = oscrypto.asymmetric.dsa_verify
        elif signature_algo == 'ecdsa':
            # ASN.1 - 1.2.840.10045.4
            verify_func = oscrypto.asymmetric.ecdsa_verify
        else:
            logging.error(
                'Unknown signature algorithm %s:\n  %s\n  %s'
                % (
                    signature_algo,
                    hexlify(certificate.chosen.sha256).decode(),
                    certificate.chosen.subject.human_friendly,
                ),
            )
            return

        try:
            verify_func(public_key, signature, signature_file, digest_algorithm)
            if not first_verified_signer_info:
                first_verified_signer_info = signer_info
                first_verified_signer_info_signing_certificate = certificate

        except oscrypto.errors.SignatureError as e:
            logging.error(
                '"%s", skipping:\n  %s\n  %s' % (
                    e,
                    hexlify(certificate.chosen.sha256).decode(),
                    certificate.chosen.subject.human_friendly),
            )

    if first_verified_signer_info_signing_certificate:
        return first_verified_signer_info_signing_certificate


def load_stats_fdroid_signing_key_fingerprints():
    """Load signing-key fingerprints stored in file generated by fdroid publish.

    Returns
    -------
    dict
        containing the signing-key fingerprints.
    """
    jar_file = os.path.join('stats', 'publishsigkeys.jar')
    if not os.path.isfile(jar_file):
        return {}
    try:
        verify_deprecated_jar_signature(jar_file)
    except VerificationException as e:
        raise FDroidException("Signature validation of '{}' failed! "
                              "Please run publish again to rebuild this file.".format(jar_file)) from e

    jar_sigkey = apk_signer_fingerprint(jar_file)
    repo_key_sig = config.get('repo_key_sha256')
    if repo_key_sig:
        if jar_sigkey != repo_key_sig:
            raise FDroidException("Signature key fingerprint of file '{}' does not match repo_key_sha256 in config.yml (found fingerprint: '{}')".format(jar_file, jar_sigkey))
    else:
        logging.warning("repo_key_sha256 not in config.yml, setting it to the signature key fingerprint of '{}'".format(jar_file))
        config['repo_key_sha256'] = jar_sigkey
        write_to_config(config, 'repo_key_sha256')

    with zipfile.ZipFile(jar_file, 'r') as f:
        return json.loads(str(f.read('publishsigkeys.json'), 'utf-8'))


def write_to_config(thisconfig, key, value=None, config_file=None):
    """Write a key/value to the local config.yml or config.py.

    NOTE: only supports writing string variables.

    Parameters
    ----------
    thisconfig
        config dictionary
    key
        variable name in config to be overwritten/added
    value
        optional value to be written, instead of fetched
        from 'thisconfig' dictionary.
    """
    if value is None:
        origkey = key + '_orig'
        value = thisconfig[origkey] if origkey in thisconfig else thisconfig[key]
    if config_file:
        cfg = config_file
    elif os.path.exists('config.py') and not os.path.exists('config.yml'):
        cfg = 'config.py'
    else:
        cfg = 'config.yml'

    # load config file, create one if it doesn't exist
    if not os.path.exists(cfg):
        open(cfg, 'a').close()
        logging.info("Creating empty " + cfg)
    with open(cfg, 'r') as f:
        lines = f.readlines()

    # make sure the file ends with a carraige return
    if len(lines) > 0:
        if not lines[-1].endswith('\n'):
            lines[-1] += '\n'

    # regex for finding and replacing python string variable
    # definitions/initializations
    if cfg.endswith('.py'):
        pattern = re.compile(r'^[\s#]*' + key + r'\s*=\s*"[^"]*"')
        repl = key + ' = "' + value + '"'
        pattern2 = re.compile(r'^[\s#]*' + key + r"\s*=\s*'[^']*'")
        repl2 = key + " = '" + value + "'"
    else:
        # assume .yml as default
        pattern = re.compile(r'^[\s#]*' + key + r':.*')
        repl = yaml.dump({key: value}, default_flow_style=False)
        pattern2 = pattern
        repl2 = repl

    # If we replaced this line once, we make sure won't be a
    # second instance of this line for this key in the document.
    didRepl = False
    # edit config file
    with open(cfg, 'w') as f:
        for line in lines:
            if pattern.match(line) or pattern2.match(line):
                if not didRepl:
                    line = pattern.sub(repl, line)
                    line = pattern2.sub(repl2, line)
                    f.write(line)
                    didRepl = True
            else:
                f.write(line)
        if not didRepl:
            f.write('\n')
            f.write(repl)
            f.write('\n')


def parse_xml(path):
    return XMLElementTree.parse(path).getroot()


def string_is_integer(string):
    try:
        int(string, 0)
        return True
    except ValueError:
        try:
            int(string)
            return True
        except ValueError:
            return False


def version_code_string_to_int(vercode):
    """Convert an version code string of any base into an int."""
    # TODO: Python 3.6 allows underscores in numeric literals
    vercode = vercode.replace('_', '')
    try:
        return int(vercode, 0)
    except ValueError:
        return int(vercode)


def get_app_display_name(app):
    """Get a human readable name for the app for logging and sorting.

    When trying to find a localized name, this first tries en-US since
    that his the historical language used for sorting.

    """
    if app.get('Name'):
        return app['Name']
    if app.get('localized'):
        localized = app['localized'].get(DEFAULT_LOCALE)
        if not localized:
            for v in app['localized'].values():
                localized = v
                break
        if localized.get('name'):
            return localized['name']
    return app.get('AutoName') or app['id']


def local_rsync(options, from_paths: List[str], todir: str):
    """Rsync method for local to local copying of things.

    This is an rsync wrapper with all the settings for safe use within
    the various fdroidserver use cases. This uses stricter rsync
    checking on all files since people using offline mode are already
    prioritizing security above ease and speed.

    """
    rsyncargs = ['rsync', '--recursive', '--safe-links', '--times', '--perms',
                 '--one-file-system', '--delete', '--chmod=Da+rx,Fa-x,a+r,u+w']
    if not options.no_checksum:
        rsyncargs.append('--checksum')
    if options.verbose:
        rsyncargs += ['--verbose']
    if options.quiet:
        rsyncargs += ['--quiet']
    logging.debug(' '.join(rsyncargs + from_paths + [todir]))
    if subprocess.call(rsyncargs + from_paths + [todir]) != 0:
        raise FDroidException()


def deploy_build_log_with_rsync(appid, vercode, log_content):
    """Upload build log of one individual app build to an fdroid repository.

    Parameters
    ----------
    appid
        package name for dientifying to which app this log belongs.
    vercode
        version of the app to which this build belongs.
    log_content
        Content of the log which is about to be posted.
        Should be either a string or bytes. (bytes will
        be decoded as 'utf-8')
    """
    if not log_content:
        logging.warning(_('skip deploying full build logs: log content is empty'))
        return

    if not os.path.exists('repo'):
        os.mkdir('repo')

    # gzip compress log file
    log_gz_path = os.path.join('repo',
                               '{appid}_{versionCode}.log.gz'.format(appid=appid,
                                                                     versionCode=vercode))

    with gzip.open(log_gz_path, 'wb') as f:
        if isinstance(log_content, str):
            f.write(bytes(log_content, 'utf-8'))
        else:
            f.write(log_content)
    rsync_status_file_to_repo(log_gz_path)


def rsync_status_file_to_repo(path, repo_subdir=None):
    """Copy a build log or status JSON to the repo using rsync."""
    if not config.get('deploy_process_logs', False):
        logging.debug(_('skip deploying full build logs: not enabled in config'))
        return

    for d in config.get('serverwebroot', []):
        webroot = d['url']
        cmd = ['rsync',
               '--archive',
               '--delete-after',
               '--safe-links']
        if options.verbose:
            cmd += ['--verbose']
        if options.quiet:
            cmd += ['--quiet']
        if 'identity_file' in config:
            cmd += ['-e', 'ssh -oBatchMode=yes -oIdentitiesOnly=yes -i ' + config['identity_file']]

        dest_path = os.path.join(webroot, "repo")
        if repo_subdir is not None:
            dest_path = os.path.join(dest_path, repo_subdir)
        if not dest_path.endswith('/'):
            dest_path += '/'  # make sure rsync knows this is a directory
        cmd += [path, dest_path]

        retcode = subprocess.call(cmd)
        if retcode:
            logging.error(_('process log deploy {path} to {dest} failed!')
                          .format(path=path, dest=webroot))
        else:
            logging.debug(_('deployed process log {path} to {dest}')
                          .format(path=path, dest=webroot))


def get_per_app_repos():
    """Per-app repos are dirs named with the packageName of a single app."""
    # Android packageNames are Java packages, they may contain uppercase or
    # lowercase letters ('A' through 'Z'), numbers, and underscores
    # ('_'). However, individual package name parts may only start with
    # letters. https://developer.android.com/guide/topics/manifest/manifest-element.html#package
    p = re.compile('^([a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)*)?$')

    repos = []
    for root, dirs, files in os.walk(os.getcwd()):
        for d in dirs:
            print('checking', root, 'for', d)
            if d in ('archive', 'metadata', 'repo', 'srclibs', 'tmp'):
                # standard parts of an fdroid repo, so never packageNames
                continue
            elif p.match(d) \
                    and os.path.exists(os.path.join(d, 'fdroid', 'repo', 'index.jar')):
                repos.append(d)
        break
    return repos


# list of index files that are never gpg-signed
NO_GPG_INDEX_FILES = [
    "entry.jar",
    "index-v1.jar",
    "index.css",
    "index.html",
    "index.jar",
    "index.png",
    "index.xml",
]

# list of index files that are signed by gpgsign.py to make a .asc file
GPG_INDEX_FILES = [
    "altstore-index.json",
    "entry.json",
    "index-v1.json",
    "index-v2.json",
]


INDEX_FILES = sorted(
    NO_GPG_INDEX_FILES + GPG_INDEX_FILES + [i + '.asc' for i in GPG_INDEX_FILES]
)


def is_repo_file(filename, for_gpg_signing=False):
    """Whether the file in a repo is a build product to be delivered to users."""
    if isinstance(filename, str):
        filename = filename.encode('utf-8', errors="surrogateescape")
    ignore_files = [i.encode() for i in NO_GPG_INDEX_FILES]
    ignore_files.append(b'index_unsigned.jar')
    if not for_gpg_signing:
        ignore_files += [i.encode() for i in GPG_INDEX_FILES]

    return (
        os.path.isfile(filename)
        and not filename.endswith(b'.asc')
        and not filename.endswith(b'.sig')
        and not filename.endswith(b'.idsig')
        and not filename.endswith(b'.log.gz')
        and os.path.basename(filename) not in ignore_files
    )


def get_examples_dir():
    """Return the dir where the fdroidserver example files are available."""
    examplesdir = None
    tmp = os.path.dirname(sys.argv[0])
    if os.path.basename(tmp) == 'bin':
        egg_links = glob.glob(os.path.join(tmp, '..',
                                           'local/lib/python3.*/site-packages/fdroidserver.egg-link'))
        if egg_links:
            # installed from local git repo
            examplesdir = os.path.join(open(egg_links[0]).readline().rstrip(), 'examples')
        else:
            # try .egg layout
            examplesdir = os.path.dirname(os.path.dirname(__file__)) + '/share/doc/fdroidserver/examples'
            if not os.path.exists(examplesdir):  # use UNIX layout
                examplesdir = os.path.dirname(tmp) + '/share/doc/fdroidserver/examples'
    else:
        # we're running straight out of the git repo
        prefix = os.path.normpath(os.path.join(os.path.dirname(__file__), '..'))
        examplesdir = prefix + '/examples'

    return examplesdir


def get_android_tools_versions():
    """Get a list of the versions of all installed Android SDK/NDK components."""
    global config
    sdk_path = config['sdk_path']
    if sdk_path[-1] != '/':
        sdk_path += '/'
    components = set()
    for ndk_path in config.get('ndk_paths', {}).values():
        version = get_ndk_version(ndk_path)
        components.add((os.path.relpath(ndk_path, sdk_path), str(version)))

    pattern = re.compile(r'^Pkg.Revision *= *(.+)', re.MULTILINE)
    for root, dirs, files in os.walk(sdk_path):
        if 'source.properties' in files:
            source_properties = os.path.join(root, 'source.properties')
            with open(source_properties, 'r') as fp:
                m = pattern.search(fp.read())
                if m:
                    components.add((os.path.relpath(root, sdk_path), m.group(1)))

    return sorted(components)


def get_android_tools_version_log():
    """Get a list of the versions of all installed Android SDK/NDK components."""
    log = '== Installed Android Tools ==\n\n'
    components = get_android_tools_versions()
    for name, version in sorted(components):
        log += '* ' + name + ' (' + version + ')\n'

    return log


def calculate_math_string(expr):
    ops = {
        ast.Add: operator.add,
        ast.Mult: operator.mul,
        ast.Sub: operator.sub,
        ast.USub: operator.neg,
        ast.Pow: operator.pow,
    }

    def execute_ast(node):
        if isinstance(node, ast.Num):  # <number>
            return node.n
        elif isinstance(node, ast.BinOp):  # <left> <operator> <right>
            return ops[type(node.op)](execute_ast(node.left),
                                      execute_ast(node.right))
        elif isinstance(node, ast.UnaryOp):  # <operator> <operand> e.g., -1
            return ops[type(node.op)](ast.literal_eval(node.operand))
        else:
            raise SyntaxError(node)

    try:
        if '#' in expr:
            raise SyntaxError('no comments allowed')
        return execute_ast(ast.parse(expr, mode='eval').body)
    except SyntaxError as exc:
        raise SyntaxError("could not parse expression '{expr}', "
                          "only basic math operations are allowed (+, -, *)"
                          .format(expr=expr)) from exc


def force_exit(exitvalue=0):
    """Force exit when thread operations could block the exit.

    The build command has to use some threading stuff to handle the
    timeout and locks.  This seems to prevent the command from
    exiting, unless this hack is used.

    """
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(exitvalue)


YAML_LINT_CONFIG = {'extends': 'default',
                    'rules': {'document-start': 'disable',
                              'line-length': 'disable',
                              'truthy': 'disable'}}


def run_yamllint(path, indent=0):
    path = Path(path)
    try:
        import yamllint.config
        import yamllint.linter
    except ImportError:
        return ''

    result = []
    with path.open('r', encoding='utf-8') as f:
        problems = yamllint.linter.run(f, yamllint.config.YamlLintConfig(json.dumps(YAML_LINT_CONFIG)))
    for problem in problems:
        result.append(' ' * indent + str(path) + ':' + str(problem.line) + ': ' + problem.message)
    return '\n'.join(result)


def calculate_IPFS_cid(filename):
    """Calculate the IPFS CID of a file and add it to the index.

    uses ipfs_cid package at https://packages.debian.org/sid/ipfs-cid
    Returns CIDv1 of a file as per IPFS recommendation
    """
    cmd = config and config.get('ipfs_cid')
    if not cmd:
        return
    file_cid = subprocess.run([cmd, filename], capture_output=True)

    if file_cid.returncode == 0:
        cid_output = file_cid.stdout.decode()
        cid_output_dict = json.loads(cid_output)
        return cid_output_dict['CIDv1']


def sha256sum(filename):
    """Calculate the sha256 of the given file."""
    sha = hashlib.sha256()
    with open(filename, 'rb') as f:
        while True:
            t = f.read(16384)
            if len(t) == 0:
                break
            sha.update(t)
    return sha.hexdigest()


def sha256base64(filename):
    """Calculate the sha256 of the given file as URL-safe base64."""
    hasher = hashlib.sha256()
    with open(filename, 'rb') as f:
        while True:
            t = f.read(16384)
            if len(t) == 0:
                break
            hasher.update(t)
    return urlsafe_b64encode(hasher.digest()).decode()


def get_ndk_version(ndk_path):
    """Get the version info from the metadata in the NDK package.

    Since r11, the info is nice and easy to find in
    sources.properties.  Before, there was a kludgey format in
    RELEASE.txt.  This is only needed for r10e.

    """
    source_properties = os.path.join(ndk_path, 'source.properties')
    release_txt = os.path.join(ndk_path, 'RELEASE.TXT')
    if os.path.exists(source_properties):
        with open(source_properties) as fp:
            m = re.search(r'^Pkg.Revision *= *(.+)', fp.read(), flags=re.MULTILINE)
            if m:
                return m.group(1)
    elif os.path.exists(release_txt):
        with open(release_txt) as fp:
            return fp.read().split('-')[0]


def auto_install_ndk(build):
    """Auto-install the NDK in the build, this assumes its in a buildserver guest VM.

    Download, verify, and install the NDK version as specified via the
    "ndk:" field in the build entry.  As it uncompresses the zipball,
    this forces the permissions to work for all users, since this
    might uncompress as root and then be used from a different user.

    This needs to be able to install multiple versions of the NDK,
    since this is also used in CI builds, where multiple `fdroid build
    --onserver` calls can run in a single session.  The production
    buildserver is reset between every build.

    The default ANDROID_SDK_ROOT base dir of /opt/android-sdk is hard-coded in
    buildserver/Vagrantfile.  The $ANDROID_HOME/ndk subdir is where Android
    Studio will install the NDK into versioned subdirs.
    https://developer.android.com/studio/projects/configure-agp-ndk#agp_version_41

    Also, r10e and older cannot be handled via this mechanism because
    they are packaged differently.

    """
    import sdkmanager

    global config
    if build.get('disable'):
        return
    ndk = build.get('ndk')
    if not ndk:
        return
    if isinstance(ndk, str):
        sdkmanager.build_package_list(use_net=True)
        _install_ndk(ndk)
    elif isinstance(ndk, list):
        sdkmanager.build_package_list(use_net=True)
        for n in ndk:
            _install_ndk(n)
    else:
        raise BuildException(_('Invalid ndk: entry in build: "{ndk}"')
                             .format(ndk=str(ndk)))


def _install_ndk(ndk):
    """Install specified NDK if it is not already installed.

    Parameters
    ----------
    ndk
        The NDK version to install, either in "release" form (r21e) or
        "revision" form (21.4.7075529).
    """
    import sdkmanager

    sdk_path = config['sdk_path']
    sdkmanager.install(f'ndk;{ndk}', sdk_path)
    for found in glob.glob(f'{sdk_path}/ndk/*'):
        version = get_ndk_version(found)
        if 'ndk_paths' not in config:
            config['ndk_paths'] = dict()
        config['ndk_paths'][ndk] = found
        config['ndk_paths'][version] = found
        logging.info(
            _('Set NDK {release} ({version}) up').format(release=ndk, version=version)
        )


FDROIDORG_MIRRORS = [
    {
        'isPrimary': True,
        'url': 'https://f-droid.org/repo',
        'dnsA': ['65.21.79.229', '136.243.44.143'],
        'dnsAAAA': ['2a01:4f8:212:c98::2', '2a01:4f9:3b:546d::2'],
        'worksWithoutSNI': True,
    },
    {
        'url': 'http://fdroidorg6cooksyluodepej4erfctzk7rrjpjbbr6wx24jh3lqyfwyd.onion/fdroid/repo'
    },
    {
        'url': 'http://dotsrccccbidkzg7oc7oj4ugxrlfbt64qebyunxbrgqhxiwj3nl6vcad.onion/fdroid/repo'
    },
    {
        'url': 'http://ftpfaudev4triw2vxiwzf4334e3mynz7osqgtozhbc77fixncqzbyoyd.onion/fdroid/repo'
    },
    {
        'url': 'http://lysator7eknrfl47rlyxvgeamrv7ucefgrrlhk7rouv3sna25asetwid.onion/pub/fdroid/repo'
    },
    {
        'url': 'http://mirror.ossplanetnyou5xifr6liw5vhzwc2g2fmmlohza25wwgnnaw65ytfsad.onion/fdroid/repo'
    },
    {'url': 'https://fdroid.tetaneutral.net/fdroid/repo', 'countryCode': 'FR'},
    {
        'url': 'https://ftp.agdsn.de/fdroid/repo',
        'countryCode': 'DE',
        "dnsA": ["141.30.235.39"],
        "dnsAAAA": ["2a13:dd85:b00:12::1"],
        "worksWithoutSNI": True,
    },
    {
        'url': 'https://ftp.fau.de/fdroid/repo',
        'countryCode': 'DE',
        "dnsA": ["131.188.12.211"],
        "dnsAAAA": ["2001:638:a000:1021:21::1"],
        "worksWithoutSNI": True,
    },
    {'url': 'https://ftp.gwdg.de/pub/android/fdroid/repo', 'countryCode': 'DE'},
    {
        'url': 'https://ftp.lysator.liu.se/pub/fdroid/repo',
        'countryCode': 'SE',
        "dnsA": ["130.236.254.251", "130.236.254.253"],
        "dnsAAAA": ["2001:6b0:17:f0a0::fb", "2001:6b0:17:f0a0::fd"],
        "worksWithoutSNI": True,
    },
    {'url': 'https://mirror.cyberbits.eu/fdroid/repo', 'countryCode': 'FR'},
    {
        'url': 'https://mirror.fcix.net/fdroid/repo',
        'countryCode': 'US',
        "dnsA": ["23.152.160.16"],
        "dnsAAAA": ["2620:13b:0:1000::16"],
        "worksWithoutSNI": True,
    },
    {'url': 'https://mirror.kumi.systems/fdroid/repo', 'countryCode': 'AT'},
    {'url': 'https://mirror.level66.network/fdroid/repo', 'countryCode': 'DE'},
    {'url': 'https://mirror.ossplanet.net/fdroid/repo', 'countryCode': 'TW'},
    {'url': 'https://mirrors.dotsrc.org/fdroid/repo', 'countryCode': 'DK'},
    {'url': 'https://opencolo.mm.fcix.net/fdroid/repo', 'countryCode': 'US'},
    {
        'url': 'https://plug-mirror.rcac.purdue.edu/fdroid/repo',
        'countryCode': 'US',
        "dnsA": ["128.211.151.252"],
        "dnsAAAA": ["2001:18e8:804:35::1337"],
        "worksWithoutSNI": True,
    },
]
FDROIDORG_FINGERPRINT = (
    '43238D512C1E5EB2D6569F4A3AFBF5523418B82E0A3ED1552770ABB9A9C9CCAB'
)
