#!/usr/bin/env python3
#
# metadata.py - part of the FDroid server tools
# Copyright (C) 2013, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
# Copyright (C) 2017-2018 Michael Pöhn <michael.poehn@fsfe.org>
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

import git
from pathlib import Path
import math
import platform
import os
import re
import logging
import ruamel.yaml
from collections import OrderedDict

from . import common
from . import _
from .exception import MetaDataException

srclibs = None
warnings_action = None

# validates usernames based on a loose collection of rules from GitHub, GitLab,
# Liberapay and issuehunt.  This is mostly to block abuse.
VALID_USERNAME_REGEX = re.compile(r'^[a-z\d](?:[a-z\d/._-]){0,38}$', re.IGNORECASE)


def _warn_or_exception(value, cause=None):
    """Output warning or Exception depending on -W."""
    if warnings_action == 'ignore':
        pass
    elif warnings_action == 'error':
        if cause:
            raise MetaDataException(value) from cause
        else:
            raise MetaDataException(value)
    else:
        logging.warning(value)


yaml_app_field_order = [
    'Disabled',
    'AntiFeatures',
    'Categories',
    'License',
    'AuthorName',
    'AuthorEmail',
    'AuthorWebSite',
    'WebSite',
    'SourceCode',
    'IssueTracker',
    'Translation',
    'Changelog',
    'Donate',
    'Liberapay',
    'OpenCollective',
    'Bitcoin',
    'Litecoin',
    '\n',
    'Name',
    'AutoName',
    'Summary',
    'Description',
    '\n',
    'RequiresRoot',
    '\n',
    'RepoType',
    'Repo',
    'Binaries',
    '\n',
    'Builds',
    '\n',
    'AllowedAPKSigningKeys',
    '\n',
    'MaintainerNotes',
    '\n',
    'ArchivePolicy',
    'AutoUpdateMode',
    'UpdateCheckMode',
    'UpdateCheckIgnore',
    'VercodeOperation',
    'UpdateCheckName',
    'UpdateCheckData',
    'CurrentVersion',
    'CurrentVersionCode',
    '\n',
    'NoSourceSince',
]


yaml_app_fields = [x for x in yaml_app_field_order if x != '\n']


class App(dict):
    def __init__(self, copydict=None):
        if copydict:
            super().__init__(copydict)
            return
        super().__init__()

        self.Disabled = None
        self.AntiFeatures = dict()
        self.Provides = None
        self.Categories = []
        self.License = 'Unknown'
        self.AuthorName = None
        self.AuthorEmail = None
        self.AuthorWebSite = None
        self.WebSite = ''
        self.SourceCode = ''
        self.IssueTracker = ''
        self.Translation = ''
        self.Changelog = ''
        self.Donate = None
        self.Liberapay = None
        self.OpenCollective = None
        self.Bitcoin = None
        self.Litecoin = None
        self.Name = None
        self.AutoName = ''
        self.Summary = ''
        self.Description = ''
        self.RequiresRoot = False
        self.RepoType = ''
        self.Repo = ''
        self.Binaries = None
        self.AllowedAPKSigningKeys = []
        self.MaintainerNotes = ''
        self.ArchivePolicy = None
        self.AutoUpdateMode = 'None'
        self.UpdateCheckMode = 'None'
        self.UpdateCheckIgnore = None
        self.VercodeOperation = []
        self.UpdateCheckName = None
        self.UpdateCheckData = None
        self.CurrentVersion = ''
        self.CurrentVersionCode = None
        self.NoSourceSince = ''

        self.id = None
        self.metadatapath = None
        self.Builds = []
        self.added = None
        self.lastUpdated = None

    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            raise AttributeError("No such attribute: " + name)

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        if name in self:
            del self[name]
        else:
            raise AttributeError("No such attribute: " + name)


TYPE_STRING = 2
TYPE_BOOL = 3
TYPE_LIST = 4
TYPE_SCRIPT = 5
TYPE_MULTILINE = 6
TYPE_BUILD = 7
TYPE_INT = 8
TYPE_STRINGMAP = 9

fieldtypes = {
    'Description': TYPE_MULTILINE,
    'MaintainerNotes': TYPE_MULTILINE,
    'Categories': TYPE_LIST,
    'AntiFeatures': TYPE_STRINGMAP,
    'RequiresRoot': TYPE_BOOL,
    'AllowedAPKSigningKeys': TYPE_LIST,
    'Builds': TYPE_BUILD,
    'VercodeOperation': TYPE_LIST,
    'CurrentVersionCode': TYPE_INT,
    'ArchivePolicy': TYPE_INT,
}


def fieldtype(name):
    name = name.replace(' ', '')
    if name in fieldtypes:
        return fieldtypes[name]
    return TYPE_STRING


# In the order in which they are laid out on files
build_flags = [
    'versionName',
    'versionCode',
    'disable',
    'commit',
    'timeout',
    'subdir',
    'submodules',
    'sudo',
    'init',
    'patch',
    'gradle',
    'maven',
    'output',
    'binary',
    'srclibs',
    'oldsdkloc',
    'encoding',
    'forceversion',
    'forcevercode',
    'rm',
    'extlibs',
    'prebuild',
    'androidupdate',
    'target',
    'scanignore',
    'scandelete',
    'build',
    'buildjni',
    'ndk',
    'preassemble',
    'gradleprops',
    'antcommands',
    'postbuild',
    'novcheck',
    'antifeatures',
]


class Build(dict):
    def __init__(self, copydict=None):
        super().__init__()
        self.disable = ''
        self.commit = None
        self.timeout = None
        self.subdir = None
        self.submodules = False
        self.sudo = ''
        self.init = ''
        self.patch = []
        self.gradle = []
        self.maven = None
        self.output = None
        self.binary = None
        self.srclibs = []
        self.oldsdkloc = False
        self.encoding = None
        self.forceversion = False
        self.forcevercode = False
        self.rm = []
        self.extlibs = []
        self.prebuild = ''
        self.androidupdate = []
        self.target = None
        self.scanignore = []
        self.scandelete = []
        self.build = ''
        self.buildjni = []
        self.ndk = None
        self.preassemble = []
        self.gradleprops = []
        self.antcommands = []
        self.postbuild = ''
        self.novcheck = False
        self.antifeatures = dict()
        if copydict:
            super().__init__(copydict)
            return

    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            raise AttributeError("No such attribute: " + name)

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        if name in self:
            del self[name]
        else:
            raise AttributeError("No such attribute: " + name)

    @classmethod
    def to_yaml(cls, representer, node):
        return representer.represent_dict(node)

    def build_method(self):
        for f in ['maven', 'gradle']:
            if self.get(f):
                return f
        if self.output:
            return 'raw'
        return 'ant'

    # like build_method, but prioritize output=
    def output_method(self):
        if self.output:
            return 'raw'
        for f in ['maven', 'gradle']:
            if self.get(f):
                return f
        return 'ant'

    def ndk_path(self) -> str:
        """Return the path string of the first configured NDK or an empty string."""
        ndk = self.ndk
        if isinstance(ndk, list):
            ndk = self.ndk[0]
        path = common.config['ndk_paths'].get(ndk)
        if path and not isinstance(path, str):
            raise TypeError('NDK path is not string')
        if path:
            return path
        for vsn, path in common.config['ndk_paths'].items():
            if not vsn.endswith("_orig") and path and os.path.basename(path) == ndk:
                return path
        return ''


flagtypes = {
    'versionCode': TYPE_INT,
    'extlibs': TYPE_LIST,
    'srclibs': TYPE_LIST,
    'patch': TYPE_LIST,
    'rm': TYPE_LIST,
    'buildjni': TYPE_LIST,
    'preassemble': TYPE_LIST,
    'androidupdate': TYPE_LIST,
    'scanignore': TYPE_LIST,
    'scandelete': TYPE_LIST,
    'gradle': TYPE_LIST,
    'antcommands': TYPE_LIST,
    'gradleprops': TYPE_LIST,
    'sudo': TYPE_SCRIPT,
    'init': TYPE_SCRIPT,
    'prebuild': TYPE_SCRIPT,
    'build': TYPE_SCRIPT,
    'postbuild': TYPE_SCRIPT,
    'submodules': TYPE_BOOL,
    'oldsdkloc': TYPE_BOOL,
    'forceversion': TYPE_BOOL,
    'forcevercode': TYPE_BOOL,
    'novcheck': TYPE_BOOL,
    'antifeatures': TYPE_STRINGMAP,
    'timeout': TYPE_INT,
}


def flagtype(name):
    if name in flagtypes:
        return flagtypes[name]
    return TYPE_STRING


class FieldValidator:
    """Designate App metadata field types and checks that it matches.

    'name'     - The long name of the field type
    'matching' - List of possible values or regex expression
    'sep'      - Separator to use if value may be a list
    'fields'   - Metadata fields (Field:Value) of this type
    """

    def __init__(self, name, matching, fields):
        self.name = name
        self.matching = matching
        self.compiled = re.compile(matching)
        self.fields = fields

    def check(self, v, appid):
        if not v:
            return
        if type(v) == list:
            values = v
        else:
            values = [v]
        for v in values:
            if not self.compiled.match(v):
                _warn_or_exception(
                    _(
                        "'{value}' is not a valid {field} in {appid}. Regex pattern: {pattern}"
                    ).format(
                        value=v, field=self.name, appid=appid, pattern=self.matching
                    )
                )


# Generic value types
valuetypes = {
    FieldValidator("Liberapay",
                   VALID_USERNAME_REGEX,
                   ['Liberapay']),

    FieldValidator("Open Collective",
                   VALID_USERNAME_REGEX,
                   ['OpenCollective']),

    FieldValidator("HTTP link",
                   r'^http[s]?://',
                   ["WebSite", "SourceCode", "IssueTracker", "Translation", "Changelog", "Donate"]),

    FieldValidator("Email",
                   r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
                   ["AuthorEmail"]),

    FieldValidator("Bitcoin address",
                   r'^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$',
                   ["Bitcoin"]),

    FieldValidator("Litecoin address",
                   r'^([LM3][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[a-z0-9]{39})$',
                   ["Litecoin"]),

    FieldValidator("Repo Type",
                   r'^(git|git-svn|svn|hg|bzr|srclib)$',
                   ["RepoType"]),

    FieldValidator("Binaries",
                   r'^http[s]?://',
                   ["Binaries"]),

    FieldValidator("AllowedAPKSigningKeys",
                   r'^[a-fA-F0-9]{64}$',
                   ["AllowedAPKSigningKeys"]),

    FieldValidator("Auto Update Mode",
                   r"^(Version.*|None)$",
                   ["AutoUpdateMode"]),

    FieldValidator("Update Check Mode",
                   r"^(Tags|Tags .+|RepoManifest|RepoManifest/.+|HTTP|Static|None)$",
                   ["UpdateCheckMode"])
}


# Check an app's metadata information for integrity errors
def check_metadata(app):
    for v in valuetypes:
        for k in v.fields:
            v.check(app[k], app.id)


def parse_yaml_srclib(metadatapath):
    thisinfo = {'RepoType': '', 'Repo': '', 'Subdir': None, 'Prepare': None}

    if not metadatapath.exists():
        _warn_or_exception(
            _("Invalid scrlib metadata: '{file}' does not exist").format(
                file=metadatapath
            )
        )
        return thisinfo

    with metadatapath.open("r", encoding="utf-8") as f:
        try:
            yaml = ruamel.yaml.YAML(typ='safe')
            data = yaml.load(f)
            if type(data) is not dict:
                if platform.system() == 'Windows':
                    # Handle symlink on Windows
                    symlink = metadatapath.parent / metadatapath.read_text(encoding='utf-8')
                    if symlink.is_file():
                        with symlink.open("r", encoding="utf-8") as s:
                            data = yaml.load(s)
            if type(data) is not dict:
                raise ruamel.yaml.YAMLError(
                    _('{file} is blank or corrupt!').format(file=metadatapath)
                )
        except ruamel.yaml.YAMLError as e:
            _warn_or_exception(_("Invalid srclib metadata: could not "
                                 "parse '{file}'")
                               .format(file=metadatapath) + '\n'
                               + common.run_yamllint(metadatapath, indent=4),
                               cause=e)
            return thisinfo

    for key in data:
        if key not in thisinfo:
            _warn_or_exception(
                _("Invalid srclib metadata: unknown key '{key}' in '{file}'").format(
                    key=key, file=metadatapath
                )
            )
            return thisinfo
        else:
            if key == 'Subdir':
                if isinstance(data[key], str):
                    thisinfo[key] = data[key].split(',')
                elif isinstance(data[key], list):
                    thisinfo[key] = data[key]
                elif data[key] is None:
                    thisinfo[key] = ['']
            elif key == 'Prepare' or flagtype(key) == TYPE_SCRIPT:
                if isinstance(data[key], list):
                    thisinfo[key] = data[key]
                else:
                    thisinfo[key] = [data[key]] if data[key] else []
            else:
                thisinfo[key] = str(data[key] or '')

    return thisinfo


def read_srclibs():
    """Read all srclib metadata.

    The information read will be accessible as metadata.srclibs, which is a
    dictionary, keyed on srclib name, with the values each being a dictionary
    in the same format as that returned by the parse_yaml_srclib function.

    A MetaDataException is raised if there are any problems with the srclib
    metadata.
    """
    global srclibs

    # They were already loaded
    if srclibs is not None:
        return

    srclibs = {}

    srcdir = Path('srclibs')
    srcdir.mkdir(exist_ok=True)

    for metadatapath in sorted(srcdir.glob('*.yml')):
        srclibs[metadatapath.stem] = parse_yaml_srclib(metadatapath)


def read_metadata(appid_to_vercode={}, sort_by_time=False):
    """Return a list of App instances sorted newest first.

    This reads all of the metadata files in a 'data' repository, then
    builds a list of App instances from those files.  The list is
    sorted based on creation time, newest first.  Most of the time,
    the newer files are the most interesting.

    appid_to_vercode is a dict with appids a keys and versionCodes as values.

    """
    # Always read the srclibs before the apps, since they can use a srlib as
    # their source repository.
    read_srclibs()

    apps = OrderedDict()

    for basedir in ('metadata', 'tmp'):
        Path(basedir).mkdir(exist_ok=True)

    if appid_to_vercode:
        metadatafiles = common.get_metadata_files(appid_to_vercode)
    else:
        metadatafiles = list(Path('metadata').glob('*.yml')) + list(
            Path('.').glob('.fdroid.yml')
        )

    if sort_by_time:
        entries = ((path.stat().st_mtime, path) for path in metadatafiles)
        metadatafiles = []
        for _ignored, path in sorted(entries, reverse=True):
            metadatafiles.append(path)
    else:
        # most things want the index alpha sorted for stability
        metadatafiles = sorted(metadatafiles)

    for metadatapath in metadatafiles:
        appid = metadatapath.stem
        if appid != '.fdroid' and not common.is_valid_package_name(appid):
            _warn_or_exception(
                _("{appid} from {path} is not a valid Java Package Name!").format(
                    appid=appid, path=metadatapath
                )
            )
        if appid in apps:
            _warn_or_exception(
                _("Found multiple metadata files for {appid}").format(appid=appid)
            )
        app = parse_metadata(metadatapath)
        check_metadata(app)
        apps[app.id] = app

    return apps


def parse_metadata(metadatapath):
    """Parse metadata file, also checking the source repo for .fdroid.yml.

    This function finds the relevant files, gets them parsed, converts
    dicts into App and Build instances, and combines the results into
    a single App instance.

    If this is a metadata file from fdroiddata, it will first load the
    source repo type and URL from fdroiddata, then read .fdroid.yml if
    it exists, then include the rest of the metadata as specified in
    fdroiddata, so that fdroiddata has precedence over the metadata in
    the source code.

    .fdroid.yml is embedded in the app's source repo, so it is
    "user-generated".  That means that it can have weird things in it
    that need to be removed so they don't break the overall process,
    e.g. if the upstream developer includes some broken field, it can
    be overridden in the metadata file.

    Parameters
    ----------
    metadatapath
      The file path to read. The "Application ID" aka "Package Name"
      for the application comes from this filename.

    Raises
    ------
    FDroidException when there are syntax errors.

    Returns
    -------
    Returns a dictionary containing all the details of the
    application. There are two major kinds of information in the
    dictionary. Keys beginning with capital letters correspond
    directory to identically named keys in the metadata file.  Keys
    beginning with lower case letters are generated in one way or
    another, and are not found verbatim in the metadata.

    """
    metadatapath = Path(metadatapath)
    app = App()
    app.metadatapath = metadatapath.as_posix()
    if metadatapath.suffix == '.yml':
        with metadatapath.open('r', encoding='utf-8') as mf:
            app.update(parse_yaml_metadata(mf))
    else:
        _warn_or_exception(
            _('Unknown metadata format: {path} (use: *.yml)').format(path=metadatapath)
        )

    if metadatapath.stem != '.fdroid':
        app.id = metadatapath.stem
        parse_localized_antifeatures(app)

    if metadatapath.name != '.fdroid.yml' and app.Repo:
        build_dir = common.get_build_dir(app)
        metadata_in_repo = build_dir / '.fdroid.yml'
        if metadata_in_repo.is_file():
            try:
                commit_id = common.get_head_commit_id(git.Repo(build_dir))
                logging.debug(
                    _('Including metadata from %s@%s') % (metadata_in_repo, commit_id)
                )
            # See https://github.com/PyCQA/pylint/issues/2856 .
            # pylint: disable-next=no-member
            except git.exc.InvalidGitRepositoryError:
                logging.debug(
                    _('Including metadata from {path}').format(path=metadata_in_repo)
                )
            app_in_repo = parse_metadata(metadata_in_repo)
            for k, v in app_in_repo.items():
                if k not in app:
                    app[k] = v

    builds = []
    for build in app.get('Builds', []):
        builds.append(Build(build))
    if builds:
        app['Builds'] = builds

    # if only .fdroid.yml was found, then this finds the appid
    if not app.id:
        if app.get('Builds'):
            build = app['Builds'][-1]
            if build.subdir:
                root_dir = Path(build.subdir)
            else:
                root_dir = Path('.')
            paths = common.manifest_paths(root_dir, build.gradle)
            _ignored, _ignored, app.id = common.parse_androidmanifests(paths, app)

    return app


def parse_yaml_metadata(mf):
    """Parse the .yml file and post-process it.

    This function handles parsing a metadata YAML file and converting
    all the various data types into a consistent internal
    representation.  The results are meant to update an existing App
    instance or used as a plain dict.

    Clean metadata .yml files can be used directly, but in order to
    make a better user experience for people editing .yml files, there
    is post processing.  That makes the parsing perform something like
    Strict YAML.

    """
    try:
        yaml = ruamel.yaml.YAML(typ='safe')
        yamldata = yaml.load(mf)
    except ruamel.yaml.YAMLError as e:
        _warn_or_exception(
            _("could not parse '{path}'").format(path=mf.name)
            + '\n'
            + common.run_yamllint(mf.name, indent=4),
            cause=e,
        )

    if yamldata is None or yamldata == '':
        yamldata = dict()
    if not isinstance(yamldata, dict):
        _warn_or_exception(
            _("'{path}' has invalid format, it should be a dictionary!").format(
                path=mf.name
            )
        )
        logging.error(_('Using blank dictionary instead of contents of {path}!').format(
            path=mf.name)
        )
        yamldata = dict()

    deprecated_in_yaml = ['Provides']

    for field in tuple(yamldata.keys()):
        if field not in yaml_app_fields + deprecated_in_yaml:
            msg = _("Unrecognised app field '{fieldname}' in '{path}'").format(
                fieldname=field, path=mf.name
            )
            if Path(mf.name).name == '.fdroid.yml':
                logging.error(msg)
                del yamldata[field]
            else:
                _warn_or_exception(msg)

    for deprecated_field in deprecated_in_yaml:
        if deprecated_field in yamldata:
            del yamldata[deprecated_field]
            logging.warning(
                _(
                    "Ignoring '{field}' in '{metapath}' "
                    "metadata because it is deprecated."
                ).format(field=deprecated_field, metapath=mf.name)
            )

    msg = _("Unrecognised build flag '{build_flag}' in '{path}'")
    for build in yamldata.get('Builds', []):
        for build_flag in build:
            if build_flag not in build_flags:
                _warn_or_exception(msg.format(build_flag=build_flag, path=mf.name))

    post_parse_yaml_metadata(yamldata)
    return yamldata


def parse_localized_antifeatures(app):
    """Read in localized Anti-Features files from the filesystem.

    To support easy integration with Weblate and other translation
    systems, there is a special type of metadata that can be
    maintained in a Fastlane-style directory layout, where each field
    is represented by a text file on directories that specified which
    app it belongs to, which locale, etc.  This function reads those
    in and puts them into the internal dict, to be merged with any
    related data that came from the metadata.yml file.

    This needs to be run after parse_yaml_metadata() since that
    normalizes the data structure.  Also, these values are lower
    priority than what comes from the metadata file. So this should
    not overwrite anything parse_yaml_metadata() puts into the App
    instance.

    metadata/<Application ID>/<locale>/antifeatures/<Version Code>_<Anti-Feature>.txt
    metadata/<Application ID>/<locale>/antifeatures/<Anti-Feature>.txt

    └── metadata/
        └── <Application ID>/
            ├── en-US/
            │   └── antifeatures/
            │       ├── 123_Ads.txt       -> "includes ad lib"
            │       ├── 123_Tracking.txt  -> "standard suspects"
            │       └── NoSourceSince.txt -> "it vanished"
            │
            └── zh-CN/
                └── antifeatures/
                    └── 123_Ads.txt       -> "包括广告库"

    Gets parsed into the metadata data structure:

    AntiFeatures:
      NoSourceSince:
        en-US: it vanished
    Builds:
      - versionCode: 123
        antifeatures:
          Ads:
            en-US: includes ad lib
            zh-CN: 包括广告库
          Tracking:
            en-US: standard suspects

    """
    app_dir = Path('metadata', app['id'])
    if not app_dir.is_dir():
        return
    af_dup_msg = _('Duplicate Anti-Feature declaration at {path} was ignored!')

    if app.get('AntiFeatures'):
        app_has_AntiFeatures = True
    else:
        app_has_AntiFeatures = False

    has_versionCode = re.compile(r'^-?[0-9]+_.*')
    has_antifeatures_from_app = set()
    for build in app.get('Builds', []):
        antifeatures = build.get('antifeatures')
        if antifeatures:
            has_antifeatures_from_app.add(build['versionCode'])

    for f in sorted(app_dir.glob('*/antifeatures/*.txt')):
        path = f.as_posix()
        left = path.index('/', 9)  # 9 is length of "metadata/"
        right = path.index('/', left + 1)
        locale = path[left + 1 : right]
        description = f.read_text()
        if has_versionCode.match(f.stem):
            i = f.stem.index('_')
            versionCode = int(f.stem[:i])
            antifeature = f.stem[i + 1 :]
            if versionCode in has_antifeatures_from_app:
                logging.error(af_dup_msg.format(path=f))
                continue
            if 'Builds' not in app:
                app['Builds'] = []
            found = False
            for build in app['Builds']:
                # loop though builds again, there might be duplicate versionCodes
                if versionCode == build['versionCode']:
                    found = True
                    if 'antifeatures' not in build:
                        build['antifeatures'] = dict()
                    if antifeature not in build['antifeatures']:
                        build['antifeatures'][antifeature] = dict()
                    build['antifeatures'][antifeature][locale] = description
            if not found:
                app['Builds'].append(
                    {
                        'versionCode': versionCode,
                        'antifeatures': {
                            antifeature: {locale: description},
                        },
                    }
                )
        elif app_has_AntiFeatures:
            logging.error(af_dup_msg.format(path=f))
            continue
        else:
            if 'AntiFeatures' not in app:
                app['AntiFeatures'] = dict()
            if f.stem not in app['AntiFeatures']:
                app['AntiFeatures'][f.stem] = dict()
            app['AntiFeatures'][f.stem][locale] = f.read_text()


def _normalize_type_int(k, v):
    """Normalize anything that can be reliably converted to an integer."""
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    if v is None:
        return None
    if isinstance(v, str):
        try:
            return int(v)
        except ValueError:
            pass
    msg = _('{build_flag} must be an integer, found: {value}')
    _warn_or_exception(msg.format(build_flag=k, value=v))


def _normalize_type_string(v):
    """Normalize any data to TYPE_STRING.

    YAML 1.2's booleans are all lowercase.

    Things like versionName are strings, but without quotes can be
    numbers.  Like "versionName: 1.0" would be a YAML float, but
    should be a string.

    SHA-256 values are string values, but YAML 1.2 can interpret some
    unquoted values as decimal ints.  This converts those to a string
    if they are over 50 digits.  In the wild, the longest 0 padding on
    a SHA-256 key fingerprint I found was 8 zeros.

    """
    if isinstance(v, bool):
        if v:
            return 'true'
        return 'false'
    if isinstance(v, float):
        # YAML 1.2 values for NaN, Inf, and -Inf
        if math.isnan(v):
            return '.nan'
        if math.isinf(v):
            if v > 0:
                return '.inf'
            return '-.inf'
    if v and isinstance(v, int):
        if math.log10(v) > 50:  # only if the int has this many digits
            return '%064d' % v
    return str(v)


def _normalize_type_stringmap(k, v):
    """Normalize any data to TYPE_STRINGMAP.

    The internal representation of this format is a dict of dicts,
    where the outer dict's keys are things like tag names of
    Anti-Features, the inner dict's keys are locales, and the ultimate
    values are human readable text.

    Metadata entries like AntiFeatures: can be written in many
    forms, including a simple one-entry string, a list of strings,
    a dict with keys and descriptions as values, or a dict with
    localization.

    Returns
    -------
    A dictionary with string keys, where each value is either a string
    message or a dict with locale keys and string message values.

    """
    if v is None:
        return dict()
    if isinstance(v, str) or isinstance(v, int) or isinstance(v, float):
        return {_normalize_type_string(v): dict()}
    if isinstance(v, list) or isinstance(v, tuple) or isinstance(v, set):
        retdict = dict()
        for i in v:
            if isinstance(i, dict):
                # transitional format
                if len(i) != 1:
                    _warn_or_exception(
                        _(
                            "'{value}' is not a valid {field}, should be {pattern}"
                        ).format(field=k, value=v, pattern='key: value')
                    )
                afname = _normalize_type_string(next(iter(i)))
                desc = _normalize_type_string(next(iter(i.values())))
                retdict[afname] = {common.DEFAULT_LOCALE: desc}
            else:
                retdict[_normalize_type_string(i)] = {}
        return retdict

    retdict = dict()
    for af, afdict in v.items():
        key = _normalize_type_string(af)
        if afdict:
            if isinstance(afdict, dict):
                retdict[key] = afdict
            else:
                retdict[key] = {common.DEFAULT_LOCALE: _normalize_type_string(afdict)}
        else:
            retdict[key] = dict()

    return retdict


def _normalize_type_list(k, v):
    """Normalize any data to TYPE_LIST, which is always a list of strings."""
    if isinstance(v, dict):
        msg = _('{build_flag} must be list or string, found: {value}')
        _warn_or_exception(msg.format(build_flag=k, value=v))
    elif type(v) not in (list, tuple, set):
        v = [v]
    return [_normalize_type_string(i) for i in v]


def post_parse_yaml_metadata(yamldata):
    """Convert human-readable metadata data structures into consistent data structures.

    "Be conservative in what is written out, be liberal in what is parsed."
    https://en.wikipedia.org/wiki/Robustness_principle

    This also handles conversions that make metadata YAML behave
    something like StrictYAML.  Specifically, a field should have a
    fixed value type, regardless of YAML 1.2's type auto-detection.

    TODO: None values should probably be treated as the string 'null',
    since YAML 1.2 uses that for nulls

    """
    for k, v in yamldata.items():
        _fieldtype = fieldtype(k)
        if _fieldtype == TYPE_LIST:
            if v or v == 0:
                yamldata[k] = _normalize_type_list(k, v)
        elif _fieldtype == TYPE_INT:
            # ArchivePolicy used to require " versions" in the value.
            if k == 'ArchivePolicy' and isinstance(v, str):
                v = v.split(' ', maxsplit=1)[0]
            v = _normalize_type_int(k, v)
            if v or v == 0:
                yamldata[k] = v
        elif _fieldtype == TYPE_STRING:
            if v or v == 0:
                yamldata[k] = _normalize_type_string(v)
        elif _fieldtype == TYPE_STRINGMAP:
            if v or v == 0:  # TODO probably want just `if v:`
                yamldata[k] = _normalize_type_stringmap(k, v)
        elif _fieldtype == TYPE_BOOL:
            yamldata[k] = bool(v)
        else:
            if type(v) in (float, int):
                yamldata[k] = str(v)

    builds = []
    for build in yamldata.get('Builds', []):
        for k, v in build.items():
            if v is None:
                continue

            _flagtype = flagtype(k)
            if _flagtype == TYPE_STRING:
                if v or v == 0:
                    build[k] = _normalize_type_string(v)
            elif _flagtype == TYPE_INT:
                v = _normalize_type_int(k, v)
                if v or v == 0:
                    build[k] = v
            elif _flagtype in (TYPE_LIST, TYPE_SCRIPT):
                if v or v == 0:
                    build[k] = _normalize_type_list(k, v)
            elif _flagtype == TYPE_STRINGMAP:
                if v or v == 0:
                    build[k] = _normalize_type_stringmap(k, v)
            elif _flagtype == TYPE_BOOL:
                build[k] = bool(v)

        builds.append(build)

    if builds:
        yamldata['Builds'] = sorted(builds, key=lambda build: build['versionCode'])

    no_source_since = yamldata.get("NoSourceSince")
    # do not overwrite the description if it is there
    if no_source_since and not yamldata.get('AntiFeatures', {}).get('NoSourceSince'):
        if 'AntiFeatures' not in yamldata:
            yamldata['AntiFeatures'] = dict()
        yamldata['AntiFeatures']['NoSourceSince'] = {
            common.DEFAULT_LOCALE: no_source_since
        }


def _format_multiline(value):
    """TYPE_MULTILINE with newlines in them are saved as YAML literal strings."""
    if '\n' in value:
        return ruamel.yaml.scalarstring.preserve_literal(str(value))
    return str(value)


def _format_list(value):
    """TYPE_LIST should not contain null values."""
    return [v for v in value if v]


def _format_script(value):
    """TYPE_SCRIPT with one value are converted to YAML string values."""
    value = [v for v in value if v]
    if len(value) == 1:
        return value[0]
    return value


def _format_stringmap(appid, field, stringmap, versionCode=None):
    """Format TYPE_STRINGMAP taking into account localized files in the metadata dir.

    If there are any localized versions on the filesystem already,
    then move them all there.  Otherwise, keep them in the .yml file.

    The directory for the localized files that is named after the
    field is all lower case, following the convention set by Fastlane
    metadata, and used by fdroidserver.

    """
    app_dir = Path('metadata', appid)
    try:
        next(app_dir.glob('*/%s/*.txt' % field.lower()))
        files = []
        overwrites = []
        for name, descdict in stringmap.items():
            for locale, desc in descdict.items():
                outdir = app_dir / locale / field.lower()
                if versionCode:
                    filename = '%d_%s.txt' % (versionCode, name)
                else:
                    filename = '%s.txt' % name
                outfile = outdir / filename
                files.append(str(outfile))
                if outfile.exists():
                    if desc != outfile.read_text():
                        overwrites.append(str(outfile))
                else:
                    if not outfile.parent.exists():
                        outfile.parent.mkdir(parents=True)
                    outfile.write_text(desc)
        if overwrites:
            _warn_or_exception(
                _(
                    'Conflicting "{field}" definitions between .yml and localized files:'
                ).format(field=field)
                + '\n'
                + '\n'.join(sorted(overwrites))
            )
        logging.warning(
            _('Moving Anti-Features declarations to localized files:')
            + '\n'
            + '\n'.join(sorted(files))
        )
        return
    except StopIteration:
        pass
    make_list = True
    outlist = []
    for name in sorted(stringmap):
        outlist.append(name)
        descdict = stringmap.get(name)
        if descdict and any(descdict.values()):
            make_list = False
            break
    if make_list:
        return sorted(outlist, key=str.lower)
    return stringmap


def _del_duplicated_NoSourceSince(app):
    # noqa: D403 NoSourceSince is the word.
    """NoSourceSince gets auto-added to AntiFeatures, but can also be manually added."""
    key = 'NoSourceSince'
    if key in app:
        no_source_since = app.get(key)
        af_no_source_since = app.get('AntiFeatures', dict()).get(key)
        if af_no_source_since == {common.DEFAULT_LOCALE: no_source_since}:
            del app['AntiFeatures'][key]


def _builds_to_yaml(app):
    """Reformat Builds: flags for output to YAML 1.2.

    This will strip any flag/value that is not set or is empty.
    TYPE_BOOL fields are removed when they are false.  0 is valid
    value, it should not be stripped, so there are special cases to
    handle that.

    """
    builds = ruamel.yaml.comments.CommentedSeq()
    for build in app.get('Builds', []):
        b = ruamel.yaml.comments.CommentedMap()
        for field in build_flags:
            v = build.get(field)
            if v is None or v is False or v == '' or v == dict() or v == list():
                continue
            _flagtype = flagtype(field)
            if _flagtype == TYPE_MULTILINE:
                v = _format_multiline(v)
            elif _flagtype == TYPE_LIST:
                v = _format_list(v)
            elif _flagtype == TYPE_SCRIPT:
                v = _format_script(v)
            elif _flagtype == TYPE_STRINGMAP:
                v = _format_stringmap(app['id'], field, v, build['versionCode'])

            if v or v == 0:
                b[field] = v

        builds.append(b)

    # insert extra empty lines between build entries
    for i in range(1, len(builds)):
        builds.yaml_set_comment_before_after_key(i, 'bogus')
        builds.ca.items[i][1][-1].value = '\n'

    return builds


def _app_to_yaml(app):
    cm = ruamel.yaml.comments.CommentedMap()
    insert_newline = False
    for field in yaml_app_field_order:
        if field == '\n':
            # next iteration will need to insert a newline
            insert_newline = True
        else:
            value = app.get(field)
            if value or field in ('Builds', 'ArchivePolicy'):
                _fieldtype = fieldtype(field)
                if field == 'Builds':
                    if app.get('Builds'):
                        cm.update({field: _builds_to_yaml(app)})
                elif field == 'Categories':
                    cm[field] = sorted(value, key=str.lower)
                elif field == 'AntiFeatures':
                    v = _format_stringmap(app['id'], field, value)
                    if v:
                        cm[field] = v
                elif field == 'AllowedAPKSigningKeys':
                    value = [str(i).lower() for i in value]
                    if len(value) == 1:
                        cm[field] = value[0]
                    else:
                        cm[field] = value
                elif field == 'ArchivePolicy':
                    if value is None:
                        continue
                    cm[field] = value
                elif _fieldtype == TYPE_MULTILINE:
                    v = _format_multiline(value)
                    if v:
                        cm[field] = v
                elif _fieldtype == TYPE_SCRIPT:
                    v = _format_script(value)
                    if v:
                        cm[field] = v
                else:
                    if value:
                        cm[field] = value

                if insert_newline:
                    # we need to prepend a newline in front of this field
                    insert_newline = False
                    # inserting empty lines is not supported so we add a
                    # bogus comment and over-write its value
                    cm.yaml_set_comment_before_after_key(field, 'bogus')
                    cm.ca.items[field][1][-1].value = '\n'
    return cm


def write_yaml(mf, app):
    """Write metadata in yaml format.

    Parameters
    ----------
    mf
      active file discriptor for writing
    app
      app metadata to written to the yaml file

    """
    _del_duplicated_NoSourceSince(app)
    yaml_app = _app_to_yaml(app)
    yaml = ruamel.yaml.YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.dump(yaml_app, stream=mf)


def write_metadata(metadatapath, app):
    metadatapath = Path(metadatapath)
    if metadatapath.suffix == '.yml':
        with metadatapath.open('w') as mf:
            return write_yaml(mf, app)

    _warn_or_exception(_('Unknown metadata format: %s') % metadatapath)


def add_metadata_arguments(parser):
    """Add common command line flags related to metadata processing."""
    parser.add_argument(
        "-W",
        choices=['error', 'warn', 'ignore'],
        default='error',
        help=_("force metadata errors (default) to be warnings, or to be ignored."),
    )
