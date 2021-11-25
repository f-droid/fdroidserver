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
import platform
import re
import logging
import yaml
try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader
import importlib
from collections import OrderedDict

from . import common
from . import _
from .exception import MetaDataException, FDroidException

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
    'FlattrID',
    'Liberapay',
    'LiberapayID',
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
        self.AntiFeatures = []
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
        self.FlattrID = None
        self.Liberapay = None
        self.LiberapayID = None
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
        self.VercodeOperation = None
        self.UpdateCheckName = None
        self.UpdateCheckData = None
        self.CurrentVersion = ''
        self.CurrentVersionCode = None
        self.NoSourceSince = ''

        self.id = None
        self.metadatapath = None
        self.Builds = []
        self.comments = {}
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

    def get_last_build(self):
        if len(self.Builds) > 0:
            return self.Builds[-1]
        else:
            return Build()


TYPE_STRING = 2
TYPE_BOOL = 3
TYPE_LIST = 4
TYPE_SCRIPT = 5
TYPE_MULTILINE = 6
TYPE_BUILD = 7
TYPE_INT = 8

fieldtypes = {
    'Description': TYPE_MULTILINE,
    'MaintainerNotes': TYPE_MULTILINE,
    'Categories': TYPE_LIST,
    'AntiFeatures': TYPE_LIST,
    'AllowedAPKSigningKeys': TYPE_LIST,
    'Build': TYPE_BUILD,
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
    'buildozer',
    'output',
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
        self.maven = False
        self.buildozer = False
        self.output = None
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
        self.novcheck = False
        self.antifeatures = []
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

    def build_method(self):
        for f in ['maven', 'gradle', 'buildozer']:
            if self.get(f):
                return f
        if self.output:
            return 'raw'
        return 'ant'

    # like build_method, but prioritize output=
    def output_method(self):
        if self.output:
            return 'raw'
        for f in ['maven', 'gradle', 'buildozer']:
            if self.get(f):
                return f
        return 'ant'

    def ndk_path(self):
        """Return the path to the first configured NDK or an empty string."""
        ndk = self.ndk
        if isinstance(ndk, list):
            ndk = self.ndk[0]
        return common.config['ndk_paths'].get(ndk, '')


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
    'submodules': TYPE_BOOL,
    'oldsdkloc': TYPE_BOOL,
    'forceversion': TYPE_BOOL,
    'forcevercode': TYPE_BOOL,
    'novcheck': TYPE_BOOL,
    'antifeatures': TYPE_LIST,
    'timeout': TYPE_INT,
}


def flagtype(name):
    if name in flagtypes:
        return flagtypes[name]
    return TYPE_STRING


class FieldValidator():
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
                _warn_or_exception(_("'{value}' is not a valid {field} in {appid}. Regex pattern: {pattern}")
                                   .format(value=v, field=self.name, appid=appid, pattern=self.matching))


# Generic value types
valuetypes = {
    FieldValidator("Flattr ID",
                   r'^[0-9a-z]+$',
                   ['FlattrID']),

    FieldValidator("Liberapay",
                   VALID_USERNAME_REGEX,
                   ['Liberapay']),

    FieldValidator("Liberapay ID",
                   r'^[0-9]+$',
                   ['LiberapayID']),

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
                   r'^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$',
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

    FieldValidator("Archive Policy",
                   r'^[0-9]+ versions$',
                   ["ArchivePolicy"]),

    FieldValidator("Anti-Feature",
                   r'^(Ads|Tracking|NonFreeNet|NonFreeDep|NonFreeAdd|UpstreamNonFree|NonFreeAssets|KnownVuln|ApplicationDebuggable|NoSourceSince|NSFW)$',
                   ["AntiFeatures"]),

    FieldValidator("Auto Update Mode",
                   r"^(Version.*|None)$",
                   ["AutoUpdateMode"]),

    FieldValidator("Update Check Mode",
                   r"^(Tags|Tags .+|RepoManifest|RepoManifest/.+|RepoTrunk|HTTP|Static|None)$",
                   ["UpdateCheckMode"])
}


# Check an app's metadata information for integrity errors
def check_metadata(app):
    for v in valuetypes:
        for k in v.fields:
            v.check(app[k], app.id)


def parse_yaml_srclib(metadatapath):

    thisinfo = {'RepoType': '',
                'Repo': '',
                'Subdir': None,
                'Prepare': None}

    if not metadatapath.exists():
        _warn_or_exception(_("Invalid scrlib metadata: '{file}' "
                             "does not exist"
                             .format(file=metadatapath)))
        return thisinfo

    with metadatapath.open("r", encoding="utf-8") as f:
        try:
            data = yaml.load(f, Loader=SafeLoader)
            if type(data) is not dict:
                if platform.system() == 'Windows':
                    # Handle symlink on Windows
                    symlink = metadatapath.parent / metadatapath.read_text(encoding='utf-8')
                    if symlink.is_file():
                        with symlink.open("r", encoding="utf-8") as s:
                            data = yaml.load(s, Loader=SafeLoader)
            if type(data) is not dict:
                raise yaml.error.YAMLError(_('{file} is blank or corrupt!')
                                           .format(file=metadatapath))
        except yaml.error.YAMLError as e:
            _warn_or_exception(_("Invalid srclib metadata: could not "
                                 "parse '{file}'")
                               .format(file=metadatapath) + '\n'
                               + common.run_yamllint(metadatapath, indent=4),
                               cause=e)
            return thisinfo

    for key in data.keys():
        if key not in thisinfo.keys():
            _warn_or_exception(_("Invalid srclib metadata: unknown key "
                                 "'{key}' in '{file}'")
                               .format(key=key, file=metadatapath))
            return thisinfo
        else:
            if key == 'Subdir':
                if isinstance(data[key], str):
                    thisinfo[key] = data[key].split(',')
                elif isinstance(data[key], list):
                    thisinfo[key] = data[key]
                elif data[key] is None:
                    thisinfo[key] = ['']
            elif key == 'Prepare' and isinstance(data[key], list):
                thisinfo[key] = ' && '.join(data[key])
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


def read_metadata(appids={}, sort_by_time=False):
    """Return a list of App instances sorted newest first.

    This reads all of the metadata files in a 'data' repository, then
    builds a list of App instances from those files.  The list is
    sorted based on creation time, newest first.  Most of the time,
    the newer files are the most interesting.

    appids is a dict with appids a keys and versionCodes as values.

    """
    # Always read the srclibs before the apps, since they can use a srlib as
    # their source repository.
    read_srclibs()

    apps = OrderedDict()

    for basedir in ('metadata', 'tmp'):
        Path(basedir).mkdir(exist_ok=True)

    if appids:
        vercodes = common.read_pkg_args(appids)
        metadatafiles = common.get_metadata_files(vercodes)
    else:
        metadatafiles = list(Path('metadata').glob('*.yml')) + list(
            Path('.').glob('.fdroid.yml'))

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
            _warn_or_exception(_("{appid} from {path} is not a valid Java Package Name!")
                               .format(appid=appid, path=metadatapath))
        if appid in apps:
            _warn_or_exception(_("Found multiple metadata files for {appid}")
                               .format(appid=appid))
        app = parse_metadata(metadatapath)
        check_metadata(app)
        apps[app.id] = app

    return apps


# Port legacy ';' separators
list_sep = re.compile(r'[,;]')


def split_list_values(s):
    res = []
    for v in re.split(list_sep, s):
        if not v:
            continue
        v = v.strip()
        if not v:
            continue
        res.append(v)
    return res


def sorted_builds(builds):
    return sorted(builds, key=lambda build: int(build.versionCode))


esc_newlines = re.compile(r'\\( |\n)')


def post_metadata_parse(app):
    # TODO keep native types, convert only for .txt metadata
    for k, v in app.items():
        if type(v) in (float, int):
            app[k] = str(v)

    if 'flavours' in app and app['flavours'] == [True]:
        app['flavours'] = 'yes'

    for field, fieldtype in fieldtypes.items():
        if fieldtype != TYPE_LIST:
            continue
        value = app.get(field)
        if isinstance(value, str):
            app[field] = [value, ]
        elif value is not None:
            app[field] = [str(i) for i in value]

    def _yaml_bool_unmapable(v):
        return v in (True, False, [True], [False])

    def _yaml_bool_unmap(v):
        if v is True:
            return 'yes'
        elif v is False:
            return 'no'
        elif v == [True]:
            return ['yes']
        elif v == [False]:
            return ['no']

    _bool_allowed = ('maven', 'buildozer')

    builds = []
    if 'Builds' in app:
        for build in app.get('Builds', []):
            if not isinstance(build, Build):
                build = Build(build)
            for k, v in build.items():
                if not (v is None):
                    if flagtype(k) == TYPE_LIST:
                        if _yaml_bool_unmapable(v):
                            build[k] = _yaml_bool_unmap(v)

                        if isinstance(v, str):
                            build[k] = [v]
                        elif isinstance(v, bool):
                            if v:
                                build[k] = ['yes']
                            else:
                                build[k] = []
                    elif flagtype(k) is TYPE_INT:
                        build[k] = str(v)
                    elif flagtype(k) is TYPE_STRING:
                        if isinstance(v, bool) and k in _bool_allowed:
                            build[k] = v
                        else:
                            if _yaml_bool_unmapable(v):
                                build[k] = _yaml_bool_unmap(v)
                            else:
                                build[k] = str(v)
            builds.append(build)

    app['Builds'] = sorted_builds(builds)


# Parse metadata for a single application.
#
#  'metadatapath' - the file path to read. The "Application ID" aka
#               "Package Name" for the application comes from this
#               filename. Pass None to get a blank entry.
#
# Returns a dictionary containing all the details of the application. There are
# two major kinds of information in the dictionary. Keys beginning with capital
# letters correspond directory to identically named keys in the metadata file.
# Keys beginning with lower case letters are generated in one way or another,
# and are not found verbatim in the metadata.
#
# Known keys not originating from the metadata are:
#
#  'comments'         - a list of comments from the metadata file. Each is
#                       a list of the form [field, comment] where field is
#                       the name of the field it preceded in the metadata
#                       file. Where field is None, the comment goes at the
#                       end of the file. Alternatively, 'build:version' is
#                       for a comment before a particular build version.
#  'descriptionlines' - original lines of description as formatted in the
#                       metadata file.
#


bool_true = re.compile(r'([Yy]es|[Tt]rue)')
bool_false = re.compile(r'([Nn]o|[Ff]alse)')


def _decode_bool(s):
    if bool_true.match(s):
        return True
    if bool_false.match(s):
        return False
    _warn_or_exception(_("Invalid boolean '%s'") % s)


def parse_metadata(metadatapath):
    """Parse metadata file, also checking the source repo for .fdroid.yml.

    If this is a metadata file from fdroiddata, it will first load the
    source repo type and URL from fdroiddata, then read .fdroid.yml if
    it exists, then include the rest of the metadata as specified in
    fdroiddata, so that fdroiddata has precedence over the metadata in
    the source code.

    """
    metadatapath = Path(metadatapath)
    app = App()
    app.metadatapath = metadatapath.as_posix()
    name = metadatapath.stem
    if name != '.fdroid':
        app.id = name

    if metadatapath.suffix == '.yml':
        with metadatapath.open('r', encoding='utf-8') as mf:
            parse_yaml_metadata(mf, app)
    else:
        _warn_or_exception(_('Unknown metadata format: {path} (use: *.yml)')
                           .format(path=metadatapath))

    if metadatapath.name != '.fdroid.yml' and app.Repo:
        build_dir = common.get_build_dir(app)
        metadata_in_repo = build_dir / '.fdroid.yml'
        if metadata_in_repo.is_file():
            try:
                # TODO: Python3.6: Should accept path-like
                commit_id = common.get_head_commit_id(git.Repo(str(build_dir)))
                logging.debug(_('Including metadata from %s@%s') % (metadata_in_repo, commit_id))
            except git.exc.InvalidGitRepositoryError:
                logging.debug(_('Including metadata from {path}').format(metadata_in_repo))
            app_in_repo = parse_metadata(metadata_in_repo)
            for k, v in app_in_repo.items():
                if k not in app:
                    app[k] = v

    post_metadata_parse(app)

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


def parse_yaml_metadata(mf, app):
    """Parse the .yml file and post-process it.

    Clean metadata .yml files can be used directly, but in order to
    make a better user experience for people editing .yml files, there
    is post processing.  .fdroid.yml is embedded in the app's source
    repo, so it is "user-generated".  That means that it can have
    weird things in it that need to be removed so they don't break the
    overall process.

    """
    try:
        yamldata = yaml.load(mf, Loader=SafeLoader)
    except yaml.YAMLError as e:
        _warn_or_exception(_("could not parse '{path}'")
                           .format(path=mf.name) + '\n'
                           + common.run_yamllint(mf.name, indent=4),
                           cause=e)

    deprecated_in_yaml = ['Provides']

    if yamldata:
        for field in tuple(yamldata.keys()):
            if field not in yaml_app_fields + deprecated_in_yaml:
                msg = (_("Unrecognised app field '{fieldname}' in '{path}'")
                       .format(fieldname=field, path=mf.name))
                if Path(mf.name).name == '.fdroid.yml':
                    logging.error(msg)
                    del yamldata[field]
                else:
                    _warn_or_exception(msg)

        for deprecated_field in deprecated_in_yaml:
            if deprecated_field in yamldata:
                logging.warning(_("Ignoring '{field}' in '{metapath}' "
                                  "metadata because it is deprecated.")
                                .format(field=deprecated_field,
                                        metapath=mf.name))
                del(yamldata[deprecated_field])

        if yamldata.get('Builds', None):
            for build in yamldata.get('Builds', []):
                # put all build flag keywords into a set to avoid
                # excessive looping action
                build_flag_set = set()
                for build_flag in build.keys():
                    build_flag_set.add(build_flag)
                for build_flag in build_flag_set:
                    if build_flag not in build_flags:
                        _warn_or_exception(
                            _("Unrecognised build flag '{build_flag}' "
                              "in '{path}'").format(build_flag=build_flag,
                                                    path=mf.name))
        post_parse_yaml_metadata(yamldata)
        app.update(yamldata)
    return app


def post_parse_yaml_metadata(yamldata):
    """Transform yaml metadata to our internal data format."""
    for build in yamldata.get('Builds', []):
        for flag in build.keys():
            _flagtype = flagtype(flag)

            if _flagtype is TYPE_SCRIPT:
                # concatenate script flags into a single string if they are stored as list
                if isinstance(build[flag], list):
                    build[flag] = ' && '.join(build[flag])
            elif _flagtype is TYPE_STRING:
                # things like versionNames are strings, but without quotes can be numbers
                if isinstance(build[flag], float) or isinstance(build[flag], int):
                    build[flag] = str(build[flag])
            elif _flagtype is TYPE_INT:
                # versionCode must be int
                if not isinstance(build[flag], int):
                    _warn_or_exception(_('{build_flag} must be an integer, found: {value}')
                                       .format(build_flag=flag, value=build[flag]))


def write_yaml(mf, app):
    """Write metadata in yaml format.

    Parameters
    ----------
    mf
      active file discriptor for writing
    app
      app metadata to written to the yaml file
    """
    # import rumael.yaml and check version
    try:
        import ruamel.yaml
    except ImportError as e:
        raise FDroidException('ruamel.yaml not installed, can not write metadata.') from e
    if not ruamel.yaml.__version__:
        raise FDroidException('ruamel.yaml.__version__ not accessible. Please make sure a ruamel.yaml >= 0.13 is installed..')
    m = re.match(r'(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)(-.+)?',
                 ruamel.yaml.__version__)
    if not m:
        raise FDroidException('ruamel.yaml version malfored, please install an upstream version of ruamel.yaml')
    if int(m.group('major')) < 0 or int(m.group('minor')) < 13:
        raise FDroidException('currently installed version of ruamel.yaml ({}) is too old, >= 1.13 required.'.format(ruamel.yaml.__version__))
    # suiteable version ruamel.yaml imported successfully

    _yaml_bools_true = ('y', 'Y', 'yes', 'Yes', 'YES',
                        'true', 'True', 'TRUE',
                        'on', 'On', 'ON')
    _yaml_bools_false = ('n', 'N', 'no', 'No', 'NO',
                         'false', 'False', 'FALSE',
                         'off', 'Off', 'OFF')
    _yaml_bools_plus_lists = []
    _yaml_bools_plus_lists.extend(_yaml_bools_true)
    _yaml_bools_plus_lists.extend([[x] for x in _yaml_bools_true])
    _yaml_bools_plus_lists.extend(_yaml_bools_false)
    _yaml_bools_plus_lists.extend([[x] for x in _yaml_bools_false])

    def _field_to_yaml(typ, value):
        if typ is TYPE_STRING:
            if value in _yaml_bools_plus_lists:
                return ruamel.yaml.scalarstring.SingleQuotedScalarString(str(value))
            return str(value)
        elif typ is TYPE_INT:
            return int(value)
        elif typ is TYPE_MULTILINE:
            if '\n' in value:
                return ruamel.yaml.scalarstring.preserve_literal(str(value))
            else:
                return str(value)
        elif typ is TYPE_SCRIPT:
            if type(value) == list:
                if len(value) == 1:
                    return value[0]
                else:
                    return value
            else:
                script_lines = value.split(' && ')
                if len(script_lines) > 1:
                    return script_lines
                else:
                    return value
        else:
            return value

    def _app_to_yaml(app):
        cm = ruamel.yaml.comments.CommentedMap()
        insert_newline = False
        for field in yaml_app_field_order:
            if field == '\n':
                # next iteration will need to insert a newline
                insert_newline = True
            else:
                if app.get(field) or field == 'Builds':
                    if field == 'Builds':
                        if app.get('Builds'):
                            cm.update({field: _builds_to_yaml(app)})
                    elif field == 'CurrentVersionCode':
                        cm.update({field: _field_to_yaml(TYPE_INT, getattr(app, field))})
                    elif field == 'AllowedAPKSigningKeys':
                        value = getattr(app, field)
                        if value:
                            value = [str(i).lower() for i in value]
                            if len(value) == 1:
                                cm.update({field: _field_to_yaml(TYPE_STRING, value[0])})
                            else:
                                cm.update({field: _field_to_yaml(TYPE_LIST, value)})
                    else:
                        cm.update({field: _field_to_yaml(fieldtype(field), getattr(app, field))})

                    if insert_newline:
                        # we need to prepend a newline in front of this field
                        insert_newline = False
                        # inserting empty lines is not supported so we add a
                        # bogus comment and over-write its value
                        cm.yaml_set_comment_before_after_key(field, 'bogus')
                        cm.ca.items[field][1][-1].value = '\n'
        return cm

    def _builds_to_yaml(app):
        builds = ruamel.yaml.comments.CommentedSeq()
        for build in app.get('Builds', []):
            if not isinstance(build, Build):
                build = Build(build)
            b = ruamel.yaml.comments.CommentedMap()
            for field in build_flags:
                value = getattr(build, field)
                if hasattr(build, field) and value:
                    if field == 'gradle' and value == ['off']:
                        value = [ruamel.yaml.scalarstring.SingleQuotedScalarString('off')]
                    if field in ('maven', 'buildozer'):
                        if value == 'no':
                            continue
                        elif value == 'yes':
                            value = 'yes'
                    b.update({field: _field_to_yaml(flagtype(field), value)})
            builds.append(b)

        # insert extra empty lines between build entries
        for i in range(1, len(builds)):
            builds.yaml_set_comment_before_after_key(i, 'bogus')
            builds.ca.items[i][1][-1].value = '\n'

        return builds

    yaml_app = _app_to_yaml(app)
    try:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=4, sequence=4, offset=2)
        yaml.dump(yaml_app, stream=mf)
    except AttributeError:  # Debian/stretch's version does not have YAML()
        ruamel.yaml.round_trip_dump(yaml_app, mf, indent=4, block_seq_indent=2)


build_line_sep = re.compile(r'(?<!\\),')
build_cont = re.compile(r'^[ \t]')


def write_metadata(metadatapath, app):
    metadatapath = Path(metadatapath)
    if metadatapath.suffix == '.yml':
        if importlib.util.find_spec('ruamel.yaml'):
            with metadatapath.open('w') as mf:
                return write_yaml(mf, app)
        else:
            raise FDroidException(_('ruamel.yaml not installed, can not write metadata.'))

    _warn_or_exception(_('Unknown metadata format: %s') % metadatapath)


def add_metadata_arguments(parser):
    """Add common command line flags related to metadata processing."""
    parser.add_argument("-W", choices=['error', 'warn', 'ignore'], default='error',
                        help=_("force metadata errors (default) to be warnings, or to be ignored."))
