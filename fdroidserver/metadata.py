#!/usr/bin/env python3
#
# metadata.py - part of the FDroid server tools
# Copyright (C) 2013, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
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

import json
import os
import re
import glob
import html
import logging
import textwrap
import io
import yaml
from collections import OrderedDict
# use libyaml if it is available
try:
    from yaml import CLoader
    YamlLoader = CLoader
except ImportError:
    from yaml import Loader
    YamlLoader = Loader

import fdroidserver.common
from fdroidserver import _
from fdroidserver.exception import MetaDataException, FDroidException

srclibs = None
warnings_action = None


def warn_or_exception(value):
    '''output warning or Exception depending on -W'''
    if warnings_action == 'ignore':
        pass
    elif warnings_action == 'error':
        raise MetaDataException(value)
    else:
        logging.warning(value)


# To filter which ones should be written to the metadata files if
# present
app_fields = set([
    'Disabled',
    'AntiFeatures',
    'Provides',
    'Categories',
    'License',
    'Author Name',
    'Author Email',
    'Author Web Site',
    'Web Site',
    'Source Code',
    'Issue Tracker',
    'Translation',
    'Changelog',
    'Donate',
    'FlattrID',
    'LiberapayID',
    'Bitcoin',
    'Litecoin',
    'Name',
    'Auto Name',
    'Summary',
    'Description',
    'Requires Root',
    'Repo Type',
    'Repo',
    'Binaries',
    'Maintainer Notes',
    'Archive Policy',
    'Auto Update Mode',
    'Update Check Mode',
    'Update Check Ignore',
    'Vercode Operation',
    'Update Check Name',
    'Update Check Data',
    'Current Version',
    'Current Version Code',
    'No Source Since',
    'Build',

    'comments',  # For formats that don't do inline comments
    'builds',    # For formats that do builds as a list
])


class App(dict):

    def __init__(self, copydict=None):
        if copydict:
            super().__init__(copydict)
            return
        super().__init__()

        self.Disabled = None
        self.AntiFeatures = []
        self.Provides = None
        self.Categories = ['None']
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
        self.LiberapayID = None
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
        self.builds = []
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
        if len(self.builds) > 0:
            return self.builds[-1]
        else:
            return Build()


TYPE_UNKNOWN = 0
TYPE_OBSOLETE = 1
TYPE_STRING = 2
TYPE_BOOL = 3
TYPE_LIST = 4
TYPE_SCRIPT = 5
TYPE_MULTILINE = 6
TYPE_BUILD = 7
TYPE_BUILD_V2 = 8
TYPE_INT = 9

fieldtypes = {
    'Description': TYPE_MULTILINE,
    'MaintainerNotes': TYPE_MULTILINE,
    'Categories': TYPE_LIST,
    'AntiFeatures': TYPE_LIST,
    'BuildVersion': TYPE_BUILD,
    'Build': TYPE_BUILD_V2,
    'UseBuilt': TYPE_OBSOLETE,
}


def fieldtype(name):
    name = name.replace(' ', '')
    if name in fieldtypes:
        return fieldtypes[name]
    return TYPE_STRING


# In the order in which they are laid out on files
build_flags_order = [
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

# old .txt format has version name/code inline in the 'Build:' line
# but YAML and JSON have a explicit key for them
build_flags = ['versionName', 'versionCode'] + build_flags_order


class Build(dict):

    def __init__(self, copydict=None):
        super().__init__()
        self.disable = False
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
        version = self.ndk
        if not version:
            version = 'r12b'  # falls back to latest
        paths = fdroidserver.common.config['ndk_paths']
        if version not in paths:
            return ''
        return paths[version]


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
    """
    Designates App metadata field types and checks that it matches

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
                warn_or_exception(_("'{value}' is not a valid {field} in {appid}. Regex pattern: {pattern}")
                                  .format(value=v, field=self.name, appid=appid, pattern=self.matching))


# Generic value types
valuetypes = {
    FieldValidator("Flattr ID",
                   r'^[0-9a-z]+$',
                   ['FlattrID']),

    FieldValidator("Liberapay ID",
                   r'^[0-9]+$',
                   ['LiberapayID']),

    FieldValidator("HTTP link",
                   r'^http[s]?://',
                   ["WebSite", "SourceCode", "IssueTracker", "Translation", "Changelog", "Donate"]),

    FieldValidator("Email",
                   r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
                   ["AuthorEmail"]),

    FieldValidator("Bitcoin address",
                   r'^[a-zA-Z0-9]{27,34}$',
                   ["Bitcoin"]),

    FieldValidator("Litecoin address",
                   r'^L[a-zA-Z0-9]{33}$',
                   ["Litecoin"]),

    FieldValidator("Repo Type",
                   r'^(git|git-svn|svn|hg|bzr|srclib)$',
                   ["RepoType"]),

    FieldValidator("Binaries",
                   r'^http[s]?://',
                   ["Binaries"]),

    FieldValidator("Archive Policy",
                   r'^[0-9]+ versions$',
                   ["ArchivePolicy"]),

    FieldValidator("Anti-Feature",
                   r'^(Ads|Tracking|NonFreeNet|NonFreeDep|NonFreeAdd|UpstreamNonFree|NonFreeAssets|KnownVuln|ApplicationDebuggable)$',
                   ["AntiFeatures"]),

    FieldValidator("Auto Update Mode",
                   r"^(Version .+|None)$",
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


# Formatter for descriptions. Create an instance, and call parseline() with
# each line of the description source from the metadata. At the end, call
# end() and then text_txt and text_html will contain the result.
class DescriptionFormatter:

    stNONE = 0
    stPARA = 1
    stUL = 2
    stOL = 3

    def __init__(self, linkres):
        self.bold = False
        self.ital = False
        self.state = self.stNONE
        self.laststate = self.stNONE
        self.text_html = ''
        self.text_txt = ''
        self.html = io.StringIO()
        self.text = io.StringIO()
        self.para_lines = []
        self.linkResolver = None
        self.linkResolver = linkres

    def endcur(self, notstates=None):
        if notstates and self.state in notstates:
            return
        if self.state == self.stPARA:
            self.endpara()
        elif self.state == self.stUL:
            self.endul()
        elif self.state == self.stOL:
            self.endol()

    def endpara(self):
        self.laststate = self.state
        self.state = self.stNONE
        whole_para = ' '.join(self.para_lines)
        self.addtext(whole_para)
        wrapped = textwrap.fill(whole_para, 80,
                                break_long_words=False,
                                break_on_hyphens=False)
        self.text.write(wrapped)
        self.html.write('</p>')
        del self.para_lines[:]

    def endul(self):
        self.html.write('</ul>')
        self.laststate = self.state
        self.state = self.stNONE

    def endol(self):
        self.html.write('</ol>')
        self.laststate = self.state
        self.state = self.stNONE

    def formatted(self, txt, htmlbody):
        res = ''
        if htmlbody:
            txt = html.escape(txt, quote=False)
        while True:
            index = txt.find("''")
            if index == -1:
                return res + txt
            res += txt[:index]
            txt = txt[index:]
            if txt.startswith("'''"):
                if htmlbody:
                    if self.bold:
                        res += '</b>'
                    else:
                        res += '<b>'
                self.bold = not self.bold
                txt = txt[3:]
            else:
                if htmlbody:
                    if self.ital:
                        res += '</i>'
                    else:
                        res += '<i>'
                self.ital = not self.ital
                txt = txt[2:]

    def linkify(self, txt):
        res_plain = ''
        res_html = ''
        while True:
            index = txt.find("[")
            if index == -1:
                return (res_plain + self.formatted(txt, False), res_html + self.formatted(txt, True))
            res_plain += self.formatted(txt[:index], False)
            res_html += self.formatted(txt[:index], True)
            txt = txt[index:]
            if txt.startswith("[["):
                index = txt.find("]]")
                if index == -1:
                    warn_or_exception(_("Unterminated ]]"))
                url = txt[2:index]
                if self.linkResolver:
                    url, urltext = self.linkResolver(url)
                else:
                    urltext = url
                res_html += '<a href="' + url + '">' + html.escape(urltext, quote=False) + '</a>'
                res_plain += urltext
                txt = txt[index + 2:]
            else:
                index = txt.find("]")
                if index == -1:
                    warn_or_exception(_("Unterminated ]"))
                url = txt[1:index]
                index2 = url.find(' ')
                if index2 == -1:
                    urltxt = url
                else:
                    urltxt = url[index2 + 1:]
                    url = url[:index2]
                    if url == urltxt:
                        warn_or_exception(_("URL title is just the URL, use brackets: [URL]"))
                res_html += '<a href="' + url + '">' + html.escape(urltxt, quote=False) + '</a>'
                res_plain += urltxt
                if urltxt != url:
                    res_plain += ' (' + url + ')'
                txt = txt[index + 1:]

    def addtext(self, txt):
        p, h = self.linkify(txt)
        self.html.write(h)

    def parseline(self, line):
        if not line:
            self.endcur()
        elif line.startswith('* '):
            self.endcur([self.stUL])
            if self.state != self.stUL:
                self.html.write('<ul>')
                self.state = self.stUL
                if self.laststate != self.stNONE:
                    self.text.write('\n\n')
            else:
                self.text.write('\n')
            self.text.write(line)
            self.html.write('<li>')
            self.addtext(line[1:])
            self.html.write('</li>')
        elif line.startswith('# '):
            self.endcur([self.stOL])
            if self.state != self.stOL:
                self.html.write('<ol>')
                self.state = self.stOL
                if self.laststate != self.stNONE:
                    self.text.write('\n\n')
            else:
                self.text.write('\n')
            self.text.write(line)
            self.html.write('<li>')
            self.addtext(line[1:])
            self.html.write('</li>')
        else:
            self.para_lines.append(line)
            self.endcur([self.stPARA])
            if self.state == self.stNONE:
                self.state = self.stPARA
                if self.laststate != self.stNONE:
                    self.text.write('\n\n')
                self.html.write('<p>')

    def end(self):
        self.endcur()
        self.text_txt = self.text.getvalue()
        self.text_html = self.html.getvalue()
        self.text.close()
        self.html.close()


# Parse multiple lines of description as written in a metadata file, returning
# a single string in text format and wrapped to 80 columns.
def description_txt(s):
    ps = DescriptionFormatter(None)
    for line in s.splitlines():
        ps.parseline(line)
    ps.end()
    return ps.text_txt


# Parse multiple lines of description as written in a metadata file, returning
# a single string in wiki format. Used for the Maintainer Notes field as well,
# because it's the same format.
def description_wiki(s):
    return s


# Parse multiple lines of description as written in a metadata file, returning
# a single string in HTML format.
def description_html(s, linkres):
    ps = DescriptionFormatter(linkres)
    for line in s.splitlines():
        ps.parseline(line)
    ps.end()
    return ps.text_html


def parse_srclib(metadatapath):

    thisinfo = {}

    # Defaults for fields that come from metadata
    thisinfo['Repo Type'] = ''
    thisinfo['Repo'] = ''
    thisinfo['Subdir'] = None
    thisinfo['Prepare'] = None

    if not os.path.exists(metadatapath):
        return thisinfo

    metafile = open(metadatapath, "r", encoding='utf-8')

    n = 0
    for line in metafile:
        n += 1
        line = line.rstrip('\r\n')
        if not line or line.startswith("#"):
            continue

        try:
            f, v = line.split(':', 1)
        except ValueError:
            warn_or_exception(_("Invalid metadata in %s:%d") % (line, n))

        if f == "Subdir":
            thisinfo[f] = v.split(',')
        else:
            thisinfo[f] = v

    metafile.close()

    return thisinfo


def read_srclibs():
    """Read all srclib metadata.

    The information read will be accessible as metadata.srclibs, which is a
    dictionary, keyed on srclib name, with the values each being a dictionary
    in the same format as that returned by the parse_srclib function.

    A MetaDataException is raised if there are any problems with the srclib
    metadata.
    """
    global srclibs

    # They were already loaded
    if srclibs is not None:
        return

    srclibs = {}

    srcdir = 'srclibs'
    if not os.path.exists(srcdir):
        os.makedirs(srcdir)

    for metadatapath in sorted(glob.glob(os.path.join(srcdir, '*.txt'))):
        srclibname = os.path.basename(metadatapath[:-4])
        srclibs[srclibname] = parse_srclib(metadatapath)


def read_metadata(xref=True, check_vcs=[], refresh=True, sort_by_time=False):
    """Return a list of App instances sorted newest first

    This reads all of the metadata files in a 'data' repository, then
    builds a list of App instances from those files.  The list is
    sorted based on creation time, newest first.  Most of the time,
    the newer files are the most interesting.

    If there are multiple metadata files for a single appid, then the first
    file that is parsed wins over all the others, and the rest throw an
    exception. So the original .txt format is parsed first, at least until
    newer formats stabilize.

    check_vcs is the list of appids to check for .fdroid.yml in source

    """

    # Always read the srclibs before the apps, since they can use a srlib as
    # their source repository.
    read_srclibs()

    apps = OrderedDict()

    for basedir in ('metadata', 'tmp'):
        if not os.path.exists(basedir):
            os.makedirs(basedir)

    metadatafiles = (glob.glob(os.path.join('metadata', '*.txt'))
                     + glob.glob(os.path.join('metadata', '*.json'))
                     + glob.glob(os.path.join('metadata', '*.yml'))
                     + glob.glob('.fdroid.txt')
                     + glob.glob('.fdroid.json')
                     + glob.glob('.fdroid.yml'))

    if sort_by_time:
        entries = ((os.stat(path).st_mtime, path) for path in metadatafiles)
        metadatafiles = []
        for _ignored, path in sorted(entries, reverse=True):
            metadatafiles.append(path)
    else:
        # most things want the index alpha sorted for stability
        metadatafiles = sorted(metadatafiles)

    for metadatapath in metadatafiles:
        if metadatapath == '.fdroid.txt':
            warn_or_exception(_('.fdroid.txt is not supported!  Convert to .fdroid.yml or .fdroid.json.'))
        appid, _ignored = fdroidserver.common.get_extension(os.path.basename(metadatapath))
        if appid in apps:
            warn_or_exception(_("Found multiple metadata files for {appid}")
                              .format(appid=appid))
        app = parse_metadata(metadatapath, appid in check_vcs, refresh)
        check_metadata(app)
        apps[app.id] = app

    if xref:
        # Parse all descriptions at load time, just to ensure cross-referencing
        # errors are caught early rather than when they hit the build server.
        def linkres(appid):
            if appid in apps:
                return ("fdroid.app:" + appid, "Dummy name - don't know yet")
            warn_or_exception(_("Cannot resolve app id {appid}").format(appid=appid))

        for appid, app in apps.items():
            try:
                description_html(app.Description, linkres)
            except MetaDataException as e:
                warn_or_exception(_("Problem with description of {appid}: {error}")
                                  .format(appid=appid, error=str(e)))

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


def get_default_app_info(metadatapath=None):
    if metadatapath is None:
        appid = None
    else:
        appid, _ignored = fdroidserver.common.get_extension(os.path.basename(metadatapath))

    if appid == '.fdroid':  # we have local metadata in the app's source
        if os.path.exists('AndroidManifest.xml'):
            manifestroot = fdroidserver.common.parse_xml('AndroidManifest.xml')
        else:
            pattern = re.compile(""".*manifest\.srcFile\s+'AndroidManifest\.xml'.*""")
            for root, dirs, files in os.walk(os.getcwd()):
                if 'build.gradle' in files:
                    p = os.path.join(root, 'build.gradle')
                    with open(p, 'rb') as f:
                        data = f.read()
                    m = pattern.search(data)
                    if m:
                        logging.debug('Using: ' + os.path.join(root, 'AndroidManifest.xml'))
                        manifestroot = fdroidserver.common.parse_xml(os.path.join(root, 'AndroidManifest.xml'))
                        break
        if manifestroot is None:
            warn_or_exception(_("Cannot find an appid for {path}!")
                              .format(path=metadatapath))
        appid = manifestroot.attrib['package']

    app = App()
    app.metadatapath = metadatapath
    if appid is not None:
        app.id = appid

    return app


def sorted_builds(builds):
    return sorted(builds, key=lambda build: int(build.versionCode))


esc_newlines = re.compile(r'\\( |\n)')


def post_metadata_parse(app):
    # TODO keep native types, convert only for .txt metadata
    for k, v in app.items():
        if type(v) in (float, int):
            app[k] = str(v)

    if 'Builds' in app:
        app['builds'] = app.pop('Builds')

    if 'flavours' in app and app['flavours'] == [True]:
        app['flavours'] = 'yes'

    if isinstance(app.Categories, str):
        app.Categories = [app.Categories]
    elif app.Categories is None:
        app.Categories = ['None']
    else:
        app.Categories = [str(i) for i in app.Categories]

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

    _bool_allowed = ('disable', 'maven', 'buildozer')

    builds = []
    if 'builds' in app:
        for build in app['builds']:
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

    app.builds = sorted_builds(builds)


# Parse metadata for a single application.
#
#  'metadatapath' - the filename to read. The "Application ID" aka
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
#  'builds'           - a list of dictionaries containing build information
#                       for each defined build
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
    warn_or_exception(_("Invalid boolean '%s'") % s)


def parse_metadata(metadatapath, check_vcs=False, refresh=True):
    '''parse metadata file, optionally checking the git repo for metadata first'''

    _ignored, ext = fdroidserver.common.get_extension(metadatapath)
    accepted = fdroidserver.common.config['accepted_formats']
    if ext not in accepted:
        warn_or_exception(_('"{path}" is not an accepted format, convert to: {formats}')
                          .format(path=metadatapath, formats=', '.join(accepted)))

    app = App()
    app.metadatapath = metadatapath
    name, _ignored = fdroidserver.common.get_extension(os.path.basename(metadatapath))
    if name == '.fdroid':
        check_vcs = False
    else:
        app.id = name

    with open(metadatapath, 'r', encoding='utf-8') as mf:
        if ext == 'txt':
            parse_txt_metadata(mf, app)
        elif ext == 'json':
            parse_json_metadata(mf, app)
        elif ext == 'yml':
            parse_yaml_metadata(mf, app)
        else:
            warn_or_exception(_('Unknown metadata format: {path}')
                              .format(path=metadatapath))

    if check_vcs and app.Repo:
        build_dir = fdroidserver.common.get_build_dir(app)
        metadata_in_repo = os.path.join(build_dir, '.fdroid.yml')
        if not os.path.isfile(metadata_in_repo):
            vcs, build_dir = fdroidserver.common.setup_vcs(app)
            if isinstance(vcs, fdroidserver.common.vcs_git):
                vcs.gotorevision('HEAD', refresh)  # HEAD since we can't know where else to go
        if os.path.isfile(metadata_in_repo):
            logging.debug('Including metadata from ' + metadata_in_repo)
            # do not include fields already provided by main metadata file
            app_in_repo = parse_metadata(metadata_in_repo)
            for k, v in app_in_repo.items():
                if k not in app:
                    app[k] = v

    post_metadata_parse(app)

    if not app.id:
        if app.builds:
            build = app.builds[-1]
            if build.subdir:
                root_dir = build.subdir
            else:
                root_dir = '.'
            paths = fdroidserver.common.manifest_paths(root_dir, build.gradle)
            _ignored, _ignored, app.id = fdroidserver.common.parse_androidmanifests(paths, app)

    return app


def parse_json_metadata(mf, app):

    # fdroid metadata is only strings and booleans, no floats or ints.
    # TODO create schema using https://pypi.python.org/pypi/jsonschema
    jsoninfo = json.load(mf, parse_int=lambda s: s,
                         parse_float=lambda s: s)
    app.update(jsoninfo)
    for f in ['Description', 'Maintainer Notes']:
        v = app.get(f)
        if v:
            app[f] = '\n'.join(v)
    return app


def parse_yaml_metadata(mf, app):
    yamldata = yaml.load(mf, Loader=YamlLoader)
    if yamldata:
        app.update(yamldata)
    return app


def write_yaml(mf, app):

    # import rumael.yaml and check version
    try:
        import ruamel.yaml
    except ImportError as e:
        raise FDroidException('ruamel.yaml not instlled, can not write metadata.') from e
    if not ruamel.yaml.__version__:
        raise FDroidException('ruamel.yaml.__version__ not accessible. Please make sure a ruamel.yaml >= 0.13 is installed..')
    m = re.match('(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)(-.+)?',
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

    def _class_as_dict_representer(dumper, data):
        '''Creates a YAML representation of a App/Build instance'''
        return dumper.represent_dict(data)

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
            if len(value) > 50:
                return ruamel.yaml.scalarstring.preserve_literal(value)
            else:
                return value
        else:
            return value

    def _app_to_yaml(app):
        cm = ruamel.yaml.comments.CommentedMap()
        insert_newline = False
        for field in yaml_app_field_order:
            if field is '\n':
                # next iteration will need to insert a newline
                insert_newline = True
            else:
                if app.get(field) or field is 'Builds':
                    # .txt calls it 'builds' internally, everywhere else its 'Builds'
                    if field is 'Builds':
                        if app.get('builds'):
                            cm.update({field: _builds_to_yaml(app)})
                    elif field is 'CurrentVersionCode':
                        cm.update({field: _field_to_yaml(TYPE_INT, getattr(app, field))})
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
        fields = ['versionName', 'versionCode']
        fields.extend(build_flags_order)
        builds = ruamel.yaml.comments.CommentedSeq()
        for build in app.builds:
            b = ruamel.yaml.comments.CommentedMap()
            for field in fields:
                if hasattr(build, field) and getattr(build, field):
                    value = getattr(build, field)
                    if field == 'gradle' and value == ['off']:
                        value = [ruamel.yaml.scalarstring.SingleQuotedScalarString('off')]
                    if field in ('disable', 'maven', 'buildozer'):
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

    yaml_app_field_order = [
        'Disabled',
        'AntiFeatures',
        'Provides',
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
        'LiberapayID',
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

    yaml_app = _app_to_yaml(app)
    ruamel.yaml.round_trip_dump(yaml_app, mf, indent=4, block_seq_indent=2)


build_line_sep = re.compile(r'(?<!\\),')
build_cont = re.compile(r'^[ \t]')


def parse_txt_metadata(mf, app):

    linedesc = None

    def add_buildflag(p, build):
        if not p.strip():
            warn_or_exception(_("Empty build flag at {linedesc}")
                              .format(linedesc=linedesc))
        bv = p.split('=', 1)
        if len(bv) != 2:
            warn_or_exception(_("Invalid build flag at {line} in {linedesc}")
                              .format(line=buildlines[0], linedesc=linedesc))

        pk, pv = bv
        pk = pk.lstrip()
        if pk == 'update':
            pk = 'androidupdate'  # avoid conflicting with Build(dict).update()
        t = flagtype(pk)
        if t == TYPE_LIST:
            pv = split_list_values(pv)
            build[pk] = pv
        elif t == TYPE_STRING or t == TYPE_SCRIPT:
            build[pk] = pv
        elif t == TYPE_BOOL:
            build[pk] = _decode_bool(pv)
        elif t == TYPE_INT:
            build[pk] = int(pv)

    def parse_buildline(lines):
        v = "".join(lines)
        parts = [p.replace("\\,", ",") for p in re.split(build_line_sep, v)]
        if len(parts) < 3:
            warn_or_exception(_("Invalid build format: {value} in {name}")
                              .format(value=v, name=mf.name))
        build = Build()
        build.versionName = parts[0]
        build.versionCode = parts[1]
        check_versionCode(build.versionCode)

        if parts[2].startswith('!'):
            # For backwards compatibility, handle old-style disabling,
            # including attempting to extract the commit from the message
            build.disable = parts[2][1:]
            commit = 'unknown - see disabled'
            index = parts[2].rfind('at ')
            if index != -1:
                commit = parts[2][index + 3:]
                if commit.endswith(')'):
                    commit = commit[:-1]
            build.commit = commit
        else:
            build.commit = parts[2]
        for p in parts[3:]:
            add_buildflag(p, build)

        return build

    def check_versionCode(versionCode):
        try:
            int(versionCode)
        except ValueError:
            warn_or_exception(_('Invalid versionCode: "{versionCode}" is not an integer!')
                              .format(versionCode=versionCode))

    def add_comments(key):
        if not curcomments:
            return
        app.comments[key] = list(curcomments)
        del curcomments[:]

    mode = 0
    buildlines = []
    multiline_lines = []
    curcomments = []
    build = None
    vc_seen = set()

    app.builds = []

    c = 0
    for line in mf:
        c += 1
        linedesc = "%s:%d" % (mf.name, c)
        line = line.rstrip('\r\n')
        if mode == 3:
            if build_cont.match(line):
                if line.endswith('\\'):
                    buildlines.append(line[:-1].lstrip())
                else:
                    buildlines.append(line.lstrip())
                    bl = ''.join(buildlines)
                    add_buildflag(bl, build)
                    del buildlines[:]
            else:
                if not build.commit and not build.disable:
                    warn_or_exception(_("No commit specified for {versionName} in {linedesc}")
                                      .format(versionName=build.versionName, linedesc=linedesc))

                app.builds.append(build)
                add_comments('build:' + build.versionCode)
                mode = 0

        if mode == 0:
            if not line:
                continue
            if line.startswith("#"):
                curcomments.append(line[1:].strip())
                continue
            try:
                f, v = line.split(':', 1)
            except ValueError:
                warn_or_exception(_("Invalid metadata in: ") + linedesc)

            if f not in app_fields:
                warn_or_exception(_('Unrecognised app field: ') + f)

            # Translate obsolete fields...
            if f == 'Market Version':
                f = 'Current Version'
            if f == 'Market Version Code':
                f = 'Current Version Code'

            f = f.replace(' ', '')

            ftype = fieldtype(f)
            if ftype not in [TYPE_BUILD, TYPE_BUILD_V2]:
                add_comments(f)
            if ftype == TYPE_MULTILINE:
                mode = 1
                if v:
                    warn_or_exception(_("Unexpected text on same line as {field} in {linedesc}")
                                      .format(field=f, linedesc=linedesc))
            elif ftype == TYPE_STRING:
                app[f] = v
            elif ftype == TYPE_LIST:
                app[f] = split_list_values(v)
            elif ftype == TYPE_BUILD:
                if v.endswith("\\"):
                    mode = 2
                    del buildlines[:]
                    buildlines.append(v[:-1])
                else:
                    build = parse_buildline([v])
                    app.builds.append(build)
                    add_comments('build:' + app.builds[-1].versionCode)
            elif ftype == TYPE_BUILD_V2:
                vv = v.split(',')
                if len(vv) != 2:
                    warn_or_exception(_('Build should have comma-separated '
                                        'versionName and versionCode, '
                                        'not "{value}", in {linedesc}')
                                      .format(value=v, linedesc=linedesc))
                build = Build()
                build.versionName = vv[0]
                build.versionCode = vv[1]
                check_versionCode(build.versionCode)

                if build.versionCode in vc_seen:
                    warn_or_exception(_('Duplicate build recipe found for versionCode {versionCode} in {linedesc}')
                                      .format(versionCode=build.versionCode, linedesc=linedesc))
                vc_seen.add(build.versionCode)
                del buildlines[:]
                mode = 3
            elif ftype == TYPE_OBSOLETE:
                pass        # Just throw it away!
            else:
                warn_or_exception(_("Unrecognised field '{field}' in {linedesc}")
                                  .format(field=f, linedesc=linedesc))
        elif mode == 1:     # Multiline field
            if line == '.':
                mode = 0
                app[f] = '\n'.join(multiline_lines)
                del multiline_lines[:]
            else:
                multiline_lines.append(line)
        elif mode == 2:     # Line continuation mode in Build Version
            if line.endswith("\\"):
                buildlines.append(line[:-1])
            else:
                buildlines.append(line)
                build = parse_buildline(buildlines)
                app.builds.append(build)
                add_comments('build:' + app.builds[-1].versionCode)
                mode = 0
    add_comments(None)

    # Mode at end of file should always be 0
    if mode == 1:
        warn_or_exception(_("{field} not terminated in {name}")
                          .format(field=f, name=mf.name))
    if mode == 2:
        warn_or_exception(_("Unterminated continuation in {name}")
                          .format(name=mf.name))
    if mode == 3:
        warn_or_exception(_("Unterminated build in {name}")
                          .format(name=mf.name))

    return app


def write_plaintext_metadata(mf, app, w_comment, w_field, w_build):

    def field_to_attr(f):
        """
        Translates human-readable field names to attribute names, e.g.
        'Auto Name' to 'AutoName'
        """
        return f.replace(' ', '')

    def attr_to_field(k):
        """
        Translates attribute names to human-readable field names, e.g.
        'AutoName' to 'Auto Name'
        """
        if k in app_fields:
            return k
        f = re.sub(r'([a-z])([A-Z])', r'\1 \2', k)
        return f

    def w_comments(key):
        if key not in app.comments:
            return
        for line in app.comments[key]:
            w_comment(line)

    def w_field_always(f, v=None):
        key = field_to_attr(f)
        if v is None:
            v = app.get(key)
        w_comments(key)
        w_field(f, v)

    def w_field_nonempty(f, v=None):
        key = field_to_attr(f)
        if v is None:
            v = app.get(key)
        w_comments(key)
        if v:
            w_field(f, v)

    w_field_nonempty('Disabled')
    w_field_nonempty('AntiFeatures')
    w_field_nonempty('Provides')
    w_field_always('Categories')
    w_field_always('License')
    w_field_nonempty('Author Name')
    w_field_nonempty('Author Email')
    w_field_nonempty('Author Web Site')
    w_field_always('Web Site')
    w_field_always('Source Code')
    w_field_always('Issue Tracker')
    w_field_nonempty('Translation')
    w_field_nonempty('Changelog')
    w_field_nonempty('Donate')
    w_field_nonempty('FlattrID')
    w_field_nonempty('LiberapayID')
    w_field_nonempty('Bitcoin')
    w_field_nonempty('Litecoin')
    mf.write('\n')
    w_field_nonempty('Name')
    w_field_nonempty('Auto Name')
    w_field_nonempty('Summary')
    w_field_nonempty('Description', description_txt(app.Description))
    mf.write('\n')
    if app.RequiresRoot:
        w_field_always('Requires Root', 'yes')
        mf.write('\n')
    if app.RepoType:
        w_field_always('Repo Type')
        w_field_always('Repo')
        if app.Binaries:
            w_field_always('Binaries')
        mf.write('\n')

    for build in app.builds:

        if build.versionName == "Ignore":
            continue

        w_comments('build:%s' % build.versionCode)
        w_build(build)
        mf.write('\n')

    if app.MaintainerNotes:
        w_field_always('Maintainer Notes', app.MaintainerNotes)
        mf.write('\n')

    w_field_nonempty('Archive Policy')
    w_field_always('Auto Update Mode')
    w_field_always('Update Check Mode')
    w_field_nonempty('Update Check Ignore')
    w_field_nonempty('Vercode Operation')
    w_field_nonempty('Update Check Name')
    w_field_nonempty('Update Check Data')
    if app.CurrentVersion:
        w_field_always('Current Version')
        w_field_always('Current Version Code')
    if app.NoSourceSince:
        mf.write('\n')
        w_field_always('No Source Since')
    w_comments(None)


# Write a metadata file in txt format.
#
# 'mf'      - Writer interface (file, StringIO, ...)
# 'app'     - The app data
def write_txt(mf, app):

    def w_comment(line):
        mf.write("# %s\n" % line)

    def w_field(f, v):
        t = fieldtype(f)
        if t == TYPE_LIST:
            v = ','.join(v)
        elif t == TYPE_MULTILINE:
            v = '\n' + v + '\n.'
        mf.write("%s:%s\n" % (f, v))

    def w_build(build):
        mf.write("Build:%s,%s\n" % (build.versionName, build.versionCode))

        for f in build_flags_order:
            v = build.get(f)
            if not v:
                continue

            t = flagtype(f)
            if f == 'androidupdate':
                f = 'update'  # avoid conflicting with Build(dict).update()
            mf.write('    %s=' % f)
            if t == TYPE_STRING or t == TYPE_INT:
                mf.write(v)
            elif t == TYPE_BOOL:
                mf.write('yes')
            elif t == TYPE_SCRIPT:
                first = True
                for s in v.split(' && '):
                    if first:
                        first = False
                    else:
                        mf.write(' && \\\n        ')
                    mf.write(s.strip())
            elif t == TYPE_LIST:
                mf.write(','.join(v))

            mf.write('\n')

    write_plaintext_metadata(mf, app, w_comment, w_field, w_build)


def write_metadata(metadatapath, app):
    _ignored, ext = fdroidserver.common.get_extension(metadatapath)
    accepted = fdroidserver.common.config['accepted_formats']
    if ext not in accepted:
        warn_or_exception(_('Cannot write "{path}", not an accepted format, use: {formats}')
                          .format(path=metadatapath, formats=', '.join(accepted)))

    try:
        with open(metadatapath, 'w', encoding='utf8') as mf:
            if ext == 'txt':
                return write_txt(mf, app)
            elif ext == 'yml':
                return write_yaml(mf, app)
    except FDroidException as e:
        os.remove(metadatapath)
        raise e

    warn_or_exception(_('Unknown metadata format: %s') % metadatapath)


def add_metadata_arguments(parser):
    '''add common command line flags related to metadata processing'''
    parser.add_argument("-W", choices=['error', 'warn', 'ignore'], default='error',
                        help=_("force metadata errors (default) to be warnings, or to be ignored."))
