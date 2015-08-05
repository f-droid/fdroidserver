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
import cgi
import logging
import textwrap
import io

import yaml
# use libyaml if it is available
try:
    from yaml import CLoader
    YamlLoader = CLoader
except ImportError:
    from yaml import Loader
    YamlLoader = Loader

# use the C implementation when available
import xml.etree.cElementTree as ElementTree

import fdroidserver.common

srclibs = None


class MetaDataException(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

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
    'Web Site',
    'Source Code',
    'Issue Tracker',
    'Changelog',
    'Donate',
    'FlattrID',
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

    'comments',  # For formats that don't do inline comments
    'builds',    # For formats that do builds as a list
])


class App():

    def __init__(self):
        self.Disabled = None
        self.AntiFeatures = []
        self.Provides = None
        self.Categories = ['None']
        self.License = 'Unknown'
        self.AuthorName = None
        self.AuthorEmail = None
        self.WebSite = ''
        self.SourceCode = ''
        self.IssueTracker = ''
        self.Changelog = ''
        self.Donate = None
        self.FlattrID = None
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
        self.lastupdated = None
        self._modified = set()

    # Translates human-readable field names to attribute names, e.g.
    # 'Auto Name' to 'AutoName'
    @classmethod
    def field_to_attr(cls, f):
        return f.replace(' ', '')

    # Translates attribute names to human-readable field names, e.g.
    # 'AutoName' to 'Auto Name'
    @classmethod
    def attr_to_field(cls, k):
        if k in app_fields:
            return k
        f = re.sub(r'([a-z])([A-Z])', r'\1 \2', k)
        return f

    # Constructs an old-fashioned dict with the human-readable field
    # names. Should only be used for tests.
    def field_dict(self):
        d = {}
        for k, v in self.__dict__.items():
            if k == 'builds':
                d['builds'] = []
                for build in v:
                    b = {k: v for k, v in build.__dict__.items() if not k.startswith('_')}
                    d['builds'].append(b)
            elif not k.startswith('_'):
                f = App.attr_to_field(k)
                d[f] = v
        return d

    # Gets the value associated to a field name, e.g. 'Auto Name'
    def get_field(self, f):
        if f not in app_fields:
            raise MetaDataException('Unrecognised app field: ' + f)
        k = App.field_to_attr(f)
        return getattr(self, k)

    # Sets the value associated to a field name, e.g. 'Auto Name'
    def set_field(self, f, v):
        if f not in app_fields:
            raise MetaDataException('Unrecognised app field: ' + f)
        k = App.field_to_attr(f)
        self.__dict__[k] = v
        self._modified.add(k)

    # Appends to the value associated to a field name, e.g. 'Auto Name'
    def append_field(self, f, v):
        if f not in app_fields:
            raise MetaDataException('Unrecognised app field: ' + f)
        k = App.field_to_attr(f)
        if k not in self.__dict__:
            self.__dict__[k] = [v]
        else:
            self.__dict__[k].append(v)

    # Like dict.update(), but using human-readable field names
    def update_fields(self, d):
        for f, v in d.items():
            if f == 'builds':
                for b in v:
                    build = Build()
                    build.update_flags(b)
                    self.builds.append(build)
            else:
                self.set_field(f, v)

TYPE_UNKNOWN = 0
TYPE_OBSOLETE = 1
TYPE_STRING = 2
TYPE_BOOL = 3
TYPE_LIST = 4
TYPE_SCRIPT = 5
TYPE_MULTILINE = 6
TYPE_BUILD = 7
TYPE_BUILD_V2 = 8

fieldtypes = {
    'Description': TYPE_MULTILINE,
    'Maintainer Notes': TYPE_MULTILINE,
    'Categories': TYPE_LIST,
    'AntiFeatures': TYPE_LIST,
    'Build Version': TYPE_BUILD,
    'Build': TYPE_BUILD_V2,
    'Use Built': TYPE_OBSOLETE,
}


def fieldtype(name):
    if name in fieldtypes:
        return fieldtypes[name]
    return TYPE_STRING


# In the order in which they are laid out on files
build_flags_order = [
    'disable',
    'commit',
    'subdir',
    'submodules',
    'init',
    'patch',
    'gradle',
    'maven',
    'kivy',
    'output',
    'srclibs',
    'oldsdkloc',
    'encoding',
    'forceversion',
    'forcevercode',
    'rm',
    'extlibs',
    'prebuild',
    'update',
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
]


build_flags = set(build_flags_order + ['version', 'vercode'])


class Build():

    def __init__(self):
        self.disable = False
        self.commit = None
        self.subdir = None
        self.submodules = False
        self.init = ''
        self.patch = []
        self.gradle = []
        self.maven = False
        self.kivy = False
        self.output = None
        self.srclibs = []
        self.oldsdkloc = False
        self.encoding = None
        self.forceversion = False
        self.forcevercode = False
        self.rm = []
        self.extlibs = []
        self.prebuild = ''
        self.update = []
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

        self._modified = set()

    def get_flag(self, f):
        if f not in build_flags:
            raise MetaDataException('Unrecognised build flag: ' + f)
        return getattr(self, f)

    def set_flag(self, f, v):
        if f == 'versionName':
            f = 'version'
        if f == 'versionCode':
            f = 'vercode'
        if f not in build_flags:
            raise MetaDataException('Unrecognised build flag: ' + f)
        self.__dict__[f] = v
        self._modified.add(f)

    def append_flag(self, f, v):
        if f not in build_flags:
            raise MetaDataException('Unrecognised build flag: ' + f)
        if f not in self.__dict__:
            self.__dict__[f] = [v]
        else:
            self.__dict__[f].append(v)

    def build_method(self):
        for f in ['maven', 'gradle', 'kivy']:
            if self.get_flag(f):
                return f
        if self.output:
            return 'raw'
        return 'ant'

    # like build_method, but prioritize output=
    def output_method(self):
        if self.output:
            return 'raw'
        for f in ['maven', 'gradle', 'kivy']:
            if self.get_flag(f):
                return f
        return 'ant'

    def ndk_path(self):
        version = self.ndk
        if not version:
            version = 'r10e'  # falls back to latest
        paths = fdroidserver.common.config['ndk_paths']
        if version not in paths:
            return ''
        return paths[version]

    def update_flags(self, d):
        for f, v in d.items():
            self.set_flag(f, v)

flagtypes = {
    'extlibs': TYPE_LIST,
    'srclibs': TYPE_LIST,
    'patch': TYPE_LIST,
    'rm': TYPE_LIST,
    'buildjni': TYPE_LIST,
    'preassemble': TYPE_LIST,
    'update': TYPE_LIST,
    'scanignore': TYPE_LIST,
    'scandelete': TYPE_LIST,
    'gradle': TYPE_LIST,
    'antcommands': TYPE_LIST,
    'gradleprops': TYPE_LIST,
    'init': TYPE_SCRIPT,
    'prebuild': TYPE_SCRIPT,
    'build': TYPE_SCRIPT,
    'submodules': TYPE_BOOL,
    'oldsdkloc': TYPE_BOOL,
    'forceversion': TYPE_BOOL,
    'forcevercode': TYPE_BOOL,
    'novcheck': TYPE_BOOL,
}


def flagtype(name):
    if name in flagtypes:
        return flagtypes[name]
    return TYPE_STRING


# Designates a metadata field type and checks that it matches
#
# 'name'     - The long name of the field type
# 'matching' - List of possible values or regex expression
# 'sep'      - Separator to use if value may be a list
# 'fields'   - Metadata fields (Field:Value) of this type
# 'flags'    - Build flags (flag=value) of this type
#
class FieldValidator():

    def __init__(self, name, matching, fields, flags):
        self.name = name
        self.matching = matching
        self.compiled = re.compile(matching)
        self.fields = fields
        self.flags = flags

    def check(self, v, appid):
        if not v:
            return
        if type(v) == list:
            values = v
        else:
            values = [v]
        for v in values:
            if not self.compiled.match(v):
                raise MetaDataException("'%s' is not a valid %s in %s. Regex pattern: %s"
                                        % (v, self.name, appid, self.matching))

# Generic value types
valuetypes = {
    FieldValidator("Integer",
                   r'^[1-9][0-9]*$',
                   [],
                   ['vercode']),

    FieldValidator("Hexadecimal",
                   r'^[0-9a-f]+$',
                   ['FlattrID'],
                   []),

    FieldValidator("HTTP link",
                   r'^http[s]?://',
                   ["WebSite", "SourceCode", "IssueTracker", "Changelog", "Donate"], []),

    FieldValidator("Email",
                   r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
                   ["AuthorEmail"], []),

    FieldValidator("Bitcoin address",
                   r'^[a-zA-Z0-9]{27,34}$',
                   ["Bitcoin"],
                   []),

    FieldValidator("Litecoin address",
                   r'^L[a-zA-Z0-9]{33}$',
                   ["Litecoin"],
                   []),

    FieldValidator("Repo Type",
                   r'^(git|git-svn|svn|hg|bzr|srclib)$',
                   ["RepoType"],
                   []),

    FieldValidator("Binaries",
                   r'^http[s]?://',
                   ["Binaries"],
                   []),

    FieldValidator("Archive Policy",
                   r'^[0-9]+ versions$',
                   ["ArchivePolicy"],
                   []),

    FieldValidator("Anti-Feature",
                   r'^(Ads|Tracking|NonFreeNet|NonFreeDep|NonFreeAdd|UpstreamNonFree|NonFreeAssets)$',
                   ["AntiFeatures"],
                   []),

    FieldValidator("Auto Update Mode",
                   r"^(Version .+|None)$",
                   ["AutoUpdateMode"],
                   []),

    FieldValidator("Update Check Mode",
                   r"^(Tags|Tags .+|RepoManifest|RepoManifest/.+|RepoTrunk|HTTP|Static|None)$",
                   ["UpdateCheckMode"],
                   [])
}


# Check an app's metadata information for integrity errors
def check_metadata(app):
    for v in valuetypes:
        for k in v.fields:
            if k not in app._modified:
                continue
            v.check(app.__dict__[k], app.id)
        for build in app.builds:
            for k in v.flags:
                if k not in build._modified:
                    continue
                v.check(build.__dict__[k], app.id)


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

    def formatted(self, txt, html):
        res = ''
        if html:
            txt = cgi.escape(txt)
        while True:
            index = txt.find("''")
            if index == -1:
                return res + txt
            res += txt[:index]
            txt = txt[index:]
            if txt.startswith("'''"):
                if html:
                    if self.bold:
                        res += '</b>'
                    else:
                        res += '<b>'
                self.bold = not self.bold
                txt = txt[3:]
            else:
                if html:
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
                    raise MetaDataException("Unterminated ]]")
                url = txt[2:index]
                if self.linkResolver:
                    url, urltext = self.linkResolver(url)
                else:
                    urltext = url
                res_html += '<a href="' + url + '">' + cgi.escape(urltext) + '</a>'
                res_plain += urltext
                txt = txt[index + 2:]
            else:
                index = txt.find("]")
                if index == -1:
                    raise MetaDataException("Unterminated ]")
                url = txt[1:index]
                index2 = url.find(' ')
                if index2 == -1:
                    urltxt = url
                else:
                    urltxt = url[index2 + 1:]
                    url = url[:index2]
                    if url == urltxt:
                        raise MetaDataException("Url title is just the URL - use [url]")
                res_html += '<a href="' + url + '">' + cgi.escape(urltxt) + '</a>'
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
            raise MetaDataException("Invalid metadata in %s:%d" % (line, n))

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


# Read all metadata. Returns a list of 'app' objects (which are dictionaries as
# returned by the parse_txt_metadata function.
def read_metadata(xref=True):

    # Always read the srclibs before the apps, since they can use a srlib as
    # their source repository.
    read_srclibs()

    apps = {}

    for basedir in ('metadata', 'tmp'):
        if not os.path.exists(basedir):
            os.makedirs(basedir)

    # If there are multiple metadata files for a single appid, then the first
    # file that is parsed wins over all the others, and the rest throw an
    # exception. So the original .txt format is parsed first, at least until
    # newer formats stabilize.

    for metadatapath in sorted(glob.glob(os.path.join('metadata', '*.txt'))
                               + glob.glob(os.path.join('metadata', '*.json'))
                               + glob.glob(os.path.join('metadata', '*.xml'))
                               + glob.glob(os.path.join('metadata', '*.yaml'))
                               + glob.glob('.fdroid.json')
                               + glob.glob('.fdroid.xml')
                               + glob.glob('.fdroid.yaml')):
        app = parse_metadata(metadatapath)
        if app.id in apps:
            raise MetaDataException("Found multiple metadata files for " + app.id)
        check_metadata(app)
        apps[app.id] = app

    if xref:
        # Parse all descriptions at load time, just to ensure cross-referencing
        # errors are caught early rather than when they hit the build server.
        def linkres(appid):
            if appid in apps:
                return ("fdroid.app:" + appid, "Dummy name - don't know yet")
            raise MetaDataException("Cannot resolve app id " + appid)

        for appid, app in apps.items():
            try:
                description_html(app.Description, linkres)
            except MetaDataException as e:
                raise MetaDataException("Problem with description of " + appid +
                                        " - " + str(e))

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
        appid, _ = fdroidserver.common.get_extension(os.path.basename(metadatapath))

    if appid == '.fdroid':  # we have local metadata in the app's source
        if os.path.exists('AndroidManifest.xml'):
            manifestroot = fdroidserver.common.parse_xml('AndroidManifest.xml')
        else:
            pattern = re.compile(""".*manifest\.srcFile\s+'AndroidManifest\.xml'.*""")
            for root, dirs, files in os.walk(os.getcwd()):
                if 'build.gradle' in files:
                    p = os.path.join(root, 'build.gradle')
                    with open(p) as f:
                        data = f.read()
                    m = pattern.search(data)
                    if m:
                        logging.debug('Using: ' + os.path.join(root, 'AndroidManifest.xml'))
                        manifestroot = fdroidserver.common.parse_xml(os.path.join(root, 'AndroidManifest.xml'))
                        break
        if manifestroot is None:
            raise MetaDataException("Cannot find a packageName for {0}!".format(metadatapath))
        appid = manifestroot.attrib['package']

    app = App()
    app.metadatapath = metadatapath
    if appid is not None:
        app.id = appid

    return app


def sorted_builds(builds):
    return sorted(builds, key=lambda build: int(build.vercode))


esc_newlines = re.compile(r'\\( |\n)')


# This function uses __dict__ to be faster
def post_metadata_parse(app):

    for k in app._modified:
        v = app.__dict__[k]
        if type(v) in (float, int):
            app.__dict__[k] = str(v)

    for build in app.builds:
        for k in build._modified:
            v = build.__dict__[k]
            if type(v) in (float, int):
                build.__dict__[k] = str(v)
                continue
            ftype = flagtype(k)

            if ftype == TYPE_SCRIPT:
                build.__dict__[k] = re.sub(esc_newlines, '', v).lstrip().rstrip()
            elif ftype == TYPE_BOOL:
                # TODO handle this using <xsd:element type="xsd:boolean> in a schema
                if isinstance(v, str):
                    build.__dict__[k] = _decode_bool(v)
            elif ftype == TYPE_STRING:
                if isinstance(v, bool) and v:
                    build.__dict__[k] = 'yes'

    if not app.Description:
        app.Description = 'No description available'

    app.builds = sorted_builds(app.builds)


# Parse metadata for a single application.
#
#  'metadatapath' - the filename to read. The package id for the application comes
#               from this filename. Pass None to get a blank entry.
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
    raise MetaDataException("Invalid bool '%s'" % s)


def parse_metadata(metadatapath):
    _, ext = fdroidserver.common.get_extension(metadatapath)
    accepted = fdroidserver.common.config['accepted_formats']
    if ext not in accepted:
        raise MetaDataException('"%s" is not an accepted format, convert to: %s' % (
            metadatapath, ', '.join(accepted)))

    app = App()
    app.metadatapath = metadatapath
    app.id, _ = fdroidserver.common.get_extension(os.path.basename(metadatapath))

    with open(metadatapath, 'r', encoding='utf-8') as mf:
        if ext == 'txt':
            parse_txt_metadata(mf, app)
        elif ext == 'json':
            parse_json_metadata(mf, app)
        elif ext == 'xml':
            parse_xml_metadata(mf, app)
        elif ext == 'yaml':
            parse_yaml_metadata(mf, app)
        else:
            raise MetaDataException('Unknown metadata format: %s' % metadatapath)

    post_metadata_parse(app)
    return app


def parse_json_metadata(mf, app):

    # fdroid metadata is only strings and booleans, no floats or ints.
    # TODO create schema using https://pypi.python.org/pypi/jsonschema
    jsoninfo = json.load(mf, parse_int=lambda s: s,
                         parse_float=lambda s: s)
    app.update_fields(jsoninfo)
    for f in ['Description', 'Maintainer Notes']:
        v = app.get_field(f)
        app.set_field(f, '\n'.join(v))
    return app


def parse_xml_metadata(mf, app):

    tree = ElementTree.ElementTree(file=mf)
    root = tree.getroot()

    if root.tag != 'resources':
        raise MetaDataException('resources file does not have root element <resources/>')

    for child in root:
        if child.tag != 'builds':
            # builds does not have name="" attrib
            name = child.attrib['name']

        if child.tag == 'string':
            app.set_field(name, child.text)
        elif child.tag == 'string-array':
            for item in child:
                app.append_field(name, item.text)
        elif child.tag == 'builds':
            for b in child:
                build = Build()
                for key in b:
                    build.set_flag(key.tag, key.text)
                app.builds.append(build)

    # TODO handle this using <xsd:element type="xsd:boolean> in a schema
    if not isinstance(app.RequiresRoot, bool):
        app.RequiresRoot = app.RequiresRoot == 'true'

    return app


def parse_yaml_metadata(mf, app):

    yamlinfo = yaml.load(mf, Loader=YamlLoader)
    app.update_fields(yamlinfo)
    return app


build_line_sep = re.compile(r'(?<!\\),')
build_cont = re.compile(r'^[ \t]')


def parse_txt_metadata(mf, app):

    linedesc = None

    def add_buildflag(p, build):
        if not p.strip():
            raise MetaDataException("Empty build flag at {1}"
                                    .format(buildlines[0], linedesc))
        bv = p.split('=', 1)
        if len(bv) != 2:
            raise MetaDataException("Invalid build flag at {0} in {1}"
                                    .format(buildlines[0], linedesc))

        pk, pv = bv
        pk = pk.lstrip()
        t = flagtype(pk)
        if t == TYPE_LIST:
            pv = split_list_values(pv)
            build.set_flag(pk, pv)
        elif t == TYPE_STRING or t == TYPE_SCRIPT:
            build.set_flag(pk, pv)
        elif t == TYPE_BOOL:
            build.set_flag(pk, _decode_bool(pv))

    def parse_buildline(lines):
        v = "".join(lines)
        parts = [p.replace("\\,", ",") for p in re.split(build_line_sep, v)]
        if len(parts) < 3:
            raise MetaDataException("Invalid build format: " + v + " in " + mf.name)
        build = Build()
        build.version = parts[0]
        build.vercode = parts[1]
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
                    raise MetaDataException("No commit specified for {0} in {1}"
                                            .format(build.version, linedesc))

                app.builds.append(build)
                add_comments('build:' + build.vercode)
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
                raise MetaDataException("Invalid metadata in " + linedesc)

            # Translate obsolete fields...
            if f == 'Market Version':
                f = 'Current Version'
            if f == 'Market Version Code':
                f = 'Current Version Code'

            ftype = fieldtype(f)
            if ftype not in [TYPE_BUILD, TYPE_BUILD_V2]:
                add_comments(f)
            if ftype == TYPE_MULTILINE:
                mode = 1
                if v:
                    raise MetaDataException("Unexpected text on same line as " + f + " in " + linedesc)
            elif ftype == TYPE_STRING:
                app.set_field(f, v)
            elif ftype == TYPE_LIST:
                app.set_field(f, split_list_values(v))
            elif ftype == TYPE_BUILD:
                if v.endswith("\\"):
                    mode = 2
                    del buildlines[:]
                    buildlines.append(v[:-1])
                else:
                    build = parse_buildline([v])
                    app.builds.append(build)
                    add_comments('build:' + app.builds[-1].vercode)
            elif ftype == TYPE_BUILD_V2:
                vv = v.split(',')
                if len(vv) != 2:
                    raise MetaDataException('Build should have comma-separated version and vercode, not "{0}", in {1}'
                                            .format(v, linedesc))
                build = Build()
                build.version = vv[0]
                build.vercode = vv[1]
                if build.vercode in vc_seen:
                    raise MetaDataException('Duplicate build recipe found for vercode %s in %s' % (
                                            build.vercode, linedesc))
                vc_seen.add(build.vercode)
                del buildlines[:]
                mode = 3
            elif ftype == TYPE_OBSOLETE:
                pass        # Just throw it away!
            else:
                raise MetaDataException("Unrecognised field '" + f + "' in " + linedesc)
        elif mode == 1:     # Multiline field
            if line == '.':
                mode = 0
                app.set_field(f, '\n'.join(multiline_lines))
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
                add_comments('build:' + app.builds[-1].vercode)
                mode = 0
    add_comments(None)

    # Mode at end of file should always be 0
    if mode == 1:
        raise MetaDataException(f + " not terminated in " + mf.name)
    if mode == 2:
        raise MetaDataException("Unterminated continuation in " + mf.name)
    if mode == 3:
        raise MetaDataException("Unterminated build in " + mf.name)

    return app


def write_plaintext_metadata(mf, app, w_comment, w_field, w_build):

    def w_comments(key):
        if key not in app.comments:
            return
        for line in app.comments[key]:
            w_comment(line)

    def w_field_always(f, v=None):
        if v is None:
            v = app.get_field(f)
        w_comments(f)
        w_field(f, v)

    def w_field_nonempty(f, v=None):
        if v is None:
            v = app.get_field(f)
        w_comments(f)
        if v:
            w_field(f, v)

    w_field_nonempty('Disabled')
    w_field_nonempty('AntiFeatures')
    w_field_nonempty('Provides')
    w_field_always('Categories')
    w_field_always('License')
    w_field_nonempty('Author Name')
    w_field_nonempty('Author Email')
    w_field_always('Web Site')
    w_field_always('Source Code')
    w_field_always('Issue Tracker')
    w_field_nonempty('Changelog')
    w_field_nonempty('Donate')
    w_field_nonempty('FlattrID')
    w_field_nonempty('Bitcoin')
    w_field_nonempty('Litecoin')
    mf.write('\n')
    w_field_nonempty('Name')
    w_field_nonempty('Auto Name')
    w_field_always('Summary')
    w_field_always('Description', description_txt(app.Description))
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

        if build.version == "Ignore":
            continue

        w_comments('build:' + build.vercode)
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
def write_txt_metadata(mf, app):

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
        mf.write("Build:%s,%s\n" % (build.version, build.vercode))

        for f in build_flags_order:
            v = build.get_flag(f)
            if not v:
                continue

            t = flagtype(f)
            mf.write('    %s=' % f)
            if t == TYPE_STRING:
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
                    mf.write(s)
            elif t == TYPE_LIST:
                mf.write(','.join(v))

            mf.write('\n')

    write_plaintext_metadata(mf, app, w_comment, w_field, w_build)


def write_yaml_metadata(mf, app):

    def w_comment(line):
        mf.write("# %s\n" % line)

    def escape(v):
        if not v:
            return ''
        if any(c in v for c in [': ', '%', '@', '*']):
            return "'" + v.replace("'", "''") + "'"
        return v

    def w_field(f, v, prefix='', t=None):
        if t is None:
            t = fieldtype(f)
        v = ''
        if t == TYPE_LIST:
            v = '\n'
            for e in v:
                v += prefix + ' - ' + escape(e) + '\n'
        elif t == TYPE_MULTILINE:
            v = ' |\n'
            for l in v.splitlines():
                if l:
                    v += prefix + '  ' + l + '\n'
                else:
                    v += '\n'
        elif t == TYPE_BOOL:
            v = ' yes\n'
        elif t == TYPE_SCRIPT:
            cmds = [s + '&& \\' for s in v.split('&& ')]
            if len(cmds) > 0:
                cmds[-1] = cmds[-1][:-len('&& \\')]
            w_field(f, cmds, prefix, 'multiline')
            return
        else:
            v = ' ' + escape(v) + '\n'

        mf.write(prefix)
        mf.write(f)
        mf.write(":")
        mf.write(v)

    global first_build
    first_build = True

    def w_build(build):
        global first_build
        if first_build:
            mf.write("builds:\n")
            first_build = False

        w_field('versionName', build.version, '  - ', TYPE_STRING)
        w_field('versionCode', build.vercode, '    ', TYPE_STRING)
        for f in build_flags_order:
            v = build.get_flag(f)
            if not v:
                continue

            w_field(f, v, '    ', flagtype(f))

    write_plaintext_metadata(mf, app, w_comment, w_field, w_build)


def write_metadata(fmt, mf, app):
    if fmt == 'txt':
        return write_txt_metadata(mf, app)
    if fmt == 'yaml':
        return write_yaml_metadata(mf, app)
    raise MetaDataException("Unknown metadata format given")
