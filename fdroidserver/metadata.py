# -*- coding: utf-8 -*-
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

import os
import re
import glob
import cgi
import logging

from collections import OrderedDict

srclibs = None


class MetaDataException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

# In the order in which they are laid out on files
app_defaults = OrderedDict([
    ('Disabled', None),
    ('AntiFeatures', None),
    ('Provides', None),
    ('Categories', ['None']),
    ('License', 'Unknown'),
    ('Web Site', ''),
    ('Source Code', ''),
    ('Issue Tracker', ''),
    ('Donate', None),
    ('FlattrID', None),
    ('Bitcoin', None),
    ('Litecoin', None),
    ('Dogecoin', None),
    ('Name', None),
    ('Auto Name', ''),
    ('Summary', ''),
    ('Description', []),
    ('Requires Root', False),
    ('Repo Type', ''),
    ('Repo', ''),
    ('Maintainer Notes', []),
    ('Archive Policy', None),
    ('Auto Update Mode', 'None'),
    ('Update Check Mode', 'None'),
    ('Update Check Ignore', None),
    ('Vercode Operation', None),
    ('Update Check Name', None),
    ('Update Check Data', None),
    ('Current Version', ''),
    ('Current Version Code', '0'),
    ('No Source Since', ''),
    ])


# In the order in which they are laid out on files
# Sorted by their action and their place in the build timeline
flag_defaults = OrderedDict([
    ('disable', False),
    ('commit', None),
    ('subdir', None),
    ('submodules', False),
    ('init', ''),
    ('patch', []),
    ('gradle', False),
    ('maven', False),
    ('kivy', False),
    ('output', None),
    ('srclibs', []),
    ('oldsdkloc', False),
    ('encoding', None),
    ('forceversion', False),
    ('forcevercode', False),
    ('rm', []),
    ('extlibs', []),
    ('prebuild', ''),
    ('update', ['auto']),
    ('target', None),
    ('scanignore', []),
    ('scandelete', []),
    ('build', ''),
    ('buildjni', []),
    ('preassemble', []),
    ('antcommand', None),
    ('novcheck', False),
    ])


# Designates a metadata field type and checks that it matches
#
# 'name'     - The long name of the field type
# 'matching' - List of possible values or regex expression
# 'sep'      - Separator to use if value may be a list
# 'fields'   - Metadata fields (Field:Value) of this type
# 'attrs'    - Build attributes (attr=value) of this type
#
class FieldValidator():

    def __init__(self, name, matching, sep, fields, attrs):
        self.name = name
        self.matching = matching
        if type(matching) is str:
            self.compiled = re.compile(matching)
        self.sep = sep
        self.fields = fields
        self.attrs = attrs

    def _assert_regex(self, values, appid):
        for v in values:
            if not self.compiled.match(v):
                raise MetaDataException("'%s' is not a valid %s in %s. "
                                        % (v, self.name, appid) +
                                        "Regex pattern: %s" % (self.matching))

    def _assert_list(self, values, appid):
        for v in values:
            if v not in self.matching:
                raise MetaDataException("'%s' is not a valid %s in %s. "
                                        % (v, self.name, appid) +
                                        "Possible values: %s" % (", ".join(self.matching)))

    def check(self, value, appid):
        if type(value) is not str or not value:
            return
        if self.sep is not None:
            values = value.split(self.sep)
        else:
            values = [value]
        if type(self.matching) is list:
            self._assert_list(values, appid)
        else:
            self._assert_regex(values, appid)


# Generic value types
valuetypes = {
    FieldValidator("Integer",
                   r'^[1-9][0-9]*$', None,
                   [],
                   ['vercode']),

    FieldValidator("Hexadecimal",
                   r'^[0-9a-f]+$', None,
                   ['FlattrID'],
                   []),

    FieldValidator("HTTP link",
                   r'^http[s]?://', None,
                   ["Web Site", "Source Code", "Issue Tracker", "Donate"], []),

    FieldValidator("Bitcoin address",
                   r'^[a-zA-Z0-9]{27,34}$', None,
                   ["Bitcoin"],
                   []),

    FieldValidator("Litecoin address",
                   r'^L[a-zA-Z0-9]{33}$', None,
                   ["Litecoin"],
                   []),

    FieldValidator("Dogecoin address",
                   r'^D[a-zA-Z0-9]{33}$', None,
                   ["Dogecoin"],
                   []),

    FieldValidator("Boolean",
                   ['Yes', 'No'], None,
                   ["Requires Root"],
                   []),

    FieldValidator("bool",
                   ['yes', 'no'], None,
                   [],
                   ['submodules', 'oldsdkloc', 'forceversion', 'forcevercode',
                    'novcheck']),

    FieldValidator("Repo Type",
                   ['git', 'git-svn', 'svn', 'hg', 'bzr', 'srclib'], None,
                   ["Repo Type"],
                   []),

    FieldValidator("Archive Policy",
                   r'^[0-9]+ versions$', None,
                   ["Archive Policy"],
                   []),

    FieldValidator("Anti-Feature",
                   ["Ads", "Tracking", "NonFreeNet", "NonFreeDep", "NonFreeAdd", "UpstreamNonFree"], ',',
                   ["AntiFeatures"],
                   []),

    FieldValidator("Auto Update Mode",
                   r"^(Version .+|None)$", None,
                   ["Auto Update Mode"],
                   []),

    FieldValidator("Update Check Mode",
                   r"^(Tags|Tags .+|RepoManifest|RepoManifest/.+|RepoTrunk|HTTP|Static|None)$", None,
                   ["Update Check Mode"],
                   [])
    }


# Check an app's metadata information for integrity errors
def check_metadata(info):
    for v in valuetypes:
        for field in v.fields:
            v.check(info[field], info['id'])
        for build in info['builds']:
            for attr in v.attrs:
                v.check(build[attr], info['id'])


# Formatter for descriptions. Create an instance, and call parseline() with
# each line of the description source from the metadata. At the end, call
# end() and then text_plain, text_wiki and text_html will contain the result.
class DescriptionFormatter:
    stNONE = 0
    stPARA = 1
    stUL = 2
    stOL = 3
    bold = False
    ital = False
    state = stNONE
    text_plain = ''
    text_wiki = ''
    text_html = ''
    linkResolver = None

    def __init__(self, linkres):
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
        self.text_plain += '\n'
        self.text_html += '</p>'
        self.state = self.stNONE

    def endul(self):
        self.text_html += '</ul>'
        self.state = self.stNONE

    def endol(self):
        self.text_html += '</ol>'
        self.state = self.stNONE

    def formatted(self, txt, html):
        formatted = ''
        if html:
            txt = cgi.escape(txt)
        while True:
            index = txt.find("''")
            if index == -1:
                return formatted + txt
            formatted += txt[:index]
            txt = txt[index:]
            if txt.startswith("'''"):
                if html:
                    if self.bold:
                        formatted += '</b>'
                    else:
                        formatted += '<b>'
                self.bold = not self.bold
                txt = txt[3:]
            else:
                if html:
                    if self.ital:
                        formatted += '</i>'
                    else:
                        formatted += '<i>'
                self.ital = not self.ital
                txt = txt[2:]

    def linkify(self, txt):
        linkified_plain = ''
        linkified_html = ''
        while True:
            index = txt.find("[")
            if index == -1:
                return (linkified_plain + self.formatted(txt, False), linkified_html + self.formatted(txt, True))
            linkified_plain += self.formatted(txt[:index], False)
            linkified_html += self.formatted(txt[:index], True)
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
                linkified_html += '<a href="' + url + '">' + cgi.escape(urltext) + '</a>'
                linkified_plain += urltext
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
                linkified_html += '<a href="' + url + '">' + cgi.escape(urltxt) + '</a>'
                linkified_plain += urltxt
                if urltxt != url:
                    linkified_plain += ' (' + url + ')'
                txt = txt[index + 1:]

    def addtext(self, txt):
        p, h = self.linkify(txt)
        self.text_plain += p
        self.text_html += h

    def parseline(self, line):
        self.text_wiki += "%s\n" % line
        if not line:
            self.endcur()
        elif line.startswith('* '):
            self.endcur([self.stUL])
            if self.state != self.stUL:
                self.text_html += '<ul>'
                self.state = self.stUL
            self.text_html += '<li>'
            self.text_plain += '* '
            self.addtext(line[1:])
            self.text_html += '</li>'
        elif line.startswith('# '):
            self.endcur([self.stOL])
            if self.state != self.stOL:
                self.text_html += '<ol>'
                self.state = self.stOL
            self.text_html += '<li>'
            self.text_plain += '* '  # TODO: lazy - put the numbers in!
            self.addtext(line[1:])
            self.text_html += '</li>'
        else:
            self.endcur([self.stPARA])
            if self.state == self.stNONE:
                self.text_html += '<p>'
                self.state = self.stPARA
            elif self.state == self.stPARA:
                self.text_html += ' '
                self.text_plain += ' '
            self.addtext(line)

    def end(self):
        self.endcur()


# Parse multiple lines of description as written in a metadata file, returning
# a single string in plain text format.
def description_plain(lines, linkres):
    ps = DescriptionFormatter(linkres)
    for line in lines:
        ps.parseline(line)
    ps.end()
    return ps.text_plain


# Parse multiple lines of description as written in a metadata file, returning
# a single string in wiki format. Used for the Maintainer Notes field as well,
# because it's the same format.
def description_wiki(lines):
    ps = DescriptionFormatter(None)
    for line in lines:
        ps.parseline(line)
    ps.end()
    return ps.text_wiki


# Parse multiple lines of description as written in a metadata file, returning
# a single string in HTML format.
def description_html(lines, linkres):
    ps = DescriptionFormatter(linkres)
    for line in lines:
        ps.parseline(line)
    ps.end()
    return ps.text_html


def parse_srclib(metafile):

    thisinfo = {}
    if metafile and not isinstance(metafile, file):
        metafile = open(metafile, "r")

    # Defaults for fields that come from metadata
    thisinfo['Repo Type'] = ''
    thisinfo['Repo'] = ''
    thisinfo['Subdir'] = None
    thisinfo['Prepare'] = None
    thisinfo['Srclibs'] = None

    if metafile is None:
        return thisinfo

    n = 0
    for line in metafile:
        n += 1
        line = line.rstrip('\r\n')
        if not line or line.startswith("#"):
            continue

        try:
            field, value = line.split(':', 1)
        except ValueError:
            raise MetaDataException("Invalid metadata in %s:%d" % (line, n))

        if field == "Subdir":
            thisinfo[field] = value.split(',')
        else:
            thisinfo[field] = value

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

    for metafile in sorted(glob.glob(os.path.join(srcdir, '*.txt'))):
        srclibname = os.path.basename(metafile[:-4])
        srclibs[srclibname] = parse_srclib(metafile)


# Read all metadata. Returns a list of 'app' objects (which are dictionaries as
# returned by the parse_metadata function.
def read_metadata(xref=True):

    # Always read the srclibs before the apps, since they can use a srlib as
    # their source repository.
    read_srclibs()

    apps = []

    for basedir in ('metadata', 'tmp'):
        if not os.path.exists(basedir):
            os.makedirs(basedir)

    for metafile in sorted(glob.glob(os.path.join('metadata', '*.txt'))):
        appinfo = parse_metadata(metafile)
        check_metadata(appinfo)
        apps.append(appinfo)

    if xref:
        # Parse all descriptions at load time, just to ensure cross-referencing
        # errors are caught early rather than when they hit the build server.
        def linkres(link):
            for app in apps:
                if app['id'] == link:
                    return ("fdroid.app:" + link, "Dummy name - don't know yet")
            raise MetaDataException("Cannot resolve app id " + link)
        for app in apps:
            try:
                description_html(app['Description'], linkres)
            except MetaDataException, e:
                raise MetaDataException("Problem with description of " + app['id'] +
                                        " - " + str(e))

    return apps


# Get the type expected for a given metadata field.
def metafieldtype(name):
    if name in ['Description', 'Maintainer Notes']:
        return 'multiline'
    if name in ['Categories']:
        return 'list'
    if name == 'Build Version':
        return 'build'
    if name == 'Build':
        return 'buildv2'
    if name == 'Use Built':
        return 'obsolete'
    if name not in app_defaults:
        return 'unknown'
    return 'string'


def flagtype(name):
    if name in ['extlibs', 'srclibs', 'patch', 'rm', 'buildjni',
                'update', 'scanignore', 'scandelete']:
        return 'list'
    if name in ['init', 'prebuild', 'build']:
        return 'script'
    if name in ['submodules', 'oldsdkloc', 'forceversion', 'forcevercode',
                'novcheck']:
        return 'bool'
    return 'string'


def fill_build_defaults(build):

    def get_build_type():
        for t in ['maven', 'gradle', 'kivy']:
            if build[t]:
                return t
        if build['output']:
            return 'raw'
        return 'ant'

    for flag, value in flag_defaults.iteritems():
        if flag in build:
            continue
        build[flag] = value
    build['type'] = get_build_type()


# Parse metadata for a single application.
#
#  'metafile' - the filename to read. The package id for the application comes
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
#  'id'               - the application's package ID
#  'builds'           - a list of dictionaries containing build information
#                       for each defined build
#  'comments'         - a list of comments from the metadata file. Each is
#                       a tuple of the form (field, comment) where field is
#                       the name of the field it preceded in the metadata
#                       file. Where field is None, the comment goes at the
#                       end of the file. Alternatively, 'build:version' is
#                       for a comment before a particular build version.
#  'descriptionlines' - original lines of description as formatted in the
#                       metadata file.
#
def parse_metadata(metafile):

    linedesc = None

    def add_buildflag(p, thisbuild):
        bv = p.split('=', 1)
        if len(bv) != 2:
            raise MetaDataException("Invalid build flag at {0} in {1}"
                                    .format(buildlines[0], linedesc))
        pk, pv = bv
        if pk in thisbuild:
            raise MetaDataException("Duplicate definition on {0} in version {1} of {2}"
                                    .format(pk, thisbuild['version'], linedesc))

        pk = pk.lstrip()
        if pk not in flag_defaults:
            raise MetaDataException("Unrecognised build flag at {0} in {1}"
                                    .format(p, linedesc))
        t = flagtype(pk)
        if t == 'list':
            # Port legacy ';' separators
            thisbuild[pk] = [v.strip() for v in pv.replace(';', ',').split(',')]
        elif t == 'string' or t == 'script':
            thisbuild[pk] = pv
        elif t == 'bool':
            value = pv == 'yes'
            if value:
                thisbuild[pk] = True
            else:
                logging.debug("...ignoring bool flag %s" % p)

        else:
            raise MetaDataException("Unrecognised build flag type '%s' at %s in %s"
                                    % (t, p, linedesc))

    def parse_buildline(lines):
        value = "".join(lines)
        parts = [p.replace("\\,", ",")
                 for p in re.split(r"(?<!\\),", value)]
        if len(parts) < 3:
            raise MetaDataException("Invalid build format: " + value + " in " + metafile.name)
        thisbuild = {}
        thisbuild['origlines'] = lines
        thisbuild['version'] = parts[0]
        thisbuild['vercode'] = parts[1]
        if parts[2].startswith('!'):
            # For backwards compatibility, handle old-style disabling,
            # including attempting to extract the commit from the message
            thisbuild['disable'] = parts[2][1:]
            commit = 'unknown - see disabled'
            index = parts[2].rfind('at ')
            if index != -1:
                commit = parts[2][index + 3:]
                if commit.endswith(')'):
                    commit = commit[:-1]
            thisbuild['commit'] = commit
        else:
            thisbuild['commit'] = parts[2]
        for p in parts[3:]:
            add_buildflag(p, thisbuild)

        return thisbuild

    def add_comments(key):
        if not curcomments:
            return
        for comment in curcomments:
            thisinfo['comments'].append((key, comment))
        del curcomments[:]

    thisinfo = {}
    if metafile:
        if not isinstance(metafile, file):
            metafile = open(metafile, "r")
        thisinfo['id'] = metafile.name[9:-4]
    else:
        thisinfo['id'] = None

    thisinfo.update(app_defaults)

    # General defaults...
    thisinfo['builds'] = []
    thisinfo['comments'] = []

    if metafile is None:
        return thisinfo

    mode = 0
    buildlines = []
    curcomments = []
    curbuild = None
    vc_seen = {}

    c = 0
    for line in metafile:
        c += 1
        linedesc = "%s:%d" % (metafile.name, c)
        line = line.rstrip('\r\n')
        if mode == 3:
            if not any(line.startswith(s) for s in (' ', '\t')):
                if 'commit' not in curbuild and 'disable' not in curbuild:
                    raise MetaDataException("No commit specified for {0} in {1}"
                                            .format(curbuild['version'], linedesc))

                thisinfo['builds'].append(curbuild)
                add_comments('build:' + curbuild['vercode'])
                mode = 0
            else:
                if line.endswith('\\'):
                    buildlines.append(line[:-1].lstrip())
                else:
                    buildlines.append(line.lstrip())
                    bl = ''.join(buildlines)
                    add_buildflag(bl, curbuild)
                    buildlines = []

        if mode == 0:
            if not line:
                continue
            if line.startswith("#"):
                curcomments.append(line)
                continue
            try:
                field, value = line.split(':', 1)
            except ValueError:
                raise MetaDataException("Invalid metadata in " + linedesc)
            if field != field.strip() or value != value.strip():
                raise MetaDataException("Extra spacing found in " + linedesc)

            # Translate obsolete fields...
            if field == 'Market Version':
                field = 'Current Version'
            if field == 'Market Version Code':
                field = 'Current Version Code'

            fieldtype = metafieldtype(field)
            if fieldtype not in ['build', 'buildv2']:
                add_comments(field)
            if fieldtype == 'multiline':
                mode = 1
                thisinfo[field] = []
                if value:
                    raise MetaDataException("Unexpected text on same line as " + field + " in " + linedesc)
            elif fieldtype == 'string':
                thisinfo[field] = value
            elif fieldtype == 'list':
                thisinfo[field] = [v.strip() for v in value.replace(';', ',').split(',')]
            elif fieldtype == 'build':
                if value.endswith("\\"):
                    mode = 2
                    buildlines = [value[:-1]]
                else:
                    curbuild = parse_buildline([value])
                    thisinfo['builds'].append(curbuild)
                    add_comments('build:' + thisinfo['builds'][-1]['vercode'])
            elif fieldtype == 'buildv2':
                curbuild = {}
                vv = value.split(',')
                if len(vv) != 2:
                    raise MetaDataException('Build should have comma-separated version and vercode, not "{0}", in {1}'
                                            .format(value, linedesc))
                curbuild['version'] = vv[0]
                curbuild['vercode'] = vv[1]
                if curbuild['vercode'] in vc_seen:
                    raise MetaDataException('Duplicate build recipe found for vercode %s in %s' % (
                                            curbuild['vercode'], linedesc))
                vc_seen[curbuild['vercode']] = True
                buildlines = []
                mode = 3
            elif fieldtype == 'obsolete':
                pass        # Just throw it away!
            else:
                raise MetaDataException("Unrecognised field type for " + field + " in " + linedesc)
        elif mode == 1:     # Multiline field
            if line == '.':
                mode = 0
            else:
                thisinfo[field].append(line)
        elif mode == 2:     # Line continuation mode in Build Version
            if line.endswith("\\"):
                buildlines.append(line[:-1])
            else:
                buildlines.append(line)
                curbuild = parse_buildline(buildlines)
                thisinfo['builds'].append(curbuild)
                add_comments('build:' + thisinfo['builds'][-1]['vercode'])
                mode = 0
    add_comments(None)

    # Mode at end of file should always be 0...
    if mode == 1:
        raise MetaDataException(field + " not terminated in " + metafile.name)
    elif mode == 2:
        raise MetaDataException("Unterminated continuation in " + metafile.name)
    elif mode == 3:
        raise MetaDataException("Unterminated build in " + metafile.name)

    if not thisinfo['Description']:
        thisinfo['Description'].append('No description available')

    for build in thisinfo['builds']:
        fill_build_defaults(build)

    return thisinfo


# Write a metadata file.
#
# 'dest'    - The path to the output file
# 'app'     - The app data
def write_metadata(dest, app):

    def writecomments(key):
        written = 0
        for pf, comment in app['comments']:
            if pf == key:
                mf.write("%s\n" % comment)
                written += 1
        if written > 0:
            logging.debug("...writing comments for " + (key or 'EOF'))

    def writefield(field, value=None):
        writecomments(field)
        if value is None:
            value = app[field]
        t = metafieldtype(field)
        if t == 'list':
            value = ','.join(value)
        mf.write("%s:%s\n" % (field, value))

    mf = open(dest, 'w')
    if app['Disabled']:
        writefield('Disabled')
    if app['AntiFeatures']:
        writefield('AntiFeatures')
    if app['Provides']:
        writefield('Provides')
    writefield('Categories')
    writefield('License')
    writefield('Web Site')
    writefield('Source Code')
    writefield('Issue Tracker')
    if app['Donate']:
        writefield('Donate')
    if app['FlattrID']:
        writefield('FlattrID')
    if app['Bitcoin']:
        writefield('Bitcoin')
    if app['Litecoin']:
        writefield('Litecoin')
    if app['Dogecoin']:
        writefield('Dogecoin')
    mf.write('\n')
    if app['Name']:
        writefield('Name')
    if app['Auto Name']:
        writefield('Auto Name')
    writefield('Summary')
    writefield('Description', '')
    for line in app['Description']:
        mf.write("%s\n" % line)
    mf.write('.\n')
    mf.write('\n')
    if app['Requires Root']:
        writefield('Requires Root', 'Yes')
        mf.write('\n')
    if app['Repo Type']:
        writefield('Repo Type')
        writefield('Repo')
        mf.write('\n')
    for build in app['builds']:

        if build['version'] == "Ignore":
            continue

        writecomments('build:' + build['vercode'])
        mf.write("Build:%s,%s\n" % (build['version'], build['vercode']))

        def write_builditem(key, value):

            if key in ['version', 'vercode']:
                return

            if value == flag_defaults[key]:
                return

            t = flagtype(key)

            logging.debug("...writing {0} : {1}".format(key, value))
            outline = '    %s=' % key

            if t == 'string':
                outline += value
            if t == 'bool':
                outline += 'yes'
            elif t == 'script':
                outline += '&& \\\n        '.join([s.lstrip() for s in value.split('&& ')])
            elif t == 'list':
                outline += ','.join(value) if type(value) == list else value

            outline += '\n'
            mf.write(outline)

        for flag in flag_defaults:
            value = build[flag]
            if value:
                write_builditem(flag, value)
        mf.write('\n')

    if app['Maintainer Notes']:
        writefield('Maintainer Notes', '')
        for line in app['Maintainer Notes']:
            mf.write("%s\n" % line)
        mf.write('.\n')
        mf.write('\n')

    if app['Archive Policy']:
        writefield('Archive Policy')
    writefield('Auto Update Mode')
    writefield('Update Check Mode')
    if app['Update Check Ignore']:
        writefield('Update Check Ignore')
    if app['Vercode Operation']:
        writefield('Vercode Operation')
    if app['Update Check Name']:
        writefield('Update Check Name')
    if app['Update Check Data']:
        writefield('Update Check Data')
    if app['Current Version']:
        writefield('Current Version')
        writefield('Current Version Code')
    mf.write('\n')
    if app['No Source Since']:
        writefield('No Source Since')
        mf.write('\n')
    writecomments(None)
    mf.close()
