# -*- coding: utf-8 -*-
#
# common.py - part of the FDroid server tools
# Copyright (C) 2013, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013 Daniel Martí <mvdan@mvdan.cc>
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

import os, re, glob
import cgi

class MetaDataException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

# Designates a metadata field type and checks that it matches
#
# 'name'     - The long name of the field type
# 'matching' - List of possible values or regex expression
# 'sep'      - Separator to use if value may be a list
# 'fields'   - Metadata fields (Field:Value) of this type
# 'attrs'    - Build attributes (attr=value) of this type
#
class FieldType():
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
    'int' : FieldType("Integer",
        r'^[1-9][0-9]*$', None,
        [ 'FlattrID' ],
        [ 'vercode' ]),

    'http' : FieldType("HTTP link",
        r'^http[s]?://', None,
        [ "Web Site", "Source Code", "Issue Tracker", "Donate" ], []),

    'bitcoin' : FieldType("Bitcoin address",
        r'^[a-zA-Z0-9]{27,34}$', None,
        [ "Bitcoin" ],
        [ ]),

    'litecoin' : FieldType("Litecoin address",
        r'^L[a-zA-Z0-9]{33}$', None,
        [ "Litecoin" ],
        [ ]),

    'dogecoin' : FieldType("Dogecoin address",
        r'^D[a-zA-Z0-9]{33}$', None,
        [ "Dogecoin" ],
        [ ]),

    'Bool' : FieldType("Boolean",
        ['Yes', 'No'], None,
        [ "Requires Root" ],
        [ ]),

    'bool' : FieldType("Boolean",
        ['yes', 'no'], None,
        [ ],
        [ 'submodules', 'oldsdkloc', 'forceversion', 'forcevercode',
            'fixtrans', 'fixapos', 'novcheck' ]),

    'Repo Type' : FieldType("Repo Type",
        [ 'git', 'git-svn', 'svn', 'hg', 'bzr', 'srclib' ], None,
        [ "Repo Type" ],
        [ ]),

    'archive' : FieldType("Archive Policy",
        r'^[0-9]+ versions$', None,
        [ "Archive Policy" ],
        [ ]),

    'antifeatures' : FieldType("Anti-Feature",
        [ "Ads", "Tracking", "NonFreeNet", "NonFreeDep", "NonFreeAdd", "UpstreamNonFree" ], ',',
        [ "AntiFeatures" ],
        [ ]),

    'autoupdatemodes' : FieldType("Auto Update Mode",
        r"^(Version .+|None)$", None,
        [ "Auto Update Mode" ],
        [ ]),

    'updatecheckmodes' : FieldType("Update Check Mode",
        r"^(Tags|RepoManifest|RepoManifest/.+|RepoTrunk|HTTP|Static|None)$", None,
        [ "Update Check Mode" ],
        [ ])
}

# Check an app's metadata information for integrity errors
def check_metadata(info):
    for k, t in valuetypes.iteritems():
        for field in t.fields:
            if field in info:
                t.check(info[field], info['id'])
                if k == 'Bool':
                    info[field] = info[field] == "Yes"
        for build in info['builds']:
            for attr in t.attrs:
                if attr in build:
                    t.check(build[attr], info['id'])
                    if k == 'bool':
                        build[attr] = build[attr] == "yes"
                elif k == 'bool':
                    build[attr] = False

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
                txt = txt[index+2:]
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
                txt = txt[index+1:]

    def addtext(self, txt):
        p, h = self.linkify(txt)
        self.text_plain += p
        self.text_html += h

    def parseline(self, line):
        self.text_wiki += "%s\n" % line
        if not line:
            self.endcur()
        elif line.startswith('*'):
            self.endcur([self.stUL])
            if self.state != self.stUL:
                self.text_html += '<ul>'
                self.state = self.stUL
            self.text_html += '<li>'
            self.text_plain += '*'
            self.addtext(line[1:])
            self.text_html += '</li>'
        elif line.startswith('#'):
            self.endcur([self.stOL])
            if self.state != self.stOL:
                self.text_html += '<ol>'
                self.state = self.stOL
            self.text_html += '<li>'
            self.text_plain += '*' #TODO: lazy - put the numbers in!
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
def description_html(lines,linkres):
    ps = DescriptionFormatter(linkres)
    for line in lines:
        ps.parseline(line)
    ps.end()
    return ps.text_html

def parse_srclib(metafile, **kw):

    thisinfo = {}
    if metafile and not isinstance(metafile, file):
        metafile = open(metafile, "r")

    # Defaults for fields that come from metadata
    thisinfo['Repo Type'] = ''
    thisinfo['Repo'] = ''
    thisinfo['Subdir'] = None
    thisinfo['Prepare'] = None
    thisinfo['Srclibs'] = None
    thisinfo['Update Project'] = None

    if metafile is None:
        return thisinfo

    for line in metafile:
        line = line.rstrip('\r\n')
        if not line or line.startswith("#"):
            continue

        try:
            field, value = line.split(':',1)
        except ValueError:
            raise MetaDataException("Invalid metadata in " + metafile.name + " at: " + line)

        if field == "Subdir":
            thisinfo[field] = value.split(',')
        else:
            thisinfo[field] = value

    return thisinfo

# Read all metadata. Returns a list of 'app' objects (which are dictionaries as
# returned by the parse_metadata function.
def read_metadata(xref=True, package=None):
    apps = []
    for basedir in ('metadata', 'tmp'):
        if not os.path.exists(basedir):
            os.makedirs(basedir)
    for metafile in sorted(glob.glob(os.path.join('metadata', '*.txt'))):
        if package is None or metafile == os.path.join('metadata', package + '.txt'):
            try:
                appinfo = parse_metadata(metafile)
            except Exception, e:
                raise MetaDataException("Problem reading metadata file %s: - %s" % (metafile, str(e)))
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
            except Exception, e:
                raise MetaDataException("Problem with description of " + app['id'] +
                        " - " + str(e))

    return apps

# Get the type expected for a given metadata field.
def metafieldtype(name):
    if name in ['Description', 'Maintainer Notes']:
        return 'multiline'
    if name == 'Build Version':
        return 'build'
    if name == 'Build':
        return 'buildv2'
    if name == 'Use Built':
        return 'obsolete'
    return 'string'

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
                commit = parts[2][index+3:]
                if commit.endswith(')'):
                    commit = commit[:-1]
            thisbuild['commit'] = commit
        else:
            thisbuild['commit'] = parts[2]
        for p in parts[3:]:
            pk, pv = p.split('=', 1)
            thisbuild[pk.strip()] = pv

        return thisbuild

    def add_comments(key):
        if not curcomments:
            return
        for comment in curcomments:
            thisinfo['comments'].append((key, comment))
        del curcomments[:]

    def get_build_type(build):
        for t in ['maven', 'gradle', 'kivy']:
            if build.get(t, 'no') != 'no':
                return t
        return 'ant'

    thisinfo = {}
    if metafile:
        if not isinstance(metafile, file):
            metafile = open(metafile, "r")
        thisinfo['id'] = metafile.name[9:-4]
    else:
        thisinfo['id'] = None

    # Defaults for fields that come from metadata...
    thisinfo['Name'] = None
    thisinfo['Provides'] = None
    thisinfo['Auto Name'] = ''
    thisinfo['Categories'] = 'None'
    thisinfo['Description'] = []
    thisinfo['Summary'] = ''
    thisinfo['License'] = 'Unknown'
    thisinfo['Web Site'] = ''
    thisinfo['Source Code'] = ''
    thisinfo['Issue Tracker'] = ''
    thisinfo['Donate'] = None
    thisinfo['FlattrID'] = None
    thisinfo['Bitcoin'] = None
    thisinfo['Litecoin'] = None
    thisinfo['Dogecoin'] = None
    thisinfo['Disabled'] = None
    thisinfo['AntiFeatures'] = None
    thisinfo['Archive Policy'] = None
    thisinfo['Update Check Mode'] = 'None'
    thisinfo['Vercode Operation'] = None
    thisinfo['Auto Update Mode'] = 'None'
    thisinfo['Current Version'] = ''
    thisinfo['Current Version Code'] = '0'
    thisinfo['Repo Type'] = ''
    thisinfo['Repo'] = ''
    thisinfo['Requires Root'] = False
    thisinfo['No Source Since'] = ''

    # General defaults...
    thisinfo['builds'] = []
    thisinfo['comments'] = []

    if metafile is None:
        return thisinfo

    mode = 0
    buildlines = []
    curcomments = []
    curbuild = None

    for line in metafile:
        line = line.rstrip('\r\n')
        if mode == 3:
            if not any(line.startswith(s) for s in (' ', '\t')):
                if 'commit' not in curbuild and 'disable' not in curbuild:
                    raise MetaDataException("No commit specified for {0} in {1}".format(
                        curbuild['version'], metafile.name))
                thisinfo['builds'].append(curbuild)
                add_comments('build:' + curbuild['version'])
                mode = 0
            else:
                if line.endswith('\\'):
                    buildlines.append(line[:-1].lstrip())
                else:
                    buildlines.append(line.lstrip())
                    bl = ''.join(buildlines)
                    bv = bl.split('=', 1)
                    if len(bv) != 2:
                        raise MetaDataException("Invalid build flag at {0} in {1}".
                                format(buildlines[0], metafile.name))
                    name, val = bv
                    if name in curbuild:
                        raise MetaDataException("Duplicate definition on {0} in version {1} of {2}".
                                format(name, curbuild['version'], metafile.name))
                    curbuild[name] = val.lstrip()
                    buildlines = []

        if mode == 0:
            if not line:
                continue
            if line.startswith("#"):
                curcomments.append(line)
                continue
            try:
                field, value = line.split(':',1)
            except ValueError:
                raise MetaDataException("Invalid metadata in " + metafile.name + " at: " + line)

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
                    raise MetaDataException("Unexpected text on same line as " + field + " in " + metafile.name)
            elif fieldtype == 'string':
                if field == 'Category' and thisinfo['Categories'] == 'None':
                    thisinfo['Categories'] = value.replace(';',',')
                thisinfo[field] = value
            elif fieldtype == 'build':
                if value.endswith("\\"):
                    mode = 2
                    buildlines = [value[:-1]]
                else:
                    thisinfo['builds'].append(parse_buildline([value]))
                    add_comments('build:' + thisinfo['builds'][-1]['version'])
            elif fieldtype == 'buildv2':
                curbuild = {}
                vv = value.split(',')
                if len(vv) != 2:
                    raise MetaDataException('Build should have comma-separated version and vercode, not "{0}", in {1}'.
                        format(value, metafile.name))
                curbuild['version'] = vv[0]
                curbuild['vercode'] = vv[1]
                buildlines = []
                mode = 3
            elif fieldtype == 'obsolete':
                pass        # Just throw it away!
            else:
                raise MetaDataException("Unrecognised field type for " + field + " in " + metafile.name)
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
                thisinfo['builds'].append(
                    parse_buildline(buildlines))
                add_comments('build:' + thisinfo['builds'][-1]['version'])
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
        build['type'] = get_build_type(build)

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
        #if options.verbose and written > 0:
            #print "...writing comments for " + (key if key else 'EOF')

    def writefield(field, value=None):
        writecomments(field)
        if value is None:
            value = app[field]
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
        writecomments('build:' + build['version'])
        mf.write("Build:%s,%s\n" % ( build['version'], build['vercode']))

        # This defines the preferred order for the build items - as in the
        # manual, they're roughly in order of application.
        keyorder = ['disable', 'commit', 'subdir', 'submodules', 'init',
                    'gradle', 'maven', 'oldsdkloc', 'target', 'compilesdk',
                    'update', 'encoding', 'forceversion', 'forcevercode', 'rm',
                    'fixtrans', 'fixapos', 'extlibs', 'srclibs', 'patch',
                    'prebuild', 'scanignore', 'scandelete', 'build', 'buildjni',
                    'preassemble', 'bindir', 'antcommand', 'novcheck']

        def write_builditem(key, value):
            if key in ['version', 'vercode', 'origlines', 'type']:
                return
            if key in valuetypes['bool'].attrs:
                if not value:
                    return
                value = 'yes'
            #if options.verbose:
                #print "...writing {0} : {1}".format(key, value)
            outline = '    %s=' % key
            outline += '&& \\\n        '.join([s.lstrip() for s in value.split('&& ')])
            outline += '\n'
            mf.write(outline)

        for key in keyorder:
            if key in build:
                write_builditem(key, build[key])
        for key, value in build.iteritems():
            if not key in keyorder:
                write_builditem(key, value)
        mf.write('\n')

    if 'Maintainer Notes' in app:
        writefield('Maintainer Notes', '')
        for line in app['Maintainer Notes']:
            mf.write("%s\n" % line)
        mf.write('.\n')
        mf.write('\n')


    if app['Archive Policy']:
        writefield('Archive Policy')
    writefield('Auto Update Mode')
    writefield('Update Check Mode')
    if app['Vercode Operation']:
        writefield('Vercode Operation')
    if 'Update Check Data' in app:
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


