#!/usr/bin/env python3
#
# lint.py - part of the FDroid server tool
# Copyright (C) 2013-2014 Daniel Martí <mvdan@mvdan.cc>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See th
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public Licen
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from argparse import ArgumentParser
import re
import sys
import platform
import urllib.parse
from pathlib import Path

from . import _
from . import common
from . import metadata
from . import rewritemeta

config = None
options = None


def enforce_https(domain):
    return (
        re.compile(
            r'^http://([^/]*\.)?' + re.escape(domain) + r'(/.*)?', re.IGNORECASE
        ),
        domain + " URLs should always use https://",
    )


https_enforcings = [
    enforce_https('github.com'),
    enforce_https('gitlab.com'),
    enforce_https('bitbucket.org'),
    enforce_https('apache.org'),
    enforce_https('google.com'),
    enforce_https('git.code.sf.net'),
    enforce_https('svn.code.sf.net'),
    enforce_https('anongit.kde.org'),
    enforce_https('savannah.nongnu.org'),
    enforce_https('git.savannah.nongnu.org'),
    enforce_https('download.savannah.nongnu.org'),
    enforce_https('savannah.gnu.org'),
    enforce_https('git.savannah.gnu.org'),
    enforce_https('download.savannah.gnu.org'),
    enforce_https('github.io'),
    enforce_https('gitlab.io'),
    enforce_https('githubusercontent.com'),
]


def forbid_shortener(domain):
    return (
        re.compile(r'https?://[^/]*' + re.escape(domain) + r'/.*'),
        _("URL shorteners should not be used"),
    )


http_url_shorteners = [
    forbid_shortener('1url.com'),
    forbid_shortener('adf.ly'),
    forbid_shortener('bc.vc'),
    forbid_shortener('bit.do'),
    forbid_shortener('bit.ly'),
    forbid_shortener('bitly.com'),
    forbid_shortener('budurl.com'),
    forbid_shortener('buzurl.com'),
    forbid_shortener('cli.gs'),
    forbid_shortener('cur.lv'),
    forbid_shortener('cutt.us'),
    forbid_shortener('db.tt'),
    forbid_shortener('filoops.info'),
    forbid_shortener('goo.gl'),
    forbid_shortener('is.gd'),
    forbid_shortener('ity.im'),
    forbid_shortener('j.mp'),
    forbid_shortener('l.gg'),
    forbid_shortener('lnkd.in'),
    forbid_shortener('moourl.com'),
    forbid_shortener('ow.ly'),
    forbid_shortener('para.pt'),
    forbid_shortener('po.st'),
    forbid_shortener('q.gs'),
    forbid_shortener('qr.ae'),
    forbid_shortener('qr.net'),
    forbid_shortener('rdlnk.com'),
    forbid_shortener('scrnch.me'),
    forbid_shortener('short.nr'),
    forbid_shortener('sn.im'),
    forbid_shortener('snipurl.com'),
    forbid_shortener('su.pr'),
    forbid_shortener('t.co'),
    forbid_shortener('tiny.cc'),
    forbid_shortener('tinyarrows.com'),
    forbid_shortener('tinyurl.com'),
    forbid_shortener('tr.im'),
    forbid_shortener('tweez.me'),
    forbid_shortener('twitthis.com'),
    forbid_shortener('twurl.nl'),
    forbid_shortener('tyn.ee'),
    forbid_shortener('u.bb'),
    forbid_shortener('u.to'),
    forbid_shortener('ur1.ca'),
    forbid_shortener('urlof.site'),
    forbid_shortener('v.gd'),
    forbid_shortener('vzturl.com'),
    forbid_shortener('x.co'),
    forbid_shortener('xrl.us'),
    forbid_shortener('yourls.org'),
    forbid_shortener('zip.net'),
    forbid_shortener('✩.ws'),
    forbid_shortener('➡.ws'),
]

http_checks = (
    https_enforcings
    + http_url_shorteners
    + [
        (
            re.compile(r'^(?!https?://)[^/]+'),
            _("URL must start with https:// or http://"),
        ),
        (
            re.compile(r'^https://(github|gitlab)\.com(/[^/]+){2,3}\.git'),
            _("Appending .git is not necessary"),
        ),
        (
            re.compile(
                r'^https://[^/]*(github|gitlab|bitbucket|rawgit|githubusercontent)\.[a-zA-Z]+/([^/]+/){2,3}master/'
            ),
            _("Use /HEAD instead of /master to point at a file in the default branch"),
        ),
    ]
)

regex_checks = {
    'WebSite': http_checks,
    'SourceCode': http_checks,
    'Repo': https_enforcings,
    'UpdateCheckMode': https_enforcings,
    'IssueTracker': http_checks
    + [
        (re.compile(r'.*github\.com/[^/]+/[^/]+/*$'), _("/issues is missing")),
        (re.compile(r'.*gitlab\.com/[^/]+/[^/]+/*$'), _("/issues is missing")),
    ],
    'Donate': http_checks
    + [
        (
            re.compile(r'.*flattr\.com'),
            _("Flattr donation methods belong in the FlattrID: field"),
        ),
        (
            re.compile(r'.*liberapay\.com'),
            _("Liberapay donation methods belong in the Liberapay: field"),
        ),
        (
            re.compile(r'.*opencollective\.com'),
            _("OpenCollective donation methods belong in the OpenCollective: field"),
        ),
    ],
    'Changelog': http_checks,
    'Author Name': [
        (re.compile(r'^\s'), _("Unnecessary leading space")),
        (re.compile(r'.*\s$'), _("Unnecessary trailing space")),
    ],
    'Summary': [
        (
            re.compile(r'.*\b(free software|open source)\b.*', re.IGNORECASE),
            _("No need to specify that the app is Free Software"),
        ),
        (
            re.compile(
                r'.*((your|for).*android|android.*(app|device|client|port|version))',
                re.IGNORECASE,
            ),
            _("No need to specify that the app is for Android"),
        ),
        (re.compile(r'.*[a-z0-9][.!?]( |$)'), _("Punctuation should be avoided")),
        (re.compile(r'^\s'), _("Unnecessary leading space")),
        (re.compile(r'.*\s$'), _("Unnecessary trailing space")),
    ],
    'Description': https_enforcings
    + http_url_shorteners
    + [
        (re.compile(r'\s*[*#][^ .]'), _("Invalid bulleted list")),
        (
            re.compile(r'https://f-droid.org/[a-z][a-z](_[A-Za-z]{2,4})?/'),
            _("Locale included in f-droid.org URL"),
        ),
        (re.compile(r'^\s'), _("Unnecessary leading space")),
        (re.compile(r'.*\s$'), _("Unnecessary trailing space")),
        (
            re.compile(
                r'.*<(applet|base|body|button|embed|form|head|html|iframe|img|input|link|object|picture|script|source|style|svg|video).*',
                re.IGNORECASE,
            ),
            _("Forbidden HTML tags"),
        ),
        (
            re.compile(r'''.*\s+src=["']javascript:.*'''),
            _("Javascript in HTML src attributes"),
        ),
    ],
}

locale_pattern = re.compile(r"[a-z]{2,3}(-([A-Z][a-zA-Z]+|\d+|[a-z]+))*")


def check_regexes(app):
    for f, checks in regex_checks.items():
        for m, r in checks:
            v = app.get(f)
            t = metadata.fieldtype(f)
            if t == metadata.TYPE_MULTILINE:
                for line in v.splitlines():
                    if m.match(line):
                        yield "%s at line '%s': %s" % (f, line, r)
            else:
                if v is None:
                    continue
                if m.match(v):
                    yield "%s '%s': %s" % (f, v, r)


def get_lastbuild(builds):
    lowest_vercode = -1
    lastbuild = None
    for build in builds:
        if not build.disable:
            vercode = int(build.versionCode)
            if lowest_vercode == -1 or vercode < lowest_vercode:
                lowest_vercode = vercode
        if not lastbuild or int(build.versionCode) > int(lastbuild.versionCode):
            lastbuild = build
    return lastbuild


def check_update_check_data_url(app):  # noqa: D403
    """UpdateCheckData must have a valid HTTPS URL to protect checkupdates runs."""
    if app.UpdateCheckData and app.UpdateCheckMode == 'HTTP':
        urlcode, codeex, urlver, verex = app.UpdateCheckData.split('|')
        for url in (urlcode, urlver):
            if url != '.':
                parsed = urllib.parse.urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    yield _('UpdateCheckData not a valid URL: {url}').format(url=url)
                if parsed.scheme != 'https':
                    yield _('UpdateCheckData must use HTTPS URL: {url}').format(url=url)


def check_vercode_operation(app):
    if app.VercodeOperation and not common.VERCODE_OPERATION_RE.match(
        app.VercodeOperation
    ):
        yield _('Invalid VercodeOperation: {field}').format(field=app.VercodeOperation)


def check_ucm_tags(app):
    lastbuild = get_lastbuild(app.get('Builds', []))
    if (
        lastbuild is not None
        and lastbuild.commit
        and app.UpdateCheckMode == 'RepoManifest'
        and not lastbuild.commit.startswith('unknown')
        and lastbuild.versionCode == app.CurrentVersionCode
        and not lastbuild.forcevercode
        and any(s in lastbuild.commit for s in '.,_-/')
    ):
        yield _(
            "Last used commit '{commit}' looks like a tag, but UpdateCheckMode is '{ucm}'"
        ).format(commit=lastbuild.commit, ucm=app.UpdateCheckMode)


def check_char_limits(app):
    limits = config['char_limits']

    if len(app.Summary) > limits['summary']:
        yield _("Summary of length {length} is over the {limit} char limit").format(
            length=len(app.Summary), limit=limits['summary']
        )

    if len(app.Description) > limits['description']:
        yield _("Description of length {length} is over the {limit} char limit").format(
            length=len(app.Description), limit=limits['description']
        )


def check_old_links(app):
    usual_sites = [
        'github.com',
        'gitlab.com',
        'bitbucket.org',
    ]
    old_sites = [
        'gitorious.org',
        'code.google.com',
    ]
    if any(s in app.Repo for s in usual_sites):
        for f in ['WebSite', 'SourceCode', 'IssueTracker', 'Changelog']:
            v = app.get(f)
            if any(s in v for s in old_sites):
                yield _("App is in '{repo}' but has a link to {url}").format(
                    repo=app.Repo, url=v
                )


def check_useless_fields(app):
    if app.UpdateCheckName == app.id:
        yield _("UpdateCheckName is set to the known application ID, it can be removed")


filling_ucms = re.compile(r'^(Tags.*|RepoManifest.*)')


def check_checkupdates_ran(app):
    if filling_ucms.match(app.UpdateCheckMode):
        if (
            not app.AutoName
            and not app.CurrentVersion
            and app.CurrentVersionCode == '0'
        ):
            yield _(
                "UpdateCheckMode is set but it looks like checkupdates hasn't been run yet"
            )


def check_empty_fields(app):
    if not app.Categories:
        yield _("Categories are not set")


all_categories = set(
    [
        "Connectivity",
        "Development",
        "Games",
        "Graphics",
        "Internet",
        "Money",
        "Multimedia",
        "Navigation",
        "Phone & SMS",
        "Reading",
        "Science & Education",
        "Security",
        "Sports & Health",
        "System",
        "Theming",
        "Time",
        "Writing",
    ]
)


def check_categories(app):
    for categ in app.Categories:
        if categ not in all_categories:
            yield _("Categories '%s' is not valid" % categ)


def check_duplicates(app):
    links_seen = set()
    for f in ['Source Code', 'Web Site', 'Issue Tracker', 'Changelog']:
        v = app.get(f)
        if not v:
            continue
        v = v.lower()
        if v in links_seen:
            yield _("Duplicate link in '{field}': {url}").format(field=f, url=v)
        else:
            links_seen.add(v)

    name = common.get_app_display_name(app)
    if app.Summary and name:
        if app.Summary.lower() == name.lower():
            yield _("Summary '%s' is just the app's name") % app.Summary

    if app.Summary and app.Description and len(app.Description) == 1:
        if app.Summary.lower() == app.Description[0].lower():
            yield _("Description '%s' is just the app's summary") % app.Summary

    seenlines = set()
    for line in app.Description.splitlines():
        if len(line) < 1:
            continue
        if line in seenlines:
            yield _("Description has a duplicate line")
        seenlines.add(line)


desc_url = re.compile(r'(^|[^[])\[([^ ]+)( |\]|$)')


def check_mediawiki_links(app):
    wholedesc = ' '.join(app.Description)
    for um in desc_url.finditer(wholedesc):
        url = um.group(1)
        for m, r in http_checks:
            if m.match(url):
                yield _("URL {url} in Description: {error}").format(url=url, error=r)


def check_bulleted_lists(app):
    validchars = ['*', '#']
    lchar = ''
    lcount = 0
    for line in app.Description.splitlines():
        if len(line) < 1:
            lcount = 0
            continue

        if line[0] == lchar and line[1] == ' ':
            lcount += 1
            if lcount > 2 and lchar not in validchars:
                yield _(
                    "Description has a list (%s) but it isn't bulleted (*) nor numbered (#)"
                ) % lchar
                break
        else:
            lchar = line[0]
            lcount = 1


def check_builds(app):
    supported_flags = set(metadata.build_flags)
    # needed for YAML and JSON
    for build in app.get('Builds', []):
        if build.disable:
            if build.disable.startswith('Generated by import.py'):
                yield _(
                    "Build generated by `fdroid import` - remove disable line once ready"
                )
            continue
        for s in ['master', 'origin', 'HEAD', 'default', 'trunk']:
            if build.commit and build.commit.startswith(s):
                yield _(
                    "Branch '{branch}' used as commit in build '{versionName}'"
                ).format(branch=s, versionName=build.versionName)
            for srclib in build.srclibs:
                if '@' in srclib:
                    ref = srclib.split('@')[1].split('/')[0]
                    if ref.startswith(s):
                        yield _(
                            "Branch '{branch}' used as commit in srclib '{srclib}'"
                        ).format(branch=s, srclib=srclib)
                else:
                    yield _(
                        'srclibs missing name and/or @'
                    ) + ' (srclibs: ' + srclib + ')'
        for key in build.keys():
            if key not in supported_flags:
                yield _('%s is not an accepted build field') % key


def check_files_dir(app):
    dir_path = Path('metadata') / app.id
    if not dir_path.is_dir():
        return
    files = set()
    for path in dir_path.iterdir():
        name = path.name
        if not (
            path.is_file() or name == 'signatures' or locale_pattern.fullmatch(name)
        ):
            yield _("Found non-file at %s") % path
            continue
        files.add(name)

    used = {
        'signatures',
    }
    for build in app.get('Builds', []):
        for fname in build.patch:
            if fname not in files:
                yield _("Unknown file '{filename}' in build '{versionName}'").format(
                    filename=fname, versionName=build.versionName
                )
            else:
                used.add(fname)

    for name in files.difference(used):
        if locale_pattern.fullmatch(name):
            continue
        yield _("Unused file at %s") % (dir_path / name)


def check_format(app):
    if options.format and not rewritemeta.proper_format(app):
        yield _("Run rewritemeta to fix formatting")


def check_license_tag(app):
    """Ensure all license tags contain only valid/approved values."""
    if config['lint_licenses'] is None:
        return
    if app.License not in config['lint_licenses']:
        if config['lint_licenses'] == APPROVED_LICENSES:
            yield _(
                'Unexpected license tag "{}"! Only use FSF or OSI '
                'approved tags from https://spdx.org/license-list'
            ).format(app.License)
        else:
            yield _(
                'Unexpected license tag "{}"! Only use license tags '
                'configured in your config file'
            ).format(app.License)


def check_extlib_dir(apps):
    dir_path = Path('build/extlib')
    extlib_files = set()
    for path in dir_path.glob('**/*'):
        if path.is_file():
            extlib_files.add(path.relative_to(dir_path))

    used = set()
    for app in apps:
        for build in app.get('Builds', []):
            for path in build.extlibs:
                path = Path(path)
                if path not in extlib_files:
                    yield _(
                        "{appid}: Unknown extlib {path} in build '{versionName}'"
                    ).format(appid=app.id, path=path, versionName=build.versionName)
                else:
                    used.add(path)

    for path in extlib_files.difference(used):
        if path.name not in [
            '.gitignore',
            'source.txt',
            'origin.txt',
            'md5.txt',
            'LICENSE',
            'LICENSE.txt',
            'COPYING',
            'COPYING.txt',
            'NOTICE',
            'NOTICE.txt',
        ]:
            yield _("Unused extlib at %s") % (dir_path / path)


def check_app_field_types(app):
    """Check the fields have valid data types."""
    for field in app.keys():
        v = app.get(field)
        t = metadata.fieldtype(field)
        if v is None:
            continue
        elif field == 'Builds':
            if not isinstance(v, list):
                yield (
                    _(
                        "{appid}: {field} must be a '{type}', but it is a '{fieldtype}'!"
                    ).format(
                        appid=app.id,
                        field=field,
                        type='list',
                        fieldtype=v.__class__.__name__,
                    )
                )
        elif t == metadata.TYPE_LIST and not isinstance(v, list):
            yield (
                _(
                    "{appid}: {field} must be a '{type}', but it is a '{fieldtype}!'"
                ).format(
                    appid=app.id,
                    field=field,
                    type='list',
                    fieldtype=v.__class__.__name__,
                )
            )
        elif t == metadata.TYPE_STRING and not type(v) in (str, bool, dict):
            yield (
                _(
                    "{appid}: {field} must be a '{type}', but it is a '{fieldtype}'!"
                ).format(
                    appid=app.id,
                    field=field,
                    type='str',
                    fieldtype=v.__class__.__name__,
                )
            )


def check_for_unsupported_metadata_files(basedir=""):
    """Check whether any non-metadata files are in metadata/."""
    basedir = Path(basedir)
    global config

    if not (basedir / 'metadata').exists():
        return False
    return_value = False
    for f in (basedir / 'metadata').iterdir():
        if f.is_dir():
            if not Path(str(f) + '.yml').exists():
                print(_('"%s/" has no matching metadata file!') % f)
                return_value = True
        elif f.suffix == '.yml':
            packageName = f.stem
            if not common.is_valid_package_name(packageName):
                print(
                    '"'
                    + packageName
                    + '" is an invalid package name!\n'
                    + 'https://developer.android.com/studio/build/application-id'
                )
                return_value = True
        else:
            print(
                _(
                    '"{path}" is not a supported file format (use: metadata/*.yml)'
                ).format(path=f.relative_to(basedir))
            )
            return_value = True

    return return_value


def check_current_version_code(app):
    """Check that the CurrentVersionCode is currently available."""
    archive_policy = app.get('ArchivePolicy')
    if archive_policy and archive_policy.split()[0] == "0":
        return
    cv = app.get('CurrentVersionCode')
    if cv is not None and int(cv) == 0:
        return

    builds = app.get('Builds')
    active_builds = 0
    min_versionCode = None
    if builds:
        for build in builds:
            vc = int(build['versionCode'])
            if min_versionCode is None or min_versionCode > vc:
                min_versionCode = vc
            if not build.get('disable'):
                active_builds += 1
            if cv == build['versionCode']:
                break
    if active_builds == 0:
        return  # all builds are disabled
    if cv is not None and int(cv) < min_versionCode:
        yield (
            _(
                'CurrentVersionCode {cv} is less than oldest build entry {versionCode}'
            ).format(cv=cv, versionCode=min_versionCode)
        )


def main():

    global config, options

    # Parse command line...
    parser = ArgumentParser()
    common.setup_global_opts(parser)
    parser.add_argument(
        "-f",
        "--format",
        action="store_true",
        default=False,
        help=_("Also warn about formatting issues, like rewritemeta -l"),
    )
    parser.add_argument(
        '--force-yamllint',
        action="store_true",
        default=False,
        help=_(
            "When linting the entire repository yamllint is disabled by default. "
            "This option forces yamllint regardless."
        ),
    )
    parser.add_argument(
        "appid", nargs='*', help=_("application ID of file to operate on")
    )
    metadata.add_metadata_arguments(parser)
    options = parser.parse_args()
    metadata.warnings_action = options.W

    config = common.read_config(options)

    # Get all apps...
    allapps = metadata.read_metadata(options.appid)
    apps = common.read_app_args(options.appid, allapps, False)

    anywarns = check_for_unsupported_metadata_files()

    apps_check_funcs = []
    if not options.appid:
        # otherwise it finds tons of unused extlibs
        apps_check_funcs.append(check_extlib_dir)
    for check_func in apps_check_funcs:
        for warn in check_func(apps.values()):
            anywarns = True
            print(warn)

    for appid, app in apps.items():
        if app.Disabled:
            continue

        if options.force_yamllint:
            import yamllint  # throw error if it is not installed

            yamllint  # make pyflakes ignore this

        # only run yamllint when linting individual apps.
        if options.appid or options.force_yamllint:

            # run yamllint on app metadata
            ymlpath = Path('metadata') / (appid + '.yml')
            if ymlpath.is_file():
                yamllintresult = common.run_yamllint(ymlpath)
                if yamllintresult:
                    print(yamllintresult)

            # run yamllint on srclib metadata
            srclibs = set()
            for build in app.get('Builds', []):
                for srclib in build.srclibs:
                    name, _ref, _number, _subdir = common.parse_srclib_spec(srclib)
                    srclibs.add(name + '.yml')
            for srclib in srclibs:
                srclibpath = Path('srclibs') / srclib
                if srclibpath.is_file():
                    if platform.system() == 'Windows':
                        # Handle symlink on Windows
                        symlink = srclibpath.read_text()
                        if symlink in srclibs:
                            continue
                        elif (srclibpath.parent / symlink).is_file():
                            srclibpath = srclibpath.parent / symlink
                    yamllintresult = common.run_yamllint(srclibpath)
                    if yamllintresult:
                        print(yamllintresult)

        app_check_funcs = [
            check_app_field_types,
            check_regexes,
            check_update_check_data_url,
            check_vercode_operation,
            check_ucm_tags,
            check_char_limits,
            check_old_links,
            check_checkupdates_ran,
            check_useless_fields,
            check_empty_fields,
            check_categories,
            check_duplicates,
            check_mediawiki_links,
            check_bulleted_lists,
            check_builds,
            check_files_dir,
            check_format,
            check_license_tag,
            check_current_version_code,
        ]

        for check_func in app_check_funcs:
            for warn in check_func(app):
                anywarns = True
                print("%s: %s" % (appid, warn))

    if anywarns:
        sys.exit(1)


# A compiled, public domain list of official SPDX license tags.  generated
# using: `python3 -m spdx_license_list print --filter-fsf-or-osi` Only contains
# licenes approved by either FSF to be free/libre software or OSI to be open
# source
APPROVED_LICENSES = [
    '0BSD',
    'AAL',
    'AFL-1.1',
    'AFL-1.2',
    'AFL-2.0',
    'AFL-2.1',
    'AFL-3.0',
    'AGPL-3.0-only',
    'AGPL-3.0-or-later',
    'APL-1.0',
    'APSL-1.0',
    'APSL-1.1',
    'APSL-1.2',
    'APSL-2.0',
    'Apache-1.0',
    'Apache-1.1',
    'Apache-2.0',
    'Artistic-1.0',
    'Artistic-1.0-Perl',
    'Artistic-1.0-cl8',
    'Artistic-2.0',
    'Beerware',
    'BSD-1-Clause',
    'BSD-2-Clause',
    'BSD-2-Clause-FreeBSD',
    'BSD-2-Clause-Patent',
    'BSD-3-Clause',
    'BSD-3-Clause-Clear',
    'BSD-3-Clause-LBNL',
    'BSD-4-Clause',
    'BSL-1.0',
    'BitTorrent-1.1',
    'CAL-1.0',
    'CAL-1.0-Combined-Work-Exception',
    'CATOSL-1.1',
    'CC-BY-4.0',
    'CC-BY-SA-4.0',
    'CC0-1.0',
    'CDDL-1.0',
    'CECILL-2.0',
    'CECILL-2.1',
    'CECILL-B',
    'CECILL-C',
    'CNRI-Python',
    'CPAL-1.0',
    'CPL-1.0',
    'CUA-OPL-1.0',
    'ClArtistic',
    'Condor-1.1',
    'ECL-1.0',
    'ECL-2.0',
    'EFL-1.0',
    'EFL-2.0',
    'EPL-1.0',
    'EPL-2.0',
    'EUDatagrid',
    'EUPL-1.1',
    'EUPL-1.2',
    'Entessa',
    'FSFAP',
    'FTL',
    'Fair',
    'Frameworx-1.0',
    'GFDL-1.1-only',
    'GFDL-1.1-or-later',
    'GFDL-1.2-only',
    'GFDL-1.2-or-later',
    'GFDL-1.3-only',
    'GFDL-1.3-or-later',
    'GPL-2.0-only',
    'GPL-2.0-or-later',
    'GPL-3.0-only',
    'GPL-3.0-or-later',
    'HPND',
    'IJG',
    'IPA',
    'IPL-1.0',
    'ISC',
    'Imlib2',
    'Intel',
    'LGPL-2.0-only',
    'LGPL-2.0-or-later',
    'LGPL-2.1-only',
    'LGPL-2.1-or-later',
    'LGPL-3.0-only',
    'LGPL-3.0-or-later',
    'LPL-1.0',
    'LPL-1.02',
    'LPPL-1.2',
    'LPPL-1.3a',
    'LPPL-1.3c',
    'LiLiQ-P-1.1',
    'LiLiQ-R-1.1',
    'LiLiQ-Rplus-1.1',
    'MIT',
    'MIT-0',
    'MIT-CMU',
    'MPL-1.0',
    'MPL-1.1',
    'MPL-2.0',
    'MPL-2.0-no-copyleft-exception',
    'MS-PL',
    'MS-RL',
    'MirOS',
    'Motosoto',
    'MulanPSL-2.0',
    'Multics',
    'NASA-1.3',
    'NCSA',
    'NGPL',
    'NOSL',
    'NPL-1.0',
    'NPL-1.1',
    'NPOSL-3.0',
    'NTP',
    'Naumen',
    'Nokia',
    'OCLC-2.0',
    'ODbL-1.0',
    'OFL-1.0',
    'OFL-1.1',
    'OFL-1.1-RFN',
    'OFL-1.1-no-RFN',
    'OGTSL',
    'OLDAP-2.3',
    'OLDAP-2.7',
    'OLDAP-2.8',
    'OSET-PL-2.1',
    'OSL-1.0',
    'OSL-1.1',
    'OSL-2.0',
    'OSL-2.1',
    'OSL-3.0',
    'OpenSSL',
    'PHP-3.0',
    'PHP-3.01',
    'PostgreSQL',
    'Python-2.0',
    'QPL-1.0',
    'RPL-1.1',
    'RPL-1.5',
    'RPSL-1.0',
    'RSCPL',
    'Ruby',
    'SGI-B-2.0',
    'SISSL',
    'SMLNJ',
    'SPL-1.0',
    'SimPL-2.0',
    'Sleepycat',
    'UCL-1.0',
    'UPL-1.0',
    'Unicode-DFS-2016',
    'Unlicense',
    'VSL-1.0',
    'Vim',
    'W3C',
    'WTFPL',
    'Watcom-1.0',
    'X11',
    'XFree86-1.1',
    'Xnet',
    'XSkat',
    'YPL-1.1',
    'ZPL-2.0',
    'ZPL-2.1',
    'Zend-2.0',
    'Zimbra-1.3',
    'Zlib',
    'gnuplot',
    'iMatix',
    'xinetd',
]

# an F-Droid addition, until we can enforce a better option
APPROVED_LICENSES.append("PublicDomain")

if __name__ == "__main__":
    main()
