#!/usr/bin/env python3
#
# fdroidserver/__main__.py - part of the FDroid server tools
# Copyright (C) 2020 Michael Pöhn <michael.poehn@fsfe.org>
# Copyright (C) 2010-2015, Ciaran Gultnieks, ciaran@ciarang.com
# Copyright (C) 2013-2014 Daniel Marti <mvdan@mvdan.cc>
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

import sys
import os
import locale
import pkgutil
import logging
import importlib

import fdroidserver.common
import fdroidserver.metadata
from fdroidserver import _
from argparse import ArgumentError
from collections import OrderedDict


commands = OrderedDict([
    ("build", _("Build a package from source")),
    ("init", _("Quickly start a new repository")),
    ("publish", _("Sign and place packages in the repo")),
    ("gpgsign", _("Add PGP signatures using GnuPG for packages in repo")),
    ("update", _("Update repo information for new packages")),
    ("deploy", _("Interact with the repo HTTP server")),
    ("verify", _("Verify the integrity of downloaded packages")),
    ("checkupdates", _("Check for updates to applications")),
    ("import", _("Add a new application from its source code")),
    ("install", _("Install built packages on devices")),
    ("readmeta", _("Read all the metadata files and exit")),
    ("rewritemeta", _("Rewrite all the metadata files")),
    ("lint", _("Warn about possible metadata errors")),
    ("scanner", _("Scan the source code of a package")),
    ("stats", _("Update the stats of the repo")),
    ("server", _("Old, deprecated name for fdroid deploy")),
    ("signindex", _("Sign indexes created using update --nosign")),
    ("btlog", _("Update the binary transparency log for a URL")),
    ("signatures", _("Extract signatures from APKs")),
    ("nightly", _("Set up an app build for a nightly build repo")),
    ("mirror", _("Download complete mirrors of small repos")),
])


def print_help(fdroid_modules=None):
    print(_("usage: ") + _("fdroid [<command>] [-h|--help|--version|<args>]"))
    print("")
    print(_("Valid commands are:"))
    for cmd, summary in commands.items():
        print("   " + cmd + ' ' * (15 - len(cmd)) + summary)
    if fdroid_modules:
        print(_('commands from plugin modules:'))
        for command in sorted(fdroid_modules.keys()):
            print('   {:15}{}'.format(command, fdroid_modules[command]['summary']))
    print("")


def find_plugins():
    fdroid_modules = [x[1] for x in pkgutil.iter_modules() if x[1].startswith('fdroid_')]
    commands = {}
    for module_name in fdroid_modules:
        try:
            command_name = module_name[7:]
            module = importlib.import_module(module_name)
            if hasattr(module, 'fdroid_summary') and hasattr(module, 'main'):
                commands[command_name] = {'summary': module.fdroid_summary,
                                          'module': module}
        except IOError:
            # We need to keep module lookup fault tolerant because buggy
            # modules must not prevent fdroidserver from functioning
            # TODO: think about warning users or debug logs for notifying devs
            pass
    return commands


def main():
    sys.path.append(os.getcwd())
    fdroid_modules = find_plugins()

    if len(sys.argv) <= 1:
        print_help(fdroid_modules=fdroid_modules)
        sys.exit(0)

    command = sys.argv[1]
    if command not in commands and command not in fdroid_modules.keys():
        if command in ('-h', '--help'):
            print_help(fdroid_modules=fdroid_modules)
            sys.exit(0)
        elif command == '--version':
            output = _('no version info found!')
            cmddir = os.path.realpath(os.path.dirname(os.path.dirname(__file__)))
            moduledir = os.path.realpath(os.path.dirname(fdroidserver.common.__file__) + '/..')
            if cmddir == moduledir:
                # running from git
                os.chdir(cmddir)
                if os.path.isdir('.git'):
                    import subprocess
                    try:
                        output = subprocess.check_output(['git', 'describe'],
                                                         stderr=subprocess.STDOUT,
                                                         universal_newlines=True)
                    except subprocess.CalledProcessError:
                        output = 'git commit ' + subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                                                         universal_newlines=True)
                elif os.path.exists('setup.py'):
                    import re
                    m = re.search(r'''.*[\s,\(]+version\s*=\s*["']([0-9a-z.]+)["'].*''',
                                  open('setup.py').read(), flags=re.MULTILINE)
                    if m:
                        output = m.group(1) + '\n'
            else:
                from pkg_resources import get_distribution
                output = get_distribution('fdroidserver').version + '\n'
            print(output),
            sys.exit(0)
        else:
            print(_("Command '%s' not recognised.\n" % command))
            print_help(fdroid_modules=fdroid_modules)
            sys.exit(1)

    verbose = any(s in sys.argv for s in ['-v', '--verbose'])
    quiet = any(s in sys.argv for s in ['-q', '--quiet'])

    # Helpful to differentiate warnings from errors even when on quiet
    logformat = '%(levelname)s: %(message)s'
    loglevel = logging.INFO
    if verbose:
        loglevel = logging.DEBUG
    elif quiet:
        loglevel = logging.WARN

    logging.basicConfig(format=logformat, level=loglevel)

    if verbose and quiet:
        logging.critical(_("Conflicting arguments: '--verbose' and '--quiet' "
                           "can not be specified at the same time."))
        sys.exit(1)

    # temporary workaround until server.py becomes deploy.py
    if command == 'deploy':
        command = 'server'
        sys.argv.insert(2, 'update')

    # Trick optparse into displaying the right usage when --help is used.
    sys.argv[0] += ' ' + command

    del sys.argv[1]
    if command in commands.keys():
        mod = __import__('fdroidserver.' + command, None, None, [command])
    else:
        mod = fdroid_modules[command]['module']

    system_langcode, system_encoding = locale.getdefaultlocale()
    if system_encoding is None or system_encoding.lower() not in ('utf-8', 'utf8'):
        logging.warning(_("Encoding is set to '{enc}' fdroid might run "
                          "into encoding issues. Please set it to 'UTF-8' "
                          "for best results.".format(enc=system_encoding)))

    try:
        mod.main()
    # These are ours, contain a proper message and are "expected"
    except (fdroidserver.common.FDroidException,
            fdroidserver.metadata.MetaDataException) as e:
        if verbose:
            raise
        else:
            logging.critical(str(e))
        sys.exit(1)
    except ArgumentError as e:
        logging.critical(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        print('')
        fdroidserver.common.force_exit(1)
    # These should only be unexpected crashes due to bugs in the code
    # str(e) often doesn't contain a reason, so just show the backtrace
    except Exception as e:
        logging.critical(_("Unknown exception found!"))
        raise e
    sys.exit(0)


if __name__ == "__main__":
    main()
