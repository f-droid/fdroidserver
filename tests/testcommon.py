#!/usr/bin/env python3
#
# Copyright (C) 2017, Michael Poehn <michael.poehn@fsfe.org>
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
import sys
import tempfile
import unittest
import unittest.mock

from pathlib import Path


GP_FINGERPRINT = 'B7C2EEFD8DAC7806AF67DFCD92EB18126BC08312A7F2D6F3862E46013C7A6135'


class VerboseFalseOptions:
    verbose = False


class TmpCwd:
    """Context-manager for temporarily changing the current working directory."""

    def __init__(self, new_cwd):
        self.new_cwd = new_cwd

    def __enter__(self):
        self.orig_cwd = os.getcwd()
        os.chdir(self.new_cwd)

    def __exit__(self, a, b, c):
        os.chdir(self.orig_cwd)


class TmpPyPath:
    """Context-manager for temporarily adding a directory to Python path."""

    def __init__(self, additional_path):
        self.additional_path = additional_path

    def __enter__(self):
        sys.path.append(self.additional_path)

    def __exit__(self, a, b, c):
        sys.path.remove(self.additional_path)


def mock_open_to_str(mock):
    """For accessing all data written into a unittest.mock.mock_open() instance as a string."""

    return "".join(
        [x.args[0] for x in mock.mock_calls if str(x).startswith("call().write(")]
    )


def mkdtemp():
    if sys.version_info < (3, 10):  # ignore_cleanup_errors was added in 3.10
        return tempfile.TemporaryDirectory()
    else:
        return tempfile.TemporaryDirectory(ignore_cleanup_errors=True)


def mkdir_testfiles(localmodule, test):
    """Keep the test files in a labeled test dir for easy reference"""
    testroot = Path(localmodule) / '.testfiles'
    testroot.mkdir(exist_ok=True)
    testdir = testroot / unittest.TestCase.id(test)
    testdir.mkdir(exist_ok=True)
    return tempfile.mkdtemp(dir=testdir)


def mock_urlopen(status=200, body=None):
    resp = unittest.mock.MagicMock()
    resp.getcode.return_value = status
    resp.read.return_value = body
    resp.__enter__.return_value = resp
    return unittest.mock.Mock(return_value=resp)
