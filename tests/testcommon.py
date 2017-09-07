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


class TmpCwd():
    """Context-manager for temporarily changing the current working
    directory.
    """

    def __init__(self, new_cwd):
        self.new_cwd = new_cwd

    def __enter__(self):
        self.orig_cwd = os.getcwd()
        os.chdir(self.new_cwd)

    def __exit__(self, a, b, c):
        os.chdir(self.orig_cwd)
