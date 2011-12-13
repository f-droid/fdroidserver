#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# checkmarket.py - part of the FDroid server tools
# Copyright (C) 2011, Ciaran Gultnieks, ciaran@ciarang.com
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

import subprocess

#Read configuration...
repo_name = None
repo_description = None
repo_icon = None
repo_url = None
execfile('config.py')

subprocess.call('./run.sh ' + market_user + ' ' + market_password
    + ' ' + market_deviceid,
    cwd='marketcheck', shell=True)

