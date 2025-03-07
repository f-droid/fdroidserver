# Copyright (C) 2025, Hans-Christoph Steiner <hans@eds.org>
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

"""Standard YAML parsing and dumping.

YAML 1.2 is the preferred format for all data files.  When loading
F-Droid formats like config.yml and <Application ID>.yml, YAML 1.2 is
forced, and older YAML constructs should be considered an error.

It is OK to load and dump files in other YAML versions if they are
externally defined formats, like FUNDING.yml.  In those cases, these
common instances might not be appropriate to use.

There is a separate instance for dumping based on the "round trip" aka
"rt" mode.  The "rt" mode maintains order while the "safe" mode sorts
the output.  Also, yaml.version is not forced in the dumper because that
makes it write out a "%YAML 1.2" header.  F-Droid's formats are
explicitly defined as YAML 1.2 and meant to be human-editable.  So that
header gets in the way.

"""

import ruamel.yaml

yaml = ruamel.yaml.YAML(typ='safe')
yaml.version = (1, 2)

yaml_dumper = ruamel.yaml.YAML(typ='rt')
