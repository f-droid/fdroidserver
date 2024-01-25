#!/usr/bin/env python3
#
# This will update the caches suss.json from the network, then
# overwrite fdroidserver/scanner.py to add the contents of suss.json
# to the SUSS_DEFAULT variable.

import inspect
import os
import re
import sys
from pathlib import Path

localmodule = os.path.realpath(
    os.path.join(os.path.dirname(inspect.getfile(inspect.currentframe())), '..')
)
print('localmodule: ' + localmodule)
if localmodule not in sys.path:
    sys.path.insert(0, localmodule)
from fdroidserver import scanner

scanner._get_tool().refresh()
scanner_py = Path(localmodule) / 'fdroidserver/scanner.py'
contents = scanner_py.read_text()
scanner_py.write_text(
    re.sub(
        r"""SUSS_DEFAULT *= *r?'''.*""",
        """SUSS_DEFAULT = r'''""",
        contents,
        flags=re.DOTALL,
    )
)
os.system(  # nosec bandit B605 start_process_with_a_shell, don't judge me ;-)
    """cat %s >> %s"""
    % (str(scanner._scanner_cachedir() / 'suss.json'), str(scanner_py))
)
with scanner_py.open('a') as fp:
    fp.write("'''\n")
