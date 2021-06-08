# workaround the syntax error from: import fdroidserver.import

import inspect
import sys
from pathlib import Path

localmodule = Path(__file__).resolve().parent.parent
print('localmodule: ' + str(localmodule))
if localmodule not in sys.path:
    sys.path.insert(0, str(localmodule))


class Options:
    def __init__(self):
        self.rev = None
        self.subdir = None


module = __import__('fdroidserver.import')
for name, obj in inspect.getmembers(module):
    if name == 'import':
        clone_to_tmp_dir = obj.clone_to_tmp_dir
        obj.options = Options()
        options = obj.options
        break

globals().update(vars(module))
