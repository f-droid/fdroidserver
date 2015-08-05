# workaround the syntax error from: import fdroidserver.import

import inspect
import os
import sys

localmodule = os.path.realpath(
    os.path.join(os.path.dirname(inspect.getfile(inspect.currentframe())), '..'))
print('localmodule: ' + localmodule)
if localmodule not in sys.path:
    sys.path.insert(0, localmodule)

class Options:
    def __init__(self):
        self.rev = None
        self.subdir = None

module = __import__('fdroidserver.import')
for name, obj in inspect.getmembers(module):
    if name == 'import':
        get_metadata_from_url = obj.get_metadata_from_url
        obj.options = Options()
        options = obj.options
        break

globals().update(vars(module))
