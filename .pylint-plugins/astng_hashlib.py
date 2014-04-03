#
# started from http://www.logilab.org/blogentry/78354
#

from logilab.astng import MANAGER
from logilab.astng.builder import ASTNGBuilder

def hashlib_transform(module):
    if module.name == 'hashlib':
        fake = ASTNGBuilder(MANAGER).string_build('''

class fakehash(object):
  digest_size = -1
  def __init__(self, value): pass
  def digest(self):
    return u''
  def hexdigest(self):
    return u''
  def update(self, value): pass

class md5(fakehash):
  pass

class sha1(fakehash):
  pass

class sha256(fakehash):
  pass

''')
        for hashfunc in ('sha256', 'sha1', 'md5'):
            module.locals[hashfunc] = fake.locals[hashfunc]

def register(linter):
    """called when loaded by pylint --load-plugins, register our tranformation
    function here
    """
    MANAGER.register_transformer(hashlib_transform)

