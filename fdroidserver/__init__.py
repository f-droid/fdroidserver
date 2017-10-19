
import gettext
import glob
import os
import sys


# support running straight from git and standard installs
rootpaths = [
    os.path.realpath(os.path.join(os.path.dirname(__file__), '..')),
    os.path.realpath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'share')),
    os.path.join(sys.prefix, 'share'),
]

localedir = None
for rootpath in rootpaths:
    if len(glob.glob(os.path.join(rootpath, 'locale', '*', 'LC_MESSAGES', 'fdroidserver.mo'))) > 0:
        localedir = os.path.join(rootpath, 'locale')
        break

gettext.bindtextdomain('fdroidserver', localedir)
gettext.textdomain('fdroidserver')
_ = gettext.gettext
