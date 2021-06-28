import gettext
import glob
import os
import sys


# support running straight from git and standard installs
rootpaths = [
    os.path.realpath(os.path.join(os.path.dirname(__file__), '..')),
    os.path.realpath(
        os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'share')
    ),
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


from fdroidserver.exception import (FDroidException,
                                    MetaDataException,
                                    VerificationException)  # NOQA: E402
FDroidException  # NOQA: B101
MetaDataException  # NOQA: B101
VerificationException  # NOQA: B101

from fdroidserver.common import (verify_apk_signature,
                                 genkeystore as generate_keystore)  # NOQA: E402
verify_apk_signature  # NOQA: B101
generate_keystore  # NOQA: B101
from fdroidserver.index import (download_repo_index,
                                get_mirror_service_urls,
                                make as make_index)  # NOQA: E402
download_repo_index  # NOQA: B101
get_mirror_service_urls  # NOQA: B101
make_index  # NOQA: B101
from fdroidserver.update import (process_apk,
                                 process_apks,
                                 scan_apk,
                                 scan_repo_files)  # NOQA: E402
process_apk  # NOQA: B101
process_apks  # NOQA: B101
scan_apk  # NOQA: B101
scan_repo_files  # NOQA: B101
from fdroidserver.deploy import (update_awsbucket,
                                 update_servergitmirrors,
                                 update_serverwebroot)  # NOQA: E402
update_awsbucket  # NOQA: B101
update_servergitmirrors  # NOQA: B101
update_serverwebroot  # NOQA: B101
