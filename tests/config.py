
# TODO convert to config.yml!

repo_url = "https://MyFirstFDroidRepo.org/fdroid/repo"
repo_name = "My First F-Droid Repo Demo"
repo_description = """This is a repository of apps to be used with F-Droid. Applications in this repository are either official binaries built by the original application developers, or are binaries built from source by the admin of f-droid.org using the tools on https://gitlab.com/fdroid."""

archive_older = 3
archive_url = "https://f-droid.org/archive"
archive_name = "My First F-Droid Archive Demo"
archive_description = """
The repository of older versions of applications from the main demo repository.
"""

make_current_version_link = False

repo_keyalias = "sova"
keystore = "keystore.jks"
keystorepass = "r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI="
keypass = "r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI="
keydname = "CN=sova, OU=F-Droid"

mirrors = (
    'http://foobarfoobarfoobar.onion/fdroid',
    'https://foo.bar/fdroid',
)

install_list = 'org.adaway'
uninstall_list = ('com.android.vending', 'com.facebook.orca', )

repo_key_sha256 = "f49af3f11efddf20dffd70f5e3117b9976674167adca280e6b1932a0601b26f6"
