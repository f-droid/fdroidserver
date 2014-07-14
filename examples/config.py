#!/usr/bin/env python2

# Copy this file to config.py, then amend the settings below according to
# your system configuration.

# Override the path to the Android SDK, $ANDROID_HOME by default
# sdk_path = "/path/to/android-sdk"

# Override the path to the Android NDK, $ANDROID_NDK by default
# ndk_path = "/path/to/android-ndk"
# Build tools version to be used
build_tools = "20.0.0"

# Command for running Ant
# ant = "/path/to/ant"
ant = "ant"

# Command for running maven 3
# mvn3 = "/path/to/mvn"
mvn3 = "mvn"

# Command for running Gradle
# gradle = "/path/to/gradle"
gradle = "gradle"

# Set the maximum age (in days) of an index that a client should accept from
# this repo. Setting it to 0 or not setting it at all disables this
# functionality. If you do set this to a non-zero value, you need to ensure
# that your index is updated much more frequently than the specified interval.
# The same policy is applied to the archive repo, if there is one.
repo_maxage = 0

repo_url = "https://MyFirstFDroidRepo.org/fdroid/repo"
repo_name = "My First FDroid Repo Demo"
repo_icon = "fdroid-icon.png"
repo_description = """
This is a repository of apps to be used with FDroid. Applications in this
repository are either official binaries built by the original application
developers, or are binaries built from source by the admin of f-droid.org
using the tools on https://gitlab.com/u/fdroid.
"""

# As above, but for the archive repo.
# archive_older sets the number of versions kept in the main repo, with all
# older ones going to the archive. Set it to 0, and there will be no archive
# repository, and no need to define the other archive_ values.
archive_older = 3
archive_url = "https://f-droid.org/archive"
archive_name = "My First FDroid Archive Demo"
archive_icon = "fdroid-icon.png"
archive_description = """
The repository of older versions of applications from the main demo repository.
"""


# The ID of a GPG key for making detached signatures for apks. Optional.
# gpgkey = '1DBA2E89'

# The key (from the keystore defined below) to be used for signing the
# repository itself.  This is the same name you would give to keytool or
# jarsigner using -alias.  (Not needed in an unsigned repository).
# repo_keyalias = "fdroidrepo"

# The keystore to use for release keys when building. This needs to be
# somewhere safe and secure, and backed up!  The best way to manage these
# sensitive keys is to use a "smartcard" (aka Hardware Security Module). To
# configure FDroid to use a smartcard, set the keystore file using the keyword
# "NONE" (i.e. keystore = "NONE").  That makes Java find the keystore on the
# smartcard based on 'smartcardoptions' below.
# keystore = "~/.local/share/fdroidserver/keystore.jks"

# You should not need to change these at all, unless you have a very
# customized setup for using smartcards in Java with keytool/jarsigner
# smartcardoptions = "-storetype PKCS11 -providerName SunPKCS11-OpenSC \
#    -providerClass sun.security.pkcs11.SunPKCS11 \
#    -providerArg opensc-fdroid.cfg"

# The password for the keystore (at least 6 characters).  If this password is
# different than the keypass below, it can be OK to store the password in this
# file for real use.  But in general, sensitive passwords should not be stored
# in text files!
# keystorepass = "password1"

# The password for keys - the same is used for each auto-generated key as well
# as for the repository key.  You should not normally store this password in a
# file since it is a sensitive password.
# keypass = "password2"

# The distinguished name used for all keys.
keydname = "CN=Birdman, OU=Cell, O=Alcatraz, L=Alcatraz, S=California, C=US"

# Use this to override the auto-generated key aliases with specific ones
# for particular applications. Normally, just leave it empty.
keyaliases = {}
keyaliases['com.example.app'] = 'example'
# You can also force an app to use the same key alias as another one, using
# the @ prefix.
keyaliases['com.example.another.plugin'] = '@com.example.another'


# The full path to the root of the repository.  It must be specified in
# rsync/ssh format for a remote host/path. This is used for syncing a locally
# generated repo to the server that is it hosted on.  It must end in the
# standard public repo name of "/fdroid", but can be in up to three levels of
# sub-directories (i.e. /var/www/packagerepos/fdroid).  You can include
# multiple servers to sync to by wrapping the whole thing in {} or [], and
# including the serverwebroot strings in a comma-separated list.
#
# serverwebroot = 'user@example:/var/www/fdroid'
# serverwebroot = {
#     'foo.com:/usr/share/nginx/www/fdroid',
#     'bar.info:/var/www/fdroid',
#     }


# optionally specific which identity file to use when using rsync over SSH
#
# identity_file = '~/.ssh/fdroid_id_rsa'


# If you are running the repo signing process on a completely offline machine,
# which provides the best security, then you can specify a folder to sync the
# repo to when running `fdroid server update`.  This is most likely going to
# be a USB thumb drive, SD Card, or some other kind of removable media.  Make
# sure it is mounted before running `fdroid server update`.  Using the
# standard folder called 'fdroid' as the specified folder is recommended, like
# with serverwebroot.
#
# local_copy_dir = '/media/MyUSBThumbDrive/fdroid'


# If you are using local_copy_dir on an offline build/signing server, once the
# thumb drive has been plugged into the online machine, it will need to be
# synced to the copy on the online machine.  To make that happen
# automatically, set sync_from_local_copy_dir to True:
#
# sync_from_local_copy_dir = True


# To upload the repo to an Amazon S3 bucket using `fdroid server update`.
# Warning, this deletes and recreates the whole fdroid/ directory each
# time. This is based on apache-libcloud, which supports basically all cloud
# storage services, so it should be easy to port the fdroid server tools to
# any of them.
#
# awsbucket = 'myawsfdroid'
# awsaccesskeyid = 'SEE0CHAITHEIMAUR2USA'
# awssecretkey = 'yourverysecretkeywordpassphraserighthere'


# If you want to force 'fdroid server' to use a non-standard serverwebroot
#
# nonstandardwebroot = False


# Wiki details
wiki_protocol = "http"
wiki_server = "server"
wiki_path = "/wiki/"
wiki_user = "login"
wiki_password = "1234"

# Only set this to true when running a repository where you want to generate
# stats, and only then on the master build servers, not a development
# machine.
update_stats = False

# Use the following to push stats to a Carbon instance:
stats_to_carbon = False
carbon_host = '0.0.0.0'
carbon_port = 2003

# Set this to true to always use a build server. This saves specifying the
# --server option on dedicated secure build server hosts.
build_server_always = False

# Limit in number of characters that fields can take up
# Only the fields listed here are supported, defaults shown
char_limits = {
    'Summary': 50,
    'Description': 1500
}
