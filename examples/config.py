#!/usr/bin/env python3

# Copy this file to config.py, then amend the settings below according to
# your system configuration.

# Custom path to the Android SDK, defaults to $ANDROID_HOME
# sdk_path = "$ANDROID_HOME"

# Custom paths to various versions of the Android NDK, defaults to 'r12b' set
# to $ANDROID_NDK. Most users will have the latest at $ANDROID_NDK, which is
# used by default. If a version is missing or assigned to None, it is assumed
# not installed.
# ndk_paths = {
#     'r9b': None,
#     'r10e': None,
#     'r11c': None,
#     'r12b': "$ANDROID_NDK",
#     'r13b': None,
#     'r14b': None,
#     'r15c': None,
#     'r16': None,
# }

# Path to the Qt SDK. It is of the form "/path/to/Qt5.7.0/5.7"
# qt_sdk_path = ""

# java_paths = {
#     '1.8': "/usr/lib/jvm/java-8-openjdk",
# }

# Build tools version to be used
# build_tools = "25.0.2"

# Force all build to use the above version of build -tools, good for testing
# builds without having all of the possible build-tools installed.
# force_build_tools = True

# Command or path to binary for running Ant
# ant = "ant"

# Command or path to binary for running maven 3
# mvn3 = "mvn"

# Command or path to binary for running Gradle
# gradle = "gradle"

# Set the maximum age (in days) of an index that a client should accept from
# this repo. Setting it to 0 or not setting it at all disables this
# functionality. If you do set this to a non-zero value, you need to ensure
# that your index is updated much more frequently than the specified interval.
# The same policy is applied to the archive repo, if there is one.
# repo_maxage = 0

repo_url = "https://MyFirstFDroidRepo.org/fdroid/repo"
repo_name = "My First F-Droid Repo Demo"
repo_icon = "fdroid-icon.png"
repo_description = """
This is a repository of apps to be used with F-Droid. Applications in this
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
archive_name = "My First F-Droid Archive Demo"
archive_icon = "fdroid-icon.png"
archive_description = """
The repository of older versions of applications from the main demo repository.
"""

# This allows a specific kind of insecure APK to be included in the
# 'repo' section.  Since April 2017, APK signatures that use MD5 are
# no longer considered valid, jarsigner and apksigner will return an
# error when verifying.  `fdroid update` will move APKs with these
# disabled signatures to the archive.  This option stops that
# behavior, and lets those APKs stay part of 'repo'.
#
# allow_disabled_algorithms = True

# Normally, all apps are collected into a single app repository, like on
# https://f-droid.org. For certain situations, it is better to make a repo
# that is made up of APKs only from a single app. For example, an automated
# build server that publishes nightly builds.
# per_app_repos = True

# `fdroid update` will create a link to the current version of a given app.
# This provides a static path to the current APK. To disable the creation of
# this link, uncomment this:
# make_current_version_link = False

# By default, the "current version" link will be based on the "Name" of the
# app from the metadata. You can change it to use a different field from the
# metadata here:
# current_version_name_source = 'packageName'

# Optionally, override home directory for gpg
# gpghome = '/home/fdroid/somewhere/else/.gnupg'

# The ID of a GPG key for making detached signatures for apks. Optional.
# gpgkey = '1DBA2E89'

# The key (from the keystore defined below) to be used for signing the
# repository itself. This is the same name you would give to keytool or
# jarsigner using -alias. (Not needed in an unsigned repository).
# repo_keyalias = "fdroidrepo"

# Optionally, the public key for the key defined by repo_keyalias above can
# be specified here. There is no need to do this, as the public key can and
# will be retrieved from the keystore when needed. However, specifying it
# manually can allow some processing to take place without access to the
# keystore.
# repo_pubkey = "..."

# The keystore to use for release keys when building. This needs to be
# somewhere safe and secure, and backed up!  The best way to manage these
# sensitive keys is to use a "smartcard" (aka Hardware Security Module). To
# configure F-Droid to use a smartcard, set the keystore file using the keyword
# "NONE" (i.e. keystore = "NONE"). That makes Java find the keystore on the
# smartcard based on 'smartcardoptions' below.
# keystore = "~/.local/share/fdroidserver/keystore.jks"

# You should not need to change these at all, unless you have a very
# customized setup for using smartcards in Java with keytool/jarsigner
# smartcardoptions = "-storetype PKCS11 -providerName SunPKCS11-OpenSC \
#    -providerClass sun.security.pkcs11.SunPKCS11 \
#    -providerArg opensc-fdroid.cfg"

# The password for the keystore (at least 6 characters). If this password is
# different than the keypass below, it can be OK to store the password in this
# file for real use. But in general, sensitive passwords should not be stored
# in text files!
# keystorepass = "password1"

# The password for keys - the same is used for each auto-generated key as well
# as for the repository key. You should not normally store this password in a
# file since it is a sensitive password.
# keypass = "password2"

# The distinguished name used for all keys.
# keydname = "CN=Birdman, OU=Cell, O=Alcatraz, L=Alcatraz, S=California, C=US"

# Use this to override the auto-generated key aliases with specific ones
# for particular applications. Normally, just leave it empty.
# keyaliases = {}
# keyaliases['com.example.app'] = 'example'
# You can also force an app to use the same key alias as another one, using
# the @ prefix.
# keyaliases['com.example.another.plugin'] = '@com.example.another'


# The full path to the root of the repository. It must be specified in
# rsync/ssh format for a remote host/path. This is used for syncing a locally
# generated repo to the server that is it hosted on. It must end in the
# standard public repo name of "/fdroid", but can be in up to three levels of
# sub-directories (i.e. /var/www/packagerepos/fdroid). You can include
# multiple servers to sync to by wrapping the whole thing in {} or [], and
# including the serverwebroot strings in a comma-separated list.
#
# serverwebroot = 'user@example:/var/www/fdroid'
# serverwebroot = {
#     'foo.com:/usr/share/nginx/www/fdroid',
#     'bar.info:/var/www/fdroid',
#     }

# The full URL to a git remote repository. You can include
# multiple servers to mirror to by wrapping the whole thing in {} or [], and
# including the servergitmirrors strings in a comma-separated list.
# Servers listed here will also be automatically inserted in the mirrors list.
#
# servergitmirrors = 'https://github.com/user/repo'
# servergitmirrors = {
#     'https://github.com/user/repo',
#     'https://gitlab.com/user/repo',
#     }

# Any mirrors of this repo, for example all of the servers declared in
# serverwebroot and all the servers declared in servergitmirrors,
# will automatically be used by the client.  If one
# mirror is not working, then the client will try another.  If the
# client has Tor enabled, then the client will prefer mirrors with
# .onion addresses. This base URL will be used for both the main repo
# and the archive, if it is enabled.  So these URLs should end in the
# 'fdroid' base of the F-Droid part of the web server like serverwebroot.
#
# mirrors = (
#     'https://foo.bar/fdroid',
#     'http://foobarfoobarfoobar.onion/fdroid',
# )

# optionally specify which identity file to use when using rsync or git over SSH
#
# identity_file = '~/.ssh/fdroid_id_rsa'


# If you are running the repo signing process on a completely offline machine,
# which provides the best security, then you can specify a folder to sync the
# repo to when running `fdroid server update`. This is most likely going to
# be a USB thumb drive, SD Card, or some other kind of removable media. Make
# sure it is mounted before running `fdroid server update`. Using the
# standard folder called 'fdroid' as the specified folder is recommended, like
# with serverwebroot.
#
# local_copy_dir = '/media/MyUSBThumbDrive/fdroid'


# If you are using local_copy_dir on an offline build/signing server, once the
# thumb drive has been plugged into the online machine, it will need to be
# synced to the copy on the online machine. To make that happen
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


# If you want to upload the release apk file to androidobservatory.org
#
# androidobservatory = False


# If you want to upload the release apk file to virustotal.com
# You have to enter your profile apikey to enable the upload.
#
# virustotal_apikey = "virustotal_apikey"


# The build logs can be posted to a mediawiki instance, like on f-droid.org.
# wiki_protocol = "http"
# wiki_server = "server"
# wiki_path = "/wiki/"
# wiki_user = "login"
# wiki_password = "1234"

# Keep a log of all generated index files in a git repo to provide a
# "binary transparency" log for anyone to check the history of the
# binaries that are published.  This is in the form of a "git remote",
# which this machine where `fdroid update` is run has already been
# configured to allow push access (e.g. ssh key, username/password, etc)
# binary_transparency_remote = "git@gitlab.com:fdroid/binary-transparency-log.git"

# Only set this to true when running a repository where you want to generate
# stats, and only then on the master build servers, not a development
# machine. If you want to keep the "added" and "last updated" dates for each
# app and APK in your repo, then you should enable this.
# update_stats = True

# When used with stats, this is a list of IP addresses that are ignored for
# calculation purposes.
# stats_ignore = []

# Server stats logs are retrieved from. Required when update_stats is True.
# stats_server = "example.com"

# User stats logs are retrieved from. Required when update_stats is True.
# stats_user = "bob"

# Use the following to push stats to a Carbon instance:
# stats_to_carbon = False
# carbon_host = '0.0.0.0'
# carbon_port = 2003

# Set this to true to always use a build server. This saves specifying the
# --server option on dedicated secure build server hosts.
# build_server_always = True

# By default, fdroid will use YAML .yml and the custom .txt metadata formats. It
# is also possible to have metadata in JSON by adding 'json'.
# accepted_formats = ('txt', 'yml')

# Limit in number of characters that fields can take up
# Only the fields listed here are supported, defaults shown
# char_limits = {
#     'Summary': 80,
#     'Description': 4000,
# }

# It is possible for the server operator to specify lists of apps that
# must be installed or uninstalled on the client (aka "push installs).
# If the user has opted in, or the device is already setup to respond
# to these requests, then F-Droid will automatically install/uninstall
# the packageNames listed.  This is protected by the same signing key
# as the app index metadata.
#
# install_list = (
#     'at.bitfire.davdroid',
#     'com.fsck.k9',
#     'us.replicant',
# )
#
# uninstall_list = (
#     'com.facebook.orca',
#     'com.android.vending',
# )
