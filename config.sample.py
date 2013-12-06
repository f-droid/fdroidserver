
# Copy this file to config.py, then amend the settings below according to
# your system configuration.

# Path to the Android SDK ($ANDROID_HOME)
sdk_path = "/path/to/android-sdk-linux_86"

# Path to the Android NDK ($ANDROID_NDK)
# Legacy toolchains are only needed by some apps
ndk_path = "/path/to/android-ndk-r9"

# Build tools version to be used
build_tools = "18.1.1"

# Command for running maven 3 (could be mvn, mvn3, or a full path)
mvn3 = "mvn3"

# Command for running Gradle
gradle = "gradle"

# Android gradle plugin version
# "0.5.+" -> gradle 1.7
# "0.6.+" -> gradle 1.8
gradle_plugin = "0.6.+"

# Max height and width (in pixels) for the icons in the repo
# This corresponds to 72x72 pixels, i.e. mdpi
icon_max_size = 72

# Set the maximum age (in days) of an index that a client should accept from
# this repo. Setting it to 0 or not setting it at all disables this
# functionality. If you do set this to a non-zero value, you need to ensure
# that your index is updated much more frequently than the specified interval.
# The same policy is applied to the archive repo, if there is one.
repo_maxage = 0

repo_url = "https://f-droid.org/repo"
repo_name = "F-Droid"
repo_icon = "fdroid-icon.png"
repo_description = """
The official repository of the F-Droid client. Applications in this repository 
are either official binaries built by the original application developers, or
are binaries built from source by the admin of f-droid.org using the tools on
https://gitorious.org/f-droid.
"""

# As above, but for the archive repo.
# archive_older sets the number of versions kept in the main repo, with all
# older ones going to the archive. Set it to 0, and there will be no archive
# repository, and no need to define the other archive_ values.
archive_older = 3
archive_url = "https://f-droid.org/archive"
archive_name = "F-Droid Archive"
archive_icon = "fdroid-icon.png"
archive_description = """
The archive repository of the F-Droid client. This contains older versions
of applications from the main repository.
"""


#The key (from the keystore defined below) to be used for signing the
#repository itself. Can be None for an unsigned repository.
repo_keyalias = None

#The keystore to use for release keys when building. This needs to be
#somewhere safe and secure, and backed up!
keystore = "/home/me/somewhere/my.keystore"

#The password for the keystore (at least 6 characters).
keystorepass = "password1"

#The password for keys - the same is used for each auto-generated key
#as well as for the repository key.
keypass = "password2"

#The distinguished name used for all keys.
keydname = "CN=Birdman, OU=Cell, O=Alcatraz, L=Alcatraz, S=California, C=US"

#Use this to override the auto-generated key aliases with specific ones
#for particular applications. Normally, just leave it empty.
keyaliases = {}
keyaliases['com.example.app'] = 'example'
#You can also force an app to use the same key alias as another one, using
#the @ prefix.
keyaliases['com.example.another.plugin'] = '@com.example.another'

#The ssh path to the server's public web root directory. This is used for
#uploading data, etc.
serverwebroot = 'user@example:/var/www/repo'

#Wiki details
wiki_protocol = "http"
wiki_server = "server"
wiki_path = "/wiki/"
wiki_user = "login"
wiki_password = "1234"

#Only set this to true when running a repository where you want to generate
#stats, and only then on the master build servers, not a development
#machine.
update_stats = False

#Use the following to push stats to a Carbon instance:
stats_to_carbon = False
carbon_host = '0.0.0.0'
carbon_port = 2003


#Set this to true to always use a build server. This saves specifying the
#--server option on dedicated secure build server hosts.
build_server_always = False

