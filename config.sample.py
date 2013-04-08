
#Copy this file to config.py, then amend the settings below according to
#your system configuration.

sdk_path = "/path/to/android-sdk-linux_86"
ndk_path = "/path/to/android-ndk-r5"

#You probably don't need to change this...
javacc_path = "/usr/share/java"

#Command for running maven 3 (could be mvn, mvn3, or a full path)
mvn3 = "mvn3"

repo_url = "http://f-droid.org/repo"
repo_name = "FDroid"
repo_icon = "fdroid-icon.png"
repo_description = """
The official FDroid repository. Applications in this repository are official
binaries built by the original application developers.
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
wiki_server = "server"
wiki_path = "/wiki/"
wiki_user = "login"
wiki_password = "1234"

#Only set this to true when running a repository where you want to generate
#stats, and only then on the master build servers, not a development
#machine.
update_stats = False


#Set this to true to always use a build server. This saves specifying the
#--server option on dedicated secure build server hosts.
build_server_always = False

