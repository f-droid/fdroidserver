
#Copy this file to config.py, then amend the settings below according to
#your system configuration.

aapt_path = "/path/to/android-sdk-linux_86/platforms/android-4/tools/aapt"

ndk_path = "/path/to/android-ndk-r5"

repo_url = "http://f-droid.org/repo"
repo_name = "FDroid"
repo_icon = "fdroid-icon.png"
repo_description = """
The official FDroid repository. Applications in this repository are official
binaries built by the original application developers.
"""

#The keystore to use for release keys when building. This needs to be
#somewhere safe and secure, and backed up!
keystore = "/home/me/somewhere/my.keystore"

#The password for the keystore.
keystorepass = "foo"

#The password for keys - the same is used for each auto-generated key.
keypass = "foo2"

#The distinguished name used for all keys.
keydname = "CN=Birdman, OU=Cell, O=Alcatraz, L=Alcatraz, S=California, C=US"

#Use this to override the auto-generated key aliases with specific ones
#for particular applications. Normally, just leave it empty.
keyaliases = {}
keyaliases['com.example.app'] = 'example'


