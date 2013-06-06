# You will need to alter these before running makebuildserver.py

# Name of the base box to use...
basebox = "raring32"

# Location where raring32.box can be found, if you don't already have
# it. Could be set to https://f-droid.org/raring32.box if you like...
baseboxurl = "/shares/software/OS and Boot/raring32.box"

memory = 3584

# Debian package proxy server - set this to None unless you have one...
aptproxy = "http://192.168.0.19:8000"

# Set to True if your base box is 64 bit...
arch64 = False
