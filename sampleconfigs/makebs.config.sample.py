#!/usr/bin/env python2

# You will need to alter these before running ./makebuildserver

# Name of the base box to use...
basebox = "testing32"

# Location where raring32.box can be found, if you don't already have
# it. For security reasons, it's recommended that you make your own
# in a secure environment using trusted media (see the manual) but
# you can use this default if you like...
baseboxurl = "https://f-droid.org/testing32.box"

memory = 3584

# Debian package proxy server - set this to None unless you have one...
aptproxy = "http://192.168.0.19:8000"

# Set to True if your base box is 64 bit...
arch64 = False
