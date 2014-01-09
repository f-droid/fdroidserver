#!/usr/bin/env python2
#
# You may want to alter these before running ./makebuildserver

# Name of the base box to use
basebox = "testing32"

# Location where raring32.box can be found, if you don't already have
# it. For security reasons, it's recommended that you make your own
# in a secure environment using trusted media (see the manual) but
# you can use this default if you like...
baseboxurl = "https://f-droid.org/testing32.box"

memory = 3584

# Debian package proxy server - if you have one, e.g. "http://192.168.0.19:8000"
aptproxy = None

# Set to True if your base box is 64 bit (e.g. testing32.box isn't)
arch64 = False
