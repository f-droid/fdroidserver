#!/usr/bin/env python2
#
# You may want to alter these before running ./makebuildserver

# Name of the base box to use
# basebox = "jessie32"

# Location where testing32.box can be found, if you don't already have
# it. For security reasons, it's recommended that you make your own
# in a secure environment using trusted media (see the manual) but
# you can use this default if you like...
# baseboxurl = "https://f-droid.org/jessie32.box"
#
# or if you have a cached local copy, you can use that first:
# baseboxurl = ["file:///home/fdroid/fdroidserver/cache/jessie32.box", "https://f-droid.org/jessie32.box"]

# To specify which Debian mirror the build server VM should use, by
# default it uses http.debian.net, which auto-detects which is the
# best mirror to use.
#
# debian_mirror = 'http://ftp.uk.debian.org/debian/'

# The amount of RAM the build server will have
# memory = 3584

# The number of CPUs the build server will have
# cpus = 1

# Debian package proxy server - if you have one
# aptproxy = "http://192.168.0.19:8000"

# Set to True if your base box is 64 bit (e.g. testing32.box isn't)
# arch64 = True
