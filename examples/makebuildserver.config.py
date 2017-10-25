#!/usr/bin/env python3
#
# You may want to alter these before running ./makebuildserver

# Name of the base box to use
# basebox = "jessie64"

# Location where testing32.box can be found, if you don't already have
# it. For security reasons, it's recommended that you make your own
# in a secure environment using trusted media (see the manual) but
# you can use this default if you like...
# baseboxurl = "https://f-droid.org/jessie64.box"
#
# or if you have a cached local copy, you can use that first:
# baseboxurl = ["file:///home/fdroid/fdroidserver/cache/jessie64.box", "https://f-droid.org/jessie64.box"]

# In the process of setting up the build server, many gigs of files
# are downloaded (Android SDK components, gradle, etc).  These are
# cached so that they are not redownloaded each time. By default,
# these are stored in ~/.cache/fdroidserver
#
# cachedir = 'buildserver/cache'

# A big part of creating a new instance is downloading packages from Debian.
# This setups up a folder in ~/.cache/fdroidserver to cache the downloaded
# packages when rebuilding the build server from scratch.  This requires
# that virtualbox-guest-utils is installed.
#
# apt_package_cache = True

# The buildserver can use some local caches to speed up builds,
# especially when the internet connection is slow and/or expensive.
# If enabled, the buildserver setup will look for standard caches in
# your HOME dir and copy them to the buildserver VM. Be aware: this
# will reduce the isolation of the buildserver from your host machine,
# so the buildserver will provide an environment only as trustworthy
# as the host machine's environment.
#
# copy_caches_from_host = True

# To specify which Debian mirror the build server VM should use, by
# default it uses http.debian.net, which auto-detects which is the
# best mirror to use.
#
# debian_mirror = 'http://ftp.uk.debian.org/debian/'

# The amount of RAM the build server will have (default: 2048)
# memory = 3584

# The number of CPUs the build server will have
# cpus = 1

# Debian package proxy server - if you have one
# aptproxy = "http://192.168.0.19:8000"

# If this is running on an older machine or on a virtualized system,
# it can run a lot slower. If the provisioning fails with a warning
# about the timeout, extend the timeout here. (default: 600 seconds)
#
# boot_timeout = 1200

# By default, this whole process uses VirtualBox as the provider, but
# QEMU+KVM is also supported via the libvirt plugin to vagrant. If
# this is run within a KVM guest, then libvirt's QEMU+KVM will be used
# automatically.  It can also be manually enabled by uncommenting
# below:
#
# vm_provider = 'libvirt'
