#!/usr/bin/env python3
#
# You may want to alter these before running ./makebuildserver

# Name of the Vagrant basebox to use, by default it will be downloaded
# from Vagrant Cloud.  For release builds setup, generate the basebox
# locally using https://gitlab.com/fdroid/basebox, add it to Vagrant,
# then set this to the local basebox name.
# This defaults to "fdroid/basebox-stretch64" which will download a
# prebuilt basebox from https://app.vagrantup.com/fdroid.
#
# (If you change this value you have to supply the `--clean` option on
#  your next `makebuildserver` run.)
#
# basebox = "basebox-stretch64"

# This allows you to pin your basebox to a specific versions. It defaults
# the most recent basebox version which can be aumotaically verifyed by
# `makebuildserver`.
# Please note that vagrant does not support versioning of locally added
# boxes, so we can't support that either.
#
# (If you change this value you have to supply the `--clean` option on
#  your next `makebuildserver` run.)
#
# basebox_version = "0.1"

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

# By default libvirt uses 'virtio' for both network and disk drivers.
# Some systems (eg. nesting VMware ESXi) do not support virtio. As a
# workaround for such rare cases, this setting allows to configure
# KVM/libvirt to emulate hardware rather than using virtio.
#
# libvirt_disk_bus = 'sata'
# libvirt_nic_model_type = 'rtl8139'

# Sometimes, it is not possible to use the 9p synced folder type with
# libvirt, like if running a KVM buildserver instance inside of a
# VMware ESXi guest.  In that case, using NFS or another method is
# required.
#
# synced_folder_type = 'nfs'
