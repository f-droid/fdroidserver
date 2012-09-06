#!/bin/bash
set -e
rm -f buildserver.box
cd buildserver
vagrant halt
vagrant up
vagrant halt
vagrant package --base `VBoxManage list vms | grep buildserver | sed 's/"\(.*\)".*/\1/'` --output buildserver.box
vagrant box add buildserver buildserver.box -f && rm buildserver.box

