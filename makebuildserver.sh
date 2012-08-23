#!/bin/bash
set -e
rm -f buildserver.box
cd buildserver
vagrant up
vagrant ssh -c "sudo shutdown -h now"
cd ..
# Just to wait until it's shut down!
sleep 20
vagrant package --base `VBoxManage list vms | grep buildserver | sed 's/"\(.*\)".*/\1/'` --output buildserver.box
vagrant box add buildserver buildserver.box -f && rm buildserver.box

