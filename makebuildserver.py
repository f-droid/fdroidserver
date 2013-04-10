#!/usr/bin/python

import os
import sys
import subprocess
import time

def vagrant(params, cwd=None):
    p = subprocess.Popen(['vagrant'] + params, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    return (p.returncode, out, err)

boxfile = 'buildserver.box'
serverdir = 'buildserver'

if not os.path.exists('makebuildserver.py') or not os.path.exists(serverdir):
    print 'This must be run from the correct directory!'
    sys.exit(1)

if os.path.exists(boxfile):
    os.remove(boxfile)

vagrant(['halt'], serverdir)
print "Configuring build server VM"
returncode, out, err = vagrant(['up'], serverdir)
with open(os.path.join(serverdir, 'up.log'), 'w') as log:
    log.write('==stdout==\n' + out + '\n\n')
    log.write('==stderr==\n' + err + '\n\n')
if returncode != 0:
    print "Failed to configure server"
    sys.exit(1)
print "Stopping build server VM"
vagrant(['halt'], serverdir)

print "Waiting for build server VM to be finished"
ready = False
while not ready:
    time.sleep(2)
    returncode, out, err = vagrant(['status'], serverdir)
    if returncode != 0:
        print "Error while checking status"
        sys.exit(1)
    for line in out.splitlines():
        if line.startswith("default"):
            if line.find("poweroff") != -1:
                ready = True
            else:
                print "Status: " + line

print "Packaging"
vagrant(['package', '--output', os.path.join('..', boxfile)], serverdir)
print "Adding box"
vagrant(['box', 'add', 'buildserver', boxfile, '-f'])

os.remove(boxfile)

