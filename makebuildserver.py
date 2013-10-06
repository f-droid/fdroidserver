#!/usr/bin/python

import os
import sys
import subprocess
import time

execfile('makebs.config.py', globals())

def vagrant(params, cwd=None, printout=False):
    """Run vagrant.

    :param: list of parameters to pass to vagrant
    :cwd: directory to run in, or None for current directory
    :printout: True to print output in realtime, False to just
               return it
    :returns: (ret, out) where ret is the return code, and out
               is the stdout (and stderr) from vagrant
    """
    p = subprocess.Popen(['vagrant'] + params, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = ''
    if printout:
        while True:
            line = p.stdout.readline()
            if len(line) == 0:
                break
            print line,
            out += line
        p.wait()
    else:
        out = p.communicate()[0]
    return (p.returncode, out)

boxfile = 'buildserver.box'
serverdir = 'buildserver'

if not os.path.exists('makebuildserver.py') or not os.path.exists(serverdir):
    print 'This must be run from the correct directory!'
    sys.exit(1)

if os.path.exists(boxfile):
    os.remove(boxfile)


# Update cached files.
cachedir = os.path.join('buildserver', 'cache')
if not os.path.exists(cachedir):
    os.mkdir(cachedir)
cachefiles = [
    ('android-sdk_r21.0.1-linux.tgz',
     'http://dl.google.com/android/android-sdk_r21.0.1-linux.tgz',
     'e797ff3abbdc0fe2e7299e82e92ade830fa922ddd045d9a5a2d187c5c1a2661c'),
    ('gradle-1.7-bin.zip',
     'http://services.gradle.org/distributions/gradle-1.7-bin.zip',
     '360c97d51621b5a1ecf66748c718594e5f790ae4fbc1499543e0c006033c9d30')]
if arch64:
    cachefiles.extend([
    ('android-ndk-r9-linux-x64_64.tar.bz2',
     'http://dl.google.com/android/ndk/android-ndk-r9-linux-x86_64.tar.bz2',
     '8a6013bfd8a8709592c53086c4f841933f5f2b175dd030326406d24ff4daa267')])
else:
    cachefiles.extend([
    ('android-ndk-r9-linux-x86.tar.bz2',
     'http://dl.google.com/android/ndk/android-ndk-r9-linux-x86.tar.bz2',
     '30f3da01e4d8d3415777b5d88a0b70fac5a4620807fd28110f9bc4c8093f6b6e')])
wanted = []
for f, src, shasum in cachefiles:
    if not os.path.exists(os.path.join(cachedir, f)):
        print "Downloading " + f + " to cache"
        if subprocess.call(['wget', src], cwd=cachedir) != 0:
            print "...download of " + f + " failed."
            sys.exit(1)
    if shasum:
        p = subprocess.Popen(['shasum', '-a', '256', os.path.join(cachedir, f)],
                stdout=subprocess.PIPE)
        v = p.communicate()[0].split(' ')[0]
        if v != shasum:
            print "Invalid shasum of '" + v + "' detected for " + f
            sys.exit(1)
        else:
            print "...shasum verified for " + f

    wanted.append(f)


# Generate an appropriate Vagrantfile for the buildserver, based on our
# settings...
vagrantfile = """
Vagrant::Config.run do |config|

  config.vm.box = "{0}"
  config.vm.box_url = "{1}"

  config.vm.customize ["modifyvm", :id, "--memory", "{2}"]

  config.vm.provision :shell, :path => "fixpaths.sh"
""".format(basebox, baseboxurl, memory)
if aptproxy:
    vagrantfile += """
  config.vm.provision :shell, :inline => 'sudo echo "Acquire::http {{ Proxy \\"{0}\\"; }};" > /etc/apt/apt.conf.d/02proxy && sudo apt-get update'
""".format(aptproxy)
vagrantfile += """
  config.vm.provision :chef_solo do |chef|
    chef.cookbooks_path = "cookbooks"
    chef.log_level = :debug 
    chef.json = {
      :settings => {
        :sdk_loc => "/home/vagrant/android-sdk",
        :ndk_loc => "/home/vagrant/android-ndk",
        :user => "vagrant"
      }
    }
    chef.add_recipe "fdroidbuild-general"
    chef.add_recipe "android-sdk"
    chef.add_recipe "android-ndk"
  end
end
"""

# Check against the existing Vagrantfile, and if they differ, we need to
# create a new box:
vf = os.path.join(serverdir, 'Vagrantfile')
writevf = True
if os.path.exists(vf):
    vagrant(['halt'], serverdir)
    with open(vf, 'r') as f:
        oldvf = f.read()
    if oldvf != vagrantfile:
        print "Server configuration has changed, rebuild from scratch is required"
        vagrant(['destroy', '-f'], serverdir)
    else:
        print "Re-provisioning existing server"
        writevf = False
else:
    print "No existing server - building from scratch"
if writevf:
    with open(vf, 'w') as f:
        f.write(vagrantfile)


print "Configuring build server VM"
returncode, out = vagrant(['up'], serverdir, printout=True)
with open(os.path.join(serverdir, 'up.log'), 'w') as log:
    log.write(out)
if returncode != 0:
    print "Failed to configure server"
    sys.exit(1)
print "Stopping build server VM"
vagrant(['halt'], serverdir)

print "Waiting for build server VM to be finished"
ready = False
while not ready:
    time.sleep(2)
    returncode, out = vagrant(['status'], serverdir)
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

