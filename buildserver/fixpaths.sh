#!/bin/sh

fixit()
{
  #Fix sudoers so the PATH gets passed through, otherwise chef
  #provisioning doesn't work.
  if [ -z "$1" ]; then
    export EDITOR=$0 && sudo -E visudo
  else
    echo "Fix sudoers"
    echo "Defaults exempt_group=admin" >> $1
  fi
  #Stick the gems bin onto root's path as well.
  sudo echo "PATH=$PATH:/var/lib/gems/1.8/bin" >>/root/.bashrc
  # Restart sudo so it gets the changes straight away
  sudo /etc/init.d/sudo restart
}

sudo grep "exempt_group" /etc/sudoers -q
if [ "$?" -eq "1" ]; then
  fixit
fi

