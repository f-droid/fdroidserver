#!/bin/bash
#
# This script syncs the entire repo to the primary mirrors.  It is
# meant to run in a cronjob quite frequently, as often as there are
# files to send.
#
# This script expects the receiving side to have the following
# preceeding the ssh key entry in ~/.ssh/authorized_keys:
#   command="rsync --server -logDtpre.iLsfx --log-format=X --delete --delay-updates . /path/to/htdocs/fdroid/",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty
#
set -e
(
flock -n 200
set -e
cd /home/fdroid
for section in repo archive; do
    echo "Started $section at `date`:"
    for host in fdroid@ftp-push.lysator.liu.se fdroid@plug-mirror.rcac.purdue.edu fdroid@ftp.agdsn.de; do
        set -x
        # be super careful with the trailing slashes here! if one is wrong, it'll delete the entire section!
        rsync --archive --delay-updates --progress --delete \
              --timeout=3600 \
              /home/fdroid/public_html/${section} \
              ${host}:/srv/fdroid-mirror.at.or.at/htdocs/fdroid/ &
        set +x
    done
    wait
done
) 200>/var/lock/root_fdroidmirrortomirror
