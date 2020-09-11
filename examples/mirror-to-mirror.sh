#!/bin/bash
set -e
(
flock -n 200
set -e
cd /home/fdroid
rsync --delay-updates --progress -a --delete /home/fdroid/public_html/archive/ fdroid@fdroid-mirror.at.or.at:/srv/fdroid-mirror.at.or.at/htdocs/fdroid/archive/
rsync --delay-updates --progress -a --delete /home/fdroid/public_html/repo/ fdroid@fdroid-mirror.at.or.at:/srv/fdroid-mirror.at.or.at/htdocs/fdroid/repo/
) 200>/var/lock/root_fdroidmirrortomirror
