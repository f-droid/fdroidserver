#!/bin/bash
set -e
./gendocs.sh --email admin@f-droid.org fdroid "F-Droid Server Manual"
scp -r manual/* fdroid@f-droid.org:public_html/manual/
rm fdroid.cps fdroid.ky fdroid.vr fdroid.aux fdroid.fn fdroid.log fdroid.toc
rm fdroid.cp  fdroid.info fdroid.pg fdroid.tp

