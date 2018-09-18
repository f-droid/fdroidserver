#!/bin/sh

set -e
set -x

testsdir=$(cd $(dirname $0); pwd)/..

for apk in $testsdir/repo/*.apk /tmp/fdroid/repo/presentation-noAnalytics-release-unsigned.apk; do
    cd $ANDROID_HOME/build-tools
    for f in [1-9]*.*; do
        test -e $f/aapt || continue
        logdir=$testsdir/build-tools/$f
        test -e $logdir || mkdir $logdir
        packageName=`28.0.1/aapt dump badging "$apk" | sed -En "s,^package: name='([^']+)'.*,\1,p"`
        versionCode=`28.0.1/aapt dump badging "$apk" | sed -En "s,.*versionCode='([0-9]*)'.*,\1,p"`
        $f/aapt dump badging "$apk" > $logdir/aapt-output-${packageName}_${versionCode}.txt
    done
done
