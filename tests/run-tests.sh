#!/bin/sh

set -e
set -x

if [ -z $WORKSPACE ]; then
    WORKSPACE=`dirname $(pwd)`
    echo "Setting Workspace to $WORKSPACE"
fi

# allow the location of the script to be overridden
if [ -z $fdroid ]; then
    fdroid="$WORKSPACE/fdroid"
fi

#------------------------------------------------------------------------------#
# setup a new repo from scratch

REPOROOT=`mktemp --directory --tmpdir=$WORKSPACE`
cd $REPOROOT
$fdroid init
for f in `ls -1 ../../*/bin/*.apk`; do
    name=$(basename $(dirname `dirname $f`))
    echo "name $name"
    apk=${name}_`basename $f`
    echo "apk $apk"
    cp $f $REPOROOT/repo/$apk
done
# delete any 'unaligned' duplicates
rm -f $REPOROOT/repo/*unaligned*.apk


$fdroid update -c
$fdroid update
