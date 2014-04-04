#!/bin/sh

set -e
set -x

copy_apks_into_repo() {
    for f in `ls -1 ../../*/bin/*.apk`; do
        name=$(basename $(dirname `dirname $f`))
        echo "name $name"
        apk=${name}_`basename $f`
        echo "apk $apk"
        cp $f $1/repo/$apk
    done
    # delete any 'unaligned' duplicates
    rm -f $1/repo/*unaligned*.apk
}

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
copy_apks_into_repo $REPOROOT
$fdroid update -c
$fdroid update


#------------------------------------------------------------------------------#
# setup a new repo from scratch and generate a keystore

REPOROOT=`mktemp --directory --tmpdir=$WORKSPACE`
KEYSTORE=$REPOROOT/keystore.jks
cd $REPOROOT
$fdroid init --keystore $KEYSTORE
test -e $KEYSTORE
copy_apks_into_repo $REPOROOT
$fdroid update -c
$fdroid update
test -e repo/index.xml
test -e repo/index.jar
