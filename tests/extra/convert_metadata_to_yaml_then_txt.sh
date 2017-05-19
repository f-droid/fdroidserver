#! /bin/bash

if [ ! -d metadata ]; then
    echo 'no metadata directory present'
    exit 1
fi

fdroid rewritemeta --to yml
fdroid rewritemeta --to txt

echo '## stripping maven, kivy, disable buildflags if they are set to "no"'
sed -i '/^    maven=no$/d' metadata/*.txt
sed -i '/^    kivy=no$/d' metadata/*.txt
sed -i '/^    disable=no$/d' metadata/*.txt
