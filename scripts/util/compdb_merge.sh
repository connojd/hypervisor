#!/bin/bash

# $1 = BUILD_ROOT_DIR

files=$(find $1 -name compile_commands.json | grep --invert-match x86_64-test-elf)

if [[ -z $files ]];
then
    exit 0
fi

compdb=$1/../compile_commands.json
touch $compdb

for f in $files
do
    cat $f >> $compdb
done
