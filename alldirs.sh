#!/bin/bash

# Iterate all dirs with Makefile in them

for aa in *;
do
    if [ -d $aa ] ; then
        if [ -f $aa/Makefile ] ; then
            echo Make files in: \"$aa\"
            cd $aa
            make $1
            cd ..
        fi
    fi
done



