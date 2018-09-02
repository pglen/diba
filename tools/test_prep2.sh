#!/bin/bash
echo Prep $1
OUT=`basename $1 .exe`.org
#echo \'$1\' \'$2\' basename: \'$OUT\'
$1 | $2 > $OUT
	




