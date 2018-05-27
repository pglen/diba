#!/bin/bash
OUT=`basename $1 .exe`.org
#echo \'$1\' \'$2\' basename: \'$OUT\'
$1 | $2 > $OUT
	



