#!/bin/bash
#echo Testing $1
$1 | $2 > test.tmp
diff `basename $1 .exe`.org test.tmp
	




