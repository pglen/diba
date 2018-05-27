#!/bin/bash
#echo Testing $1
$1 > test.tmp
diff `basename $1 .exe`.org test.tmp
	




