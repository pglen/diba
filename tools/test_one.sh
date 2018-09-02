#!/bin/bash
echo Testing file $1
$1 > test.tmp
diff `basename $1 .exe`.org test.tmp
	





