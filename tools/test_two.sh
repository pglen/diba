#!/bin/bash
echo Testing file $1
$1 | $2 > test.tmp
diff `basename $1 .exe`.org test.tmp
	





