#!/bin/bash
CLINE=`ps | grep dibaserv | awk '{ print $1 }'`
#echo $CLINE
if [ "$CLINE" != "" ]; then
    kill $CLINE
else
    echo "Server not running."
fi
