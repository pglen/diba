#!/bin/bash

# Simple interface for platform ID. Print $1 (arg 1) for Linux and
# print $2 (arg 2) for others.

TTT=`uname | grep -i Linux`
if  [ "$TTT" == "Linux" ] ; then
  echo $1 
else
  echo $2
  fi



