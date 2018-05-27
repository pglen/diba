#!/bin/bash

grep -IR --exclude .git/ --exclude Doxyfile/ --exclude *.js --exclude *.html  $1 ../* 




