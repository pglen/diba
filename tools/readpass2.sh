#!/bin/bash
stty -echo
printf "Password: "
read PASSWORD
stty echo
printf $PASSWORD "\n"



