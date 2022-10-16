#!/bin/bash

unset password
echo -n "Enter password: "
while IFS= read -p "$prompt" -r -s -n 1 char
do
    # Enter - accept password
    if [[ $char == $'\0' ]] ; then
        break
    fi
    # Backspace
    if [[ $char == $'\177' ]] ; then
        prompt=$'\b \b'
        password="${password%?}"
    else
        prompt='*'
        password+="$char"
    fi
done

echo
echo "Done. Password=$password"


