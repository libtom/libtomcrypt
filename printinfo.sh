#!/bin/bash

version=$(git describe --tags --always --dirty 2>/dev/null)
if [ ! -e ".git" ] || [ -z $version ]
then
	version=$(grep "^VERSION=" makefile | sed "s/.*=//")
fi
echo "Testing version:" $version
#grep "VERSION=" makefile | perl -e "@a = split('=', <>); print @a[1];"`

# get uname
echo "uname="`uname -a`

# get gcc name
echo "gcc="`gcc -dumpversion`
echo
