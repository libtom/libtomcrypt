#!/bin/bash

if [ -z "$(echo $CC | grep "gcc")" ]; then
    echo "no gcc detected, early exit success"
    exit 0
fi

# output version
bash printinfo.sh

bash build.sh " $1" " $2" " $3 " "$4 -fprofile-arcs -ftest-coverage " "$5 -lgcov"
if [ -a testok.txt ] && [ -f testok.txt ]; then
   echo
else
	echo
	echo "Test failed"
	exit 1
fi

cpp-coveralls

exit 0

# $Source$
# $Revision$
# $Date$
