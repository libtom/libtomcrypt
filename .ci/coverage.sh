#!/bin/bash

set -e

if [ "$TRAVIS_CI" == "private" ]; then
    exit 0
fi

if [ "$#" != "5" ]; then
    echo "Usage is: ${0} \"coverage\" \"<prepend CFLAGS>\" \"<makefile>\" \"<append CFLAGS>\" <math library to link to>"
    echo "CC=gcc ${0} \"coverage\" \" \" \"makefile\" \"-DUSE_LTM -DLTM_DESC -I../libtommath\" ../libtommath/libtommath.a"
    exit -1
fi

if [ -z "$(echo $CC | grep "gcc")" ]; then
    echo "no gcc detected, early exit success"
    exit 0
fi

if [ "$(echo $3 | grep -v 'makefile[.]')" == "" ]; then
    echo "only run $0 for the regular makefile, early exit success"
    exit 0
fi

# output version
bash .ci/printinfo.sh

bash .ci/build.sh " $1" " $2" " $3 COVERAGE=1" "$4" "$5"
if [ -a testok.txt ] && [ -f testok.txt ]; then
   echo
else
   echo
   echo "Test failed"
   exit 1
fi

bash .ci/coverage_more.sh "$5" > test_coverage_more.txt || { rm -f testok.txt && exit 1 ; }

make lcov-single
# if this isn't run on Travis CI create coverage locally
if [ "$TRAVIS" == "" ]; then
   make lcov-html
else
   coveralls-lcov coverage.info
fi

exit 0

# ref:         $Format:%D$
# git commit:  $Format:%H$
# commit time: $Format:%ai$
