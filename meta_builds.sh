#!/bin/bash
#
# This builds different stuff depending on the compiler:
# gcc - valgrind, coverage
# clang - asan, ubsan, scan-build
# both - the two testbuild's NOTEST and NOFILE

set -e

if [ "$#" = "5" -a "$(echo $3 | grep -v 'makefile[.]')" = "" ]; then
   echo "only run $0 for the regular makefile, early exit success"
   exit 0
fi

function run_gcc() {
   bash check_source.sh "CHECK_SOURCES" "$2" "$3" "$4" "$5"

   make clean &>/dev/null

   bash coverage.sh "COVERAGE" "$2" "$3" "$4" "$5"

   make clean &>/dev/null

   make CFLAGS="$2 $CFLAGS $4" EXTRALIBS="$5" test LTC_DEBUG=2

   valgrind --error-exitcode=666 --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all ./test

   make clean &>/dev/null

   make CFLAGS="-fsanitize=address -fno-omit-frame-pointer -static-libasan $2 $CFLAGS $4" EXTRALIBS="-lasan $5" test LTC_DEBUG=1
   ASAN_OPTIONS=verbosity=1 ./test t ltm
   ASAN_OPTIONS=verbosity=1 ./test t gmp
}

function run_clang() {
   bash scan_build.sh "SCAN_BUILD" "$2" "$3" "$4" "$5"

   make clean &>/dev/null

   make LDFLAGS="-fsanitize=undefined" CFLAGS="$2 $CFLAGS $4" EXTRALIBS="$5" all LTC_DEBUG=1
   UBSAN_OPTIONS=verbosity=1 ./test t ltm
   UBSAN_OPTIONS=verbosity=1 ./test t gmp
}


make clean &>/dev/null

EXTRALIBS="$5 -lgmp"

if [ -z "$(echo $CC | grep "clang")" ]; then
   run_gcc "$1" "$2" "$3" "$4" "$EXTRALIBS"
else
   run_clang "$1" "$2" "$3" "$4" "$EXTRALIBS"
fi

make clean &>/dev/null

bash testbuild.sh "NOTEST" "-DLTC_NO_TEST" "$3" "$4" "$5"

make clean &>/dev/null

bash testbuild.sh "NOFILE" "-DLTC_NO_FILE" "$3" "$4" "$5"
