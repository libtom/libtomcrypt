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

   make CFLAGS="$2 $CFLAGS $4" EXTRALIBS="$5" test LTC_DEBUG=1 1>gcc_1.txt 2>gcc_2.txt

   valgrind --error-exitcode=666 --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all ./test 1>test_std.txt 2> test_err.txt

   make clean &>/dev/null

   make CFLAGS="-fsanitize=address -fno-omit-frame-pointer -static-libasan $2 $CFLAGS $4" EXTRALIBS="-lasan $5" test LTC_DEBUG=1 1>gcc_1.txt 2>gcc_2.txt
   ASAN_OPTIONS=verbosity=1 ./test t ltm 1>test_std.txt 2> test_err.txt
   ASAN_OPTIONS=verbosity=1 ./test t gmp 1>test_std.txt 2> test_err.txt
}

function run_clang() {
   scan_build=$(which scan-build)
   [ -z "$scan_build" ] && scan_build=$(find /usr/bin/ -name 'scan-build-*' | sort -nr | head -n1) || true
   [ -z "$scan_build" ] && { echo "couldn't find clang scan-build"; exit 1; } || echo "run $scan_build"
   $scan_build --status-bugs make all CFLAGS="$2 $CFLAGS $4" EXTRALIBS="$5"

   make clean &>/dev/null

   make LDFLAGS="-fsanitize=undefined" CFLAGS="$2 $CFLAGS $4" EXTRALIBS="$5" all LTC_DEBUG=1 1>gcc_1.txt 2>gcc_2.txt
   UBSAN_OPTIONS=verbosity=1 ./test t ltm 1>test_std.txt 2> test_err.txt
   UBSAN_OPTIONS=verbosity=1 ./test t gmp 1>test_std.txt 2> test_err.txt
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
