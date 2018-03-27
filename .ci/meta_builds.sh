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

if [ -f /proc/cpuinfo ]
then
   MAKE_JOBS=$(( ($(cat /proc/cpuinfo | grep -E '^processor[[:space:]]*:' | tail -n -1 | cut -d':' -f2) + 1) * 2 + 1 ))
else
   MAKE_JOBS=8
fi

function run_gcc() {
   bash .ci/check_source.sh "CHECK_SOURCES" "$2" "$3" "$4" "$5"

   make clean &>/dev/null

   echo
   echo "Build for ASAN..."

   make -j$MAKE_JOBS CFLAGS="-fsanitize=address -fno-omit-frame-pointer -static-libasan $2 $CFLAGS $4" EXTRALIBS="-lasan $5" test LTC_DEBUG=1 V=1 1>gcc_1.txt 2>gcc_2.txt

   echo
   echo "Run ASAN tests with LTM..."

   ASAN_OPTIONS=verbosity=1 ./test t ltm 1>test_std.txt 2> test_err.txt || exit 1

   if echo $2 | grep -q GMP ; then
      echo
      echo "Run ASAN tests with GMP..."

      ASAN_OPTIONS=verbosity=1 ./test t gmp 1>test_std.txt 2> test_err.txt || exit 1
   fi

   make clean &>/dev/null

   echo
   echo "Create code coverage"

   bash .ci/coverage.sh "COVERAGE" "$2" "$3" "$4" "$5"
}

function run_clang() {
   # output version
   bash .ci/printinfo.sh

   scan_build=$(which scan-build)
   [ -z "$scan_build" ] && scan_build=$(find /usr/bin/ -name 'scan-build-*' | sort -nr | head -n1) || true
   [ -z "$scan_build" ] && { echo "couldn't find clang scan-build"; exit 1; } || echo "run $scan_build"
   $scan_build --status-bugs make -j$MAKE_JOBS all CFLAGS="$2 $CFLAGS $4" EXTRALIBS="$5"

   make clean &>/dev/null

   echo
   echo "Build for UBSAN..."

   make -j$MAKE_JOBS LDFLAGS="-fsanitize=undefined" CFLAGS="$2 $CFLAGS $4" EXTRALIBS="$5" all LTC_DEBUG=1 V=1 1>gcc_1.txt 2>gcc_2.txt

   echo "Run UBSAN tests with LTM..."
   UBSAN_OPTIONS=verbosity=1 ./test t ltm 1>test_std.txt 2> test_err.txt || exit 1

   if echo $2 | grep -q GMP ; then
      echo
      echo "Run UBSAN tests with GMP..."

      UBSAN_OPTIONS=verbosity=1 ./test t gmp 1>test_std.txt 2> test_err.txt || exit 1
   fi
}

make clean &>/dev/null

EXTRALIBS="$5"

echo $2 | grep -q GMP && EXTRALIBS="$EXTRALIBS -lgmp"

if [ -z "$(echo $CC | grep "clang")" ]; then
   run_gcc "$1" "$2" "$3" "$4" "$EXTRALIBS"
else
   run_clang "$1" "$2" "$3" "$4" "$EXTRALIBS"
fi

make clean &>/dev/null

bash .ci/testbuild.sh "NOTEST" "-DLTC_NO_TEST" "$3" "$4" "$5"

make clean &>/dev/null

bash .ci/testbuild.sh "NOFILE" "-DLTC_NO_FILE" "$3" "$4" "$5"

make clean &>/dev/null

echo
echo "Build full debug..."

make -j$MAKE_JOBS CFLAGS="$2 $CFLAGS $4" EXTRALIBS="$EXTRALIBS" all_test LTC_DEBUG=2 V=1 1>gcc_1.txt 2>gcc_2.txt

# ref:         $Format:%D$
# git commit:  $Format:%H$
# commit time: $Format:%ai$
