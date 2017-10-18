#!/bin/bash

set -e

if [ "$#" = "5" -a "$(echo $3 | grep -v 'makefile[.]')" = "" ]; then
   echo "only run $0 for the regular makefile, early exit success"
   exit 0
fi

# output version
bash printinfo.sh

make clean &>/dev/null

echo "Build for valgrind..."

make CFLAGS="$2 $CFLAGS $4" EXTRALIBS="$5" test LTC_DEBUG=1 1>gcc_1.txt 2>gcc_2.txt

echo "Run tests with valgrind..."

for i in `seq 1 10` ; do sleep 300 && echo "Valgrind tests in Progress..."; done &
alive_pid=$!

valgrind --error-exitcode=666 --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all ./test 1>test_std.txt 2>test_err.txt || { kill $alive_pid; echo "Valgrind failed"; exit 1; }

kill $alive_pid
