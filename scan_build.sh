#!/bin/bash
if [ "$TRAVIS_CI" != "" ] && [ -z "$(echo $CC | grep "clang")" ]; then
    echo "no clang detected, early exit success"
    exit 0
fi

if [ "$#" = "5" -a "$(echo $3 | grep -v 'makefile[.]')" = "" ]; then
    echo "only run $0 for the regular makefile, early exit success"
    exit 0
fi

# output version
bash printinfo.sh

make clean > /dev/null

scan_build=$(which scan-build)
[ -z "$scan_build" ] && scan_build=$(find /usr/bin/ -name 'scan-build-*' | sort -nr | head -n1) || true
[ -z "$scan_build" ] && { echo "couldn't find clang scan-build"; exit 1; } || echo "run $scan_build"
$scan_build --status-bugs make -f makefile.unix all CFLAGS="$2" EXTRALIBS="$5"
