#!/bin/bash
[ "$TRAVIS_CI" != "" ] && sudo apt-get install clang -y -qq || true

# output version
bash printinfo.sh

make clean > /dev/null

scan-build make -f makefile.unix all
