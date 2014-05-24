#!/bin/bash

if [ $# -lt 3 ]
then
  echo "usage is: ${0##*/} <path to coverity scan> <path to libtommath include files> <path to libtommath.a>"
  echo "e.g. \"${0##*/} \"/usr/local/bin/coverity\" \"/path/to/libtommath\" /path/to/libtommath/libtommath.a\""
  exit -1
fi

PATH=$PATH:$1/bin

make clean
CFLAGS=" -O2 -DUSE_LTM -DLTM_DESC -I${2}" EXTRALIBS="${3}" cov-build --dir cov-int  make -f makefile -j3 IGNORE_SPEED=1 1>gcc_1.txt

# zipup everything
tar caf libtomcrypt.lzma cov-int

mytoken=$(cat .coverity_token)
mymail=$(cat .coverity_mail)
myversion=$(git describe --dirty)

curl --form project=libtomcrypt \
  --form token=${mytoken} \
  --form email=${mymail} \
  --form file=@libtomcrypt.lzma \
  --form version='"${myversion}"' \
  --form description='"libtomcrypt version ${myversion}"' \
  https://scan.coverity.com/builds?project=libtomcrypt
