#!/bin/bash

if [ "$#" != "5" ]; then
    echo "Usage is: ${0} \"build_options\" \"<prepend CFLAGS>\" \"<makefile>\" \"<append CFLAGS>\" <math library to link to>"
    echo "CC=gcc ${0} \"build_options\" \" \" \"makefile\" \"-DUSE_LTM -DLTM_DESC -I../libtommath\" ../libtommath/libtommath.a"
    exit -1
fi

# output version
bash .ci/printinfo.sh

set -e

options=(
-DLTC_EASY
-DLTC_FORTUNA_RESEED_RATELIMIT_STATIC
-DLTC_FORTUNA_USE_ENCRYPT_ONLY
-DLTC_MECC_FP
-DLTC_NO_TABLES
-DLTC_NO_FAST
-DLTC_NO_STRUCT_PADDING
-DLTC_NO_ASM
-DLTC_NO_DEPRECATED_APIS
-DLTC_NO_ECC_TIMING_RESISTANT
-DLTC_NO_RSA_BLINDING
-DLTC_PTHREAD
-DLTC_SMALL_CODE
-DLTC_SMALL_STACK
)

make clean V=0
make pre_gen
for opt in ${options[@]}; do
  echo "Build: $opt"
  CFLAGS="$2 $CFLAGS $4 $opt" EXTRALIBS="$5" make -j$(nproc) -f $3 AMALGAM=1 all 1>>gcc_1.txt 2>>gcc_2.txt
  ./small
  make clean V=0
done

# we don't want LTC_EASY when running the tests now
unset 'options[0]'

echo "All: ${options[@]}"
CFLAGS="$2 $CFLAGS $4 ${options[@]}" EXTRALIBS="$5" make -j$(nproc) -f $3 AMALGAM=1 all 1>>gcc_1.txt 2>>gcc_2.txt
./test >test_std.txt 2>test_err.txt

exit 0
