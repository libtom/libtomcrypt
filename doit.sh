#!/bin/sh

_includedir=/opt/local/include
_libdir=/opt/local/lib

set -x

optflags="-O2 -g -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -m64 -mtune=generic"

export CC=x86_64-apple-darwin15-gcc-6.1.0
export CFLAGS="${optflags} -I${_includedir}/libtommath -DLTM_DESC -DUSE_LTM"

make -f makefile clean

# -- %build

make -j4 LT=glibtool INCPATH="${_includedir}" LIBPATH="${_libdir}" EXTRALIBS="-L${_libdir} -ltommath" -f makefile.shared

#make INCPATH="${_includedir}" LIBPATH="${_libdir}" -f makefile docs

# -- %check

make -j4 INCPATH="${_includedir}" LIBPATH="${_libdir}" EXTRALIBS="-L${_libdir} -ltommath" test
./test

# -- %install

sudo make -j4 INCPATH="${_includedir}" LIBPATH="${_libdir}" EXTRALIBS="-L${_libdir} -ltommath" -f makefile.shared DESTDIR="" install

