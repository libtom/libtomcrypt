#!/bin/sh

set -e

if [ -d /usr/local/share/aclocal ]; then
  ACLOCAL_DIR=/usr/local/share/aclocal
elif [ -d /opt/local/share/aclocal ]; then
  ACLOCAL_DIR=/opt/local/share/aclocal
elif [ -d /usr/share/aclocal ]; then
  ACLOCAL_DIR=/usr/share/aclocal
fi

if [ `uname -s` = Darwin ]; then
  glibtoolize --automake --copy
else
  libtoolize --automake --copy
fi

autoheader
aclocal -I m4
automake --add-missing --copy
autoconf
