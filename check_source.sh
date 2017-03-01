#!/bin/bash

# output version
bash printinfo.sh

make clean > /dev/null

if [ -f check-source.pl ] ; then
  echo "checking white spaces..."
  perl check-source.pl || exit 1
fi

exit 0

# $Source$
# $Revision$
# $Date$
