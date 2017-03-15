#!/bin/bash

# output version
bash printinfo.sh

make clean > /dev/null

echo "checking..."
./helper.pl --check-source --check-makefiles --check-defines|| exit 1

exit 0

# $Source$
# $Revision$
# $Date$
