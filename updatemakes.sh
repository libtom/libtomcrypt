#!/bin/bash

./helper.pl --update-makefiles || exit 1

makefiles=(makefile makefile.shared makefile.unix makefile.mingw makefile.msvc)
vcproj=(libtomcrypt_VS2008.vcproj libtomcrypt_VS2005.vcproj)

if [ $# -eq 1 ] && [ "$1" == "-c" ]; then
  git add ${makefiles[@]} ${vcproj[@]} && git commit -m 'Update makefiles'
fi

exit 0
