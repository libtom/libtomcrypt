#!/bin/bash

./helper.pl --update-makefiles || exit 1

makefiles=(makefile makefile_include.mk makefile.shared makefile.unix makefile.mingw makefile.msvc)
vcxproj=(libtomcrypt.vcxproj)

if [ $# -eq 1 ] && [ "$1" == "-c" ]; then
  git add ${makefiles[@]} ${vcxproj[@]} doc/Doxyfile && git commit -m 'Update makefiles'
fi

exit 0

# ref:         $Format:%D$
# git commit:  $Format:%H$
# commit time: $Format:%ai$
