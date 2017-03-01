#!/bin/bash

makefiles=(makefile makefile.icc makefile.shared makefile.unix makefile.mingw)

function update_makefile() {
	perl filter.pl $1 tmplist
	sed -e 's/ *$//' < tmp.delme > $1
	rm -f tmp.delme
}

bash genlist.sh > tmplist

for i in "${makefiles[@]}"
do
  update_makefile "$i"
done

perl filter.pl makefile.msvc tmplist
sed -e 's/\.o /.obj /g' -e 's/ *$//' < tmp.delme > makefile.msvc
rm -f tmp.delme

rm -f tmplist

if [ $# -eq 1 ] && [ "$1" == "-c" ]; then
  git add ${makefiles[@]} makefile.msvc && git commit -m 'Update makefiles'
fi
