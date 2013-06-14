#!/bin/bash

bash genlist.sh > tmplist

perl filter.pl makefile tmplist
sed -e 's/ *$//' < tmp.delme > makefile
rm -f tmp.delme

perl filter.pl makefile.icc tmplist
sed -e 's/ *$//' < tmp.delme > makefile.icc
rm -f tmp.delme

perl filter.pl makefile.shared tmplist
sed -e 's/ *$//' < tmp.delme > makefile.shared
rm -f tmp.delme

perl filter.pl makefile.unix tmplist
sed -e 's/ *$//' < tmp.delme > makefile.unix
rm -f tmp.delme

perl filter.pl makefile.mingw tmplist
mv -f tmp.delme makefile.mingw

perl filter.pl makefile.msvc tmplist
sed -e 's/\.o /.obj /g' -e 's/ *$//' < tmp.delme > makefile.msvc
rm -f tmp.delme

rm -f tmplist
