#!/bin/bash
git clone git://sourceware.org/git/binutils-gdb.git
mv binutils-gdb source
cd source/
git checkout 11855d8a1f11b102a702ab76e95b22082cccf2f8

CC=gcc CXX=g++ CFLAGS="-DFORTIFY_SOURCE=2 -fstack-protector-all -fsanitize=address -fno-omit-frame-pointer -ggdb -Wno-error" CXXFLAGS="$CFLAGS" ./configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim LIBS='-ldl -lutil'

make CFLAGS="-ldl -lutil -fsanitize=address -ggdb" CXXFLAGS="-fsanitize=address -ldl -lutil -ggdb" LDFLAGS=" -ldl -lutil -fsanitize=address" -j10

cp binutils/nm-new ../

cd ../
