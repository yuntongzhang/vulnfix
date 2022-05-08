#!/bin/bash
git clone git://sourceware.org/git/binutils-gdb.git
mv binutils-gdb source
cd source/
git checkout 515f23e63c0074ab531bc954f84ca40c6281a724

ASAN_OPTIONS=detect_leaks=0 CC=gcc CXX=g++ CFLAGS="-DFORTIFY_SOURCE=2 -fno-omit-frame-pointer -fsanitize=address -ggdb -Wno-error" CXXFLAGS="$CFLAGS" ./configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim LIBS='-ldl -lutil'

ASAN_OPTIONS=detect_leaks=0 make CFLAGS="-ldl -lutil -fsanitize=address -ggdb" CXXFLAGS="-fsanitize=address -ldl -lutil -ggdb" LDFLAGS=" -ldl -lutil -fsanitize=address" -j10

cp binutils/nm-new ../

cd ../
