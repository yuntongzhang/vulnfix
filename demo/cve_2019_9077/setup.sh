#!/bin/bash
git clone git://sourceware.org/git/binutils-gdb.git source
cd source/
git checkout c72e75a64030b0f6535a80481f37968ad55c333a

CC=gcc CXX=g++ CFLAGS="-DFORTIFY_SOURCE=2 -fstack-protector-all -fsanitize=undefined,address -fno-omit-frame-pointer -ggdb -Wno-error" ./configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim LIBS='-ldl -lutil'

ASAN_OPTIONS=detect_leaks=0 make CFLAGS="-ldl -lutil -fsanitize=address -fsanitize=undefined -g" CXXFLAGS="$CFLAGS" LDFLAGS=" -ldl -lutil -fsanitize=address -fsanitize=undefined" -j10

cp binutils/readelf ../

cd ../
