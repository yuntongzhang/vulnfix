#!/bin/bash
git clone git://sourceware.org/git/binutils-gdb.git
mv binutils-gdb source
cd source/
git checkout 7a31b38ef87d133d8204cae67a97f1989d25fa18

ASAN_OPTIONS=detect_leaks=0 CC=gcc CXX=g++ CFLAGS="-DFORTIFY_SOURCE=2 -fstack-protector-all -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer -g -Wno-error" CXXFLAGS="$CFLAGS" ./configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim LIBS='-ldl -lutil'

ASAN_OPTIONS=detect_leaks=0 make CFLAGS="-ldl -lutil -fsanitize=address -fsanitize=undefined -g" CXXFLAGS="-fsanitize=address -fsanitize=undefined -ldl -lutil -g" LDFLAGS=" -ldl -lutil -fsanitize=address -fsanitize=undefined" -j10

cp binutils/objdump ../

cd ../
