#!/bin/bash
git clone git://sourceware.org/git/binutils-gdb.git
mv binutils-gdb source
cd source/
git checkout 53f7e8ea7fad1fcff1b58f4cbd74e192e0bcbc1d

ASAN_OPTIONS=detect_leaks=0 CC=gcc CXX=g++ CFLAGS="-DFORTIFY_SOURCE=2 -fstack-protector-all -fsanitize=undefined,address -fno-omit-frame-pointer -ggdb -Wno-error" ./configure --disable-shared --disable-gdb --disable-libdecnumber --disable-readline --disable-sim LIBS='-ldl -lutil'

ASAN_OPTIONS=detect_leaks=0 make CFLAGS="-ldl -lutil -fsanitize=address -fsanitize=undefined -g" CXXFLAGS="-fsanitize=address -fsanitize=undefined -ldl -lutil -g" LDFLAGS=" -ldl -lutil -fsanitize=address -fsanitize=undefined" -j10

cp binutils/readelf ../

cd ../
