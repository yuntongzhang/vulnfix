#!/bin/bash
unzip source.zip
cd source/

autoreconf -i
./configure
make CFLAGS="-static -g -fsanitize=address -fsanitize=undefined" CXXFLAGS="-static -g -fsanitize=address -fsanitize=undefined" LDFLAGS="-fsanitize=address -fsanitize=undefined" -j10

cp src/appl/imginfo ../
