#!/bin/bash
unzip source.zip
cd source/

autoreconf -i
./configure
make CFLAGS="-static -fsanitize=address -g" CXXFLAGS="-static -fsanitize=address -g" -j10

cp src/appl/imginfo ../
