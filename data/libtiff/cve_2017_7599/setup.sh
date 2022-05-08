#!/bin/bash

git clone https://github.com/vadz/libtiff.git
mv libtiff source
cd source/
git checkout 3cfd62d

./configure
make CFLAGS="-fsanitize=float-cast-overflow,address -static -ggdb" CXXFLAGS="-fsanitize=float-cast-overflow,address -static -ggdb" LDFLAGS="-fsanitize=float-cast-overflow,address" -j10

cp tools/tiffcp ../
