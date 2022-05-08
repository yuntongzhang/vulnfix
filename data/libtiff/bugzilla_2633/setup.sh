#!/bin/bash

git clone https://github.com/vadz/libtiff.git
mv libtiff source
cd source/
git checkout f3069a5

./configure
make CFLAGS="-static -fsanitize=address -fsanitize=undefined -g" CXXFLAGS="-static -fsanitize=address -fsanitize=undefined -g" -j10

cp tools/tiff2ps ../
