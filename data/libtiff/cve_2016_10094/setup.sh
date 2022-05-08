#!/bin/bash

git clone https://github.com/vadz/libtiff.git
mv libtiff source
cd source/
git checkout b28076b

./configure
make CFLAGS="-static -fsanitize=address -fsanitize=undefined -g" CXXFLAGS="-static -fsanitize=address -fsanitize=undefined -g" -j10

cp tools/tiff2pdf ../
