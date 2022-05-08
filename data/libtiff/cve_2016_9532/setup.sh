#!/bin/bash

git clone https://github.com/vadz/libtiff.git
mv libtiff source
cd source/
git checkout d651abc

./configure
# not using UBSAN as it triggers another bug in POC before the bug in this CVE
make CFLAGS="-static -fsanitize=address -g" CXXFLAGS="-static -fsanitize=address -g" -j10

cp tools/tiffcrop ../
