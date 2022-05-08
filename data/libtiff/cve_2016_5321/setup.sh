#!/bin/bash

unzip source.zip
cd source/

./configure
make CFLAGS="-static -fsanitize=address -fsanitize=undefined -g" CXXFLAGS="-static -fsanitize=address -fsanitize=undefined -g" LDFLAGS="-fsanitize=address -fsanitize=undefined" -j10

cp tools/tiffcrop ../
