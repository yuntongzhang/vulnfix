#!/bin/bash

git clone https://github.com/libming/libming.git
mv libming source
cd source/
git checkout c4d20b1

./autogen.sh
./configure --disable-freetype
make CFLAGS="-static -fsanitize=address -fsanitize=undefined -g" CXXFLAGS="-static -fsanitize=address -fsanitize=undefined -g"

cp util/swftophp ../
