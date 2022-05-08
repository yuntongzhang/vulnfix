#!/bin/bash

git clone https://github.com/libming/libming.git
mv libming source
cd source/
git checkout cc6a386

./autogen.sh
./configure --disable-freetype
make CFLAGS="-static -fsanitize=address -fsanitize=undefined -g" CXXFLAGS="-static -fsanitize=address -fsanitize=undefined -g"

cp util/listmp3 ../
