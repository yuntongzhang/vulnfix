#!/bin/bash

git clone https://github.com/libjpeg-turbo/libjpeg-turbo.git
mv libjpeg-turbo source
cd source/
git checkout 4f24016

autoreconf -fiv
./configure
make CFLAGS="-static -fsanitize=address -fsanitize=undefined -g" CXXFLAGS="-static -fsanitize=address -fsanitize=undefined -g" -j10

cp ./djpeg ../
