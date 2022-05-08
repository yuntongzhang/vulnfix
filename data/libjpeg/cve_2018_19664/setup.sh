#!/bin/bash

git clone https://github.com/libjpeg-turbo/libjpeg-turbo.git
mv libjpeg-turbo source
cd source/
git checkout beefb62

export CXXFLAGS="-fsanitize=address -fsanitize=undefined -g"
export CFLAGS="-fsanitize=address -fsanitize=undefined -g"
cmake -DCMAKE_BUILD_TYPE=Debug CMakeLists.txt
make -j10

cp ./djpeg ../
