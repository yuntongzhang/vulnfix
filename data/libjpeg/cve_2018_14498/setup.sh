#!/bin/bash

# needed to remove `register` modifiers for all variables in the buggy function
# so use the zip file instead of clone
unzip source.zip
cd source/

export CXXFLAGS="-O0 -fsanitize=address -fsanitize=undefined"
export CFLAGS="-O0 -fsanitize=address -fsanitize=undefined"
# Use the debug build option
# (non-debug option uses O3, and makes converting fix location from
# line number to binary address very hard and inaccurate)
cmake -DCMAKE_BUILD_TYPE=Debug CMakeLists.txt
make -j10

cp ./cjpeg ../
