#!/bin/bash

unzip source.zip
cd source/

./configure CC=clang-10 CXX=clang++-10
make CFLAGS="-static -fsanitize=address,implicit-conversion -g" CXXFLAGS="-static -fsanitize=address,implicit-conversion -g" LDFLAGS=" -fsanitize=address,implicit-conversion" -j10

cp src/potrace ../
