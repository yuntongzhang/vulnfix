#!/bin/bash

git clone https://github.com/coreutils/coreutils.git source
cd source/
git checkout 68c5eec

# for AFL argv fuzz
sed -i '1283i #include "/home/yuntong/vulnfix/thirdparty/AFL/experimental/argv_fuzzing/argv-fuzz-inl.h"' src/split.c
sed -i '1288i AFL_INIT_SET02("./split", "/home/yuntong/vulnfix/data/coreutils/gnubug_25003/dummy");' src/split.c
# avoid writing out a lot of files during fuzzing
sed -i '595i return false;' src/split.c
# not bulding man pages
sed -i '229d' Makefile.am

./bootstrap
export FORCE_UNSAFE_CONFIGURE=1 && ./configure
make CFLAGS="-Wno-error -fsanitize=address -fsanitize=undefined -g" CXXFLAGS="-Wno-error -fsanitize=address -fsanitize=undefined -g" -j10

cp src/split ../
