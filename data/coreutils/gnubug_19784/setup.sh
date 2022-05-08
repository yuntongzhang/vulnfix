#!/bin/bash

git clone https://github.com/coreutils/coreutils.git source
cd source/
git checkout 658529a

# for AFL argv fuzz
sed -i '29i #include "/home/yuntong/vulnfix/thirdparty/AFL/experimental/argv_fuzzing/argv-fuzz-inl.h"' src/make-prime-list.c
sed -i '175i AFL_INIT_SET0("./make-prime-list");' src/make-prime-list.c

./bootstrap
export FORCE_UNSAFE_CONFIGURE=1 && ./configure && make CFLAGS="-Wno-error -fsanitize=address -g" src/make-prime-list

cp src/make-prime-list ../
