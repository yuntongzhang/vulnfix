#!/bin/bash

git clone https://github.com/coreutils/coreutils.git source
cd source/
git checkout 8d34b45

# for AFL argv fuzz
sed -i '1215i #include "/home/yuntong/vulnfix/thirdparty/AFL/experimental/argv_fuzzing/argv-fuzz-inl.h"' src/shred.c
sed -i '1220i AFL_INIT_SET03("./shred", "/home/yuntong/vulnfix/data/coreutils/gnubug_26545/dummy");' src/shred.c
# -u option can cause a lot of files to be writting to disk during fuzzing; disable that
sed -i '1260i break;' src/shred.c
# remove and recreate output so that it does not grow too big.
sed -i '1320i FILE* file_ptr = fopen(file[i], "w"); fclose(file_ptr);' src/shred.c
# not bulding man pages
sed -i '217d' Makefile.am

./bootstrap
export FORCE_UNSAFE_CONFIGURE=1 && ./configure
make CFLAGS="-Wno-error -fsanitize=address -ggdb" CXXFLAGS="-Wno-error -fsanitize=address -ggdb" LDFLAGS="-fsanitize=address" -j10

cp src/shred ../
