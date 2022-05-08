#!/bin/bash

# download libarchive source (v3.2.0)
wget https://libarchive.org/downloads/libarchive-3.2.0.zip
unzip libarchive-3.2.0.zip
rm libarchive-3.2.0.zip
mv libarchive-3.2.0 source

# compile bsdtar
#   w/o OPENSSL : type inconsistency introduced around v1.1.0
#   w/  UBSAN   : to check exploit
cd source/
./configure --without-openssl
# do not include other ubsan to avoid a NULL error which is always caught
make CFLAGS="-fsanitize=address -fsanitize=signed-integer-overflow -static -ggdb" CXXFLAGS="-fsanitize=address -fsanitize=signed-integer-overflow -static -ggdb" LDFLAGS="-fsanitize=address -fsanitize=signed-integer-overflow" -j10

cp ./bsdtar ../
