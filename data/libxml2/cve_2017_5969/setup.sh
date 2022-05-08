#!/bin/bash

git clone https://gitlab.gnome.org/GNOME/libxml2.git
mv libxml2 source
cd source/
git checkout 362b3229

./autogen.sh
make CFLAGS="-static -fsanitize=address -g" CXXFLAGS="-static -fsanitize=address -g" LDFLAGS="-fsanitize=address" -j10

cp ./xmllint ../
