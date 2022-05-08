#!/bin/bash

git clone https://gitlab.gnome.org/GNOME/libxml2.git
mv libxml2 source
cd source/
git checkout 4ea74a44

./autogen.sh
make CFLAGS="-static -fsanitize=address -g" CXXFLAGS="-static -fsanitize=address -g" LDFLAGS="-fsanitize=address" -j10

cp ./xmllint ../
