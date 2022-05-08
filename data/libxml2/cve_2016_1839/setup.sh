#!/bin/bash

git clone https://gitlab.gnome.org/GNOME/libxml2.git
mv libxml2 source
cd source/
git checkout db07dd61

./autogen.sh
make CFLAGS="-static -fsanitize=address -fsanitize=undefined -g" CXXFLAGS="-static -fsanitize=address -fsanitize=undefined -g" -j10

cp ./xmllint ../
