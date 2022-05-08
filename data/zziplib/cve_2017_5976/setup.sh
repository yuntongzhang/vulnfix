#!/bin/bash

git clone https://github.com/gdraheim/zziplib.git
mv zziplib source
cd source/
git checkout 3a4ffcd
cd docs/
wget https://github.com/LuaDist/libzzip/raw/master/docs/zziplib-manpages.tar
cd ../

./configure
make CFLAGS="-static -fsanitize=address -g" CXXFLAGS="-static -fsanitize=address -g" -j10

version_dir="$(uname -s)_$(uname -r)_$(uname -m).d"
# finalize the parameterized config file
sed -i "s/<parameter-dir>/$version_dir/g" ../config

cp $version_dir/bins/unzzipcat-mem ../
