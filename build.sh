#!/bin/bash

if [ -t 1 ]
then
    RED="\033[31m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    BOLD="\033[1m"
    OFF="\033[0m"
else
    RED=
    GREEN=
    YELLOW=
    BOLD=
    OFF=
fi

set -e

ROOT=`pwd`

# STEP (1): build e9patch
pushd $ROOT/thirdparty

if [ ! -x e9patch/e9patch ]
then
    echo -e "${YELLOW}$0${OFF}: building e9patch..."
    pushd e9patch
    ./build.sh
    popd
    echo -e "${YELLOW}$0${OFF}: e9patch has been built!"
else
	echo -e "${YELLOW}$0${OFF}: using existing e9patch..."
fi

# STEP (2): build cvc5
if [ ! -x cvc5/build/bin/cvc5 ]
then
    echo -e "${YELLOW}$0${OFF}: building cvc5..."
    pushd cvc5
    ./configure.sh --auto-download
    cd ./build
    make -j`nproc`
    # make check
    cd ..
    popd
    echo -e "${YELLOW}$0${OFF}: cvc5 has been built!"
else
    echo -e "${YELLOW}$0${OFF}: using existing cvc5..."
fi

# STEP (3): build daikon
if [ ! -e daikon/daikon.jar ]
then
    echo -e "${YELLOW}$0${OFF}: setting up daikon env vars..."
    # daikon requires some env vars to be setup
    echo 'export DAIKONDIR=/home/yuntong/vulnfix/thirdparty/daikon' >> ~/.bashrc
    echo 'source $DAIKONDIR/scripts/daikon.bashrc' >> ~/.bashrc
    source ~/.bashrc
    echo -e "${YELLOW}$0${OFF}: building daikon..."
    pushd daikon
    make daikon.jar
    popd
    echo -e "${YELLOW}$0${OFF}: daikon has been built!"
else
    echo -e "${YELLOW}$0${OFF}: using existing daikon..."
fi

# STEP (4): build AFL
echo -e "${YELLOW}$0${OFF}: building AFL..."
pushd AFL
make
popd
echo -e "${YELLOW}$0${OFF}: AFL has been built!"

popd

# STEP (5): setting symlinks for e9patch
pushd $ROOT/lib
echo -e "${YELLOW}$0${OFF}: setting up symlinks..."
E9_DIR=$ROOT/thirdparty/e9patch
ln -f -s $E9_DIR/e9patch e9patch
ln -f -s $E9_DIR/e9tool e9tool
ln -f -s $E9_DIR/e9compile.sh e9compile.sh
ln -f -s $E9_DIR/examples/stdlib.c stdlib.c
echo -e "${YELLOW}$0${OFF}: finished setting up symlinks!"

# STEP (6): build own libraries
echo -e "${YELLOW}$0${OFF}: building other libraies..."
make
strip e9AFLPlugin.so
chmod a-x e9AFLPlugin.so
chmod a-x afl-rt
chmod a-x afl_mark
strip e9afl
echo -e "${YELLOW}$0${OFF}: other libraries has been built!"
popd

echo -e "${YELLOW}$0${OFF}: build finished."
