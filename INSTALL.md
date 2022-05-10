# Install

## Docker

There is a docker image for VulnFix, in which the tool and dependency has been built:

```
docker pull yuntongzhang/vulnfix:tool
docker run -it --memory=30g --name vulnfix yuntongzhang/vulnfix:tool
```
Inside the container, optionally do a `git pull` to update any source changes.

## Install from source

If in any case that installing from source is preferred, the following steps serve as a reference.

Tested on ubuntu-18.

### Clone

```bash
git clone --recurse-submodules <git url of this project>
```

### Build

First, install latest `elfutils` from source:

```bash
curl -o elfutils-latest.tar.bz2 https://sourceware.org/elfutils/ftp/elfutils-latest.tar.bz2
tar -xf elfutils-latest.tar.bz2
cd elfutils-0.185/
sudo apt install pkg-config zlib1g zlib1g-dev autoconf libtool cmake
./configure --disable-debuginfod --disable-libdebuginfod
make
sudo make install
```

Now, install the other pre-requisite libraries:

```bash
sudo apt install python3-pip gdb default-jdk m4 xxd clang llvm
```

Note: for VulnFix to work properly with `clang`-compiled binaries, make sure
`llvm-symbolizer` is on PATH.

Optionally install other libraries for building the benchmark programs:

```bash
sudo apt install flex bison autopoint gperf texinfo libjpeg-dev nasm libass-dev
libmp3lame-dev dh-autoreconf unzip libopus-dev libtheora-dev libvorbis-dev
python3-dev python-dev clang-10
```

Next, install python3 libraries:

```bash
python3.8 -m pip install toml pyparsing z3-solver libclang
python3 -m pip install toml pyparsing
```

Finally, build project at project root directory with:

```bash
./build.sh
```

This will build VulnFix as well as the thirdparty dependencies.

Some of the code uses absolute path names. Before running, please change all
occurences of `/home/yuntong/vulnfix/` to the correct root directory of this project.
