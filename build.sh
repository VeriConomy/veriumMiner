#!/bin/bash

if [ "$OS" = "Windows_NT" ]; then
    ./mingw64.sh
    exit 0
fi

make clean || echo clean

rm -f config.status
./autogen.sh

if [[ "$OSTYPE" == "darwin"* ]]; then
    ./nomacro.pl
    ./configure \
        CFLAGS="-march=native -O2 -Ofast -flto -DUSE_ASM -pg" \
        --with-crypto=/usr/local/opt/openssl \
        --with-curl=/usr/local/opt/curl
    make -j4
    strip cpuminer
    exit 0
fi

# Linux build

# Debian 7.7 / Ubuntu 14.04 (gcc 4.7+)
extracflags="$extracflags -Ofast -flto -fuse-linker-plugin -ftree-loop-if-convert-stores"

if [ ! "0" = `cat /proc/cpuinfo | grep -c avx` ]; then
    extracflags="$extracflags -march=native"
fi

./configure --with-crypto --with-curl CFLAGS="-O2 $extracflags -DUSE_ASM -pg"

make -j 4

strip -s cpuminer
