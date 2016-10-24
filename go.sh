#! /bin/sh
set -x

git submodule update --init
./autogen.sh
./configure --enable-static --sysconfdir=/etc
make && sudo make install
