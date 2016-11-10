#! /bin/sh
set -x

./autogen.sh
./configure --enable-static --sysconfdir=/etc
make && sudo make install
