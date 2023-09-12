#!/bin/sh
set -e

git clone https://github.com/plougher/squashfs-tools

patch -p0 <encode_decode.patch

cd squashfs-tools/squashfs-tools
make 
