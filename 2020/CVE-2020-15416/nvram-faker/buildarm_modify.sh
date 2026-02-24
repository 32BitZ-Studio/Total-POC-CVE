#!/bin/sh

export ARCH=arm
TARGET=$1

# Sets up toolchain environment variables for arm toolchain
# Tested against armv7-eabihf, glibc from toolchains.free-electrons.com

warn()
{
	echo "$1" >&2
}

if [ ! -z $(which arm-linux-gnueabi-gcc-5) ];
then
	export CC=$(which arm-linux-gnueabi-gcc-5)
else
	warn "Not setting CC: can't locate arm-linux-gnueabi-gcc."
fi

if [ ! -z $(which arm-linux-gnueabi-ld-5) ];
then
	export LD=$(which arm-linux-gnueabi-ld-5)
else
	warn "Not setting LD: can't locate arm-linux-gnueabi-ld."
fi

if [ ! -z $(which arm-linux-gnueabi-ar-5) ];
then
	export AR=$(which arm-linux-gnueabi-ar-5)
else
	warn "Not setting AR: can't locate arm-linux-gnueabi-ar."
fi


if [ ! -z $(which arm-linux-gnueabi-strip-5) ];
then
	export STRIP=$(which arm-linux-gnueabi-strip-5)
else
	warn "Not setting STRIP: can't locate arm-linux-gnueabi-strip."
fi

if [ ! -z $(which arm-linux-gnueabi-nm-5) ];
then
	export NM=$(which arm-linux-gnueabi-nm-5)
else
	warn "Not setting NM: can't lcoate arm-linux-gnueabi-nm."
fi


make $TARGET || exit $?
