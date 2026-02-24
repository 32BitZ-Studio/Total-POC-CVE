#!/bin/bash

../toolchain/bin/aarch64-linux-android-gcc-4.9 -w -pie x.c  -o a.out
adb push a.out /sdcard/
adb shell "su -c 'cp /sdcard/a.out /data/a.out'"
