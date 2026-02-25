#!/bin/sh

arm-linux-gnueabi-as bind_shell.s -o bind_shell.o && arm-linux-gnueabi-ld -N bind_shell.o -o bind_shell && arm-linux-gnueabi-strip bind_shell
rm bind_shell.o
