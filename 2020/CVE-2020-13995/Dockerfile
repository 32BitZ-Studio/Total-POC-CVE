# We build in two stages. First installs all dependencies needed
# to compile and run the binary. Second has only dependencies needed
# to run the binary.
FROM debian:11-slim as builder

# build-essential: compilers to build from source
# gcc-multilib: to run the 32-bit extract75 binary
# python3 and python3-pip: to rewrite our executable errno (see below)
# libc6-dbg: used for Mayhem advanced triage
# vim and gdb: debugging
# curl: to install gdb extension gef (https://hugsy.github.io/gef/install/)
# procps: installs ps for gef 
# file: installs file for gef 
RUN apt-get update && apt-get install -y build-essential libc6-dbg python3 python3-pip libc6-i386 vim gdb curl file procps gcc-multilib nano

# Install gef, the gdb extension that makes hacking easier.
RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Make sure we have the right locale for gef
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

# Copy in the original files. Always good to have handy unedited versions for 
# comparison
WORKDIR /originals
COPY originals .

# The original binaries do not run. This shows a trick when a symbol isn't found.
# In this case, the original extract75 depends on ancient errno behavior.
# We use lief to rewrite the binary by changing `errno` to point to `stdin`. 
# That way all symbols are resolved. Neat trick, huh?
WORKDIR /binaries
RUN tar xf /originals/extract_redhat_linux.tar
COPY scripts/rewrite_errno.py .
RUN pip3 install lief
RUN ./rewrite_errno.py
RUN chmod 755 extract75-patched

# Let's build from source as well. This will be easier for the labs.
# You can always go back through with the binaries afterwords.
WORKDIR /src
RUN tar xf /originals/extract_unix_source.tar

# Rewrite old code to compile with the modern errno
RUN sed -i '1s/^/#include <errno.h>\n/' j_io.c
RUN sed -i '1s/^/#include <errno.h>\n/' j_string.c

# Clear out the CFLAGS definition in the makefile so it doesn't
# override our settings when we call 'make'.
RUN sed -i 's/CFLAGS= -DUSE_MD5 -g//' makefile

# The included makefile doesn't actually use CFLAGS so we'll fix that.
RUN sed -i 's/ -g -o / -g $(CFLAGS) -o /' makefile

# Make sure we build it like it was originally built. That is,
# without any defenses.
RUN make CFLAGS="-DUSE_MD5 -g -m32 -no-pie -Wa,--execstack -fno-stack-protector"

# extract75 requires DFFPATH be set. We're given all files, though :)
ENV DFFPATH "/src/"

# Copy in our one example seed file. This will reduce Mayhem analysis time,
# often significantly. 
# (Mayhem uses /testsuite as the default test suite if it exists.)
COPY testsuite /testsuite

# We typically include crashing cases in /exploit. It's just an habit.
COPY exploit /exploit

# We are going to start the image with our host directory mounted here.
RUN echo "set number" > /root/.vimrc
WORKDIR /mnt
