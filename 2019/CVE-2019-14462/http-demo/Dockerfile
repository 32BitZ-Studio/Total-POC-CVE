FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-system-x86 \
    && rm -rf /var/lib/apt/lists/*

COPY kernel-x86_64-pc99 /sel4-image/
COPY capdl-loader-image-x86_64-pc99 /sel4-image/

EXPOSE 8443

CMD qemu-system-x86_64 \
    -machine q35 \
    -cpu qemu64,+rdrand,+fsgsbase,+xsave,+xsaveopt \
    -m 512 \
    -nographic \
    -netdev user,id=net0,net=192.168.1.0/24,host=192.168.1.1,hostfwd=tcp::8443-192.168.1.10:443 \
    -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
    -kernel /sel4-image/kernel-x86_64-pc99 \
    -initrd /sel4-image/capdl-loader-image-x86_64-pc99
