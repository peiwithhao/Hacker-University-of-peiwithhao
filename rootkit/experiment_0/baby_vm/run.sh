#!/bin/sh
qemu-system-x86_64 \
    -m 1024M \
    -kernel ./bzImage \
    -initrd ./rootfs.cpio \
    -append "root=/dev/ram console=ttyS0 oops=panic panic=1 loglevel=0 quiet nokaslr nopti" \
    -cpu kvm64,+smep \
    -smp cores=2,threads=1 \
    -netdev user,id=t0 \
    --enable-kvm \
    -nographic \
    -no-reboot \
    -s
