#!/bin/bash
gdb -ex "directory /home/peiwithhao/Kernel/kernel_source/linux-6.3.4" \
    -ex "file vmlinux" \
    -ex "target remote localhost:1234"
