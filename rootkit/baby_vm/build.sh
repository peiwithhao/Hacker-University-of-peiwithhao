#!/bin/bash
cp ../baby_hook/pwhrootkit.ko ./fs_extract/
cd fs_extract
find . | cpio -o --format=newc >../rootfs.cpio
