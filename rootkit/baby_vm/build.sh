#!/bin/bash
cp ../baby_hide/pwhkit.ko ./fs_extract/
cd fs_extract
find . | cpio -o --format=newc >../rootfs.cpio
