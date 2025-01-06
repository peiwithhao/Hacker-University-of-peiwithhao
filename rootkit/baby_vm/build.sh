#!/bin/bash
cd fs_extract
find . | cpio -o --format=newc >../rootfs.cpio
