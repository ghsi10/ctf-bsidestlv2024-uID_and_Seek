#!/bin/sh

cd fs
gcc -o exploit -static ../exp.c
find . -print0 | cpio --null -ov --format=newc > ../initramfs.cpio
gzip -c ../initramfs.cpio > ../initramfs.cpio.gz
rm ../initramfs.cpio