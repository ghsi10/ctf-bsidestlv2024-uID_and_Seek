#!/bin/sh

mkdir fs
cd fs
cp ../initramfs.cpio.gz .
gunzip initramfs.cpio.gz
cpio -idm < initramfs.cpio
rm initramfs.cpio
