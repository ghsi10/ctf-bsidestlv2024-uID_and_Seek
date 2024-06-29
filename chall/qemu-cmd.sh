#!/bin/bash

qemu-system-x86_64 \
  -m 128M \
  -nographic \
  -kernel ./bzImage \
  -append 'console=ttyS0 loglevel=3 oops=panic panic=1 kaslr' \
  -monitor /dev/null \
  -initrd ./initramfs.cpio.gz \
  -cpu qemu64