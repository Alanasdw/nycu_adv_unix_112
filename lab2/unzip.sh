#!/bin/bash

filename=./dist/rootfs

rm -rf rootfs

bzip2 -dk $filename.cpio.bz2
mv $filename.cpio.bz2 $filename.cpio.bz2.old
mkdir rootfs

(cd rootfs && cpio -id < ../$filename.cpio)

rm $filename.cpio
