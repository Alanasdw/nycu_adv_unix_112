#!/bin/bash

dir_name=rootfs

(cd $dir_name; find . | cpio -ov -H newc > ../$dir_name.cpio)
# mv $dir_name/$dir_name.cpio .
bzip2 $dir_name.cpio
mv $dir_name.cpio.bz2 dist/
