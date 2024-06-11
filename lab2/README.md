
simply work with `make`

For cross-compilation, use `make ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu-` instead

To run the code, do the following steps:

1. run command ./unzip.sh to extract the compressed kernel
2. make install in the maze directory
3. run command ./zip.sh to compress the kernel back to a qemu recognizable file format
4. run command ./qemu.sh to start the VM to run the kernel module

There is a prelab to get familiar with kernel module development.
