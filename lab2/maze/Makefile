
obj-m     += maze.o
ccflags-y += -DEXPORT_SYMTAB

all: maze.ko

maze.ko: maze.c
	make -C ../dist/modulebuild M=$(PWD) modules

clean:
	rm -f hello
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
	cp mazetest maze.ko ../rootfs/modules
