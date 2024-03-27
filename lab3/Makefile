.PHONY: all clean run

CC = gcc
CFLAGS = -Wall -g
SHARED_LIB = -lmaze -L. -Wl,-rpath,$(shell pwd)

SOURCE = maze.c
TARGET = maze

LIB = libmaze_dummy.c
LIBFLAGS = -Wall -shared -fPIC
LIBTARGET = libmaze.so

PRELOAD_LIB = libsolver.c
PRELOAD_LIBTARGET = libsolver.so

all: $(LIBTARGET) $(TARGET) $(PRELOAD_LIBTARGET)

$(TARGET): $(SOURCE) $(LIBTARGET)
	$(CC) $(CFLAGS) -o $@ $< $(SHARED_LIB)

$(LIBTARGET): $(LIB)
	$(CC) $(LIBFLAGS) -o $@ $^

$(PRELOAD_LIBTARGET): $(PRELOAD_LIB)
# 	remember to link for dlopen, mprotect
	$(CC) $(LIBFLAGS) -g -ldl -lc -o $@ $^

run: all
	LD_PRELOAD=./libsolver.so ./maze

clean:
	rm -f $(TARGET) $(LIBTARGET) $(PRELOAD_LIBTARGET)
