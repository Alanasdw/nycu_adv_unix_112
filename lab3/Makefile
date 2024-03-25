.PHONY: all clean

CC = gcc
CFLAGS = -Wall -g
SHARED_LIB = -lmaze -L. -Wl,-rpath,$(shell pwd)

SOURCE = maze.c
TARGET = maze

LIB = libmaze_dummy.c
LIBFLAGS = -Wall -shared -fPIC
LIBTARGET = libmaze.so


all: $(LIBTARGET) $(TARGET)

$(TARGET): $(SOURCE) $(LIBTARGET)
	$(CC) $(CFLAGS) -o $@ $< $(SHARED_LIB)

$(LIBTARGET): $(LIB)
	$(CC) $(LIBFLAGS) -o $@ $^

clean:
	rm -f $(TARGET) $(LIBTARGET)
