.PHONY: all clean run

CC = gcc
CFLAGS = -Wall -g

SOURCE = logger.c
TARGET = logger

LIBFLAGS = -Wall -shared -fPIC
PRELOAD_LIB = libinject.c
PRELOAD_LIBTARGET = logger.so

all: $(TARGET) $(PRELOAD_LIBTARGET)

$(TARGET): $(SOURCE) $(LIBTARGET)
	$(CC) $(CFLAGS) -o $@ $<

$(PRELOAD_LIBTARGET): $(PRELOAD_LIB)
# 	remember to link for dlopen
	$(CC) $(LIBFLAGS) -g -ldl -lc -o $@ $<

run: all
	./logger

clean:
	rm -f $(TARGET) $(PRELOAD_LIBTARGET)
