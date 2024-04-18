.PHONY: all clean run

CC = gcc
CFLAGS = -Wall -g

SOURCE = logger.c
TARGET = logger

LIBFLAGS = -Wall -shared -fPIC
PRELOAD_LIB = libinject.c
PRELOAD_LIBTARGET = logger.so

PLAYGROUND_FILE = file.txt

all: $(TARGET) $(PRELOAD_LIBTARGET) $(PLAYGROUND_FILE)

$(PLAYGROUND_FILE):
	touch $@

$(TARGET): $(SOURCE) $(LIBTARGET)
	$(CC) $(CFLAGS) -o $@ $<

$(PRELOAD_LIBTARGET): $(PRELOAD_LIB)
# 	remember to link for dlopen
	$(CC) $(LIBFLAGS) -g -ldl -lc -o $@ $<

clean:
	rm -f $(TARGET) $(PRELOAD_LIBTARGET) $(PLAYGROUND_FILE)
