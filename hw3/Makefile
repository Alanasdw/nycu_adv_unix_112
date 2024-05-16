.PHONY: all clean

CC = gcc
CFLAGS = -Wall -g

SOURCE = sdb.c 
TARGET = $(SOURCE:.c=)

LIBNAME = capstone
LIBPATH = -L/usr/lib/x86_64-linux-gnu/

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBPATH) -l$(LIBNAME)

clean:
	rm $(TARGET)
