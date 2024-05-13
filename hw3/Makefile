.PHONY: all clean

CC = gcc
CFLAGS = -Wall -g

SOURCE = sdb.c 
TARGET = $(SOURCE:.c=)

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm $(TARGET)
