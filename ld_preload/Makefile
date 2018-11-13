CC = gcc
CFLAGS = -Wall -Wextra -ggdb

.PHONY: all
all: main evil_lib.so

main: main.c
	$(CC) $(CFLAGS) -o $@ $<

evil_lib.so: evil_lib.c
	$(CC) $(CFLAGS) -shared -fPIC -Wl,-soname,evil_lib.so.6 -lc -ldl -o $@ $<

.PHONY: clean
clean:
	-rm main evil_lib.so
