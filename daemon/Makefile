CC = gcc
CFLAGS = -Wall -Wextra

daemon: daemon.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean
clean:
	-rm daemon
