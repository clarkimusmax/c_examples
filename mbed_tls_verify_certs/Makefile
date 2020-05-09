CC = gcc

# MBED_DIR needs to point to the MBED TLS code directory
#
# Simple steps to get and build MBED TLS
# Download the current version from https://tls.mbed.org (be sure to change
#  the version numbers below):
# 	1) Download the source:
# 		wget https://tls.mbed.org/download/mbedtls-2.16.6-apache.tgz
# 	2) Extract it in your project dir:
# 		tar -xzf mbedtls-2.16.6-apache.tgz
# 	3) Build the libraries:
# 		cd mbedtls-2.16.6; make
MBED_DIR = mbedtls-2.16.6

MBED_INC_DIR = $(MBED_DIR)/include/

CFLAGS = -I $(MBED_INC_DIR) -I $(MBED_INC_DIR) -Wall -Wextra -s

MBED_LIBS = $(MBED_DIR)/library/libmbedtls.a \
	    $(MBED_DIR)/library/libmbedx509.a \
	    $(MBED_DIR)/library/libmbedcrypto.a

.PHONY: all
all: tls_client tls_server

tls_client: tls_client.o $(MBED_LIBS)
	$(CC) $(CFLAGS) -o $@ $^

tls_server: tls_server.o $(MBED_LIBS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	-rm *.o tls_client tls_server
