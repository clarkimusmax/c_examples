CC = gcc

INC_DIR = include
MBED_INC_DIR = mbedtls-2.13.0/include/

CFLAGS = -I $(MBED_INC_DIR) -I $(INC_DIR) -Wall -Wextra -s

# This needs to point to the mbedtls TLS, X509, and crypto static libraries
#
# Simple steps to get these static libs (alternatively, you can use the most 
# current version from https://tls.mbed.org, just change the version numbers 
# below):
# 	1) Download the source:
# 		wget https://tls.mbed.org/download/mbedtls-2.13.0-apache.tgz
# 	2) Extract it in your project dir:
# 		tar -xzf mbedtls-2.13.0-apache.tgz
# 	3) Build the libraries:
# 		cd mbedtls-2.13.0; make
MBED_LIBS = mbedtls-2.13.0/library/libmbedtls.a \
	    mbedtls-2.13.0/library/libmbedx509.a \
	    mbedtls-2.13.0/library/libmbedcrypto.a

.PHONY: all
all: tls_client

tls_client: tls_client.o $(MBED_LIBS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	-rm *.o tls_client
