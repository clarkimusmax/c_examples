# Description
Simple TLS Client using MBED TLS static libraries.  

Based on this example: https://github.com/ARMmbed/mbedtls/blob/development/programs/ssl/ssl_client1.c

# Build
You will need to download the mbedtls source and build the static libraries. 

Simple steps to get these static libs (alternatively, you can use the most 
current version from https://tls.mbed.org, just change the version numbers 
below):

1) Download the source:
`wget https://tls.mbed.org/download/mbedtls-2.13.0-apache.tgz`

2) Extract it in your project dir:
`tar -xzf mbedtls-2.13.0-apache.tgz`

3) Build the libraries:
`cd mbedtls-2.13.0; make`

# Usage
'./tls_client [IPv4 Address] [Port]'

You can test the client with the included Python HTTP/S server.  The server 
takes no options but can be modified to change the listening port.
`./https_server.py`
