# Description
Simple MBEDTLS Client & Server implementing certificate verification

Based on this and other MBED TLS documentation or source examples:
<https://github.com/ARMmbed/mbedtls/blob/development/programs/ssl/>

# Build
You will need to download the mbedtls source and build the static libraries. 

Simple steps to get these static libs (alternatively, you can use the most 
current version from https://tls.mbed.org, just change the version numbers 
below and in the `Makefile`):

1. Download the source:
`wget https://tls.mbed.org/download/mbedtls-2.16.6-apache.tgz`

2. Extract it in your project dir:
`tar -xzf mbedtls-2.16.6-apache.tgz`

3. Build the libraries:
``` cd mbedtls-2.16.6; make -j `nproc`; cd .. ```

4. Build the TLS client and server:
``` `make -j `nproc` ```

# Usage
* Start by generating keys and certificates for a CA, server, and client:
`./gen_certs.sh`

* Run the server
`./tls_server [Port]

* Run the tls client
`./tls_client [Address] [Port]`

You can optionally test the client with the included Python HTTP/S server.
The python server takes no options but can be modified to change the listening
port.
`./https_server.py`

# TODO
* `getopt`
* Actual HTTP/S
* Print and/or log cert info
* Re-write `gen_certs.sh` using the MBED API
