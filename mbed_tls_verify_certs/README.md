# Description
Simple MBEDTLS Client & Server implementing certificate verification

Based on this and other MBED TLS documentation or source examples:
<https://github.com/ARMmbed/mbedtls/blob/development/programs/ssl/>

# Build
You will need to download the mbedtls source and build it. This can be done 
manually (<https://tls.mbed.org>)or by running the included script:
`download_current_mbedtls.sh` .

1. Download the source (requires curl): 
`./download_current_mbedtls.sh`

4. Build it with Make: 
``` `make -j `nproc` ```

# Usage
* Start by generating keys and certificates for a CA, server, and client:
`./gen_certs.sh`

* Run the server
`./tls_server [Port]`

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
